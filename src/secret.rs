// Webhook HMAC secret loading. The secret is the entire forge boundary, so the
// file path is treated as hostile: absolute-path requirement, no symlink at the
// final component, ancestor-chain lockdown, O_NOFOLLOW open, fstat-via-fd, and
// a hard read cap. See read_secret_file for the full rationale.

use std::path::{Path, PathBuf};

use crate::fs_security::{current_euid, darwin_acl, verify_ancestor_chain, O_NOFOLLOW};

pub(crate) const MAX_SECRET_FILE_BYTES: u64 = 4096;
// 16 bytes ≈ 128 bits of entropy if the secret is generated with `openssl
// rand` / similar. GitHub itself allows any length, but the secret is the
// entire forge boundary and a short one is a silent footgun.
pub(crate) const MIN_SECRET_BYTES: usize = 16;

pub(crate) fn load_secret() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let env_secret = std::env::var("GH_WEBHOOK_SECRET").ok();
    let env_file = std::env::var("GH_WEBHOOK_SECRET_FILE").ok();
    // Refuse ambiguity: silently picking one source over the other is a
    // footgun when an operator leaves a stale env value around. Force them
    // to remove one.
    if env_secret.is_some() && env_file.is_some() {
        return Err(
            "both GH_WEBHOOK_SECRET and GH_WEBHOOK_SECRET_FILE are set; unset one (the file is recommended — env vars are visible via /proc/PID/environ)".into(),
        );
    }
    let bytes = if let Some(s) = env_secret {
        eprintln!(
            "warning: loading webhook secret from GH_WEBHOOK_SECRET env var; prefer GH_WEBHOOK_SECRET_FILE (env vars are visible via /proc/PID/environ)"
        );
        if s.is_empty() {
            return Err("GH_WEBHOOK_SECRET is set but empty".into());
        }
        s.into_bytes()
    } else if let Some(path) = env_file {
        let path = PathBuf::from(path);
        let mut bytes = read_secret_file(&path)?;
        // Strip trailing CR/LF so secrets generated via shell redirection or
        // by tools that emit CRLF (Windows, some CI runners) work without
        // surprise. A misplaced \r in the key silently 401s every request.
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        if bytes.is_empty() {
            return Err("secret file is empty".into());
        }
        eprintln!("loaded webhook secret from {}", path.display());
        bytes
    } else {
        return Err("set GH_WEBHOOK_SECRET_FILE (recommended) or GH_WEBHOOK_SECRET".into());
    };
    if bytes.len() < MIN_SECRET_BYTES {
        return Err(format!(
            "webhook secret is {} bytes; refusing to start with anything shorter than {}",
            bytes.len(),
            MIN_SECRET_BYTES
        )
        .into());
    }
    Ok(bytes)
}

// Open, verify, and read the secret file in one pipeline. Splitting these
// across stat-then-read (the previous shape) was a TOCTOU footgun: a local
// attacker with write access to the parent dir could swap the file between
// the stat and the read, so the bytes loaded weren't the bytes verified.
//
// The defences now compose:
//   1. The user-given path must be absolute. Relative paths skip ancestor
//      verification, which would defeat the whole exercise.
//   2. symlink_metadata first — reject if the final component is a symlink.
//      canonicalize (next) would silently follow it.
//   3. canonicalize so verify_ancestor_chain walks real ancestors, the same
//      reasoning as prepare_spool().
//   4. verify_ancestor_chain on the canonical path: every parent up to /
//      must be a real dir owned by root or service uid, no group/other
//      write. A world-writable parent is the precondition the attack
//      depends on; locking it down removes the swap opportunity.
//   5. Open the canonical path with O_NOFOLLOW. After canonicalize this
//      shouldn't fire, but it closes the race where someone repoints a
//      component between canonicalize and open.
//   6. fstat via the opened fd, not stat by path. The fd is bound to one
//      inode; any subsequent swap of the path is irrelevant.
//   7. Read from the fd, hard-capped at MAX_SECRET_FILE_BYTES + 1 so a
//      concurrent writer growing the file can't bypass the size check
//      derived from fstat.
#[cfg(unix)]
pub(crate) fn read_secret_file(
    path: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if !path.is_absolute() {
        return Err(format!(
            "GH_WEBHOOK_SECRET_FILE must be an absolute path; got {}",
            path.display()
        )
        .into());
    }
    let pre = std::fs::symlink_metadata(path).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("secret file {} cannot be stat'd: {}", path.display(), e).into()
        },
    )?;
    if pre.file_type().is_symlink() {
        return Err(format!(
            "secret file {} is a symlink; configure the real path so the ancestor lockdown applies to it",
            path.display()
        )
        .into());
    }
    let canon =
        std::fs::canonicalize(path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!(
                "secret file {} cannot be canonicalized: {}",
                path.display(),
                e
            )
            .into()
        })?;
    verify_ancestor_chain(&canon)?;
    read_secret_open_fd(&canon)
}

// Open-and-read pipeline split out from read_secret_file so the ancestor
// lockdown isn't in the way of unit tests (test files live under a temp dir
// in a usually-1777 /tmp, which the ancestor walk would reject by design).
#[cfg(unix)]
pub(crate) fn read_secret_open_fd(
    path: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!(
                "secret file {} cannot be opened: {} (O_NOFOLLOW rejects a symlink at the final path component)",
                path.display(),
                e
            )
            .into()
        })?;
    let md = f
        .metadata()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!(
                "secret file {} cannot be stat'd via fd: {}",
                path.display(),
                e
            )
            .into()
        })?;
    if !md.file_type().is_file() {
        return Err(format!(
            "secret file {} is not a regular file (devices/sockets/FIFOs rejected)",
            path.display()
        )
        .into());
    }
    let our_uid = current_euid();
    if md.uid() != our_uid {
        return Err(format!(
            "secret file {} is owned by uid {} but this process runs as uid {}",
            path.display(),
            md.uid(),
            our_uid
        )
        .into());
    }
    // Reject any group/other access bit. There is no legitimate reason for
    // a webhook HMAC secret file to be readable or writable by anyone but
    // the service uid.
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "secret file {} mode {:o} is too permissive; require 0600 or stricter",
            path.display(),
            md.mode() & 0o777
        )
        .into());
    }
    if md.size() > MAX_SECRET_FILE_BYTES {
        return Err(format!(
            "secret file {} is {} bytes; refusing to read more than {}",
            path.display(),
            md.size(),
            MAX_SECRET_FILE_BYTES
        )
        .into());
    }
    // On Darwin, the 0600 mode check above can be bypassed by an ACL. Check
    // via the same fd we fstat'd, so the check is bound to this inode.
    darwin_acl::reject_grant_acl_fd(f.as_raw_fd(), &format!("secret file {}", path.display()))?;
    let mut bytes = Vec::with_capacity(md.size() as usize);
    (&mut f)
        .take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    // fstat told us md.size() ≤ MAX_SECRET_FILE_BYTES above, but a same-uid
    // writer could grow the file between stat and read. The take() above
    // bounds how many bytes we read; this check turns "read more than the
    // limit" into a hard refusal instead of a silent truncation.
    if bytes.len() > MAX_SECRET_FILE_BYTES as usize {
        return Err(format!(
            "secret file {} grew past {} bytes during read; refusing to use a truncated/raced secret",
            path.display(),
            MAX_SECRET_FILE_BYTES
        )
        .into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn read_secret_open_fd_rejects_unsafe_files() {
        use crate::test_support::tempdir_like;
        use std::os::unix::fs::PermissionsExt;
        let outer = tempdir_like::TempDir::new("secret").unwrap();
        let root = outer.path();

        // Symlink at the final path component → O_NOFOLLOW fires on open.
        let target = root.join("real-secret");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_secret_open_fd(&link).is_err());

        // Group/world readable rejected from fd metadata.
        let lax = root.join("lax-secret");
        std::fs::write(&lax, b"x").unwrap();
        std::fs::set_permissions(&lax, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret_open_fd(&lax).is_err());

        // Oversized rejected before the read cap kicks in.
        let big = root.join("big-secret");
        std::fs::write(&big, vec![b'x'; MAX_SECRET_FILE_BYTES as usize + 1]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_secret_open_fd(&big).is_err());

        // A 0600 regular file under the size limit, owned by us, is read
        // back faithfully.
        let ok = root.join("ok-secret");
        let expected: &[u8] = b"sufficiently-long-secret-bytes";
        std::fs::write(&ok, expected).unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes =
            read_secret_open_fd(&ok).expect("0600 file owned by us under size limit should load");
        assert_eq!(bytes, expected);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn read_secret_file_rejects_relative_path() {
        // Relative paths skip the ancestor-chain lockdown by virtue of
        // having no real ancestors to walk; refuse them at the door.
        assert!(read_secret_file(Path::new("relative/secret")).is_err());
    }
}
