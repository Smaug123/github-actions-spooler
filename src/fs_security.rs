// POSIX (and, on Darwin, ACL-aware) filesystem-security primitives shared by
// the secret loader and the spool. Every check here is euid-based: ownership
// via fstat/symlink_metadata, mode bits, O_NOFOLLOW, and an ancestor-directory
// walk. The crate is Unix-only (see the compile_error! in main.rs); these
// helpers assume POSIX semantics throughout.

use std::io;
use std::path::Path;

use tokio::fs;

// open(2)'s O_NOFOLLOW flag value. Defined inline per-target instead of
// pulling in libc/nix — same reason `geteuid` is reached via an inline
// `extern "C"`. Values come from <fcntl.h> on each platform and are stable
// kernel ABI. Add a branch for any new target the flake decides to build.
#[cfg(all(unix, target_os = "linux"))]
pub(crate) const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    )
))]
pub(crate) const O_NOFOLLOW: i32 = 0x100;

pub(crate) fn current_euid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

pub(crate) async fn create_dir_secure(path: &Path) -> io::Result<()> {
    let already_existed = fs::metadata(path).await.is_ok();
    if !already_existed {
        fs::create_dir_all(path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 0700 — uid-only. Each enqueued file holds a valid (body,
            // signature) pair that would re-verify against the service
            // secret, so anyone who can read new/ can replay deliveries
            // into a downstream that re-checks HMAC. Don't extend that
            // trust to the group by default.
            fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_dir_secure(
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::symlink_metadata(path)?;
    if !md.file_type().is_dir() {
        return Err(format!(
            "{} is not a directory (symlinks are rejected for spool components)",
            path.display()
        )
        .into());
    }
    let our_uid = current_euid();
    if md.uid() != our_uid {
        return Err(format!(
            "{} is owned by uid {} but this process runs as uid {}",
            path.display(),
            md.uid(),
            our_uid
        )
        .into());
    }
    // Reject any group/other bit (read, write, or execute). Files inside
    // new/ contain replayable signed payloads; leaving the dir even
    // group-readable hands every group member a fresh forgery on demand.
    let bad = md.mode() & 0o077;
    if bad != 0 {
        return Err(format!(
            "{} is group/other accessible (mode {:o}); spool components must be 0700 or stricter",
            path.display(),
            md.mode() & 0o777
        )
        .into());
    }
    // The mode check above is bypassable by an ACL on Darwin; reject one here.
    darwin_acl::reject_grant_acl_path_nofollow(path)?;
    Ok(())
}

pub(crate) fn verify_ancestor_chain(
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::MetadataExt;
    let our_uid = current_euid();
    let Some(mut current) = path.parent() else {
        return Ok(());
    };
    loop {
        if current.as_os_str().is_empty() {
            break;
        }
        let md = std::fs::symlink_metadata(current).map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("ancestor {} cannot be stat'd: {}", current.display(), e).into()
            },
        )?;
        if !md.file_type().is_dir() {
            return Err(format!(
                "ancestor {} of spool root is not a real directory (symlinks rejected)",
                current.display()
            )
            .into());
        }
        if md.uid() != 0 && md.uid() != our_uid {
            return Err(format!(
                "ancestor {} of spool root is owned by uid {} (must be root or {})",
                current.display(),
                md.uid(),
                our_uid
            )
            .into());
        }
        if md.mode() & 0o022 != 0 {
            return Err(format!(
                "ancestor {} of spool root has group/other write bits (mode {:o})",
                current.display(),
                md.mode() & 0o777
            )
            .into());
        }
        // A write-granting ACL on an ancestor lets another user swap the tree;
        // the write-bit check above misses it on Darwin. ALLOW-only, so the
        // default `deny delete` ACLs on macOS system dirs don't trip this.
        darwin_acl::reject_grant_acl_path_nofollow(current)?;
        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
    }
    Ok(())
}

// On macOS, POSIX mode bits are not the whole story: an ACL can grant another
// local principal read/write to an object whose st_mode is 0600/0700, silently
// defeating the owner+mode checks the rest of this crate relies on. These
// helpers reject any object carrying an access-granting (ALLOW) ACE. DENY ACEs
// are tolerated on purpose — macOS ships default `deny delete` ACLs on system
// directories (e.g. /Users) that the ancestor walk crosses, and a DENY only
// further restricts access. Reached via inline FFI into libSystem, the same
// way `geteuid` above is, rather than pulling in a crate.
#[cfg(target_os = "macos")]
pub(crate) mod darwin_acl {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::RawFd;
    use std::path::Path;

    // acl_t / acl_entry_t are opaque pointers; acl_type_t / acl_tag_t are
    // 32-bit ints (see <sys/acl.h>).
    type AclT = *mut c_void;
    type AclEntryT = *mut c_void;

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    // Darwin's ACL_NEXT_ENTRY is -1, NOT 1. The 1 value is the FreeBSD
    // convention; on macOS <sys/acl.h> defines `ACL_FIRST_ENTRY = 0,
    // ACL_NEXT_ENTRY = -1`. Passing 1 here would request the entry at index
    // 1 (a non-portable "index" extension), not the next one.
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_ALLOW: i32 = 1;
    // <errno.h>: acl_get_fd / acl_get_link_np return NULL and set errno to
    // ENOENT when the object simply has no ACL of the requested type. Any
    // other errno means the lookup itself failed and we must fail closed.
    const ENOENT: i32 = 2;

    extern "C" {
        fn acl_get_fd(fd: c_int) -> AclT;
        fn acl_get_link_np(path: *const c_char, acl_type: c_int) -> AclT;
        fn acl_get_entry(acl: AclT, entry_id: c_int, entry_p: *mut AclEntryT) -> c_int;
        fn acl_get_tag_type(entry: AclEntryT, tag_p: *mut i32) -> c_int;
        fn acl_free(obj: *mut c_void) -> c_int;
    }

    // Interpret an ACL handle from acl_get_fd / acl_get_link_np:
    //   Ok(true)  -> holds at least one access-granting ALLOW entry.
    //   Ok(false) -> object has no extended ACL (NULL + errno ENOENT).
    //   Err(..)   -> the lookup itself failed; callers MUST fail closed
    //                rather than accept an object whose ACL couldn't be read.
    // A NULL handle is overloaded on macOS: it signals both "no ACL" (ENOENT)
    // and genuine errors (ENOMEM/EACCES/EINVAL/...), so reading errno is the
    // only way to tell them apart. errno is read immediately after the null
    // check — nothing between the FFI call and here touches it. Always frees a
    // non-NULL acl.
    unsafe fn acl_grants_access(
        acl: AclT,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if acl.is_null() {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ENOENT) {
                return Ok(false);
            }
            return Err(format!("ACL lookup failed: {err}").into());
        }
        let mut found_allow = false;
        let mut entry: AclEntryT = std::ptr::null_mut();
        // On macOS (POSIX.1e draft 17) acl_get_entry returns 0 when it yields
        // an entry and -1 on exhaustion or error — NOT the FreeBSD 1/0/-1
        // convention. Continue while it returns 0; stop on anything else.
        let mut entry_id = ACL_FIRST_ENTRY;
        while acl_get_entry(acl, entry_id, &mut entry) == 0 {
            entry_id = ACL_NEXT_ENTRY;
            let mut tag: i32 = 0;
            if acl_get_tag_type(entry, &mut tag) == 0 && tag == ACL_EXTENDED_ALLOW {
                found_allow = true;
                break;
            }
        }
        acl_free(acl);
        Ok(found_allow)
    }

    pub(crate) fn reject_grant_acl_fd(
        fd: RawFd,
        label: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // acl_get_fd returns the ACL_TYPE_EXTENDED ACL for the open fd.
        let grants = unsafe { acl_grants_access(acl_get_fd(fd)) }.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> { format!("{label}: {e}").into() },
        )?;
        if grants {
            return Err(format!(
                "{label} carries an access-granting (ALLOW) ACL; clear it with `chmod -N` — \
                 this binary's filesystem security relies on POSIX mode bits only, and an ACL \
                 can grant another local user access despite a 0600/0700 mode"
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn reject_grant_acl_path_nofollow(
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cpath = CString::new(path.as_os_str().as_bytes()).map_err(
            |_| -> Box<dyn std::error::Error + Send + Sync> {
                format!("path {} contains an interior NUL byte", path.display()).into()
            },
        )?;
        // acl_get_link_np does not follow a final symlink, matching the
        // symlink_metadata / O_NOFOLLOW posture elsewhere.
        let grants =
            unsafe { acl_grants_access(acl_get_link_np(cpath.as_ptr(), ACL_TYPE_EXTENDED)) }
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("{}: {e}", path.display()).into()
                })?;
        if grants {
            return Err(format!(
                "{} carries an access-granting (ALLOW) ACL; clear it with `chmod -N {}` — \
                 this binary's filesystem security relies on POSIX mode bits only",
                path.display(),
                path.display()
            )
            .into());
        }
        Ok(())
    }
}

// On non-Darwin Unix targets the spool relies on POSIX mode bits alone. Linux
// POSIX.1e ACLs can also grant access despite the mode bits, but that's a
// separate gap the review did not raise and is intentionally out of scope; for
// now these no-ops keep the call sites target-agnostic.
#[cfg(not(target_os = "macos"))]
pub(crate) mod darwin_acl {
    use std::os::unix::io::RawFd;
    use std::path::Path;

    #[inline]
    pub(crate) fn reject_grant_acl_fd(
        _fd: RawFd,
        _label: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    #[inline]
    pub(crate) fn reject_grant_acl_path_nofollow(
        _path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_dir_secure_rejects_unsafe_dirs() {
        use crate::test_support::tempdir_like;
        use std::os::unix::fs::PermissionsExt;
        let outer = tempdir_like::TempDir::new("verify").unwrap();
        let root = outer.path();

        // Regular file is not a directory.
        let file = root.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(verify_dir_secure(&file).is_err());

        // Symlink to a dir is rejected (we use symlink_metadata, not metadata).
        let target = root.join("real");
        std::fs::create_dir(&target).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(verify_dir_secure(&link).is_err());

        // Group/other writable is rejected.
        let lax = root.join("lax");
        std::fs::create_dir(&lax).unwrap();
        std::fs::set_permissions(&lax, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(verify_dir_secure(&lax).is_err());

        // Group-readable-only is also rejected: the dir holds replayable
        // signed bodies, and 0o077 means no group/other bits at all.
        let group_read = root.join("group-read");
        std::fs::create_dir(&group_read).unwrap();
        std::fs::set_permissions(&group_read, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(verify_dir_secure(&group_read).is_err());

        // A 0700 dir owned by us passes.
        let ok = root.join("ok");
        std::fs::create_dir(&ok).unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o700)).unwrap();
        verify_dir_secure(&ok).expect("0700 dir owned by us should verify");
    }

    // Exercises the real Darwin ACL helpers. Only compiled on macOS — on
    // other targets `darwin_acl` is the no-op stub and ACLs/`chmod +a` don't
    // exist. These guard the FFI convention bug where the entry-iteration
    // loop silently never ran (acl_get_entry returns 0 not 1 on macOS, and
    // ACL_NEXT_ENTRY is -1 not 1), which made every ACL check pass.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn darwin_acl_rejects_allow_and_tolerates_deny() {
        use crate::test_support::tempdir_like;
        use std::os::unix::io::AsRawFd;
        use std::path::Path;
        use std::process::Command;

        fn set_acl(path: &Path, ace: &str) {
            let status = Command::new("/bin/chmod")
                .arg("+a")
                .arg(ace)
                .arg(path)
                .status()
                .expect("run /bin/chmod +a");
            assert!(status.success(), "chmod +a {ace:?} failed");
        }

        let dir = tempdir_like::TempDir::new("acl").unwrap();
        let root = dir.path();

        // No ACL -> passes (both path and fd variants).
        let plain = root.join("plain");
        std::fs::write(&plain, b"x").unwrap();
        darwin_acl::reject_grant_acl_path_nofollow(&plain)
            .expect("file with no ACL must pass the path check");
        {
            let f = std::fs::File::open(&plain).unwrap();
            darwin_acl::reject_grant_acl_fd(f.as_raw_fd(), "plain")
                .expect("file with no ACL must pass the fd check");
        }

        // An access-granting ALLOW ACE -> rejected. This is the assertion
        // that fails against the pre-fix code (the loop never ran, so the
        // ALLOW ACE was never seen) and passes after.
        let allow = root.join("allow");
        std::fs::write(&allow, b"x").unwrap();
        set_acl(&allow, "everyone allow read");
        assert!(
            darwin_acl::reject_grant_acl_path_nofollow(&allow).is_err(),
            "an everyone-allow-read ACE must be rejected (path)"
        );
        {
            let f = std::fs::File::open(&allow).unwrap();
            assert!(
                darwin_acl::reject_grant_acl_fd(f.as_raw_fd(), "allow").is_err(),
                "an everyone-allow-read ACE must be rejected (fd)"
            );
        }

        // A DENY-only ACE -> tolerated. macOS ships default `deny delete`
        // ACLs on system dirs the ancestor walk crosses; a DENY only further
        // restricts access, so it must not trip the check.
        let deny = root.join("deny");
        std::fs::write(&deny, b"x").unwrap();
        set_acl(&deny, "everyone deny delete");
        darwin_acl::reject_grant_acl_path_nofollow(&deny)
            .expect("a deny-only ACE must be tolerated");
    }
}
