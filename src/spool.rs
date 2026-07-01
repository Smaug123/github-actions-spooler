// Maildir-style durable queue: prepare/verify the spool root and its tmp/ and
// new/ subdirs at startup, then write one file per accepted job via the
// tmp/ -> rename -> new/ handoff. new/ is the trust boundary to the consumer —
// see the Envelope doc comment for what the consumer must re-verify.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::fs_security::{create_dir_secure, darwin_acl, verify_ancestor_chain, verify_dir_secure};

// v2 added the advisory prioritization hints (head_branch, head_sha,
// job_name). It's a purely additive change — a v1 consumer that ignores
// unknown fields keeps working — but the bump lets a consumer assert "these
// hints are present" rather than probing for them.
pub(crate) const ENVELOPE_SCHEMA: u32 = 2;

pub(crate) async fn prepare_spool(
    root: PathBuf,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    // Reject a symlinked SPOOL_DIR before anything touches it. canonicalize()
    // below follows every symlink in the path, so without this check a
    // symlinked root would be silently accepted and every downstream check
    // would apply to the resolved target — making the documented "SPOOL_DIR
    // ... must be real directories (no symlinks)" contract vacuous for the
    // root, even though tmp/ and new/ already get this rejection via
    // symlink_metadata in verify_dir_secure. A not-yet-existing root is created
    // as a real directory by create_dir_secure below, so only a pre-existing
    // symlink can trip this; a NotFound (or other) stat error falls through to
    // create_dir_secure/canonicalize, which surface a clearer error.
    //
    // lstat()/symlink_metadata() follows a *final* symlink when the path
    // carries a trailing slash (POSIX: the slash demands directory
    // resolution), so a "/var/spool/link/"-style value — trailing slashes are
    // common in directory env vars — would slip past a naive check. Strip
    // trailing separators via components().as_path() so we lstat the final
    // component itself.
    let root_stem = root.components().as_path();
    if std::fs::symlink_metadata(root_stem).is_ok_and(|md| md.file_type().is_symlink()) {
        return Err(format!(
            "SPOOL_DIR {} is a symlink; spool components must be real directories (no symlinks)",
            root.display()
        )
        .into());
    }
    create_dir_secure(&root).await?;
    // Canonicalize after the root exists so verify_ancestor_chain walks the
    // real ancestors rather than textual `..`-laden ones. canonicalize
    // requires the path to exist, hence the ordering.
    let root =
        std::fs::canonicalize(&root).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!(
                "SPOOL_DIR {} cannot be canonicalized: {}",
                root.display(),
                e
            )
            .into()
        })?;
    let tmp = root.join("tmp");
    let new = root.join("new");
    create_dir_secure(&tmp).await?;
    create_dir_secure(&new).await?;
    verify_dir_secure(&root)?;
    verify_dir_secure(&tmp)?;
    verify_dir_secure(&new)?;
    // Ancestors must be locked down too, otherwise another local user can
    // swap the tree out from under us after these checks pass.
    verify_ancestor_chain(&root)?;
    sweep_tmp(&tmp).await?;
    Ok(root)
}

// Make prior rename/unlink operations in `dir` durable by fsyncing the
// directory itself. tokio doesn't expose directory fsync, so do it on the
// blocking pool.
async fn fsync_dir(dir: PathBuf) -> io::Result<()> {
    tokio::task::spawn_blocking(move || -> io::Result<()> { std::fs::File::open(&dir)?.sync_all() })
        .await
        .map_err(io::Error::other)?
}

async fn sweep_tmp(tmp: &Path) -> io::Result<()> {
    let mut entries = fs::read_dir(tmp).await?;
    let mut swept_any = false;
    let mut failures = 0usize;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        match fs::remove_file(&path).await {
            Ok(()) => {
                eprintln!("swept stale tmp file: {}", path.display());
                swept_any = true;
            }
            Err(e) => {
                // remove_file also fails on a leftover subdirectory
                // (EISDIR/EPERM), which is exactly the unremovable case we
                // must not start past.
                eprintln!(
                    "error: failed to sweep stale tmp entry {}: {}",
                    path.display(),
                    e
                );
                failures += 1;
            }
        }
    }
    if swept_any {
        // Make the unlinks durable so a crash right after sweep doesn't
        // leave the same files there for the next startup to re-sweep.
        fsync_dir(tmp.to_path_buf()).await?;
    }
    // A leftover tmp/{id}.job (or a stale directory) we couldn't remove would
    // pin every future delivery for that id at InFlight/503 until manual
    // cleanup. Refuse to start with an incompletely-swept tmp/ rather than
    // serve in that state.
    if failures > 0 {
        return Err(io::Error::other(format!(
            "{failures} stale entr{} in {} could not be removed; clear tmp/ manually before restarting",
            if failures == 1 { "y" } else { "ies" },
            tmp.display()
        )));
    }
    Ok(())
}

// Consumers of new/ MUST:
//   1. Treat the envelope as advisory metadata. It is NOT covered by
//      GitHub's HMAC and a local writer with the right uid/group could
//      pair a valid (body, signature) with tampered envelope fields.
//      Derive every trust-relevant field (repo_id, action,
//      workflow_job.id, labels, head_sha) from the HMAC-verified body, not
//      from the envelope. The head_branch/head_sha/job_name hints exist so
//      the consumer can order/prioritize the queue without parsing every
//      body; sorting on a forged hint only reorders work, but anything that
//      determines *what runs* (e.g. the sha you check out) must come from
//      the verified body.
//   2. Re-verify HMAC-SHA256 over the raw body using the consumer's own
//      copy of the secret. The signature in the envelope can serve as the
//      expected value (it's deterministic — HMAC(secret, body)), but the
//      authoritative check is "does HMAC(my-secret, raw-body) match".
//   3. Reject files whose filename's numeric stem doesn't equal
//      workflow_job.id parsed from the verified body.
//   4. Maintain persistent dedup on workflow_job.id parsed from the body.
//      The spooler dedups within new/ via the filename, but once the
//      consumer moves a file out, a replay would re-enqueue under the
//      same id.
#[derive(Serialize)]
pub(crate) struct Envelope<'a> {
    pub(crate) schema: u32,
    pub(crate) event: &'a str,
    pub(crate) delivery: &'a str,
    pub(crate) repo_id: u64,
    pub(crate) repo: &'a str,
    pub(crate) action: &'a str,
    pub(crate) workflow_job_id: u64,
    // Advisory prioritization hints lifted from the verified body
    // (workflow_job.head_branch / head_sha / name). Empty string when the
    // field is absent or non-string. See the consumer-MUST note above:
    // safe to sort on, never to trust.
    pub(crate) head_branch: &'a str,
    pub(crate) head_sha: &'a str,
    pub(crate) job_name: &'a str,
    pub(crate) received_at_ms: u64,
    pub(crate) signature: &'a str,
}

pub(crate) enum EnqueueResult {
    Wrote,
    Duplicate,
    // Another writer holds tmp/{id} and new/{id} doesn't exist yet.
    // Distinguishing this from a real I/O failure keeps the operator's
    // logs honest. NOTE: GitHub does *not* automatically redeliver
    // failed webhooks (the 503 surfaced from this state is recorded as
    // a failed delivery on the repo's Recent Deliveries page), so the
    // operator — or a companion redelivery monitor — must replay the
    // delivery if the other in-flight writer also failed.
    InFlight,
}

pub(crate) async fn enqueue(
    spool_dir: &Path,
    filename: &str,
    header_line: &[u8],
    body: &[u8],
) -> io::Result<EnqueueResult> {
    // Defence-in-depth: the only caller passes "{u64}.job" (digits + suffix),
    // but reject anything that could escape spool_dir/{tmp,new}/ in case a
    // future refactor changes the source. Path::join silently swallows an
    // absolute path or `..` segment.
    if filename.is_empty()
        || filename.len() > 128
        || filename.starts_with('.')
        || filename.bytes().any(|b| b == b'/' || b == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing unsafe filename {filename:?}"),
        ));
    }

    let tmp_path = spool_dir.join("tmp").join(filename);
    let new_path = spool_dir.join("new").join(filename);

    // Fast path: this delivery was already enqueued by an earlier successful
    // request whose 200 was lost in transit. Ack as duplicate without
    // rewriting. Two concurrent writers can both pass this check;
    // `create_new(true)` on `tmp/{id}` serialises them, so the loser falls
    // through to the AlreadyExists branch below and reports Duplicate (if
    // the winner has since landed `new/{id}`) or InFlight. An actual
    // overwrite of `new/{id}` only happens when the consumer drains the
    // earlier file between W1's rename and W2's fast-path; in that window
    // W2 sees no `new/{id}`, claims a fresh `tmp/{id}`, and renames over
    // nothing. The *body* for a given `workflow_job_id` is HMAC-verified
    // and pinned to action=queued, so consumer-side dedup on
    // `workflow_job.id` parsed from the verified body is what keeps that
    // case safe — the envelope is recomputed on every call
    // (received_at_ms, delivery, and potentially signature/repo all
    // differ) so the file is NOT byte-identical across writes.
    if fs::metadata(&new_path).await.is_ok() {
        // A prior request may have renamed new/{id} into place but died (e.g.
        // via a failed directory fsync -> 500) before that rename was durable.
        // fsync new/ now so acking Duplicate honours the "2xx == durably
        // queued" contract; if the fsync fails we surface 500 and the next
        // redelivery retries it — turning the retry into the recovery the
        // original 500 asked for.
        fsync_dir(spool_dir.join("new")).await?;
        return Ok(EnqueueResult::Duplicate);
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        // 0600 — uid-only. The file contains the raw webhook body plus its
        // GitHub-issued signature, which together replay successfully
        // against any consumer that re-verifies HMAC. There's no
        // legitimate reason for a group member to read it.
        opts.mode(0o600);
    }
    let mut f = match opts.open(&tmp_path).await {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // Either a concurrent request for the same delivery is in flight
            // (rare — GitHub retries serially with backoff) or the startup
            // sweep missed a stale tmp. Re-check new/ in case the other
            // writer just finished; otherwise report InFlight so the
            // caller can ask GitHub to retry without claiming a real
            // I/O failure happened.
            if fs::metadata(&new_path).await.is_ok() {
                // Same durability reasoning as the pre-open fast path: fsync
                // new/ before acking Duplicate so a not-yet-durable rename by
                // the other writer can't be lost behind a 200.
                fsync_dir(spool_dir.join("new")).await?;
                return Ok(EnqueueResult::Duplicate);
            }
            return Ok(EnqueueResult::InFlight);
        }
        Err(e) => return Err(e),
    };

    // Defence-in-depth on Darwin: tmp/ is verified ACL-free at startup so a
    // freshly created file can't inherit a grant, but an ACL on this fd would
    // expose the signed body — reject and clean up if one somehow appears.
    {
        use std::os::unix::io::AsRawFd;
        if let Err(e) = darwin_acl::reject_grant_acl_fd(f.as_raw_fd(), "enqueued spool file") {
            drop(f);
            let _ = fs::remove_file(&tmp_path).await;
            return Err(io::Error::other(e));
        }
    }

    // From here on, any error must unlink tmp_path before returning. A leaked
    // tmp/{id} would cause every future retry for the same workflow_job_id to
    // collide on create_new and return InFlight (503) until the process
    // restarts and sweep_tmp runs.
    let write_result = async {
        f.write_all(header_line).await?;
        f.write_all(b"\n").await?;
        f.write_all(body).await?;
        f.sync_all().await?;
        Ok::<(), io::Error>(())
    }
    .await;
    drop(f);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, &new_path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(e);
    }

    // Make the rename itself durable by fsyncing the containing directory.
    fsync_dir(spool_dir.join("new")).await?;

    Ok(EnqueueResult::Wrote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fresh_spool;

    #[cfg(unix)]
    #[tokio::test]
    async fn prepare_spool_rejects_symlinked_root() {
        // A symlinked SPOOL_DIR must be rejected outright rather than silently
        // resolved to its target by canonicalize(). Otherwise the documented
        // "SPOOL_DIR ... must be real directories (no symlinks)" contract is
        // vacuous for the root, even though tmp/ and new/ already get the
        // symlink rejection via verify_dir_secure. The trailing-slash form
        // must be rejected too: lstat() follows a final symlink when the path
        // ends in '/', so the guard normalizes the separator away first.
        use crate::test_support::tempdir_like;
        let outer = tempdir_like::TempDir::new("spool-symlink").unwrap();
        let target = outer.path().join("real-root");
        std::fs::create_dir(&target).unwrap();
        let link = outer.path().join("link-root");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let with_slash = PathBuf::from(format!("{}/", link.display()));
        for root in [link.clone(), with_slash] {
            let err = prepare_spool(root.clone())
                .await
                .expect_err("a symlinked SPOOL_DIR must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("symlink"),
                "error should name the symlink rejection for {root:?}, got: {msg}"
            );
        }

        // The rejection must fire before anything is written through the link,
        // so the target is left untouched by either form.
        assert!(
            !target.join("tmp").exists(),
            "tmp/ must not be created via the symlink"
        );
        assert!(
            !target.join("new").exists(),
            "new/ must not be created via the symlink"
        );
    }

    #[tokio::test]
    async fn enqueue_writes_to_new_and_acks_duplicate_on_repeat() {
        let (_dir, root) = fresh_spool().await;
        let header = br#"{"schema":1,"delivery":"d1"}"#;
        let body = br#"{"hello":"world"}"#;

        let first = enqueue(&root, "d1.job", header, body).await.unwrap();
        assert!(matches!(first, EnqueueResult::Wrote));

        let second = enqueue(&root, "d1.job", header, body).await.unwrap();
        assert!(matches!(second, EnqueueResult::Duplicate));

        let contents = fs::read(root.join("new").join("d1.job")).await.unwrap();
        let nl = contents.iter().position(|&b| b == b'\n').unwrap();
        assert_eq!(&contents[..nl], header);
        assert_eq!(&contents[nl + 1..], body);

        let mut tmp_entries = fs::read_dir(root.join("tmp")).await.unwrap();
        assert!(tmp_entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn enqueue_rejects_unsafe_filenames() {
        let (_dir, root) = fresh_spool().await;
        let header = br#"{"schema":1}"#;
        let body = br#"{}"#;
        for bad in &["", "../etc/passwd", "a/b", ".hidden", "x\0y"] {
            let result = enqueue(&root, bad, header, body).await;
            assert!(
                result.is_err(),
                "filename {bad:?} should be rejected by the guard"
            );
        }
        // Nothing should have been written.
        let mut tmp = fs::read_dir(root.join("tmp")).await.unwrap();
        assert!(tmp.next_entry().await.unwrap().is_none());
        let mut new = fs::read_dir(root.join("new")).await.unwrap();
        assert!(new.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn enqueue_cleans_up_tmp_when_rename_fails() {
        // If rename fails after a successful write, the tmp file must be
        // unlinked — otherwise the next retry for the same id would forever
        // collide on create_new and return InFlight until restart.
        let (_dir, root) = fresh_spool().await;
        // Remove new/ so the rename has no target dir. The fast-path
        // metadata check on new/{id} returns Err here (not Ok), so the
        // code proceeds to open tmp/{id} and only fails at fs::rename.
        fs::remove_dir(root.join("new")).await.unwrap();

        let header = br#"{"schema":1}"#;
        let body = br#"{}"#;
        let result = enqueue(&root, "42.job", header, body).await;
        assert!(result.is_err(), "rename should fail without new/");

        let mut tmp = fs::read_dir(root.join("tmp")).await.unwrap();
        assert!(
            tmp.next_entry().await.unwrap().is_none(),
            "tmp/ should be cleaned up after a failed rename"
        );
    }

    #[tokio::test]
    async fn enqueue_concurrent_writer_returns_in_flight() {
        // Simulate a concurrent in-flight writer by pre-creating tmp/{id}
        // without ever moving it to new/. The next enqueue for the same id
        // must report InFlight rather than an I/O failure.
        let (_dir, root) = fresh_spool().await;
        fs::write(root.join("tmp").join("99.job"), b"in progress")
            .await
            .unwrap();
        let header = br#"{"schema":1}"#;
        let body = br#"{}"#;
        let result = enqueue(&root, "99.job", header, body).await.unwrap();
        assert!(matches!(result, EnqueueResult::InFlight));
    }
}
