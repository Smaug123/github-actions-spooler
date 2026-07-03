// gh-webhook-spool: accept GitHub workflow_job webhooks on localhost, verify
// HMAC-SHA256, drop anything not from a hardcoded repo allowlist or not
// matching the expected runner labels, and durably append one file per
// accepted job to a maildir-style queue (tmp/ -> rename -> new/).
//
// The implementation is split across modules:
//   * fs_security — POSIX/Darwin filesystem-security primitives (euid checks,
//     ancestor-chain walk, mode/ACL verification, O_NOFOLLOW).
//   * secret      — HMAC secret loading with the TOCTOU-hardened pipeline.
//   * spool       — the maildir-style durable queue (prepare/sweep/enqueue).
//   * webhook     — the HTTP policy core (`process`) and axum glue.
// This file holds the config (ALLOWED_REPO_IDS/EXPECTED_LABELS), AppState
// construction, and startup/serve wiring.
//
// Security posture:
//   * HMAC is verified against the raw request bytes BEFORE any parsing.
//   * Constant-time comparison via the `hmac` crate's `verify_slice`.
//   * Body size is capped via axum's DefaultBodyLimit; an oversize request
//     never reaches the handler.
//   * Default bind is 127.0.0.1 and a non-loopback LISTEN_ADDR is refused
//     unless ALLOW_NON_LOOPBACK_BIND=1; this binary expects to sit behind
//     a TLS reverse proxy.
//   * At startup, root/tmp/new must be real directories (no symlinks) owned
//     by the running euid with no group/other write bits. new/ is the trust
//     handoff to the consumer — anyone who can write there bypasses HMAC.
//   * Only workflow_job events with action=queued are spooled; everything
//     else is acked silently so a misconfigured "send me everything"
//     webhook can't produce unrelated runner work.
//   * Repo allowlisting uses repository.id (immutable across rename and
//     transfer) rather than repository.full_name. Allowlist misses receive
//     200 with no enqueue, so the list is not enumerable.
//   * Non-private repos are refused. The workflow_job payload doesn't
//     include head_repository so we can't directly detect a fork PR, but
//     refusing public/internal repos cuts off the public-fork-PR class.
//     The check requires BOTH repository.private == true AND
//     repository.visibility == "private": GitHub Enterprise's "internal"
//     visibility reports private=true and would slip past a private-only
//     gate. Missing visibility is treated as non-private (fail closed).
//     The residual risk (a collaborator of a private repo privately
//     forking and submitting a PR) is documented in the README.
//   * Filenames are the GitHub workflow_job.id (an authenticated payload
//     field). GitHub's HMAC covers only the body, so the X-GitHub-Delivery
//     header is attacker-controllable for anyone holding a valid signed
//     body; keying on a body field instead means a fresh delivery ID can't
//     turn a replay into a new queue entry. Dedup is in-queue only — once
//     the consumer moves a file out of new/, a replay will re-enqueue.
//     The consumer is expected to maintain persistent dedup on
//     workflow_job.id.
//
// Consumer/envelope trust boundary:
//   The envelope written ahead of the body in new/{id}.job is NOT covered
//   by GitHub's HMAC. The signature stored inside it is genuine, but every
//   other envelope field is attacker-controllable for any process that
//   shares the service uid/group. Consumers MUST:
//     1. Split the file at the first '\n'. Re-compute HMAC-SHA256 over the
//        body using the consumer's own copy of the secret. If it doesn't
//        match the stored signature (or recompute and compare directly,
//        ignoring the stored signature), the file is forged — discard.
//     2. Parse the verified body and derive repo_id, action,
//        workflow_job.id, and labels from THAT. The envelope is advisory
//        metadata (timestamp, free-text repo hint) only.
//     3. Reject any file whose filename's numeric stem doesn't match
//        workflow_job.id parsed from the body.

// The security model relies on POSIX semantics throughout: euid-based
// ownership checks, O_NOFOLLOW, mode bits, fstat via an opened fd, ancestor
// directory verification. Building on a non-Unix target would silently strip
// every one of those checks (the per-platform helpers in fs_security are
// #[cfg(unix)] gated). Refuse to compile rather than ship a binary that
// quietly turns off its own filesystem defences.
//
// On macOS the mode bits alone are not enough: an ACL can grant another local
// principal access to an object whose st_mode is 0600/0700. So on Darwin every
// mode-bit check is paired with an ACL check (see fs_security::darwin_acl) that
// rejects any object — secret file, spool dirs, their ancestors, and enqueued
// files — carrying an access-granting ALLOW ACE. DENY ACEs are tolerated:
// macOS ships default `deny delete` ACLs on system directories the ancestor
// walk crosses. (Linux POSIX.1e ACLs are a separate, out-of-scope gap.)
#[cfg(not(unix))]
compile_error!(
    "gh-webhook-spool requires a Unix target: the secret-file and spool-dir \
     checks depend on POSIX uid/mode/O_NOFOLLOW semantics that have no \
     portable analogue on other platforms."
);

mod fs_security;
mod launchd;
mod secret;
mod spool;
mod webhook;

#[cfg(test)]
mod test_support;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use axum::Router;
use tokio::net::TcpListener;

use secret::load_secret;
use spool::prepare_spool;
use webhook::{webhook, AppState};

const MAX_BODY_BYTES: usize = 5 * 1024 * 1024; // 5 MiB

// Edit these lists to control which webhooks are enqueued. The repo ID comes
// from `repository.id` in the webhook payload — it's immutable across rename
// and transfer, unlike full_name. EXPECTED_LABELS is matched against
// `workflow_job.labels`. Both lists are required: empty refuses to start.
//
// Every repo listed here MUST be private. The handler requires both
// `repository.private == true` and `repository.visibility == "private"` at
// runtime; public, internal, or missing-visibility deliveries get ack'd and
// dropped with a log line. See README "Threat model" for why public/internal
// repos are out of scope and what residual risk remains for private-repo
// collaborators.
const ALLOWED_REPO_IDS: &[u64] = &[];
const EXPECTED_LABELS: &[&str] = &[];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Apply the compile-time refusals first so we don't create spool
    // directories for a binary that's about to exit.
    let allowed_repo_ids: HashSet<u64> = ALLOWED_REPO_IDS.iter().copied().collect();
    let expected_labels: HashSet<&'static str> = EXPECTED_LABELS.iter().copied().collect();
    if allowed_repo_ids.is_empty() {
        return Err("ALLOWED_REPO_IDS is empty; refusing to start. Set at least one repository.id in src/main.rs.".into());
    }
    if expected_labels.is_empty() {
        return Err("EXPECTED_LABELS is empty; refusing to start. Set at least one runner label in src/main.rs (matched as a required subset of workflow_job.labels).".into());
    }

    let secret = load_secret()?;
    let spool_dir = std::env::var("SPOOL_DIR")
        .map(PathBuf::from)
        .map_err(|_| "SPOOL_DIR must point at the queue root directory")?;
    if !spool_dir.is_absolute() {
        return Err(format!(
            "SPOOL_DIR must be an absolute path; got {}",
            spool_dir.display()
        )
        .into());
    }
    let spool_dir = prepare_spool(spool_dir).await?;
    let state = Arc::new(AppState {
        secret,
        spool_dir,
        allowed_repo_ids,
        expected_labels,
    });

    // A non-loopback listener requires an explicit override no matter how the
    // socket is obtained — whether we bind it or launchd hands it to us. Read
    // the flag once; both acquisition paths below enforce the same gate.
    let allow_non_loopback = std::env::var("ALLOW_NON_LOOPBACK_BIND")
        .map(|v| v == "1")
        .unwrap_or(false);

    // The route the handler is mounted on. Configurable so the deployment can
    // match whatever path the GitHub App's webhook URL uses (e.g. a hard-to-
    // guess `/github/<uuid>`); the path is not a security boundary — the HMAC
    // is — but matching it avoids a reverse-proxy rewrite. It is mounted
    // verbatim as a literal route (see validate_webhook_path), so reject
    // anything that isn't loudly at startup.
    let webhook_path = std::env::var("WEBHOOK_PATH").unwrap_or_else(|_| "/webhook".into());
    validate_webhook_path(&webhook_path)?;

    let app = Router::new()
        .route(&webhook_path, post(webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    // Acquire the listening socket. Two mutually exclusive modes:
    //   * LAUNCHD_SOCKET_NAME set -> adopt the socket launchd created for that
    //     `Sockets` entry (macOS socket activation). launchd owns the socket
    //     across restarts, so the kernel queues connections in the accept
    //     backlog while we're down: `launchctl kickstart -k` drops zero
    //     deliveries — which matters because GitHub never auto-redelivers a
    //     failed webhook. LISTEN_ADDR is ignored here; the bind address lives
    //     in the plist, and the loopback gate is re-enforced on the inherited
    //     socket via getsockname (see launchd::adopt_listener_fd).
    //   * otherwise -> bind LISTEN_ADDR ourselves (default 127.0.0.1:8080),
    //     the mode used for `cargo run`, the tests, and non-launchd hosts.
    // No silent fallback: a set-but-failing LAUNCHD_SOCKET_NAME refuses to
    // start rather than quietly binding a fresh socket and losing zero-drop.
    let (listener, bound_addr, mode) = match std::env::var("LAUNCHD_SOCKET_NAME") {
        Ok(name) if !name.is_empty() => {
            let (l, addr) = launchd::listener_from_launchd(&name, allow_non_loopback)
                .map_err(|e| format!("LAUNCHD_SOCKET_NAME={name:?}: {e}"))?;
            (l, addr, "launchd socket activation")
        }
        _ => {
            let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
            let addr: SocketAddr = listen.parse()?;
            launchd::check_loopback(&addr, allow_non_loopback)?;
            let l = TcpListener::bind(addr).await?;
            (l, addr, "self-bound")
        }
    };
    eprintln!("gh-webhook-spool listening on {bound_addr} ({mode}), webhook path {webhook_path}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Validate WEBHOOK_PATH and accept it only if it is a *literal* path that
/// axum will mount verbatim. axum 0.7 (matchit 0.7) treats a `:name` segment
/// as a named capture and a `*name` segment as a catch-all: `/github/:uuid`
/// would match `/github/anything` rather than the literal segment the operator
/// intended, and a malformed pattern panics inside `Router::route` at startup.
/// `:` and `*` are matchit's complete metacharacter set, so a leading-slash
/// path containing neither is a purely static route — matched exactly and safe
/// to insert. A real hard-to-guess `/github/<uuid>` path contains neither, so
/// rejecting them costs nothing and turns a silent-mismatch / startup-panic
/// footgun into a clear config error.
fn validate_webhook_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("WEBHOOK_PATH must start with '/'; got {path:?}"));
    }
    if let Some(c) = path.chars().find(|&c| c == ':' || c == '*') {
        return Err(format!(
            "WEBHOOK_PATH must be a literal path but contains {c:?}: axum 0.7 \
             treats a ':name'/'*name' segment as a capture/catch-all, so \
             {path:?} would not match literally (and a malformed pattern panics \
             at startup). Use a path with no ':' or '*'."
        ));
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // Mounting `path` on a fresh Router must not panic. This is the invariant
    // validate_webhook_path exists to guarantee: axum's `Router::route` panics
    // on a malformed pattern, so "accepted => never panics at startup" is the
    // property we actually care about. catch_unwind because the failure mode is
    // a panic, not an error return.
    fn route_panics(path: &str) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let _ = Router::<()>::new().route(path, post(|| async {}));
        }))
        .is_err()
    }

    #[test]
    fn default_and_literal_paths_are_accepted() {
        for p in [
            "/webhook",
            "/",
            "/github/3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            "/a/b/c",
            "/deeply/nested/literal_path-1",
        ] {
            assert!(validate_webhook_path(p).is_ok(), "should accept {p:?}");
        }
    }

    #[test]
    fn missing_leading_slash_is_rejected() {
        for p in ["", "webhook", "github/x", ":x", "*x"] {
            assert!(validate_webhook_path(p).is_err(), "should reject {p:?}");
        }
    }

    #[test]
    fn capture_and_wildcard_segments_are_rejected() {
        for p in [
            "/github/:uuid",
            "/:x",
            "/a/:b/c",
            "/github/*rest",
            "/*",
            "/a/*catchall",
            "/mix/:a/*b",
        ] {
            assert!(validate_webhook_path(p).is_err(), "should reject {p:?}");
        }
    }

    // A ':'/'*' anywhere is conservatively rejected, even mid-segment where
    // matchit might treat it as literal — the rule is "no metacharacters at
    // all", which is simpler to reason about and loses no legitimate path.
    #[test]
    fn metacharacters_anywhere_are_rejected() {
        for p in ["/foo:bar", "/foo*bar", "/a/b:c/d", "/a/b*c/d"] {
            assert!(validate_webhook_path(p).is_err(), "should reject {p:?}");
        }
    }

    // Deterministic sweep over generated paths, exercising both directions of
    // the invariant with no PBT dependency:
    //   * every accepted (literal) path mounts on a Router without panicking;
    //   * prefixing the first segment with ':'/'*' flips it to Err.
    #[test]
    fn accepted_paths_never_panic_the_router() {
        const ALPHABET: &[u8] = b"abz09_-/";
        // A small LCG gives reproducible pseudo-random strings without needing
        // Math.random-style nondeterminism (which would break test replay).
        let mut lcg: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as usize
        };

        for _ in 0..4000 {
            let len = 1 + next() % 12;
            let mut body: String = (0..len)
                .map(|_| ALPHABET[next() % ALPHABET.len()] as char)
                .collect();
            let path = format!("/{body}");

            // Literal path: validator accepts AND the real router accepts it.
            assert!(
                validate_webhook_path(&path).is_ok(),
                "validator rejected literal path {path:?}"
            );
            assert!(
                !route_panics(&path),
                "Router::route panicked on validator-accepted path {path:?}"
            );

            // Now make it a capture/wildcard at a segment head: must be rejected.
            body.insert(0, ':');
            let captured = format!("/{body}");
            assert!(
                validate_webhook_path(&captured).is_err(),
                "validator accepted capture path {captured:?}"
            );
            body.remove(0);
            body.insert(0, '*');
            let wildcarded = format!("/{body}");
            assert!(
                validate_webhook_path(&wildcarded).is_err(),
                "validator accepted wildcard path {wildcarded:?}"
            );
        }
    }
}
