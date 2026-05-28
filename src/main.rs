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

    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let addr: SocketAddr = listen.parse()?;
    if !addr.ip().is_loopback() {
        // The whole threat model assumes loopback-only ingress: no rate
        // limiting, no TLS, no IP allowlisting in this binary. Fail loud
        // rather than warn-and-bind, otherwise a typo in LISTEN_ADDR
        // exposes a raw HTTP handler to the network.
        let allow = std::env::var("ALLOW_NON_LOOPBACK_BIND")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !allow {
            return Err(format!(
                "refusing to bind {addr}: this binary expects to sit behind a TLS reverse proxy on loopback. \
                 Set ALLOW_NON_LOOPBACK_BIND=1 to override (only when an external network policy guarantees \
                 nothing untrusted can reach the listener)."
            )
            .into());
        }
        eprintln!("warning: binding {addr} per ALLOW_NON_LOOPBACK_BIND=1");
    }

    // The route the handler is mounted on. Configurable so the deployment can
    // match whatever path the GitHub App's webhook URL uses (e.g. a hard-to-
    // guess `/github/<uuid>`); the path is not a security boundary — the HMAC
    // is — but matching it avoids a reverse-proxy rewrite. axum requires a
    // leading slash, so reject anything else loudly at startup.
    let webhook_path = std::env::var("WEBHOOK_PATH").unwrap_or_else(|_| "/webhook".into());
    if !webhook_path.starts_with('/') {
        return Err(format!("WEBHOOK_PATH must start with '/'; got {webhook_path:?}").into());
    }

    let app = Router::new()
        .route(&webhook_path, post(webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    eprintln!("gh-webhook-spool listening on {addr}, webhook path {webhook_path}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
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
