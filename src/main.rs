// gh-webhook-spool: accept GitHub workflow_job webhooks on localhost, verify
// HMAC-SHA256, drop anything not from a hardcoded repo allowlist or not
// matching the expected runner labels, and durably append one file per
// accepted job to a maildir-style queue (tmp/ -> rename -> new/).
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
// every one of those checks (the per-platform helpers below are #[cfg(unix)]
// gated). Refuse to compile rather than ship a binary that quietly turns off
// its own filesystem defences.
#[cfg(not(unix))]
compile_error!(
    "gh-webhook-spool requires a Unix target: the secret-file and spool-dir \
     checks depend on POSIX uid/mode/O_NOFOLLOW semantics that have no \
     portable analogue on other platforms."
);

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

const MAX_BODY_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
const MAX_DELIVERY_ID_LEN: usize = 64;
// GitHub's longest current event name is `secret_scanning_alert_location`
// (31 chars). 40 leaves room for a future event-name extension without
// inviting an attacker (who'd already need a valid HMAC) to scribble a
// 64-byte string into our log lines.
const MAX_EVENT_LEN: usize = 40;
const MAX_SECRET_FILE_BYTES: u64 = 4096;
// open(2)'s O_NOFOLLOW flag value. Defined inline per-target instead of
// pulling in libc/nix — same reason `geteuid` is reached via an inline
// `extern "C"`. Values come from <fcntl.h> on each platform and are stable
// kernel ABI. Add a branch for any new target the flake decides to build.
#[cfg(all(unix, target_os = "linux"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    )
))]
const O_NOFOLLOW: i32 = 0x100;
// 16 bytes ≈ 128 bits of entropy if the secret is generated with `openssl
// rand` / similar. GitHub itself allows any length, but the secret is the
// entire forge boundary and a short one is a silent footgun.
const MIN_SECRET_BYTES: usize = 16;
const ENVELOPE_SCHEMA: u32 = 1;

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

pub struct AppState {
    secret: Vec<u8>,
    spool_dir: PathBuf,
    allowed_repo_ids: HashSet<u64>,
    expected_labels: HashSet<&'static str>,
}

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

    let app = Router::new()
        .route("/webhook", post(webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    eprintln!("gh-webhook-spool listening on {addr}");
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

fn load_secret() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
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
fn read_secret_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
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
fn read_secret_open_fd(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

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

async fn prepare_spool(root: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
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

async fn create_dir_secure(path: &Path) -> io::Result<()> {
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
fn verify_dir_secure(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    Ok(())
}

fn verify_ancestor_chain(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

fn current_euid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

async fn sweep_tmp(tmp: &Path) -> io::Result<()> {
    let mut entries = fs::read_dir(tmp).await?;
    let mut swept_any = false;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        match fs::remove_file(&path).await {
            Ok(()) => {
                eprintln!("swept stale tmp file: {}", path.display());
                swept_any = true;
            }
            Err(e) => eprintln!(
                "warning: failed to sweep stale tmp file {}: {}",
                path.display(),
                e
            ),
        }
    }
    if swept_any {
        // Make the unlinks durable so a crash right after sweep doesn't
        // leave the same files there for the next startup to re-sweep.
        let tmp_owned = tmp.to_path_buf();
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            let dir = std::fs::File::open(&tmp_owned)?;
            dir.sync_all()
        })
        .await
        .map_err(io::Error::other)??;
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Outcome {
    Accepted,     // 200; newly enqueued
    Duplicate,    // 200; idempotent retry of an already-enqueued delivery
    Acknowledged, // 200; intentionally not enqueued (ping, unallowed repo, wrong event/action/labels, no-repo event)
    // 503; another writer holds tmp/ for this id and new/ doesn't show
    // the result yet. GitHub does NOT automatically redeliver failed
    // webhook deliveries
    // (https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries):
    // a 503 here will surface in the repo's "Recent Deliveries" page as
    // a failed delivery, and the operator (or a companion redelivery
    // monitor) must request redelivery via the GitHub API/UI. See
    // README "Operations → Failed deliveries".
    InFlight,
    Unauthorized, // 401
    BadRequest,   // 400
    // 500; an I/O error or schema failure prevented us from writing the
    // file. Same retry caveat as InFlight — GitHub will not auto-retry.
    InternalError,
}

impl Outcome {
    fn status(self) -> StatusCode {
        match self {
            Outcome::Accepted | Outcome::Duplicate | Outcome::Acknowledged => StatusCode::OK,
            Outcome::InFlight => StatusCode::SERVICE_UNAVAILABLE,
            Outcome::Unauthorized => StatusCode::UNAUTHORIZED,
            Outcome::BadRequest => StatusCode::BAD_REQUEST,
            Outcome::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Outcome {
    fn into_response(self) -> axum::response::Response {
        self.status().into_response()
    }
}

async fn webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Outcome {
    process(&state, &headers, &body).await
}

pub async fn process(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Outcome {
    // 1. Authenticate by HMAC against the raw bytes, before parsing anything.
    let Some(sig_hex_raw) = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("sha256="))
    else {
        return Outcome::Unauthorized;
    };
    let provided = match hex::decode(sig_hex_raw) {
        Ok(b) if b.len() == 32 => b,
        _ => return Outcome::Unauthorized,
    };
    // Normalize the hex case so the envelope's stored signature is stable
    // regardless of what case the caller sent (hex::decode accepts both).
    let sig_hex = sig_hex_raw.to_ascii_lowercase();
    let mut mac = HmacSha256::new_from_slice(&state.secret).expect("HMAC accepts any key length");
    mac.update(body);
    if mac.verify_slice(&provided).is_err() {
        return Outcome::Unauthorized;
    }

    // 2. Pull and sanitize the GitHub event header.
    let event = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_valid_event(event) {
        return Outcome::BadRequest;
    }

    // Ping is the GitHub webhook health-check. Accept silently.
    if event == "ping" {
        return Outcome::Acknowledged;
    }

    // 3. Only workflow_job spins up runners. Drop everything else silently
    //    so a misconfigured "send me everything" webhook can't accidentally
    //    enqueue push/pull_request/etc.
    if event != "workflow_job" {
        return Outcome::Acknowledged;
    }

    // From here the delivery header is load-bearing (envelope + log lines),
    // so validate now. Unrelated events with weird delivery headers above
    // would have been ack'd already without ever needing the value.
    let delivery = headers
        .get("x-github-delivery")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_valid_delivery(delivery) {
        return Outcome::BadRequest;
    }

    // 4. Require application/json. GitHub also supports form-urlencoded
    //    (`payload=<json>`) which would HMAC-verify but fail the JSON parse
    //    below — produce a clearer error so an operator can fix the webhook
    //    config rather than chasing a phantom HMAC mismatch.
    if !content_type_is_json(headers) {
        eprintln!(
            "rejecting delivery {delivery}: content-type is not application/json \
             (set the GitHub webhook content type to JSON, not application/x-www-form-urlencoded)"
        );
        return Outcome::BadRequest;
    }

    // 5. Parse just enough of the body to apply our policy.
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Outcome::BadRequest,
    };
    let Some(repo_id) = parsed
        .get("repository")
        .and_then(|r| r.get("id"))
        .and_then(|n| n.as_u64())
    else {
        return Outcome::Acknowledged;
    };
    if !state.allowed_repo_ids.contains(&repo_id) {
        // Silent so the allowlist is not enumerable.
        return Outcome::Acknowledged;
    }

    // Refuse non-private repositories. The workflow_job payload doesn't
    // include head_repository, so we can't directly tell a fork PR apart
    // from a maintainer push, but refusing non-private repos eliminates the
    // public-fork-PR class entirely (the high-risk one). A residual risk
    // remains for collaborators of private repos who could privately fork
    // and submit PRs — see README's threat-model section. The repo is
    // already past the ID allowlist here, so a non-private answer means the
    // operator listed a public repo or the visibility changed under us;
    // log loudly so it's noticeable.
    //
    // The check requires both `private == true` AND `visibility == "private"`.
    // On GitHub Enterprise, `internal` is a separate repository visibility
    // that reports `private: true` but is readable by every full enterprise
    // member — a `private`-only gate would let it through. If `visibility`
    // is absent from the payload (older webhook deliveries, custom proxies,
    // future schema changes), fail closed.
    let repo = parsed.get("repository");
    let is_private = repo
        .and_then(|r| r.get("private"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let visibility = repo
        .and_then(|r| r.get("visibility"))
        .and_then(|v| v.as_str());
    if !is_private || visibility != Some("private") {
        eprintln!(
            "rejecting delivery {delivery}: repository.id={repo_id} private={is_private} visibility={visibility:?} (workflow_job spool refuses public/internal repos by design; both private==true and visibility==\"private\" required)"
        );
        return Outcome::Acknowledged;
    }

    let action = parsed.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "queued" {
        return Outcome::Acknowledged;
    }

    // workflow_job.id is the dedup key: it's an authenticated field (covered
    // by the HMAC) and unique per job in GitHub's database, so replays with
    // a fresh X-GitHub-Delivery header can't manufacture a new queue entry.
    let Some(workflow_job_id) = parsed
        .get("workflow_job")
        .and_then(|j| j.get("id"))
        .and_then(|n| n.as_u64())
    else {
        return Outcome::Acknowledged;
    };

    // 6. EXPECTED_LABELS subset semantic: every configured label must appear
    //    in workflow_job.labels. This matches how GitHub itself selects
    //    runners (a runner with labels {a,b,c} can run a job that requests
    //    any non-empty subset of those). Empty EXPECTED_LABELS is refused
    //    at startup, so within process() it's never empty in production.
    let job_labels: HashSet<&str> = parsed
        .get("workflow_job")
        .and_then(|j| j.get("labels"))
        .and_then(|l| l.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let all_present = state.expected_labels.iter().all(|l| job_labels.contains(l));
    if !all_present {
        return Outcome::Acknowledged;
    }

    // 7. Build a self-describing envelope and durably write to the queue.
    //    repo_name is included for human-readable logs and downstream
    //    display; the trust decision was made on repo_id above.
    let repo_name = parsed
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");
    let received_at_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let signature = format!("sha256={sig_hex}");
    let envelope = Envelope {
        schema: ENVELOPE_SCHEMA,
        event,
        delivery,
        repo_id,
        repo: repo_name,
        action,
        workflow_job_id,
        received_at_ms,
        signature: &signature,
    };
    let header_line = match serde_json::to_vec(&envelope) {
        Ok(v) => v,
        Err(_) => return Outcome::InternalError,
    };

    // Filename is workflow_job.id, an authenticated payload field. See the
    // module header for the replay reasoning.
    let filename = format!("{workflow_job_id}.job");
    let repo_log = sanitize_for_log(repo_name);
    match enqueue(&state.spool_dir, &filename, &header_line, body).await {
        Ok(EnqueueResult::Wrote) => {
            eprintln!(
                "enqueued delivery={delivery} workflow_job_id={workflow_job_id} event={event} action={action} repo_id={repo_id} repo={repo_log}"
            );
            Outcome::Accepted
        }
        Ok(EnqueueResult::Duplicate) => {
            eprintln!(
                "duplicate delivery={delivery} workflow_job_id={workflow_job_id} event={event} action={action} repo_id={repo_id} repo={repo_log}"
            );
            Outcome::Duplicate
        }
        Ok(EnqueueResult::InFlight) => {
            // GitHub does not auto-retry on 503 — this delivery will need
            // manual redelivery via the GitHub UI/API (or a companion
            // monitor). Log loudly so operators notice in `Recent
            // Deliveries`.
            eprintln!(
                "concurrent writer holds tmp/ delivery={delivery} workflow_job_id={workflow_job_id}; returning 503 — GitHub will NOT auto-retry, request redelivery if the other writer also failed"
            );
            Outcome::InFlight
        }
        Err(e) => {
            // Same caveat as InFlight: GitHub won't retry the 500. The
            // delivery is recorded as failed in the GitHub UI; replay
            // from there.
            eprintln!(
                "enqueue failed for delivery {delivery} workflow_job_id={workflow_job_id}: {e} (GitHub does not auto-retry — request redelivery from the webhook's Recent Deliveries page)"
            );
            Outcome::InternalError
        }
    }
}

// Consumers of new/ MUST:
//   1. Treat the envelope as advisory metadata. It is NOT covered by
//      GitHub's HMAC and a local writer with the right uid/group could
//      pair a valid (body, signature) with tampered envelope fields.
//      Derive every trust-relevant field (repo_id, action,
//      workflow_job.id, labels) from the HMAC-verified body, not from
//      the envelope.
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
struct Envelope<'a> {
    schema: u32,
    event: &'a str,
    delivery: &'a str,
    repo_id: u64,
    repo: &'a str,
    action: &'a str,
    workflow_job_id: u64,
    received_at_ms: u64,
    signature: &'a str,
}

pub enum EnqueueResult {
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

pub async fn enqueue(
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
                return Ok(EnqueueResult::Duplicate);
            }
            return Ok(EnqueueResult::InFlight);
        }
        Err(e) => return Err(e),
    };

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
    // tokio doesn't expose directory fsync; do it on the blocking pool.
    let new_dir = spool_dir.join("new");
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let dir = std::fs::File::open(&new_dir)?;
        dir.sync_all()
    })
    .await
    .map_err(io::Error::other)??;

    Ok(EnqueueResult::Wrote)
}

fn is_valid_delivery(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_DELIVERY_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_valid_event(s: &str) -> bool {
    // GitHub event names are lowercase ASCII with `_` separators. We also
    // accept digits so a future `workflow_v2`-shaped event name can flow
    // through to our "ack and drop" path instead of pinning the delivery in
    // a 400-retry loop.
    !s.is_empty()
        && s.len() <= MAX_EVENT_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

// repo full_name is pulled from the JSON body and logged. GitHub's own repo
// names are restricted ASCII, but the body is JSON and could in principle
// hold control characters that would mangle stderr. Strip control chars and
// cap the length so a misbehaving (allowlisted) repo name can't spam logs.
fn sanitize_for_log(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(128).collect()
}

fn content_type_is_json(headers: &HeaderMap) -> bool {
    let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    // Tolerate "application/json; charset=utf-8" and friends.
    let main = ct.split(';').next().unwrap_or("").trim();
    main.eq_ignore_ascii_case("application/json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn sign(secret: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn state_with(tmp: &Path, repo_ids: &[u64], labels: &[&'static str]) -> AppState {
        AppState {
            secret: b"shhh".to_vec(),
            spool_dir: tmp.to_path_buf(),
            allowed_repo_ids: repo_ids.iter().copied().collect(),
            expected_labels: labels.iter().copied().collect(),
        }
    }

    fn headers(event: &str, delivery: &str, sig: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-github-event", HeaderValue::from_str(event).unwrap());
        h.insert(
            "x-github-delivery",
            HeaderValue::from_str(delivery).unwrap(),
        );
        h.insert("x-hub-signature-256", HeaderValue::from_str(sig).unwrap());
        h.insert("content-type", HeaderValue::from_static("application/json"));
        h
    }

    fn wfjob_body(repo_id: u64, full_name: &str, action: &str, labels: &[&str]) -> Vec<u8> {
        wfjob_body_with_id(repo_id, full_name, action, labels, 1)
    }

    fn wfjob_body_with_id(
        repo_id: u64,
        full_name: &str,
        action: &str,
        labels: &[&str],
        workflow_job_id: u64,
    ) -> Vec<u8> {
        wfjob_body_full(
            repo_id,
            full_name,
            action,
            labels,
            workflow_job_id,
            true,
            Some("private"),
        )
    }

    fn wfjob_body_full(
        repo_id: u64,
        full_name: &str,
        action: &str,
        labels: &[&str],
        workflow_job_id: u64,
        private: bool,
        visibility: Option<&str>,
    ) -> Vec<u8> {
        let labels_json: Vec<serde_json::Value> =
            labels.iter().map(|l| serde_json::json!(l)).collect();
        let mut repo = serde_json::json!({
            "id": repo_id,
            "full_name": full_name,
            "private": private,
        });
        if let Some(v) = visibility {
            repo["visibility"] = serde_json::json!(v);
        }
        serde_json::to_vec(&serde_json::json!({
            "action": action,
            "workflow_job": { "id": workflow_job_id, "labels": labels_json },
            "repository": repo,
        }))
        .unwrap()
    }

    async fn fresh_spool() -> (tempdir_like::TempDir, PathBuf) {
        let dir = tempdir_like::TempDir::new("spool").unwrap();
        let root = dir.path().to_path_buf();
        // Tests skip the security-verify path; they just need the layout.
        fs::create_dir(root.join("tmp")).await.unwrap();
        fs::create_dir(root.join("new")).await.unwrap();
        (dir, root)
    }

    #[tokio::test]
    async fn valid_signature_for_allowed_repo_is_enqueued() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &["self-hosted"]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-0001", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Accepted);

        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        let entry = entries.next_entry().await.unwrap().expect("file in new/");
        assert_eq!(entry.file_name(), "1.job");
        let contents = fs::read(entry.path()).await.unwrap();
        let nl = contents.iter().position(|&b| b == b'\n').unwrap();
        let envelope: serde_json::Value =
            serde_json::from_slice(&contents[..nl]).expect("envelope is json");
        assert_eq!(envelope["schema"], 1);
        assert_eq!(envelope["event"], "workflow_job");
        assert_eq!(envelope["delivery"], "deadbeef-0001");
        assert_eq!(envelope["repo_id"], 42);
        assert_eq!(envelope["repo"], "octo/cat");
        assert_eq!(envelope["action"], "queued");
        assert_eq!(envelope["workflow_job_id"], 1);
        assert_eq!(&contents[nl + 1..], body.as_slice());

        let mut tmp_entries = fs::read_dir(root.join("tmp")).await.unwrap();
        assert!(
            tmp_entries.next_entry().await.unwrap().is_none(),
            "tmp/ should be empty after rename"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn enqueued_file_has_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "mode-test", &sig);
        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Accepted);

        let entry = fs::read_dir(root.join("new"))
            .await
            .unwrap()
            .next_entry()
            .await
            .unwrap()
            .unwrap();
        let md = entry.metadata().await.unwrap();
        assert_eq!(
            md.permissions().mode() & 0o777,
            0o600,
            "spool file should be 0600"
        );
    }

    #[tokio::test]
    async fn duplicate_delivery_acked_idempotently() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "dup-delivery", &sig);

        assert_eq!(process(&state, &h, &body).await, Outcome::Accepted);
        assert_eq!(process(&state, &h, &body).await, Outcome::Duplicate);

        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        let _first = entries.next_entry().await.unwrap().expect("file in new/");
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "no second file created for retried delivery"
        );
    }

    #[tokio::test]
    async fn replay_with_fresh_delivery_header_still_dedupes() {
        // X-GitHub-Delivery is unauthenticated, so an attacker holding a
        // valid (body, signature) pair could resubmit with a fresh delivery.
        // Filename is workflow_job.id from the signed body, so dedup holds.
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body_with_id(42, "octo/cat", "queued", &[], 9001);
        let sig = sign(&state.secret, &body);

        let h1 = headers("workflow_job", "real-delivery", &sig);
        assert_eq!(process(&state, &h1, &body).await, Outcome::Accepted);

        // Same body+signature, fresh delivery header.
        let h2 = headers("workflow_job", "attacker-replay-xyz", &sig);
        assert_eq!(process(&state, &h2, &body).await, Outcome::Duplicate);

        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        let entry = entries.next_entry().await.unwrap().expect("file in new/");
        assert_eq!(entry.file_name(), "9001.job");
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn label_filter_requires_all_expected_labels_present() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &["self-hosted", "my-fleet"]);

        // Missing one of the required labels -> reject.
        let body_partial = wfjob_body_with_id(42, "octo/cat", "queued", &["my-fleet", "linux"], 1);
        let sig = sign(&state.secret, &body_partial);
        let h = headers("workflow_job", "label-part", &sig);
        assert_eq!(
            process(&state, &h, &body_partial).await,
            Outcome::Acknowledged
        );

        // Job lists all required labels (plus extras) -> accept.
        let body_full = wfjob_body_with_id(
            42,
            "octo/cat",
            "queued",
            &["self-hosted", "my-fleet", "linux"],
            2,
        );
        let sig = sign(&state.secret, &body_full);
        let h = headers("workflow_job", "label-full", &sig);
        assert_eq!(process(&state, &h, &body_full).await, Outcome::Accepted);
    }

    #[tokio::test]
    async fn wrong_signature_is_unauthorized_and_does_not_enqueue() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let bad_sig = sign(b"different-secret", &body);
        let h = headers("workflow_job", "deadbeef-0002", &bad_sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Unauthorized);

        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_signature_header_is_unauthorized() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let mut h = HeaderMap::new();
        h.insert("x-github-event", HeaderValue::from_static("workflow_job"));
        h.insert("x-github-delivery", HeaderValue::from_static("d-0003"));

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Unauthorized);
    }

    #[tokio::test]
    async fn sha1_only_signature_is_unauthorized() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let mut h = HeaderMap::new();
        h.insert("x-github-event", HeaderValue::from_static("workflow_job"));
        h.insert("x-github-delivery", HeaderValue::from_static("d-0004"));
        h.insert("x-hub-signature", HeaderValue::from_static("sha1=abcdef"));

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Unauthorized);
    }

    #[tokio::test]
    async fn allowlisted_public_repo_acknowledged_but_not_enqueued() {
        // The repo ID is in the allowlist but private:false → reject.
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body_full(42, "octo/cat", "queued", &[], 1, false, Some("public"));
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-pub1", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Acknowledged);
        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn allowlisted_internal_repo_acknowledged_but_not_enqueued() {
        // GitHub Enterprise "internal" repos report private=true but
        // visibility="internal" — readable by every full enterprise
        // member. A private-only gate would let them through.
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body_full(42, "octo/cat", "queued", &[], 1, true, Some("internal"));
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-int1", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Acknowledged);
        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_visibility_field_acknowledged() {
        // Fail closed when visibility is absent — older deliveries, custom
        // proxies, or future schema changes shouldn't quietly downgrade
        // the gate to private-only.
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body_full(42, "octo/cat", "queued", &[], 1, true, None);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-novis", &sig);
        assert_eq!(process(&state, &h, &body).await, Outcome::Acknowledged);
        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_private_field_acknowledged() {
        // No `private` field present in the repository object → treat as
        // not-private and refuse, matching the fail-closed default.
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "queued",
            "workflow_job": { "id": 1, "labels": [] },
            "repository": { "id": 42, "full_name": "octo/cat", "visibility": "private" }
        }))
        .unwrap();
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-noprv", &sig);
        assert_eq!(process(&state, &h, &body).await, Outcome::Acknowledged);
    }

    #[tokio::test]
    async fn unallowed_repo_acknowledged_but_not_enqueued() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(999, "someone/else", "queued", &[]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-0005", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Acknowledged);
        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ping_event_acknowledged() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = br#"{"zen":"Speak like a human."}"#;
        let sig = sign(&state.secret, body);
        let h = headers("ping", "deadbeef-0006", &sig);

        let out = process(&state, &h, body).await;
        assert_eq!(out, Outcome::Acknowledged);
    }

    #[tokio::test]
    async fn non_workflow_job_event_is_acknowledged() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "opened", &[]);
        let sig = sign(&state.secret, &body);
        let h = headers("pull_request", "deadbeef-pr01", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Acknowledged);
        let mut entries = fs::read_dir(root.join("new")).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn workflow_job_completed_action_is_acknowledged() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "completed", &[]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-done", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Acknowledged);
    }

    #[tokio::test]
    async fn workflow_job_without_label_match_is_acknowledged() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &["my-fleet"]);
        let body = wfjob_body(42, "octo/cat", "queued", &["self-hosted", "linux"]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-label", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Acknowledged);
    }

    #[tokio::test]
    async fn workflow_job_with_label_match_is_enqueued() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &["my-fleet"]);
        let body = wfjob_body(42, "octo/cat", "queued", &["self-hosted", "my-fleet"]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "deadbeef-mat1", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::Accepted);
    }

    #[tokio::test]
    async fn unsafe_delivery_id_is_rejected() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "../etc/passwd", &sig);

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::BadRequest);
    }

    #[tokio::test]
    async fn form_urlencoded_content_type_is_bad_request() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = wfjob_body(42, "octo/cat", "queued", &[]);
        let sig = sign(&state.secret, &body);
        let mut h = headers("workflow_job", "deadbeef-ct01", &sig);
        h.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let out = process(&state, &h, &body).await;
        assert_eq!(out, Outcome::BadRequest);
    }

    #[tokio::test]
    async fn invalid_json_after_valid_hmac_is_bad_request() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = b"not json {";
        let sig = sign(&state.secret, body);
        let h = headers("workflow_job", "deadbeef-0007", &sig);

        let out = process(&state, &h, body).await;
        assert_eq!(out, Outcome::BadRequest);
    }

    #[tokio::test]
    async fn workflow_job_without_repository_is_acknowledged() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        let body = br#"{"action":"queued"}"#;
        let sig = sign(&state.secret, body);
        let h = headers("workflow_job", "deadbeef-0008", &sig);

        let out = process(&state, &h, body).await;
        assert_eq!(out, Outcome::Acknowledged);
    }

    #[tokio::test]
    async fn workflow_job_without_id_field_is_acknowledged() {
        let (_dir, root) = fresh_spool().await;
        let state = state_with(&root, &[42], &[]);
        // `private: true` so the private-repo gate doesn't ack first — we
        // want to exercise the "missing workflow_job.id" path specifically.
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "queued",
            "workflow_job": { "labels": ["self-hosted"] },
            "repository": { "id": 42, "full_name": "octo/cat", "private": true }
        }))
        .unwrap();
        let sig = sign(&state.secret, &body);
        let h = headers("workflow_job", "no-id", &sig);
        assert_eq!(process(&state, &h, &body).await, Outcome::Acknowledged);
    }

    #[test]
    fn delivery_validator_accepts_uuid_shape_only() {
        assert!(is_valid_delivery("72d3162e-cc78-11e3-81ab-4c9367dc0958"));
        assert!(is_valid_delivery("abc_123"));
        assert!(!is_valid_delivery(""));
        assert!(!is_valid_delivery("a/b"));
        assert!(!is_valid_delivery("../x"));
        assert!(!is_valid_delivery("abc.def"));
        assert!(!is_valid_delivery(&"a".repeat(MAX_DELIVERY_ID_LEN + 1)));
    }

    #[test]
    fn sanitize_for_log_strips_control_chars_and_caps_length() {
        assert_eq!(sanitize_for_log("octo/cat"), "octo/cat");
        assert_eq!(sanitize_for_log("evil\nfake-log-line"), "evilfake-log-line");
        assert_eq!(sanitize_for_log("\x1b[31mred\x1b[0m"), "[31mred[0m");
        let long: String = "a".repeat(500);
        assert_eq!(sanitize_for_log(&long).len(), 128);
    }

    #[test]
    fn event_validator_accepts_github_event_names() {
        assert!(is_valid_event("push"));
        assert!(is_valid_event("pull_request"));
        assert!(is_valid_event("ping"));
        assert!(is_valid_event("workflow_job"));
        assert!(is_valid_event("workflow_v2")); // forward-compat: digits OK
        assert!(is_valid_event("event_123"));
        assert!(!is_valid_event(""));
        assert!(!is_valid_event("Push"));
        assert!(!is_valid_event("pull-request"));
        assert!(!is_valid_event("../x"));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn read_secret_open_fd_rejects_unsafe_files() {
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

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_dir_secure_rejects_unsafe_dirs() {
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

    // A tiny in-tree replacement for `tempfile` to avoid an extra dep just
    // for tests; cleans up on drop.
    mod tempdir_like {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir(PathBuf);
        impl TempDir {
            pub fn new(prefix: &str) -> std::io::Result<Self> {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let pid = std::process::id();
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{n}"));
                std::fs::create_dir(&p)?;
                Ok(TempDir(p))
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
