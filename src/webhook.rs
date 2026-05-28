// The HTTP-facing policy core: authenticate by HMAC over the raw bytes, then
// apply the event/repo/visibility/action/label gates and hand accepted jobs to
// the spool. `process` is the testable heart; `webhook` is the thin axum glue.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::spool::{enqueue, EnqueueResult, Envelope, ENVELOPE_SCHEMA};

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) const MAX_DELIVERY_ID_LEN: usize = 64;
// GitHub's longest current event name is `secret_scanning_alert_location`
// (31 chars). 40 leaves room for a future event-name extension without
// inviting an attacker (who'd already need a valid HMAC) to scribble a
// 64-byte string into our log lines.
pub(crate) const MAX_EVENT_LEN: usize = 40;

pub(crate) struct AppState {
    pub(crate) secret: Vec<u8>,
    pub(crate) spool_dir: PathBuf,
    pub(crate) allowed_repo_ids: HashSet<u64>,
    pub(crate) expected_labels: HashSet<&'static str>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub(crate) enum Outcome {
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

pub(crate) async fn webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Outcome {
    process(&state, &headers, &body).await
}

pub(crate) async fn process(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Outcome {
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
    use crate::test_support::{
        fresh_spool, headers, sign, state_with, wfjob_body, wfjob_body_full, wfjob_body_with_id,
    };
    use axum::http::HeaderValue;
    use tokio::fs;

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
        // `private: true` AND `visibility: "private"` so the private-repo gate
        // doesn't ack first — we want to exercise the "missing
        // workflow_job.id" path specifically.
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "queued",
            "workflow_job": { "labels": ["self-hosted"] },
            "repository": {
                "id": 42,
                "full_name": "octo/cat",
                "private": true,
                "visibility": "private"
            }
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
}
