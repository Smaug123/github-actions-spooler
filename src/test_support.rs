// Shared test helpers used by the per-module `mod tests` blocks. Compiled only
// under `cfg(test)`; nothing here ships in the binary.

use std::path::{Path, PathBuf};

use axum::http::{HeaderMap, HeaderValue};
use hmac::Mac;
use tokio::fs;

use crate::webhook::{AppState, HmacSha256};

pub(crate) fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

pub(crate) fn state_with(tmp: &Path, repo_ids: &[u64], labels: &[&'static str]) -> AppState {
    AppState {
        secret: b"shhh".to_vec(),
        spool_dir: tmp.to_path_buf(),
        allowed_repo_ids: repo_ids.iter().copied().collect(),
        expected_labels: labels.iter().copied().collect(),
    }
}

pub(crate) fn headers(event: &str, delivery: &str, sig: &str) -> HeaderMap {
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

pub(crate) fn wfjob_body(repo_id: u64, full_name: &str, action: &str, labels: &[&str]) -> Vec<u8> {
    wfjob_body_with_id(repo_id, full_name, action, labels, 1)
}

pub(crate) fn wfjob_body_with_id(
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

pub(crate) fn wfjob_body_full(
    repo_id: u64,
    full_name: &str,
    action: &str,
    labels: &[&str],
    workflow_job_id: u64,
    private: bool,
    visibility: Option<&str>,
) -> Vec<u8> {
    let labels_json: Vec<serde_json::Value> = labels.iter().map(|l| serde_json::json!(l)).collect();
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

pub(crate) async fn fresh_spool() -> (tempdir_like::TempDir, PathBuf) {
    let dir = tempdir_like::TempDir::new("spool").unwrap();
    let root = dir.path().to_path_buf();
    // Tests skip the security-verify path; they just need the layout.
    fs::create_dir(root.join("tmp")).await.unwrap();
    fs::create_dir(root.join("new")).await.unwrap();
    (dir, root)
}

// A tiny in-tree replacement for `tempfile` to avoid an extra dep just
// for tests; cleans up on drop.
pub(crate) mod tempdir_like {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct TempDir(PathBuf);
    impl TempDir {
        pub(crate) fn new(prefix: &str) -> std::io::Result<Self> {
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
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
