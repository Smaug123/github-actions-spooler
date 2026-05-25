# AGENTS.md

Single-binary HMAC-verifying GitHub webhook receiver. Spools `workflow_job`
queued events to a maildir-style on-disk queue for a downstream self-hosted
runner provisioner. All source is in `src/main.rs`.

## Commands

```
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
nix build              # release binary via the flake
```

## Configuration knobs (compile-time)

- `ALLOWED_REPO_IDS: &[u64]` — `repository.id` allowlist. Empty refuses to
  start. All listed repos MUST be private; non-private repos are
  rejected at runtime.
- `EXPECTED_LABELS: &[&str]` — required runner labels, subset-of
  `workflow_job.labels`. Empty refuses to start.
- `MAX_BODY_BYTES`, `MAX_DELIVERY_ID_LEN`, `MAX_EVENT_LEN`,
  `MAX_SECRET_FILE_BYTES`, `MIN_SECRET_BYTES` — input limits.

## Invariants — do not weaken

1. HMAC verifies against the raw bytes **before** any parsing or branching
   on payload content. Use `hmac::verify_slice` (constant-time).
2. Header charsets validated before any value reaches the filesystem.
3. Allowlist by `repository.id`, never by `full_name` (full_name is mutable
   under rename/transfer).
4. Allowlist and label misses return 200 with no enqueue — silent so the
   list isn't enumerable. Private-repo and other policy misses log
   (the operator already revealed the repo was on the allowlist by
   putting it there).
5. **Non-private repos are refused.** `workflow_job` doesn't include
   `head_repository`, so this is the strongest fork-PR gate the payload
   alone supports. The gate requires both `repository.private == true`
   **and** `repository.visibility == "private"`; missing `visibility`
   fails closed. The visibility check exists because GitHub Enterprise's
   `internal` repos report `private: true` and would otherwise pass.
   See README "Threat model" for the residual risk.
6. **Dedup key is `workflow_job.id`, not the `X-GitHub-Delivery` header.**
   GitHub's HMAC covers the body only, so the delivery header is
   attacker-controllable for anyone holding a valid signed body. Filenames
   are `{workflow_job_id}.job`. Nothing else from the payload reaches a
   path.
7. `enqueue` is tmp-then-rename, fsync the file, then fsync `new/`. A
   concurrent retry while another writer holds `tmp/{id}` returns
   `Outcome::InFlight` (503), not `InternalError` — the operator's logs
   stay honest. **GitHub does not auto-retry failed repository/org webhook
   deliveries** (see README "Operations → Failed deliveries"), so a 503
   surfaces as a failed delivery on the webhook's Recent Deliveries page
   and stays there until an operator (or companion redelivery monitor)
   replays it. Any write/sync/rename error after the tmp file is opened
   MUST unlink `tmp/{id}` before returning — otherwise subsequent retries
   collide on `create_new` and return InFlight forever (until restart
   sweeps tmp).
8. `prepare_spool` canonicalizes the spool root after creating it and
   refuses to start unless `root/tmp/new` are real dirs (no symlinks)
   owned by `geteuid` with no group/other write bits, and every
   *canonical* ancestor up to `/` is a real dir owned by uid 0 or
   `geteuid` with no group/other write bits. Canonicalization matters:
   a textual parent walk would miss the real ancestors when SPOOL_DIR
   contains `..` segments. `new/` is the trust handoff to the
   consumer; anything that can write there bypasses HMAC ingress.
   **The envelope written to `new/{id}.job` is NOT authenticated** — a
   process with write access to `new/` can pair a valid (body, signature)
   with a tampered envelope. The consumer is required to derive trust
   fields from the HMAC-verified body, not the envelope; see README's
   "Consumer requirements". A future hardening would open `new/` as an
   fd at startup and use `openat`/`renameat` to close the runtime
   directory-swap window, but the static permission audit is the
   defence today.
9. `load_secret` → `read_secret_file` enforces the same ancestor lockdown
   as `prepare_spool` (every parent up to `/` must be a real dir owned by
   uid 0 or euid with no group/other write bits), rejects a final-component
   symlink at the user-given path, opens the canonicalized path with
   `O_NOFOLLOW`, and reads metadata via `fstat` on the opened fd so the
   verified bytes are the ones returned — closing the stat-then-read
   TOCTOU. Same hygiene as the spool dir because the secret bears the
   entire forge boundary.
10. `LISTEN_ADDR` non-loopback requires `ALLOW_NON_LOOPBACK_BIND=1`. The
    threat model assumes loopback-only ingress.
11. Envelope schema bumps are breaking changes for the consumer — bump
    the `ENVELOPE_SCHEMA` constant and coordinate.

## Dependencies

Keep the dep list minimal — the point of this binary is a small audited
surface. Currently: `axum`, `tokio`, `hmac`, `sha2`, `hex`, `serde`,
`serde_json`. `geteuid` is reached via an inline `extern "C"` block, and
`O_NOFOLLOW` is defined inline per-target, both to avoid pulling in `libc`
or `nix`. Add a new branch to the `O_NOFOLLOW` cfg ladder if the flake
starts building for a target outside `linux` / `macos` / `ios` / `freebsd`
/ `openbsd`.

## Tests

All tests live in `mod tests` in `src/main.rs`. `fresh_spool` builds a temp
queue layout (skips the security verify path), `wfjob_body` builds a
`workflow_job` payload, `tempdir_like` is the in-tree tempfile replacement.
Don't add a `tempfile` dep for tests.
