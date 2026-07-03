# gh-webhook-spool

*Slop status: 100% vibecoded.*

Tiny HMAC-verifying receiver for GitHub `workflow_job` webhooks. Drops
everything that isn't a queued runner request for an allowlisted repository,
then durably enqueues the job as a maildir-style file for a downstream
provisioner to pick up.

```
GitHub  ─TLS─►  reverse proxy  ─loopback─►  gh-webhook-spool  ─►  <spool>/new/
                                                                       │
                                                                       ▼
                                                                runner provisioner
```

The reverse proxy terminates TLS. The receiver authenticates every payload
by HMAC.

## Threat model

This binary is designed to feed self-hosted runners. Self-hosted runners
will execute whatever code is checked into the repo at the head commit of
the job, so the spool must not enqueue anything an untrusted actor can
influence. To that end:

- **Non-private repos are refused.** Only `workflow_job` events whose
  `repository.private == true` **and** `repository.visibility == "private"`
  are enqueued. The visibility check matters on GitHub Enterprise:
  `internal` repositories report `private: true` but are readable by every
  full enterprise member, so a `private`-only gate lets them through.
  Public, internal, and visibility-absent deliveries are silently acked
  with a log line and dropped. This eliminates the public-fork-PR class
  entirely, because public repos can be forked by anyone and PRs from
  those forks produce `workflow_job` events that the spool would otherwise
  have to process.
- **Residual risk inside private repos.** GitHub allows users with read
  access to fork a private repo within their visibility; PRs from those
  forks still emit `workflow_job` events on the base repo. The
  `workflow_job` payload doesn't carry `head_repository`, so we cannot
  reject these from the payload alone. Mitigations the operator MUST
  apply:
  1. Treat the runner as untrusted: ephemeral VMs/containers, no
     long-lived secrets on the runner host, no privileged network or
     filesystem access.
  2. Curate collaborators carefully on every repo in `ALLOWED_REPO_IDS`.
     Anyone with read access becomes part of the trust boundary.
  3. Avoid `pull_request_target` in workflows — it runs PR code with
     base-repo permissions and is the classic foot-gun.
- **The spool's HMAC check is ingress only.** The `<spool>/new/`
  directory is a filesystem trust handoff to the consumer. Any process
  running as the same uid can write files into `new/` directly,
  bypassing the HMAC check. The consumer is expected to re-verify HMAC
  against the raw body. See "Consumer requirements" below. The spool
  components are created mode `0700` and files mode `0600` so the trust
  boundary does *not* extend to the service group by default; each
  enqueued file contains a valid `(body, signature)` pair that would
  re-verify against the spooler's secret, so group read access would
  hand every group member a replayable forgery.

## Build and run

```
cargo build --release
# or
nix build && ./result/bin/gh-webhook-spool
```

## Configure (compile-time)

Edit two constants in `src/main.rs`:

```rust
const ALLOWED_REPO_IDS: &[u64]  = &[123456789];                  // repository.id values
const EXPECTED_LABELS:  &[&str] = &["self-hosted", "my-fleet"];  // required runner labels
```

Both are required. The binary refuses to start with either empty —
provisioning anything you didn't intend is the failure mode this is meant
to prevent.

`EXPECTED_LABELS` uses **subset** semantics: every label listed here must
appear in the job's `workflow_job.labels`. A job that requests
`runs-on: [self-hosted, my-fleet, linux]` will match an `EXPECTED_LABELS`
of `["self-hosted", "my-fleet"]`; a job that requests
`runs-on: [self-hosted]` will not. Pick a unique fleet identifier label
that no other runner pool uses.

## Configure (runtime)

| Variable                    | Purpose                                              |
| --------------------------- | ---------------------------------------------------- |
| `GH_WEBHOOK_SECRET_FILE`    | Absolute path to a file holding the secret. **Recommended.** Must be a regular file owned by the service uid, mode `0600`, ≤4096 bytes. The path is opened with `O_NOFOLLOW` (final-component symlinks rejected) and the metadata used to clear it is read via `fstat` on the opened fd. Every ancestor directory up to `/` must be a real dir owned by uid 0 or the service uid with no group/other write bits, so a local attacker can't race startup by swapping the file. Trailing CR/LF stripped. |
| `GH_WEBHOOK_SECRET`         | Shared secret string. Discouraged: env vars are visible via `/proc/PID/environ`. Setting both this and `_FILE` is a startup error — pick one. |
| `SPOOL_DIR`                 | Queue root (absolute path). `tmp/` and `new/` are auto-created. |
| `LISTEN_ADDR`               | Bind address. Default `127.0.0.1:8080`. **Ignored when `LAUNCHD_SOCKET_NAME` is set** — the bind address then comes from the plist. |
| `LAUNCHD_SOCKET_NAME`       | macOS only. Set to the key of an entry in the launchd job's `Sockets` dict to take that socket from launchd (socket activation) instead of binding one. Enables zero-drop restarts (see *Operations → Zero-downtime restarts*). Unset ⇒ the binary binds `LISTEN_ADDR` itself. If set but activation fails, startup is refused (no silent fallback). The loopback check still applies, re-derived from the inherited socket's own address. |
| `WEBHOOK_PATH`              | Route the handler is mounted on. Default `/webhook`. Set this to match the GitHub App's webhook URL path (e.g. a hard-to-guess `/github/<uuid>`) so no reverse-proxy rewrite is needed. Must be a **literal** path starting with `/`, matched verbatim — it is *not* an axum route pattern, so `:name`/`*name` segments are not captures/wildcards. Startup is refused if it contains `:` or `*`. The path is not a security boundary — the HMAC is. |
| `ALLOW_NON_LOOPBACK_BIND`   | Set to `1` to permit a non-loopback `LISTEN_ADDR`. Without this the binary refuses to start, because the threat model assumes loopback-only ingress behind a TLS proxy. |

The secret (from either source) must be ≥16 bytes after trailing CR/LF
stripping. Shorter secrets are a startup error — GitHub allows shorter
ones but they're the entire forge boundary and a 16-byte (~128-bit)
floor is the bare minimum that makes brute-force impractical.

`SPOOL_DIR`, its `tmp/` and `new/`, must be real directories (no symlinks)
**owned by the service uid** — the service has to write to them. Every
**ancestor directory up to `/`** must also be a real directory, owned by
uid 0 or by the service uid, with no group/other write bits. Mode `0700`
(no group/other bits at all) on the spool components themselves; the
verifier rejects anything looser. The binary refuses to start otherwise.
Don't place `SPOOL_DIR` under `/tmp` or any other world-writable tree.

```
GH_WEBHOOK_SECRET_FILE=/etc/gh-webhook-spool/secret \
SPOOL_DIR=/var/spool/gh-webhook-spool \
gh-webhook-spool
```

## What gets enqueued

- HMAC must verify against the `X-Hub-Signature-256` header.
- Event must be `workflow_job`; action must be `queued`.
- `Content-Type` must be `application/json` (set the GitHub webhook config
  to JSON, not form-urlencoded).
- `repository.id` must appear in `ALLOWED_REPO_IDS`.
- `repository.private` must be `true` **and** `repository.visibility`
  must be `"private"` (so GHE `internal` repos are rejected, and
  visibility-absent deliveries fail closed).
- Every label in `EXPECTED_LABELS` must appear in `workflow_job.labels`.

Anything else gets 200 with no enqueue. HMAC failures are 401; charset
and content-type failures are 400. An enqueue I/O failure returns 500,
and a concurrent retry that arrives while an earlier write is still
in flight returns 503. Two responses come from the framework before the
handler runs: a body over the 5 MiB cap is rejected with 413, and a
non-`POST` request to the webhook path gets 405. (A `workflow_job`
payload is tens of KB, so 413 shouldn't occur in practice — but note
that, being deterministic in the body, it would fail every redelivery
attempt, so a failed-delivery monitor must not retry it forever.)

**GitHub does not automatically redeliver failed webhook deliveries**
([docs](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries)).
A 5xx response here means the delivery shows up as failed on the repo's
*Settings → Webhooks → Recent Deliveries* page and stays there until
something redelivers it. See *Operations → Failed deliveries* below.

## Queue format

Each accepted job is written to `<SPOOL_DIR>/new/{workflow_job_id}.job` as:

```
<envelope JSON>\n<raw webhook body>
```

Envelope (schema v2):

```json
{
  "schema": 2,
  "event": "workflow_job",
  "delivery": "deadbeef-1234",
  "repo_id": 123456789,
  "repo": "owner/repo",
  "action": "queued",
  "workflow_job_id": 987654321,
  "head_branch": "main",
  "head_sha": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
  "job_name": "all-required-checks-complete",
  "received_at_ms": 1716643200000,
  "signature": "sha256=..."
}
```

`head_branch`, `head_sha`, and `job_name` (schema v2+) are **advisory
prioritization hints** so the consumer can order the queue without parsing
every body. They're lifted verbatim from `workflow_job.head_branch`,
`workflow_job.head_sha`, and `workflow_job.name` in the verified body —
`job_name` is the check/job name, i.e. what GitHub Actions `needs:` graphs
key on, so a consumer can prefer cheap unblocking jobs. Each defaults to
`""` if the delivery omits it. **They are not re-authenticated on the
filesystem side** (see "Consumer requirements"): sorting on a forged hint
only reorders work, but anything that decides *what runs* must be re-derived
from the body. Schema v2 is purely additive — a v1 consumer that ignores
unknown fields keeps working.

The filename is still `{workflow_job_id}.job` — all the new metadata lives
in the file, so existing consumers and the dedup/idempotency contract are
unaffected.

The filename uses `workflow_job_id` because it's an **authenticated**
field — GitHub's HMAC covers the body, not the `X-GitHub-Delivery`
header. Keying dedup on a header would let anyone holding a valid signed
body replay it with a fresh delivery ID. The stored `signature` is
lowercased before being written, so consumers can compare byte-wise.

## Consumer requirements

**The envelope is NOT authenticated.** Only the raw body that follows the
envelope is covered by GitHub's HMAC. A local writer with the service
uid/group could pair a valid `(body, signature)` with a tampered
envelope (e.g. swap `repo_id` to a different allowlisted repo, or change
`workflow_job_id` to anything they like). The spooler's own ingress check
protects only network deliveries; the filesystem handoff is a separate
trust boundary.

The consumer running against `<SPOOL_DIR>/new/` MUST therefore:

1. **Split at the first `\n`** to separate the envelope (advisory) from
   the body (authoritative).
2. **Re-verify HMAC-SHA256** over the raw body using the consumer's own
   copy of the secret. The signature stored in the envelope is the
   expected value (it's deterministic — `HMAC(secret, body)` — and the
   spooler lowercases it before writing), but the authoritative check is
   "does `HMAC(my-secret, raw-body)` match". If it doesn't, discard.
3. **Derive every trust-relevant field from the verified body**, not
   from the envelope. That includes `repo_id`, `action`,
   `workflow_job.id`, `labels`, and `head_sha` if you use it to decide
   what code to run. Treat envelope fields like `received_at_ms`, `repo`
   (the human-readable name), and the `head_branch`/`head_sha`/`job_name`
   prioritization hints as advisory metadata only — fine to sort on, but a
   local writer could forge them, so re-read anything load-bearing from the
   body.
4. **Reject envelope/filename/body mismatches.** If the filename's
   numeric stem doesn't match `workflow_job.id` parsed from the verified
   body, the file is forged — discard.
5. **Maintain persistent dedup on `workflow_job.id` from the body.** The
   spooler dedups within `new/` (a second arrival under the same id
   ack's as duplicate), but once the consumer moves a file out, a replay
   would re-enqueue. Idempotent provisioning closes the gap.
6. Treat read access to `new/` as sensitive — each file contains a valid
   `(body, signature)` pair that would re-verify against the spooler's
   secret.

## Operations

- Logs are stderr-only: one line per accepted/duplicate delivery, plus
  warnings and errors.
- Graceful shutdown on `SIGTERM` and `SIGINT`.

### Zero-downtime restarts (macOS socket activation)

By default the process binds `LISTEN_ADDR` itself, so during a restart the
listener is gone and the reverse proxy gets connection-refused — and because
**GitHub does not auto-redeliver**, any webhook that arrives in that window is
a permanently lost job.

On macOS you can hand ownership of the listening socket to launchd instead.
Declare a `Sockets` entry in the launchd job and set `LAUNCHD_SOCKET_NAME` to
its key (see [`contrib/local.gh-webhook-spool.plist`](contrib/local.gh-webhook-spool.plist)).
launchd holds the socket for the lifetime of the job configuration, so the
kernel keeps queuing incoming connections in the accept backlog while the
process is down and the next instance drains them. An upgrade is then just:

```
ln -sfn /nix/store/<new-hash>/bin/gh-webhook-spool /usr/local/bin/gh-webhook-spool
launchctl kickstart -k system/local.gh-webhook-spool
```

with zero dropped connections. Graceful shutdown drains in-flight requests
before the old process exits; launchd retains the socket and its backlog across
the swap.

Notes:

- `LISTEN_ADDR` is ignored in this mode; the bind address is the plist's
  `SockNodeName`/`SockServiceName`. Use a **numeric** loopback `SockNodeName`
  (e.g. `127.0.0.1`) so exactly one socket is created — a hostname resolving
  to both IPv4 and IPv6 yields two, which the binary refuses (it serves a
  single listener).
- The loopback gate (invariant: loopback-only ingress) is **still enforced**,
  re-derived from the inherited socket's own address via `getsockname`. A
  non-loopback activated socket is refused unless `ALLOW_NON_LOOPBACK_BIND=1`,
  exactly as for a self-bound one.
- There is **no silent fallback**: if `LAUNCHD_SOCKET_NAME` is set and
  activation fails (wrong name, not launchd-managed, non-macOS), the binary
  refuses to start rather than quietly bind a fresh socket and lose the
  zero-drop property.
- Socket activation closes the *planned-restart* window. It does not replace a
  redelivery/reconciliation monitor for *unplanned* outages (see *Failed
  deliveries* below) — the two are complementary.
- On startup, `tmp/*` is swept; partial writes from a previous crash are
  removed.
- Enqueued files are created mode `0600` (uid-only). Each file holds a
  valid signed body that would re-verify against the spooler's secret,
  so group/other access would expose replayable payloads.

### Failed deliveries

GitHub's webhook delivery does **not** include an automatic retry — a
5xx (or any other failed delivery) is recorded on the webhook's
*Recent Deliveries* page and will sit there until a human or a
companion process redelivers it. This binary returns 5xx in two
situations:

- **500** — enqueue I/O failure (disk full, fsync failure, rename
  failure, JSON serialization of the envelope failed).
- **503** — a concurrent writer holds `tmp/{workflow_job_id}` and
  `new/{workflow_job_id}` doesn't exist yet. Rare; usually a duplicate
  GitHub delivery that arrived before the first one finished writing.
  The other writer normally succeeds and the operator's only action
  is to confirm the file landed in `new/`.

Because authenticated, allowlisted jobs are dropped on the floor if
nothing replays them, **operators are expected to run a separate
failed-delivery monitor** alongside this binary. The minimum viable
shape is a process that periodically does two steps:

1. **List** recent deliveries with
   [`GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries`](https://docs.github.com/en/rest/repos/webhooks/repo-deliveries#list-deliveries-for-a-repository-webhook)
   (paginated; each item carries an `id` plus a `status` / `status_code`),
   or the organisation-scoped
   `GET /orgs/{org}/hooks/{hook_id}/deliveries`.
2. For each delivery whose status indicates failure, **redeliver** it with
   [`POST /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}/attempts`](https://docs.github.com/en/rest/webhooks/repo-deliveries#redeliver-a-delivery-for-a-repository-webhook)
   (or the equivalent organisation-scoped endpoint).

Note that the `attempts` endpoint only *redelivers a single delivery* — it
does not list anything, so the list step above is required first. Without
this monitor, a 5xx from this binary silently loses the workflow job. The
spool itself is idempotent on `workflow_job_id` (replay-safe), so a
redelivery monitor that over-delivers is harmless.

