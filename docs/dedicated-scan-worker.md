# Dedicated scan worker

The Portal accepts submissions, stores durable jobs and immutable input envelopes in PostgreSQL and its artifact volume, and ingests authoritative evidence. `scan-worker` acquires declared sources and runs scanner phases outside the Portal. Remediation candidate Helm lint/render and Trivy config verification run in `patch-worker`, with a separate attempt identity and input digest. Missing, invalid, or unrelated candidate evidence blocks validation. Schrödinger deployment validation remains a separate workflow.

## Deploy and isolate

Build the unified image with the release workflow. Deploy `portal`, `portal-control`, `patch-worker`, and `scan-worker` from the same image version; `build.ps1` recreates and checks all four. Set a distinct random `CATS_SCAN_WORKER_TOKEN` of at least 32 ASCII characters, without example/placeholder text. Protect environment files and retain the existing encryption key during upgrades.

`portal-control` runs `app.scan_control` on port 8001 with no published host port. Only this listener exposes `/internal/scan-worker`; the public Portal listener does not mount the worker protocol. The worker uses `http://portal-control:8001` on internal `scan_control`, plus `scan_egress` for acquisition. It has no database credentials, Docker socket, or membership in the default database network. The control listener also joins the default network for PostgreSQL. Compose networking does not provide an egress destination allowlist: enforce registry/chart destinations and private infrastructure restrictions on the deployment host.

The worker is a root control broker with a read-only root filesystem, `no-new-privileges`, all capabilities dropped except `SETUID`, `SETGID`, and `CHOWN`. Scanner and acquisition subprocesses drop to a separate attempt UID/GID, starting at 10002, with private workspace permissions. Concurrent attempts use distinct UIDs. Worker bearer tokens, database configuration, encryption keys, and patch-worker credentials are removed from scanner environments. This broker design requires a real Linux container test; the container itself runs as root.

Before direct Compose deployment, create the configured registry-auth directory. Set `CATS_SCAN_REGISTRY_AUTH_SOURCE` to an absolute existing directory to avoid Compose-relative path ambiguity. `build.ps1` creates an absent directory and checks that it is a real directory and that an optional `config.json` is valid JSON. Compose mounts it read-only and disables automatic bind-path creation. An empty directory supports public sources. Use pull-only registry credentials scoped to approved repositories in Docker `auths`; site-wide credential helpers are not copied to attempts.

Only authenticated service scans with the required service permission receive the service credential policy. The broker copies credentials only for registry hosts explicitly referenced by that attempt. Other scans receive an empty auth directory. Anonymous submissions are disabled by default (`CATS_SCAN_ALLOW_ANONYMOUS=false`); if deliberately enabled, they cannot use service credentials and require a job capability for access. Owned jobs require owner or service authorization for status, cancellation, artifacts, and downloads.

The worker uses a stable `CATS_SCAN_WORKER_ID` (default `scan-worker`). A single shared token is bound to this identity. For multiple workers or rotation, configure `CATS_SCAN_WORKER_CREDENTIALS` on the control listener as a JSON mapping from worker ID to `current` and optional `previous` tokens; each worker uses its own ID and token. Remove the previous token after the overlap window. Deploy across hosts only with protected transport and a restricted control network.

## Controls and storage

| Setting | Compose/default value | Purpose |
| --- | --- | --- |
| `CATS_SCAN_CONCURRENCY` | 2 | Active attempts per worker process |
| `CATS_SCAN_LEASE_SECONDS` | 90 | Lease renewed approximately every third of the interval |
| `CATS_SCAN_JOB_TIMEOUT` | 3600 | Whole attempt deadline in seconds |
| `CATS_SCAN_QUEUE_CAPACITY` | 100 | Nonterminal admission bound |
| `CATS_SCAN_ANONYMOUS_QUEUE_CAPACITY` | 10 | Anonymous bound, capped below total capacity to reserve an authenticated slot |
| `CATS_SCAN_PREPARATION_TTL_SECONDS` | 900 | Expiry of interrupted preparation reservations |
| `CATS_SCAN_MAX_ATTEMPTS` | 3 | Maximum claimed attempts |
| `CATS_SCAN_DISK_BYTES` | 21474836480 | Application workspace/transfer budget |
| `CATS_SCAN_CPUS` / `CATS_SCAN_MEMORY` / `CATS_SCAN_PIDS` | 2 / 4g / 256 | Container limits |
| `CATS_SCAN_TMP_BYTES` | 536870912 | Incidental `/tmp` tmpfs size |
| `CATS_SCAN_SCANNER_UID` / `CATS_SCAN_SCANNER_GID` | 10002 / 10002 | Base scanner identity |
| `CATS_SCAN_RETENTION_DAYS` | 30 | Minimum age for eligible terminal job cleanup |
| `CATS_SCAN_CLEANUP_BATCH_SIZE` | 20 | Maximum terminal jobs cleaned per maintenance pass |

Large artifact temporary files use the persistent `/var/lib/cats-scan` disk workspace; `/tmp` is a small noexec tmpfs for incidental tools. Input and result envelopes are plain tar despite legacy `.tar.gz` filenames, avoiding compression work in the Portal. Submission preparation has a bounded two-thread pool; evidence upload writes, hashing, and unpacking run off the async request thread. Capacity exhaustion returns a busy response. These choices need measured latency evidence before a performance claim.

The application disk budget is a periodic/transfer check, not a filesystem quota. Provision a host volume quota for a hard bound. Account for source envelopes, extracted artifacts, evidence, per-attempt database snapshots, concurrent attempts, and retained Portal jobs. Candidate verification has a separate bounded patch-worker queue (default 2), timeout, and retained-attempt cap; failed/restarted attempts do not fall back to Portal scanning. Its default cleanup retention is one hour, capped at 128 retained attempts.

## Offline intelligence and trust

Policy and Grype/Trivy source volumes are mounted read-only in the scan worker. Security-data refresh/import stages and validates complete databases, publishes a hashed immutable generation, and atomically switches the current pointer. An attempt copies and verifies its selected generation into private writable caches; scanner database/policy auto-updates are disabled. Refresh does not mutate a running attempt. Later attempts select the new generation. Published generations are retained by import; plan their disk lifecycle separately from job cleanup.

Provenance records database identity and metadata, tool versions, resolved image digests where available, and timestamps. A generation replaced during execution is marked superseded. Legacy baked databases are hashed and marked unversioned; unavailable or invalid metadata is recorded explicitly. Do not interpret missing metadata as current intelligence.

Uploaded image archives require no Docker daemon. Private OCI images and declared Helm charts still require reachable sources, scoped credentials, and suitable trust. Submission CA bundles are passed to tools. `HELM_ALLOW_NETWORK=false` remains the default for dependency operations; declared chart acquisition is a separate worker step. Offline import and private OCI behavior must be checked with the actual deployed tools and database schema versions.

## Recovery and retained evidence

PostgreSQL preserves jobs, ownership, attempts, input digests, and leases across Portal/control restarts. Every claim has a fresh attempt ID/token bound to its worker. Stale, expired, cancelled, or unrelated attempts cannot submit evidence. A transient heartbeat transport failure retries within the current lease; an explicit fence rejection or lease deadline stops the scanner process group. Cancellation through `POST /api/public/jobs/{job_id}/cancel` becomes effective on worker detection, rather than instantaneously. Shutdown and whole-attempt timeout also terminate the process group.

Acquisition, timeout, storage, transfer, and infrastructure failures can retry with bounded backoff up to the attempt limit. Registry authorization, scanner execution, invalid output, evidence integrity, and ingestion failures are terminal. Failure history retains sanitized diagnostics and a bounded log tail; terminal ingestion/required-phase failures retain received evidence for review. Expired claims recover with fresh attempts. Review terminal errors and submit a new job after correcting their cause.

The Portal verifies result identity, input digest, checksums, allowed paths, scanner exit status, and immutable image identity. Identical completed transfers are duplicates; conflicting replacements are rejected. Evidence is persisted before authoritative ingestion. PostgreSQL advisory locking coordinates ingestion, and existing execution identities prevent replay. Maintenance deletes eligible expired terminal job-owned evidence/history in bounded batches. It retains service jobs, execution/image references, and definition context or ingested jobs. Orphan directories containing output are retained conservatively; only eligible incomplete orphan staging is reconciled. Preserve PostgreSQL and artifact backups together before retention expires.

Worker temporary attempt directories are removed after execution. Forced termination may leave incomplete directories; clean only confirmed inactive paths after stopping the worker. Do not remove database generations during job cleanup. The configured readiness check uses a recent successful control claim or valid attempt heartbeat, including an empty queue response. It detects prolonged control/authentication failure but does not prove scanner/tool readiness.

## Target-host validation checklist

Record image IDs, host/engine versions, configuration, fixture digests, timestamps, and observed results. Run against a disposable or approved deployment with representative artifacts:

- Render both supported Compose configurations and verify no published control port, network membership, broker capabilities, read-only root, auth bind, workspace paths, and limits. Verify the public listener returns no worker protocol and wrong/missing/rotated worker credentials fail as expected.
- Run actual bundled Syft, Grype, Trivy, Helm, and image acquisition tools on representative images, a large image archive, manifests, and Helm charts. Confirm scanner UID separation, child environment isolation, noexec behavior, actual tools' cache/lock permissions, and meaningful missing-tool/phase failures.
- Exercise authorized private OCI image and Helm pulls with a private CA; verify anonymous and unrelated jobs cannot obtain registry credentials, and credentials never appear in artifacts or logs. Test denied registry access without automatic authorization retries. Verify host DNS, routing, and firewall restrictions.
- Import compatible Grype/Trivy databases offline, scan without database network access, refresh while another scan is active, and verify pinned identities, superseded status, later-generation selection, and malformed-import rejection. Measure snapshot disk use and generation retention.
- Restart Portal, control listener, and worker independently with queued/running/received jobs. Test lease expiry, bounded retries, duplicate upload, stale result rejection, ingestion replay, process-group shutdown, cancellation during acquisition/scanning/transfer, and candidate-worker restart/failure. Use PostgreSQL for concurrent claim/advisory-lock checks.
- Fill queue/preparation capacity and constrain disk. Verify rejection/recovery and terminal failure evidence. Confirm retention removes only eligible evidence. Observe actual CPU, memory, PID, tmpfs, filesystem quota, and cleanup behavior with concurrent attempts.
- Compare Portal request latency and responsiveness during representative uploads, scans, and evidence transfer against an idle baseline. Record throughput, peak disk/memory, queue age, cancellation delay, and end-to-end deadline behavior. A healthy container or passing unit suite is insufficient performance evidence.

Local regression checks include simulated failure cases, PostgreSQL integration, and separate disposable Linux-container checks with bundled tools. The completion report records the precise checks and outcomes. Compose rendering and syntax checks establish configuration consistency. Target Ubuntu deployment, private OCI, production offline import, firewall enforcement, representative resource limits, and latency still require target-host evidence.

## Upgrade and rollback

Back up PostgreSQL and Portal artifact volumes together. Stop admission and finish or cancel active scans before replacing all four application services with the same image version. Existing in-memory jobs from an older deployment are not automatically migrated; complete or resubmit them. Retain named volumes, registry-auth configuration, and encryption key.

At worker startup, the broker recovers ownership of its existing workspace and heartbeat/readiness files using only its retained CHOWN capability. Existing readiness timestamps remain unchanged until successful control-plane contact. This supports volumes created by the former UID 10001 worker without adding DAC or FOWNER privileges.

For rollback, stop admission and workers first, preserve evidence/backups, and select the previous image and Compose configuration together. Older Portal versions may not service durable jobs; reconcile or resubmit them explicitly. Normal submission routes do not invoke the legacy Portal scanner. The legacy Portal scanner is disabled unconditionally, including when `CATS_ENABLE_LEGACY_PORTAL_SCANNER` is set.
