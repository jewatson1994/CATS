# Dedicated scan-worker remediation completion

## Scope and acceptance

Work is on `feature/dedicated-scan-worker`, starting at `c69a4e2` (original architecture baseline `ce9ee0e84e097d8fb8dfe116985c393ad96abe91`). This remediation addresses the supplied October 8 audit. No Risk Profile work, merge, or push is included. Implementation commit: `14fcc5470486cfe9a644680f515986abbac26b37`. Deployment commit: `6550e5ed5c269cef5db3e93ef7692bb5143a37c0`. Restored-workspace fix commit: `2e40c5d`. This report and the deployment guides are committed separately; its commit identifier is included in the final handoff.

The implementation has local automated coverage and isolated container checks. Production acceptance still requires the target Ubuntu host, representative private registries, compatible offline scanner databases, and the largest actual artifacts. Passing simulated scanner tests does not establish production scanner accuracy or firewall enforcement.

## Finding disposition

“Tested” below identifies implemented changes with local regression coverage. Items requiring host validation are implemented but not fully runtime-verified for deployment. Intentional Portal-local Artifacts acquisition (M10), preservation of authoritative evidence and old database generations (M2), and asynchronous remote-version errors (L6) are documented choices with justification rather than claims of unrestricted cleanup or synchronous validation. Target-host checks remain necessary where stated; they are not claimed as completed. No deployment-ready verdict is issued.

| Finding | Resolution | Verification | Remaining risk |
| --- | --- | --- | --- |
| C1: disconnected template worker | Both Compose topologies use a private control service and shared control network. | Topology regressions and Compose configuration rendering. | Actual host DNS/routing must be accepted. |
| H1: frozen databases | Offline imports publish immutable, hashed generations; every attempt selects and pins its generation. Evidence and UI expose database version/build date and supersession. | Generation/import/corruption/freshness regressions. | Real compatible Grype/Trivy database import and rescan on the deployment host remain required. |
| H2: blocking submission | Bounded preparation executor, streamed staging, plain tar envelopes, one retained archive copy. | Concurrent actual Portal health requests during 300 MiB preparation. | Full network multipart upload and largest representative artifacts need host measurements. |
| H3: silent deterministic failures | Fenced failure endpoint, sanitized categories/reasons, terminal deterministic failures, bounded retryable failures, scanner fatal-phase diagnostics. | Coordination, worker and fatal-evidence regressions. | Real tool-specific errors require host acceptance. |
| H4: heartbeat fragility | Transient failures retry until the actual lease deadline; explicit fence failures stop process groups. | Transient heartbeat/fencing tests and PostgreSQL lease tests. | Outages exceeding the lease still require a new fenced attempt. |
| H5: temporary storage | TMPDIR, Helm homes and caches use attempt disk workspace; incidental tmpfs remains small. | Deployment path checks and container checks recorded below. | Largest images/charts, host quota and memory limits remain unverified. |
| H6: anonymous private credentials | Anonymous admission disabled by default; enabled anonymous jobs get empty credentials. Service-authorized jobs receive referenced registry credentials only. Evidence requires ownership/service authorization or anonymous capability. | Access, capability and credential-isolation regressions. | Registry `auths` are host-scoped; use pull-only credentials. Credential helpers are intentionally unsupported. |
| M1: history sweep | Indexed terminal/callback fields replace full-history JSON scans; bounded maintenance. | SQLite and PostgreSQL migration/maintenance tests. | Large production history query latency must be measured. |
| M2: disk growth/orphans | Delete transient envelopes/attempt copies, avoid archive evidence echo, move accepted output, bound cleanup, expire interrupted preparation. Retention preserves service/definition/ingested jobs and execution/image references. | Submission copy measurement, cleanup/orphan/reference tests. | Authoritative historical evidence and database generations need operator lifecycle policy; application budget is not a filesystem quota. |
| M3: immutable sources | Worker-acquired charts use separate retained paths; uploaded input charts are not overwritten. | Source-boundary and ingestion tests. | Worker authenticity still depends on protected control credentials. |
| M4: worker trust | Internal-only listener; placeholder/non-ASCII credentials rejected; per-worker rotation support; scanner uses separate UID and sanitized environment. | Authentication/topology tests; Linux identity checks below. | Root control broker retains only CHOWN/SETUID/SETGID. Host control-network and transport restrictions remain essential. |
| M5: starvation | Anonymous sub-cap reserves authenticated capacity; authenticated claims have priority; preparation is bounded. | Admission and concurrent PostgreSQL tests. | Authentication and host request rate controls remain operator responsibilities. |
| M6: throughput | Consistent default of two concurrent attempts with explicit resource controls. | Deployment/default checks. | Tune concurrency against actual CPU, memory, disk and scanner workload. |
| M7: false readiness | Readiness requires recent successful control response; loop liveness is separate; authorization failures are distinct. | Worker and deployment tests. | Readiness does not establish scanner accuracy. |
| M8: registry-auth setup | Build tooling creates/validates auth directory; deployment templates document four services and auth prerequisites. | PowerShell parser and deployment checks. | Direct Compose operators must create the configured directory. |
| M9: double compression | Plain input tar and `Accept-Encoding: identity`. | Worker header tests and upload measurement. | Proxy behavior should be checked on the host. |
| M10: remaining local scanners | Remediation lint/render/config verification executes through patch-worker with digest-bound evidence; no Portal fallback. | Candidate and remediation regression tests. | Authenticated Artifacts source-management acquisition intentionally remains Portal-local, using synchronous routes and existing bounded download helpers. It is not the scan execution pipeline. |
| M11: test regressions/coverage | Durable-job fixtures, disabled legacy runner tests, PostgreSQL coordination and real Portal/worker/ingest HTTP integration. | Test results below. | HTTP integration uses a stand-in scanner; real scanner pipelines need host acceptance. |
| L1: non-ASCII auth | Byte-safe credential comparison and unauthorized response. | Authentication regression. | None identified locally. |
| L2: unstable identity | Worker instance/identity reused across claims. | Worker regression. | Multi-worker deployments need distinct configured IDs. |
| L3: legacy duplication | Shared acquisition adapter; legacy Portal runner unconditionally disabled and process cancellation path removed. | Acquisition and disabled-hook regressions. | Diagnostic stub remains to reject obsolete callers explicitly. |
| L4: orphan scanner child | Linux parent-death runner and process-group termination. | Process lifecycle coverage and container checks below. | Requires Linux; Windows local tests do not establish this behavior. |
| L5: first-start readiness | No startup database copy; liveness starts immediately, readiness requires control success. | Worker/topology tests. | Initial actual database snapshot latency still needs host measurements. |
| L6: deferred validation | Structural submission validation remains; remote acquisition errors are asynchronous and documented. | Definition/acquisition regressions. | A bad remote version is reported in job status rather than synchronous submission 422. |
| L7: status disclosure | Public status projection excludes owner IDs, raw context and private logs; access is authorized. | Access/status tests. | Anonymous users must retain their capability. |
| L8: misleading state | Scanner phase/reason retained; cancellation terminates attempt state; preparation/transfer/ingest UI labels and intelligence status added. | Lifecycle tests, frontend type check and production build. | Cancellation is bounded by detection/acquisition deadlines rather than instantaneous. |
| L9: documentation drift | Worker and template deployment guides rewritten for actual topology, security, storage and rollback. | Configuration/doc review. | Guides deliberately retain target-host acceptance requirements. |

## Architecture and security

The public Portal admits and prepares durable jobs. A separate `portal-control` listener authenticates workers and coordinates claims, leases, failures and evidence transfer. Only this listener mounts the internal protocol, and its port is not published. PostgreSQL remains authoritative for attempts, ownership, replay fencing and ingestion.

The scanner broker has no database credentials or Docker socket. On Linux, each concurrent attempt uses a separate unprivileged UID/GID. Acquisition and scanner children receive sanitized environments, scoped registry configuration, private writable cache snapshots, trust material and attempt-local temporary storage. Root filesystem is read-only, no-new-privileges is enabled, and the broker retains only three identity/ownership capabilities. Host firewall rules must restrict scanner egress; Compose networks alone do not provide destination filtering.

Remediation candidate verification uses the patch-worker's authenticated API, bounded queue and retention. Candidate bytes and returned evidence are digest-bound. Required verification failures block promotion. Schrödinger deployment validation remains a separate workflow.

## Schema and configuration

Startup applies additive scan-job columns/indexes for `definition_pending`, `anonymous`, and `finished_at`, under migration coordination. Existing jobs and evidence are retained. PostgreSQL integration verifies migration and concurrent claims/admission. Back up database and artifact volumes together before upgrade.

Required: strong `CATS_SCAN_WORKER_TOKEN` shared between the configured worker identity and control service; `CATS_SCAN_WORKER_ID`; existing database/encryption configuration; an existing registry-auth directory, empty for public-only scans. Optional `CATS_SCAN_WORKER_CREDENTIALS` maps identities to current/previous tokens for rotation. Placeholder tokens are rejected. Do not expose the control listener externally.

Important controls include concurrency (2), lease (90 seconds), attempt timeout (3600 seconds), total queue (100), anonymous queue (10), preparation TTL (900 seconds), attempt limit (3), retention (30 days for eligible unreferenced jobs), cleanup batch (20), disk budget, and CPU/memory/PID limits. `CATS_SCAN_ALLOW_ANONYMOUS=false` is the default. See deployment examples and [worker guide](dedicated-scan-worker.md) for exact environment names and semantics.

## Verification record

Local checks completed:

- Full Portal suite, first remediation run: **1,929 passed, 34 failed, 12 skipped** in 310.60 seconds. An isolated tracked export of starting commit `c69a4e2` reproduced **23 identical failures** (74 passed in the baseline subset). All 11 affected failures were corrected and their targeted regression runs pass; final full-suite results are recorded below.
- Restored-workspace coordination run before the timestamp extension: **63 passed** in 46.46 seconds. Final new/existing timestamp initialization regressions: **2 passed** in 0.59 seconds; the final source also passed the restricted Linux proof described below.
- Final full Portal suite: **1,955 passed, 23 failed, 12 skipped** in 318.06 seconds. The 23 failing test identifiers exactly match the isolated starting-branch baseline; no new failures remain in this run.
- Baseline failures: managed-validator release preparation (11), validator management (4), validator operations (3), remediation verification (3), frontend validator bootstrap (1), service-posture bound (1).
- Final root access/intelligence/submission/topology regression run: **40 passed**.
- PostgreSQL 16 coordination/hardening: **70 passed**, excluding four runtime-only tests; additional retention/reference/fatal/migration subset: **9 passed**.
- PostgreSQL Portal/control/Worker HTTP integration with actual authoritative ingest/classification succeeded. Scanner process is a stand-in; HTTP requests exercise real handlers through an in-process ASGI transport.
- Frontend type check and production build succeeded. Both supported Compose configurations rendered successfully and PowerShell parsing succeeded.
- Unified image build succeeded (final local image configuration `6fa42c39c2c8dca980a68b85a67b430a5133b01982ebd266fb1cd6eaca1367fe`). A read-only Linux container with 32 MiB incidental tmpfs ran actual Helm 4.2.3 lint/template, Syft 1.31.0 package SBOM generation, Trivy 0.69.3 configuration scanning, and Grype 0.98.0 against the baked offline schema 6.1.10 database. Scanner identity was UID/GID 10002 with no supplementary groups, no effective capabilities and no-new-privileges. Control/pipeline/OIDC secrets were absent; a 64 MiB workspace temporary file succeeded. These fixture checks do not establish private-registry or fresh-import accuracy.

The full `Worker.execute` lifecycle also succeeded in the same restricted Linux container: configuration scan completed with 17 findings and required phase exit codes zero, result envelope packed/unpacked, and scanner-owned output reclaimed and cleaned without adding capabilities. A final PostgreSQL HTTP ingestion rerun passed (1 test in 3.59 seconds). Final expanded candidate/remediation/Portal/worker suite: **227 passed** in 99.60 seconds. A further restored-volume regression passed in an actual restricted Linux container with final source mounted read-only: legacy UID 10001/mode 0700 workspace and UID 10001/mode 0600 stamps were recovered to broker ownership, heartbeat refreshed and readiness timestamp preserved, with only CHOWN/SETUID/SETGID retained. Final cleanup rotation regressions: **86 passed, 1 skipped** on SQLite, and **10 passed** on PostgreSQL 16.

Measured local preparation check: 300 MiB archive, actual asynchronous submission preparation and concurrent actual Portal `/health` requests; preparation took **1.068 seconds**, maximum observed health latency **0.003 seconds** over 69 requests, and retained job storage was **300.01 MiB**. This measures preparation and responsiveness, not network multipart upload or end-to-end real scanner throughput.

The supplied audit measured 9.573-second submission, 7.837-second worst health latency and 1,200 MiB retained storage for a 300 MiB upload. Those were on a different host/test setup. The local result supports removal of event-loop blocking and duplicate archive storage; it is not a controlled speedup comparison.

## Workflow acceptance map

| Workflow | Automated evidence | Deployment-host procedure |
| --- | --- | --- |
| A: normal service scan | Real PostgreSQL HTTP worker-to-authoritative-ingest integration, ownership and replay checks. | Scan an approved actual registry image; inspect findings, classifications, exports, service image state and worker provenance. |
| B: service definition | Exact classic repository/OCI identity acquisition and definition job regressions. | Import a definition with enabled/disabled services, exact chart versions, vendored/recursive dependencies and a private OCI source; inspect retained sources and partial-error diagnostics. |
| C: offline intelligence update | Validated immutable generations, snapshots, malformed import rejection, supersession/UI tests. | Import compatible real offline DBs, rescan disconnected, compare evidence build/version identities; import during an active scan and confirm pinned old/current new identities. |
| D: worker failure | Claims/expiry/fence/failure/process lifecycle tests on SQLite and PostgreSQL. | Kill the scan-worker during acquisition and scanning; confirm bounded recovery, no lingering scanner group, fresh attempt, stale upload rejection and accurate reason. |
| E: Portal restart | Heartbeat tolerance and actual deadline/fence regression coverage. | Restart public Portal (worker control remains separate); then briefly restart control within lease. Confirm scan continues; exceed lease and confirm safe fenced retry. |
| F: remediation | Remote candidate digest binding, evidence/promotion gating and Portal remediation regression coverage. | Remediate a known service; verify candidate lint/render/config process executes in patch-worker, inspect fresh returned evidence, exercise unavailable worker and Schrödinger validation. |
| G: large upload | 300 MiB actual preparation/health measurement, storage/copy bounds, temp workspace/tool container smoke. | Upload the largest approved image archive/chart while polling Portal health; record latency, peak workspace/memory, scanner completion and retained/transient storage. |
| H: unauthorized access | Owner/service/capability authorization, anonymous disabled/empty credentials, authenticated priority/cap and token tests. | Attempt anonymous/private scans, another user's evidence access and worker routes on public listener; verify rejection. Fill anonymous capacity and confirm authorized admission and priority. |

## Deployment acceptance and rollback

1. Preserve database/artifact backups and existing secrets; stop new scan admission and drain or cancel active work.
2. Build the unified image and render the chosen Compose configuration. Create registry-auth directory and set non-placeholder worker credentials.
3. Upgrade Portal, control, scan-worker and patch-worker together, preserving named volumes. Confirm the public listener has no worker routes and control port has no host mapping.
4. Follow the worker guide's target-host checklist: real images and archives, classic/private OCI Helm, vendored dependencies, offline database refresh/rescan, cancellation, worker kill, Portal/control restart, fenced replay, firewall, limits, quota and responsiveness measurements.
5. Accept deployment only after those checks establish representative runtime behavior. Local tests do not substitute for this acceptance.

Rollback: stop admission and workers, preserve accepted evidence and backups, and restore the previous image and Compose configuration together. Older versions do not service these durable jobs; reconcile or resubmit them explicitly. Never delete retained evidence or database volumes to roll back. The legacy Portal scanner flag is not a fallback.

## Preservation and final review

The pre-existing README change and untracked training work are outside this implementation. The named pre-existing untracked items, including inaccessible `.test-temp/startup-evidence-check2/`, are untouched and excluded from staging. Only dedicated scan-worker remediation files are committed. Explicit staging and commit-path review excludes every pre-existing untracked item and the unrelated README/training work. The inaccessible test output was never inspected, opened, permission-changed, moved, deleted or otherwise modified. All implementation changes are substantive; CRLF-safe whitespace checks find no line-ending-only changes. Starting commit `c69a4e2` and approved earlier baseline `f33fd07357190623fb8cb0d83b1b025d25df3570` are ancestors of this branch. After the documentation commit, the only pre-existing tracked modification remaining is `README.md`; its content hash was preserved. No merge or push was performed.

## Files included

- `.env.example`
- `build.ps1`
- `cats-image/Dockerfile.all-in-one`
- `compose.yaml`
- `docs/dedicated-scan-worker.md`
- `docs/scan-worker-remediation-completion.md`
- `portal/.env.example`
- `portal/app/candidate_worker.py`
- `portal/app/definition_acquisition.py`
- `portal/app/definition_routes.py`
- `portal/app/helm_downloads.py`
- `portal/app/main.py`
- `portal/app/patch_service.py`
- `portal/app/scan_access.py`
- `portal/app/scan_acquisition.py`
- `portal/app/scan_artifacts.py`
- `portal/app/scan_control.py`
- `portal/app/scan_coordination.py`
- `portal/app/scan_intelligence.py`
- `portal/app/scan_protocol.py`
- `portal/app/scan_runner.py`
- `portal/app/scan_runtime.py`
- `portal/app/scan_worker.py`
- `portal/app/security_data.py`
- `portal/frontend/src/features/self_service.tsx`
- `portal/tests/test_candidate_worker.py`
- `portal/tests/test_elapsed_time.py`
- `portal/tests/test_portal.py`
- `portal/tests/test_remediation_end_to_end.py`
- `portal/tests/test_remediation_evidence.py`
- `portal/tests/test_remediation_workflow_routes.py`
- `portal/tests/test_runtime_version.py`
- `portal/tests/test_scan_access.py`
- `portal/tests/test_scan_access_routes.py`
- `portal/tests/test_scan_coordination_hardening.py`
- `portal/tests/test_scan_definition_ui.py`
- `portal/tests/test_scan_deployment_topology.py`
- `portal/tests/test_scan_http_ingest.py`
- `portal/tests/test_scan_intelligence.py`
- `portal/tests/test_scan_submission_responsiveness.py`
- `portal/tests/test_scan_worker_coordination.py`
- `portal/tests/test_scanner_shell_lifecycle.py`
- `templates/README.md`
- `templates/compose.main.yaml`
- `templates/main.env.example`
