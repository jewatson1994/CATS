# Scan-worker architecture review and remediation — 9 October 2026

## Assessment and scope

Reviewed and corrected the actual implementation on `feature/dedicated-scan-worker`, starting at `b0d88d7`. The expected remediation commits `14fcc54`, `6550e5e`, and `2e40c5d` are ancestors. The initial checkout was `fix/oidc-clock-skew`; switching to the existing feature branch preserved the user's unrelated README changes. No merge or push is part of this review.

The architecture is connected: durable PostgreSQL coordination, an internal control listener, isolated scanner processes, verified result transfer, and authoritative Portal ingestion. The earlier audit's template-network, frozen-database, synchronous packaging, missing failure-reporting, and public control-listener defects are already addressed in this baseline. This review found additional defects in privilege enforcement, process cleanup, credential isolation, candidate verification, and ingestion cancellation, described below.

This is **not a production-readiness certification**. Real offline tools and Linux privilege behavior were exercised locally, separately from PostgreSQL/HTTP ingestion tests. Private registries, private CAs, production firewall rules, full deployment upgrades, and representative large images still require target-host acceptance. No schema migration or classification-policy change was added by this review.

## Findings, corrections, and limits

| Severity / finding | Root cause | Correction | Verification | Remaining risk |
| --- | --- | --- | --- | --- |
| High: scanner could read unfiltered site registry credentials | The read-only bind was directly traversable when host files were world-readable | Put the bind below an image-owned root-only control directory; keep per-attempt copies scoped to declared hosts | Compose topology regression and Linux permissions probe | An administrator must preserve the protected mount path; credentials remain readable by the trusted broker |
| High: broker could not stop a different-UID scanner | SETUID/SETGID/CHOWN do not authorize signalling another UID | Add only KILL to retained broker capabilities; kill remaining process-group children after normal completion too | Real Linux completion, cancellation, and timeout probes | Deliberately detached processes require stronger per-attempt cgroup/container containment |
| High: privileged artifact processing followed untrusted filesystem indirection | Validation happened at packaging, after earlier reads/writes; hardlinks were not rejected | Reclaim without following links or changing hardlinked external inodes; validate trees before processing and packing; retain the original live-log descriptor | New hardlink/packing/worker regressions; real Trivy private-cache permissions exercised | A malicious detached process can still create race conditions; process groups are not a complete hostile-code sandbox |
| High: cancellation could be overwritten or followed by ingestion | Source/definition/ingest commits released the row lock; subsequent work used stale state | Refresh with FOR UPDATE and honor cancellation after each intermediate commit | Two new regressions failed before the change (scan still ingested; SBOM became complete), then exercised on PostgreSQL | Cancellation cannot undo evidence already committed before it was accepted |
| High: empty candidate render could retain planning PASS checks | Candidate verification inherited checks for the original render | Reset render-dependent checks; require actual candidate resources | Empty-render regression and candidate suite | Real candidate tool/deployment acceptance remains required |
| High: removing a candidate resource could pass | Comparison used a set of kinds, discarding names and multiplicity | Require identity counts for raw YAML; kind counts for Helm where release-generated names differ; existing Portal same-release scope comparison remains authoritative | Missing identity, duplicate/count, and Helm release-name regressions | Helm's worker-side count check alone is not an exact scope proof |
| High: final OCI validation failed before dispatch | Required request_id was omitted | Generate a per-chart ID and require matching response ID alongside service/type/digest | Existing three failures reproduced; valid/mismatched/missing identity tests | Actual remote validator and private OCI publication not exercised here |
| Medium: redirects could forward attempt credentials/evidence | Requests redirects do not strip custom attempt headers or necessarily discard bodies | Disallow all control-plane redirects | 301/302/303/307/308 regressions | Protect the configured control transport/network |
| Medium: invalid scanner identity silently defeated separation | Root/invalid UID or nonroot broker could bypass the intended identity boundary | Fail closed for invalid scanner UID and nonroot broker | Identity configuration regressions | Windows unit tests do not establish Linux privilege isolation; Linux probe supplies that evidence |
| Medium: a stalled heartbeat could outlive local authorization | Scanner loop relied on heartbeat thread to mark lease loss | Independently check the lease deadline during execution and before transfer | Short-lease regression | Control interruptions longer than the lease still require recovery/re-execution |
| Medium: alternate credential environment and structured logs leaked values | Filtering/redaction omitted alternate auth-file variables and quoted/Bearer forms | Strip known alternate credential paths/configuration; redact JSON and standalone bearer/basic values | Environment and redaction regressions | Redaction is best effort, not an arbitrary-secret detector |
| Medium: configured intelligence sources were ignored | Environment sanitization removed broker-only source paths before generation selection | Preserve custom paths for broker pinning, then exclude them from child environment | Custom-source pinning regression; existing generation tests | Imported database compatibility must match deployed scanner versions |

Fifteen targeted security regressions were run against isolated original-HEAD module copies and failed as expected. Candidate regressions and the cancellation regressions were also reproduced before their fixes. The Linux run exposed a permission issue in the first validation ordering; reclaim now precedes validation while remaining link-safe, and the corrected run passed.

## Production lifecycle trace

| Stage | Production code / connection | Failure boundary and validation |
| --- | --- | --- |
| 1. Submit | `features/self_service.tsx`; `main.public_scan_submit`, image rescan routes, `definition_routes.process_definition` | Existing progress/results UI; forms and route tests |
| 2. Authorize | `scan_access`, Portal auth and service permission checks | Anonymous opt-in with job capability; owner/service evidence access; access-route tests |
| 3. Validate | `_start_public_scan`, definition parsing, acquisition limits | Invalid targets/versions/formats rejected; acquisition failures remain explicit |
| 4. Reserve durable job | `scan_coordination.DurableJobs` | PostgreSQL admission lock, total/anonymous caps; reservation precedes staging |
| 5. Prepare input | `_prepare_public_scan`, `_start_public_scan`, `scan_artifacts.pack` | Bounded thread pool, streamed archive staging, plain tar and digest; cleanup on failure; latency test |
| 6. Claim | `scan_control`, `scan_protocol.claim`, `scan_coordination.claim` | Stable worker identity, SKIP LOCKED plus conditional update; concurrent-claim tests |
| 7. Fence attempt | `authenticated`, `fenced`, `heartbeat`, `report_failure` | Rotatable worker credentials, per-attempt token hashes, lease and ownership checks |
| 8. Acquire | `scan_worker`, `scan_acquisition`, `definition_acquisition` | Exact chart version/name, scoped auth, limits, separate UID and workspace; failure category |
| 9. Execute | `Worker._execute`, `run-scan.sh` | Whole-attempt timeout, lease checks, process-group termination; actual Linux tools exercised |
| 10. Generate evidence | Scanner phases and worker provenance | Required phase failures retained; pinned intelligence metadata; SBOM/config/vulnerability outputs |
| 11. Package | `scan_artifacts.validate_tree/pack/unpack` | No links/special files/traversal; manifest identity, checksums and size bounds |
| 12. Transfer | Internal `/results`, worker identity encoding | Streamed disk writes and off-thread extraction; second fence before acceptance; replay comparison |
| 13. Ingest | `scan_protocol.ingest_one/_ingest_one`, `main.ingest_public_scan` | Session advisory lock survives inner commits; row locks/cancellation checks; errors retain evidence |
| 14. Reconcile | Existing `ingest`, execution `public:<job>`, image scope | Idempotent real ingest; fixed service version; pinned image identity checks |
| 15. Classify/summarize | Existing ingestion listeners and materialized-summary architecture | Reused without broad rebuild changes; existing suite covers policy/classification |
| 16. Complete | `_ingest_one`, definition completion callback, ServiceImage status | Complete/incomplete only after required ingest succeeds; fatal evidence never reports success |
| 17. Present | Public job projection and existing UI polling/results/exports | Internal owner/log/context fields excluded; all evidence routes enforce access |

The control listener has database access and no published host port. The scan-worker has neither database credentials nor Docker socket nor the database network. The Portal remains the authoritative authorization/ingestion service. The patch-worker continues remediation and candidate Helm/Trivy verification; Schrödinger remains on its independently deployed validator VM. No validator provisioning redesign was performed.

## Workflow coverage and intentional boundaries

| Workflow | Execution path and evidence level |
| --- | --- |
| Registry images, private images, image rescans and multi-image jobs | Dedicated worker path traced; request/credential/scope tests. Private OCI pulls require target-host proof |
| Uploaded image archives | Real offline tiny Docker archive scanned; 300 MiB preparation benchmark separately exercised |
| Helm uploads and configuration manifests | Real local Helm/config scan exercised; acquisition and archive tests |
| Traditional repositories and Helm OCI | Worker acquisition path, exact-version and request tests; representative private repositories not exercised live |
| Recursive/vendored Helm dependencies | Existing run-scan pipeline retained, including HELM_ALLOW_NETWORK=false default; representative dependency trees remain a host acceptance item |
| Definitions and scans without definitions | Same durable worker queue; definition result finalization and existing access tests |
| SBOM-only | Worker job kind; cancellation regression; real Syft outputs in scanner run |
| Grype/Trivy/Syft/Dockle | Actual bundled binaries executed offline; see runtime evidence below |
| Partial, failed and cancelled scans | Required-phase, summary, failure category, attempt fencing and recovery tests |
| Historical service versions and exports | Version captured at admission; existing authoritative ingestion/export paths retained and covered by regression suite |
| Candidate verification | Patch-worker process; input/attempt/digest-bound evidence; no Portal scanner fallback |
| Final deployment validation/publication | Remote request identity fixed; existing authorization and digest checks retained; live validator publication unverified |

Artifacts browsing/materialization still performs network acquisition in the Portal. This is an intentional existing non-scan workflow, so Portal egress/trust are still required. Security-data import/refresh, KEV/EPSS enrichment, and image digest enrichment remain centrally managed. None was moved into scanner children.

## Intelligence, durability, storage and performance

The existing intelligence publisher stages, validates, hashes, versions, and atomically publishes Grype/Trivy generations. Attempts copy and verify one immutable generation into writable private caches. Concurrent updates do not change an active attempt; later attempts select the new generation and provenance can flag supersession. Auto-updates are disabled in worker scanner environments. Existing tests exercise concurrent imports, pinned snapshots, tampering, missing/unversioned intelligence, and failed publication. This review repairs custom source-path consumption, and does not duplicate a separate planned mirror-management feature. Approved mirrors/manual uploads still need deployment configuration and compatibility validation.

Durable rows record service/version, ownership, phase, attempt and lease. Deterministic failures terminate through the fenced failure endpoint; retryable failures use bounded backoff. Control transport interruptions retry within the lease. Received evidence is restart-safe and ingestion is replay-safe. Cancellation now survives intermediate ingestion transactions. PostgreSQL tests exercise claims, caps, recovery, attempt ownership, additive upgrade, retention and real ingestion.

Maintenance uses indexed status/definition flags and bounded retention batches. Anonymous admission has a separate cap and authenticated claim priority. Submission reserves capacity before disk staging. Input transfer requests identity encoding; envelopes avoid redundant compression. Source archives are not retained as four copies. Service evidence, referenced executions, definition context, and published intelligence generations are deliberately retained; therefore total historical disk use is **not globally bounded** by job retention. The 20 GiB application budget is not a filesystem quota. Operators must size/quota storage and manage retained evidence/generations separately.

Ingestion remains globally serialized through the PostgreSQL advisory lock and can become a throughput bottleneck. Per-attempt intelligence copies cost disk I/O. Neither was rewritten without workload evidence. Existing classification/materialized summary behavior is preserved.

### Measured performance

Windows local preparation test, 300 MiB disk-backed archive, concurrent in-process ASGI Portal `/health` requests:

| Metric | Observed |
| --- | ---: |
| Preparation duration | 1.091 s |
| Worst health latency | 0.003 s |
| Concurrent health requests | 70 |
| Retained job bytes, expressed as MiB | 300.01 |

This exercises the actual preparation function, database reservation, envelope writes and Portal health handler. It does **not** measure multipart network ingress, large scanner execution, TLS/proxy latency, peak memory, or production disk performance. It is not directly comparable to an earlier audit on a different host.

### Real Linux runtime evidence

A disposable, network-disabled container used current worker code with actual bundled binaries from local `cats:5.5`: Syft 1.31.0, Grype 0.98.0, Trivy 0.69.3, Dockle 0.4.15 and Helm 4.2.3. A small Docker archive containing lodash 4.17.20 and a Helm fixture completed in 13.9 s. Outputs included two SBOM JSONs, eight result files, five Grype matches and 39 configuration findings, with no skipped images/charts. Grype used schema v6.1.10, built 2026-10-03; Trivy used its embedded offline checks fallback. The broker reclaimed an old UID 10001 workspace.

Independent process probes confirmed scanner UID 10002, effective capabilities zero, NoNewPrivs=1, and child termination on normal finish, cancellation and a four-second timeout. HTTP transport in this container harness was a stub; it did not perform real Portal ingestion. Conversely, the PostgreSQL HTTP integration test uses real Portal ingestion through ASGI test clients with a stand-in scanner. These are complementary checks, not a single deployed end-to-end production run.

## Automated verification

Test workspaces are under review-specific `.test-temp/review-*` paths. Windows sandbox restrictions blocked asyncio socket-pair creation in an initial run; rerunning with local socket access resolved that environmental hang. Pytest cache permission warnings are unrelated to the protected startup-evidence directory, which was not inspected.

Baseline evidence: 26 PostgreSQL coordination/HTTP checks passed; 28 deployment/bundle checks passed; 35 candidate/intelligence checks passed. The final OCI verification subset reproduced three existing failures before its request-identity repair. Security/candidate/cancellation regressions establish the newly corrected behaviors.

| Final check | Result | Scope |
| --- | --- | --- |
| Full `portal/tests` suite | 1,988 passed, 20 failed, 12 skipped in 336.06 s | Windows; default SQLite, mocks where fixtures specify them |
| Original `b0d88d7` snapshot: all five files containing final failures | 63 passed, the same 20 failed in 10.22 s | Isolated tracked-file archive; failure node IDs match exactly; no additional final failures |
| PostgreSQL 16 coordination/HTTP/ingestion/cancellation | 92 passed in 93.61 s | `test_scan_worker_coordination`, `test_scan_coordination_hardening`, `test_scan_http_ingest`, `test_scan_ingest_cancellation`; real PostgreSQL and authoritative ingestion, stand-in scanner/ASGI transport |
| Changed security/candidate/OCI/deployment checks | 66 passed in 3.38 s | Focused final regression run; overlaps full suite |
| 300 MiB responsiveness benchmark | 1 passed in 4.21 s | Actual preparation and concurrent health requests; measurements above |
| Linux offline tools and identity/process probes | Passed | Actual scanner binaries; stub control HTTP; no private registry pull |
| Root and template Compose rendering | Passed | Both `docker compose config --quiet` checks; topology also asserted by tests |

The pre-existing failures are preserved rather than weakening assertions or redesigning unrelated provisioning:

| Test file | Failures | Observed mismatch on both snapshots |
| --- | ---: | --- |
| `test_frontend.py` | 1 | Managed-validator bootstrap expectation uses missing `can_manage_validators` field |
| `test_managed_validator_release_preparation.py` | 11 | Validator asset/seal/build-wrapper expectations differ from the current build contract |
| `test_service_posture.py` | 1 | Second dashboard request expects three preparing services but observes two |
| `test_validator_management.py` | 4 | Provisioning fixtures expect removed `validator_client.self_test` |
| `test_validator_operations.py` | 3 | TLS/identity/operation fixtures differ from the current client contract |

This comparison establishes no newly failing test IDs in the completed suite; it does not make the repository's full suite green. The 12 skipped tests are not counted as validation. Full logs remain in `.test-temp/review-root/full-suite.log` and `baseline-failures.log`.

## Deployment and acceptance

1. Back up PostgreSQL and evidence together; stop admission and drain/cancel active work before upgrade. Preserve existing encryption keys, secrets, named volumes and registry configuration.
2. Rebuild the unified image: the protected registry parent is an image change. Deploy Portal, portal-control, scan-worker and patch-worker with matching image and updated Compose configuration. Updating Compose alone against an old image is insufficient.
3. Retain a strong worker token or per-worker rotation map, unique worker IDs, anonymous scanning disabled unless deliberately required, and an existing registry-auth source directory. Do not expose port 8001. Use the documented root-only registry mount path and broker capabilities including KILL.
4. Render both Compose configurations, verify health/readiness and public/internal route separation, then run the host acceptance checklist in `dedicated-scan-worker.md`.
5. On the Ubuntu target, exercise private OCI images and charts with private CA/auth, large layers/archives, vendored/recursive dependencies, SBOM-only and service-definition workflows. Test offline DB import during an active scan and inspect pinned/superseded provenance.
6. Restart each component independently; test long outages, cancellation in acquisition/execution/transfer/ingest, stale/duplicate evidence and retry exhaustion. Measure actual queue throughput, Portal latency, disk/memory/PID limits and scan/patch overlap.
7. Verify host firewall destination restrictions and storage quotas. Run a real remediation-to-candidate-to-remote-validator-to-authorized-publication case with exact artifact digests. Preserve failed static and runtime evidence separately.

Rollback must pair the previous image with its matching Compose configuration after admission/workers stop. Preserve durable job/evidence backups; older images may require explicit resubmission.

## Change inventory and repository preservation

Runtime: `scan_worker.py`, `scan_runtime.py`, `scan_artifacts.py`, `scan_protocol.py`, `candidate_worker.py`, `remediation_verification.py` under `portal/app`.

Deployment: `compose.yaml`, `templates/compose.main.yaml`, `cats-image/Dockerfile.all-in-one`.

Tests: `test_scan_worker_security.py`, `test_scan_ingest_cancellation.py`, `test_candidate_worker.py`, `test_remediation_verification.py`, `test_scan_deployment_topology.py` under `portal/tests`.

Documentation: this report and `docs/dedicated-scan-worker.md`. No database changes, dependency additions, backend performance redesign, or validator provisioning changes.

The pre-existing README edit is excluded and its SHA-256 remains `1EB362EBC21873E1D0BCD5EDD52C35B563C8971B85B41D9483EBF0AF8213CC1E`. Protected/unrelated untracked files, training documents, archives and `.test-temp/startup-evidence-check2/` are excluded and untouched. The protected directory was not inspected. Only explicit task paths are staged. Task files retain Windows/CRLF-safe checkout behavior; the diff has no line-ending-only changes.

Local implementation commits on `feature/dedicated-scan-worker`, descending from the verified `b0d88d7` baseline:

- `201c759`: Harden scan broker credentials, artifacts, and process isolation.
- `2d059bc`: Require candidate resources and bind final OCI validator responses.
- `7751bd8`: Honor cancellation across scan ingestion transaction boundaries.

The documentation commit containing this report follows those implementation commits. No merge or push was performed. The pre-existing README modification remains the only unrelated tracked edit; review-owned test evidence is not committed. There are no schema migrations or dependency changes. A full production image rebuild and the Ubuntu acceptance checklist remain required before claiming production readiness.
