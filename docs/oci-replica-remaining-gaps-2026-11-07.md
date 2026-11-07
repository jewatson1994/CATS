# OCI replica remaining-gap qualification

The remaining implementation and qualification gaps passed within the local scope documented below. No unresolved functional defect was found in this pass. Intended staging infrastructure and production acceptance remain unverified.

Baseline: `d20b8513d68c2f8477612705099299834f608073`, branch `codex/oci-approved-release-replicas`. This extends the [27-requirement qualification](oci-replica-final-qualification-2026-11-06.md) and [attestation/key-continuity completion](oci-replica-feature-completion-2026-11-07.md). Historical evidence remains unchanged. The [deployment runbook](oci-replica-deployment-runbook.md) contains the updated operating procedures.

## Corrections

- The replica image now selects a checksum-pinned AMD64 or ARM64 Cosign binary. Other architectures fail the build; frontend assets build on the builder's native platform.
- Portal `/readyz` checks the database and returns a redacted, uncached 503 during an outage. Standalone Compose uses this readiness check; `/health` remains process liveness.
- Qualification transfers now retain pinned attestation graphs as well as signatures. Existing Harbor test robots are checked for expiration, disabled state and authenticated repository access before scoped setup changes.
- Qualification probes reject HTTP/authentication/TLS errors as evidence of disconnection. The nginx publisher probe uses its unique container name, preventing another stack's shared `portal` alias from answering it.
- The local account qualification explicitly verifies the forced password-change challenge, successful change, rejection of the original password and a fresh authenticated session with the new password.
- Restart-proof validation recognizes the exact Windows and Docker Desktop Linux representations of the same bind path. It preserves the raw observations and rejects different drives, folders, ambiguous paths and changed named volumes. The corrected live check reused the original grant and unchanged restart proof.

These fixes preserve approval, trust, integrity, authentication and override enforcement. Private credentials, signing keys, database backups and runtime evidence remain outside Git.

## Requirements and observed evidence

This is the remaining-gap matrix; unaffected requirements retain their evidence in the linked comprehensive report. “Complete” applies to the stated implementation and tested scope, not an unprovided production environment.

| Requirement / prior gap | Status | Implementation and actual validation | Limits |
| --- | --- | --- | --- |
| R04: ARM replica | Complete | `portal/Dockerfile.replica`; complete ARM64 image build, ARM64 Cosign execution, signed graph verification and portal/proxy startup | Docker Desktop emulation on AMD64; native ARM capacity is unverified |
| R04/R25: TLS, local identities and recovery | Complete | `replica_deployment_qualification.py`; trusted TLS 1.3, wrong-host/untrusted-CA rejection, local password change, Secure cookies, scoped evidence access, CSRF/admin/cross-service denials and immediate role-removal enforcement | Local qualification CA/accounts, not enterprise CA or SSO |
| R05/R09: interrupted activation | Complete | `test_replica_recovery_live.py` and `replica_recovery_process.py`; actual OS kill at two flushed PostgreSQL transaction boundaries, predecessor preserved, fresh-worker recovery and unchanged replay | Controlled verified-format transaction fixtures; cryptographic registry journey is qualified separately |
| R10: live offline expiry | Complete | Real wall-clock expiry, actual TCP proxy GET/HEAD requests, TLS registry client, warmed manifest/blob cache, registry stopped, denials after expiry and HTTP-server restart | HTTP-server restart occurs in the same Python process; full container restart is separately tested below |
| R11/R12: shared artifact isolation | Complete | Both service caches warmed; registry stopped; one service's exact override allows its GET/HEAD while the other service remains denied; uses audited only to the granting service | Controlled sealed importer fixtures |
| R08/R09/R12: fresh Harbor 100/23 lifecycle | Complete | All 123 distinct runnable variants executed; real Harbor transfers, incomplete-successor rejection, 77 retained/23 retired/23 new, 100 disconnected full pulls, exact fixed/indefinite overrides and revocation, persisted grant/audit after application/database restart and sync | Approval and assessment evidence for this corpus is explicitly synthetic; cold blob cache with retained database manifest cache |
| R13/R14: alternate registry and legacy retention | Complete | Synthetic signed evidence fixture through real Distribution 2.8.3, Zot 2.1.22, TLS and Cosign; AMD64/ARM64 signed index, chart, signature, attestation and revocation verification; OCI 1.1 referrers; unrelated referrer excluded; missing-chart rejection | These versions and CATS formats only; no arbitrary third-party attestation claim |
| R13: legacy backfill | Complete | Synthetic older-format signed inventory without optional `retention_tag`; current importer and ORAS 1.3.0 create/fetch five retention tags; explicit backfill and tag-only transfer preserve signed bytes | Requires complete retained graphs and frozen service evidence; does not restore deleted content |
| R16: rotation boundaries and key backup | Complete | Production validation/configuration with real EC test signatures exercises 32 transitions, 10,000 cutovers, aggregate 4 MiB limit, missing-key rejection and same-key backup restoration followed by rotation | Bounds apply together; irreversible key loss needs authorized trust migration |
| R20/R25: restore, readiness and bounded load | Complete | Exact fresh PostgreSQL logical restore; signed evidence and cold pull through restored credentials; real DB stop/restart; 240 authenticated reads at eight clients | Local restore/read burst, not off-host durability, sustained capacity, external alert delivery or recovery SLA |
| R21: fresh real nginx assessment | Complete | Fresh scan, real package patch, hardened derivative, rescan, approval and actual Harbor replication; source-off cold pull, exact override/revocation and restart replay | Three raw configuration observations retained; scanner database timestamps recorded |
| R22/R23/R24: regression and build | Complete | Current affected-feature suite: 1,018 passed, one skipped; four additional live PostgreSQL recovery checks; complete AMD64 full/replica and ARM64 replica builds | Runs overlap; prior frontend/migration evidence is retained, not represented as freshly rerun |
| Intended staging infrastructure / production acceptance | Unverified | Local representative qualification and reproducible operating procedures are available | Requires intended DNS/CA/SSO, host/registry versions, alert destinations, sizing and backup/recovery objectives |

## Real workflows

Harbor `v2.15.4-d8841742` executed isolated source-to-target replication jobs 27 and 30 for the inventory and 28 and 29 for nginx. The inventory jobs each completed three tasks; the nginx jobs each completed two. Transfers into the target were performed by Harbor. All nine source-Harbor services were explicitly stopped and their stopped state recorded before disconnected checks.

The inventory uses two approved sets of 100 runnable image variants drawn from 123 distinct images. Its synthesized approval/evidence fixture is not a real scan or production approval. The independent nginx workflow uses actual scan, patch, rescan and Cyber approval APIs. The two forms of evidence are kept distinct.

The fresh nginx package scan changed from 194 findings to zero using the retained scanner databases. The hardened derivative changed seven raw configuration findings to three: public `KEY_SHA512` checksum false positive (`CIS-DI-0010`), inherited `RUN cd` history (`DS-0013`), and scanner Content Trust context (`CIS-DI-0005`). They remain in the recorded results, including their original severities. The runtime check verifies non-root, read-only operation without network or added capabilities, actual HTTP response bytes, health failure while nginx is stopped and recovery afterward. This does not claim vulnerability freedom beyond the recorded scanner/database scope.

An intentionally incomplete successor failed synchronization without changing the original 100-image inventory. The exact repository layer link and descriptor-cache key were restored, after which synchronization activated the successor with **77 retained, 23 retired and 23 new images**. All 23 retired roots were denied. Both fixed-duration and indefinite exact-root overrides allowed their selected image, left the other 22 retired images denied, and were revoked successfully; cached requests were then denied.

With all nine source-Harbor services stopped and an empty blob cache, all **100 successor image graphs** pulled through the replica, hash-verifying **2,101,456,523 aggregate bytes**. Shared blobs can be counted repeatedly across graphs; this is not unique stored size. The database manifest cache was retained. The independent nginx cold pull verified **63,712,617 bytes** across one manifest and 16 blobs, followed by exact override creation/revocation and unchanged restart replay.

The original indefinite inventory override and its audit records survived force-recreation of the application and database containers with the same persistent storage, followed by normal synchronization. The post-restart pull added 11 exact-grant use records; the other 22 retired images remained denied. Revocation then denied cached access without recording a successful override use. The first verification attempt stopped before reading or revoking the grant because Docker Desktop reported the certificate bind path in a different equivalent form. The corrected attempt used the same grant and restart proof, preserving the validity of the persistence check.

## Operational measurements

The quiesced restore used a stopped-volume clone and a logical PostgreSQL dump restored into fresh storage. Before application startup, **128 tables, 5,866 rows, 82 sequences and nine evidence files (3,251,219 bytes)** matched exactly. All nine evidence archives matched their signed manifests after startup. An initially empty blob cache then fetched three manifests and four blobs, verifying 22,315 bytes through restored registry credentials.

The authenticated read burst completed **240 requests with eight clients, zero errors, p95 1,134.2 ms**, within its declared 5,000 ms ceiling. This is a bounded local read test, not a capacity rating.

During the real isolated database outage, portal liveness remained 200 while portal readiness and proxy readiness returned 503. With the supplied Compose retries, Docker marked the proxy unhealthy after **108.05 seconds** and the portal after **160.83 seconds**. Both recovered healthy with authenticated reads **16 seconds** after the database restarted, without restarting the applications. External monitoring must account for that detection delay and deliver the site's alerts.

## Verification and evidence

Current affected-feature regression: **1,018 passed, one skipped, zero failures**, 123.35 seconds. The skip is Windows-host `test_real_cosign_encrypted_key_roundtrip` because host Cosign is absent. Real Linux Cosign is exercised by the registry workflows; the exact test also passed in the prior completion run. These are separate evidence claims. Focused checks after the qualification fixes: **118 passed, zero skipped or failed**, 3.60 seconds. The subsequent mount-proof correction passed **29 focused tests**, 0.99 seconds. The separate live PostgreSQL/TCP/process-kill suite passed all **four tests**, 41.11 seconds. These runs overlap and are not a unique-test total.

The initial test invocation lacked `PYTHONPATH`; the corrected restricted invocation stalled creating Python's internal loopback socket pair. A diagnostic identified that environment issue and the authorized rerun completed. Neither unsuccessful invocation is counted as passing coverage. Initial qualification failures (expired test robots, omitted attestation graphs, generic publisher alias and overly permissive proof assertions) are retained with their corrections.

The previous completion report retains the 496 frontend tests, type/build checks, broader backend and migration evidence. No frontend source changed in this pass; current container builds rebuild frontend assets. Test runs overlap and must not be summed as unique coverage.

Sanitized results, limitations and evidence SHA-256 hashes are recorded in the [machine-readable report](oci-replica-remaining-gaps-2026-11-07.json). Detailed evidence and private runtime material are retained separately under `C:\Users\lil-j\.codex\visualizations\2026\11\05\01a1ada8-46fc-7ae1-895c-a315b48a238b\remaining-20261107`.

## Deployment boundary

The remaining environment-specific work is qualification on the intended staging infrastructure: native host architecture/performance, registry policy and retention, DNS and enterprise TLS, SSO, external alert delivery, sustained workload, off-host backup custody and measured recovery objectives. These values and services were not supplied and were not invented. Unavailable private-key backups and deleted legacy graphs cannot be reconstructed by weakening trust or integrity checks.

All 51 qualification containers were stopped after the successful checks, preserving volumes, images and evidence. Unrelated untracked work is preserved. Changes are committed locally; nothing is pushed or merged.
