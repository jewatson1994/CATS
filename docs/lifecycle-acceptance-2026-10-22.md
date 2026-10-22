# Lifecycle acceptance checkpoint — 2026-10-22

## Scope and ancestry

Branch: `feature/unified-artifact-lifecycle`. The original `802624c66ac33c6921119bf53488e22169f617fa` was fast-forwarded to verified integration `e937f62322d55c9155076dd5593bb25e99deae2d`. The checkpoint includes main's separate intelligence architecture (`c6280a1`) and Discovery shared-image correction (`321cf1f`). Main and other feature branches were not changed or pushed. This report describes the commit containing this file; obtain its full ID with `git log -1 --format=%H -- docs/lifecycle-acceptance-2026-10-22.md`.

## Changes

- `patch_service.py`: reject duplicate execution IDs; fence stale observers; preserve terminal state during cancellation races; report unavailable process ownership conservatively; handle process startup and persistence failures without leaking private execution configuration.
- `scanner_inputs.py`: derive snapshot identity from bytes, reject links and special files, verify private copies and subsequent integrity, and prevent Grype database updates when a snapshot is bound. An operator digest is only an optional consistency check.
- `patch_recipes.py`: reject unknown identity fields instead of silently excluding material inputs from equivalence. The subsequent execution-bound implementation and real campaign results are documented below.
- `auth.py`, `service_posture.py`, `service_tab_queries.py`: reduce redundant queries while preserving role scope and native VEX generation checks. Batch generation/expiry lookups and reuse already loaded ownership relationships.
- Tests correct stale ownership fixtures, model registration and tracked build-script assumptions. Recovery tests exercise process failure and cancellation races. Query budgets were not raised.
- `deploy/backup/integration_signed_restore.py`: reproducible signed-package seed/verify drill for disposable PostgreSQL databases.

## Earlier checkpoint verification

These counts describe the preceding checkpoint, not a rerun of the final working tree.

Separate runs overlap; counts must not be added.

| Check | Result |
|---|---|
| Full portal backend suite | 4,087 passed, 95 skipped, 7 warnings; 722.65 seconds |
| Split PostgreSQL and proposed assessment integration | 47 passed; 241 seconds |
| Frontend | 385 tests in 58 files passed; typecheck and production build passed |
| Focused recipe/recovery/scanner suite | 49 passed; 14.67 seconds |
| Real database backup tests | 6 passed; 34.296 seconds |
| Both Docker Compose configurations | Validation passed |
| Normal CATS release image | Built successfully |
| Discovery worker image | Built successfully from the same CATS image |

The full backend command, from `portal`, was `python -m pytest tests --basetemp <external-temporary-directory> -q`, with repository and portal directories on PYTHONPATH. Its local output is `.test-temp/lifecycle-final-regression.log`. The 95 skipped checks are not counted as acceptance. PostgreSQL checks were also run separately against actual databases. An earlier full run had one warm-query-budget failure; isolated, grouped and final full reruns passed without increasing the budget. Its exact transient cause was not established.

Built CATS image: `cats:lifecycle-acceptance-20261022`, ID `sha256:c9401d55a02ba1989ca2352b64f3b154fac8b531e9e5a50a8f71813b06d8fd99`, 1,659,760,689 bytes. Discovery image: `cats-discovery:lifecycle-acceptance-20261022`, manifest `sha256:be02117adf2c080367245b63a600b35e8a58303743475cb59c49e69e68efa34e`. These builds preceded the final recipe unknown-field rejection and documentation edits; they are build verification, not images of the exact final commit. Existing deployment containers were not replaced.

## Restore and database isolation

Real PostgreSQL 16.15 testing imported two Ed25519-signed packages through the production loader, dumped intelligence, restored it into a fresh database, and verified the independent application sentinel. Ten tables, two installs, three records, two catalogs and three memberships matched. Reinstallation, rollback rejection, freshness, source trust removal and restored generation invalidation were checked. The restored database retained its logical identity but changed incarnation; application connections were recreated in a separate runtime process. Private signing keys were not persisted in committed evidence.

Reproduction: use disposable databases only. Set independent `DATABASE_URL` and `INTELLIGENCE_DATABASE_URL`; run `python deploy/backup/integration_signed_restore.py seed <evidence-directory>`, dump intelligence with `pg_dump -Fc`, restore into a fresh intelligence database, then run the script's `verify` command with that restored URL and the unchanged application URL. The drill creates fixture schemas and data and must never target production. Local evidence: `%TEMP%/cats-signed-restore-20261022`; dump SHA-256 `ebd16f4a92862d794c134c4f0b8a2a67ffe361e808ff11f779e0622d6564dd`.

This small signed EPSS fixture is not restoration of the complete deployed intelligence corpus. Backup tests also exercised operational restoration and split-database behavior. Running-worker interruption across a real restore remains unverified.

## Gateway and signing evidence

The current CATS build exercised real PostgreSQL, a TLS registry, encrypted Cosign keys and pinned verification. Ten gateway, five signed-active-release and three concurrency assertions passed. Concurrent database dispatch produced one durable job without committing unrelated caller changes. Revocation denied manifests, cached blobs and referrers; a second service sharing the artifact remained authorized. Missing active pointers and tampered signatures failed closed.

Actual Docker pull completed in 538.87 ms and Helm OCI pull in 510.32 ms. Revoked requests returned 403 in 113.14 and 99.03 ms. Ten sequential manifest requests took 49.67–70.48 ms (median 52.20 ms). These are local samples, not concurrent throughput or CPU/memory benchmarks. The harness uses seeded scan, validation and Cyber records. It proves those gateway/signing paths, not the full real upstream lifecycle. See `tests/lifecycle/README.md`. Local `.test-temp/lifecycle-acceptance-20261022-current-gateway` includes private test material and must not be committed.

## Real Copa evidence — separate connected run

The prior real Copa 0.14.1 run patched original digest `sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd` to `sha256:e269e2a739a6444fba2b114e5a5d97a14ca5206b7b31903e1dd931514c1f106a`. Syft 1.31 and Grype database dated 2026-10-03 reported 72 findings before and 4 after: 69 removed, 3 retained and 1 newly reported zlib finding, CVE-2026-85091. Eight OS packages were upgraded; all 69 targeted report entries were satisfied.

That run used public package repositories and a CLI tool container, not the deployed worker-to-Cyber flow. It must not be combined with seeded gateway evidence to claim an uninterrupted lifecycle or offline success.

## Remaining work and readiness

The real two-service lifecycle below passed. The branch is ready for controlled deployment testing; broader production acceptance remains limited as listed here.

1. Production execution-bound recipe reuse is implemented and a second service reused the real successful campaign. See the execution-binding section below for its requirements and trust boundary.
2. Persistent execution locks fence local process ownership across supervisor restart. An uncertain remote publisher fails closed and requires operator reconciliation; it is never replayed automatically or reported cancelled without evidence. Snapshot and orphan BuildKit cleanup after a hard host failure remains an operator responsibility; automatic TTL/quota cleanup is not implemented.
3. The actual sequential Patch/Scan/validation/publication/Cyber/adoption/assessment/activation flow passed using real API decisions and evidence. See the real lifecycle section below; historical seeded gateway tests remain separately identified.
4. This isolated disconnected two-service scenario passed. Running-worker restart during reassessment, concurrent revocation during real pulls, competing amendment activation stress, partial campaign operational recovery and comprehensive performance measurements remain unverified.
5. General orchestration of every requested attestation type and broader multi-platform/key-rotation acceptance remain incomplete as documented in the main guide.
6. Full-corpus intelligence recovery and representative production migration/rollback remain outstanding. Keep both database backups, stop dispatch and drain workers before rollback; preserve immutable history and pending jobs. Do not drop new tables to make an older image start.

No safety, VEX applicability, signature, Cyber authorization or compliance check was relaxed to obtain these results.

## Production execution binding — current continuation

The authenticated patch worker prepares an opaque execution handle from its administrator-controlled `CATS_PATCH_BINDING_SPEC` (schema `cats-isolated-copa-v1`). Clients cannot supply equivalence assertions. `CATS_PATCH_BINDING_ROOT` retains private prepared inputs and receipts. The specification identifies the internal Docker network, snapshot services and roots, BuildKit image/configuration, repository policy and staging registry. It must describe actual serving containers: snapshots are copied from those containers, not assumed to match a workstation path.

Canonical recipe SHA-256 covers schema version; original digest, media type and platform; engine, repository snapshot and scanner database digests; actual patch configuration/policy; and destination scope. Execution handles and job IDs are excluded from equivalence. Policy includes signing identity, trusted certificates, repository policies, OS definitions, output/source mode and remediation settings. Tool binaries, application Python sources, BuildKit and source-service images/configurations, repository metadata/package bytes and private scanner database bytes are bound. Source must be digest-qualified and the platform known. Material changes create a different recipe.

Execution rechecks the prepared inputs and actual BuildKit/network identity, uses a fresh isolated BuildKit with no prior cache, disables scanner updates for pinned databases, and records a single-use consumed receipt bound to the job, configuration, source and immutable output. Registry redirects are rejected. Current eligibility, signature identity, platform, source, destination and consumed receipt are checked before reuse. A unique database recipe claim coordinates equivalent requests; uncertain, cancelled, failed or unverifiable work is not reusable. Deployment Docker administrators, worker filesystem and Docker daemon remain trusted. This is not protection against a hostile host administrator.

A permanent local lock file uses Windows/POSIX exclusive locking. Reclaim does not permit an old publisher to finish under a new owner. Real PostgreSQL/process tests exercised termination, lease expiration, restart, cancellation and rejected stale completion: the grouped run passed 34 tests in 74.33 seconds. An uncertain remote execution retained one execution attempt and rejected unsafe retry rather than creating a second publisher. Separate recovery runs overlap and are not additive.

## Actual disconnected campaign evidence

The actual Patch API/coordinator/worker campaign `ae798f2993df4c91943ca509a1b05481` produced `127.0.0.1:15023/patched/acceptance/image-3@sha256:468ebd7f49ca3abae6b4a17fbd10380b3aa3a3fe9d6df0b088629dca4ffba707`. Copa and real scanner evidence recorded **69 applicable findings before and 0 after**. A second service's campaign returned reuse of that same execution and output without a second Copa operation. Local evidence: `.test-temp/real-lifecycle-20261022/actual-bound-campaign.json`, `actual-bound-campaign-reuse.json`, and `.test-temp/offline-real-20261022/bound-campaign-final`. Private configuration and signing material in those directories must not be committed.

The isolated test uses an internal Docker network, locally provisioned APK metadata/payloads, local registry, and the Grype database dated 2026-10-03. The test explicitly permits a 720-hour scanner age; the production default remains 120 hours. Therefore these vulnerability totals describe that fixed database, not current complete intelligence. Temporary privileged BuildKit and validator Docker access were explicitly approved for the disposable test infrastructure.

Real validator runs use the existing validator and a real Kubernetes test cluster. Eligibility is tied to the exact published reference, manifest/config/layer identities and successful cleanup. A new publication reference correctly required another validation even when content was identical. `artifact_image_validation.py` provides the scoped API; missing, running, mismatched or unverified validation cannot make an artifact eligible. Multi-platform validation is not claimed.

Signed gateway bindings now distinguish the configured original repository from the authorized effective repository on the same configured upstream. This permits stable service tags to resolve to a published replacement without changing historical manifests. Approval evidence must uniquely bind the effective digest/reference; mapping drift, ambiguous evidence and cross-host substitutions fail closed. Manifest, blob, referrer and signature requests use the authorized effective repository.

## Final continuation regression and image build

The combined current-tree patch binding, campaigns, recovery, artifact validation, publication, release revision and OCI authorization/proxy regression run passed **402 tests in 27.86 seconds**. After the final chained-amendment integrity corrections, the authorization/proxy/revision suite passed **71 tests in 3.89 seconds** (overlapping, not additive). The Python dependency/stdlib and effective system CA binding checks passed separately (17 tests, overlapping the combined run). These counts are not additive. Runtime identity includes installed dependency bytes, standard-library bytes, Python implementation/version and interpreter bytes; generated bytecode caches are excluded. Custom CA bytes are also retained in recipe policy. Host kernel, Docker daemon and non-Python system libraries remain trusted deployment boundaries.

The normal release build passed for `cats:lifecycle-final-20261022`: OCI index `sha256:d2f36955a038940b2e9efcf927a556381d0047c9b800f07b0a521e8de9863ff3`, image manifest `sha256:295b24dfdcafdd173b4c64a8ecfdf873c41c7f97d2b2d2b99d35aa91526d0211`, configuration `sha256:fa4b13ba0215f30caa24ba6bc803dc144e104e35433479cd0347ffe608c15b65`, 1,659,799,945 bytes. Discovery uses this same image. Build command: `python scripts/build-cats-release.py --cats-version lifecycle-final-20261022 --tag cats:lifecycle-final-20261022 --scanner-base catscan-base:local`. Local build log: `.test-temp/lifecycle-final-release-build.log`.

Compose validation passed for the main and validator files, their deployment templates, and the main configuration with the OCI proxy overlay. No frontend code changed in this continuation; the earlier frontend results above are historical rather than a new run.

## Real two-service lifecycle and independent revocation

The uninterrupted local sequence used actual Copa, Syft/Grype, separate PostgreSQL operational/intelligence databases, deployed workers, Kubernetes validation, local TLS publication, Cosign, and authorized test-operator Cyber API decisions. Successful scan, validation and approval records were not seeded to bypass these stages.

Original digest: `sha256:02ad8ed19ee32cf981eefbc32aec95e85c50ed246133ca8a4b3b7a30b17a77d1`. Replacement: `sha256:468ebd7f49ca3abae6b4a17fbd10380b3aa3a3fe9d6df0b088629dca4ffba707`. Two catalog artifacts, one immutable lineage and one patch execution served both services. Validator runs 5 and 6 verified the published artifact and completed cleanup. Separate Dockle findings (non-root, healthcheck and content trust) were reviewed under the configured policy; zero applicable vulnerability findings does not mean zero configuration findings.

Producer `acceptance-one` obtained actual Cyber approval 5 and signed active revision 5. Receiver `acceptance-two` adopted recommendation 1 through proposal 1. Automatic assessment `0cc1dcbee8c64ccc8764b1618670eb38` dispatched scan `432cc6be7738405fa3c0a7a772a973f1`, retained the original requested reference alongside the effective patched digest, and became ready while its original active revision remained unchanged. Actual Cyber approval 6 activated signed revision 6.

Both stable service tags returned HTTP 200 with the identical patched manifest. Seven image blobs and two signature blobs per service passed SHA-256 verification. Revoking the receiver denied its stable tag, direct digest, blob and signature routes (403), while producer access and integrity checks remained successful. Evidence is in ignored `actual-gateway-both-final.json`, `actual-gateway-revoked.json` and `actual-chain-progress.json` under `.test-temp/real-lifecycle-20261022`. Test credentials and private keys must not be committed.

The run exposed and corrected proposed requested/effective reference ingestion, scanner CA propagation, inert Cosign image configuration handling and chained amendment source-evidence verification. `oci_authorization._payload_evidence_matches` follows retained immutable amendment evidence back to the original source; ambiguous, tampered, cyclic or over-depth chains fail closed. Chained amendment cases are automated regression evidence; this real operational scenario used one amendment.

This proves the local configured container lifecycle. General attestation orchestration, multi-platform and key-rotation acceptance, production-volume load, and full intelligence-corpus restore remain separate limitations, not implied successes. The fixed offline scanner database and explicitly configured age allowance described above remain material test constraints.

Actual Docker-client verification also passed against this real PostgreSQL lifecycle state. Pulling `127.0.0.1:15026/acceptance/acceptance-one:stable` returned the patched manifest above. The saved image configuration bytes independently verified as `sha256:845ebb0bd5347df6f14466e0f36a85d2e02229ce0f3e4bfc86a97497ebb88704`. Pulling the revoked receiver's stable reference failed with HTTP 403. Evidence: `.test-temp/real-lifecycle-20261022/actual-docker-pull.json`. Temporary gateway and Docker credentials were removed. The gateway client connection in this local test was loopback HTTP; upstream registry publication used TLS. This is not a production gateway TLS acceptance claim.

## Final main integration verification (2026-10-22)

The isolated integration merged feature `3d7b2385a2c860518cbbbcce2b9d93bd4a37acb5` into remote main `321cf1f93715a77737cffbc4fe5497065ddd9b30` as merge commit `1c9ae64f0cd4c61c6d23ce72ce2e4335b78c1bce`. There were no textual conflicts and the initial merged tree matched the feature tree. An unused frontend state declaration was removed to satisfy the required lint check. Existing branches and operational data were preserved.

Fresh frontend verification passed 385 tests in 58 files, typecheck, lint and production build. Split-database verification passed 66 real PostgreSQL cases (24 split intelligence, 23 split proposal, 13 risk/VEX, five patch restart, one durable lease), plus 54 supporting routing/pool/schema/release cases. Eight optional SQL-parser checks skipped because pglast was unavailable. Twenty-five initial Windows temporary-directory setup errors all passed on retry with a fresh explicit basetemp; they were not application assertion failures. The Linux backup suite passed six tests. A separate real pg_dump/pg_restore drill passed signed-package seed and verification against independent operational, intelligence and restored databases. This is a bounded restore fixture, not full intelligence-corpus recovery.

Both normal Compose configurations validated. The normal release rebuilt after the frontend cleanup as `cats:lifecycle-final-merged-20261022`, image ID `sha256:848af1311230e74090d9a54250d5f402b4f42915022e532b3d91da636162f93d`. Discovery uses the same image. A real final-image smoke test imported the Discovery worker and rendered Compose v2.39.4 through the sandbox with UID 10003, read-only filesystem, dropped capabilities, no-new-privileges, repository seccomp, temporary storage and no network.

The merged-code TLS registry harness passed ten gateway checks, five signed active-revision checks and three concurrency invariants, including real Cosign signing/verification and tamper rejection. Actual Docker and Helm pulls took 585 ms and 631 ms; revoked requests returned 403 in 116 ms and 108 ms. These are local single-operation measurements, not production benchmarks. This harness seeds initial scan/approval/validation fixtures and therefore does not replace the actual Copa-to-Cyber evidence above. The full real patch chain was not rerun during this merge checkpoint. Final-image rebuilding changed only frontend cleanup after the gateway run.

Additional OCI attestation/signature/transport and scanner identity checks passed 47 tests. Private test keys, credentials, registry state, temporary reports and database dumps remain excluded from version control. The tracked embedded-intelligence release key is public; private-key header literals in signing validation are not embedded private keys.

Deployment remains a separate operator action. Back up both databases and retain the previous release image before deployment; drain workers before rollback. Older application images may not understand newer lifecycle jobs or signed revisions. Do not delete or rewrite immutable history to make an older image run; restore a coordinated backup when a database rollback is necessary. Production-scale concurrency, full intelligence-corpus recovery, broad multi-platform acceptance, key rotation and complete attestation orchestration remain documented hardening work.

The final full backend run passed 4,178 tests, with 100 skips and seven warnings, in 786.53 seconds. An initial overlapping frontend build produced three transient HTTP 503 page tests while generated frontend assets were unavailable; the affected module passed independently, and the complete backend suite passed after the frontend build finished. No backend workaround was introduced.
