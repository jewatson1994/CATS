# Lifecycle acceptance checkpoint — 2026-10-22

## Scope and ancestry

Branch: `feature/unified-artifact-lifecycle`. The original `802624c66ac33c6921119bf53488e22169f617fa` was fast-forwarded to verified integration `e937f62322d55c9155076dd5593bb25e99deae2d`. The checkpoint includes main's separate intelligence architecture (`c6280a1`) and Discovery shared-image correction (`321cf1f`). Main and other feature branches were not changed or pushed. This report describes the commit containing this file; obtain its full ID with `git log -1 --format=%H -- docs/lifecycle-acceptance-2026-10-22.md`.

## Changes

- `patch_service.py`: reject duplicate execution IDs; fence stale observers; preserve terminal state during cancellation races; report unavailable process ownership conservatively; handle process startup and persistence failures without leaking private execution configuration.
- `scanner_inputs.py`: derive snapshot identity from bytes, reject links and special files, verify private copies and subsequent integrity, and prevent Grype database updates when a snapshot is bound. An operator digest is only an optional consistency check.
- `patch_recipes.py`: reject unknown identity fields instead of silently excluding material inputs from equivalence. Production automatic reuse remains disabled pending authenticated execution binding.
- `auth.py`, `service_posture.py`, `service_tab_queries.py`: reduce redundant queries while preserving role scope and native VEX generation checks. Batch generation/expiry lookups and reuse already loaded ownership relationships.
- Tests correct stale ownership fixtures, model registration and tracked build-script assumptions. Recovery tests exercise process failure and cancellation races. Query budgets were not raised.
- `deploy/backup/integration_signed_restore.py`: reproducible signed-package seed/verify drill for disposable PostgreSQL databases.

## Verification

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

This is a verified integration checkpoint for isolated deployment testing, **not full operational acceptance**.

1. Production equivalent-recipe reuse is still disabled. The worker must prepare and authenticate immutable package metadata/payloads, target platform, tool/runtime identity, policy and actual consumed inputs. Mutable mirror URLs or operator assertions are insufficient. Coordination tests alone do not close this implementation gap.
2. Patch supervisor restart loses process ownership. Conservative cancellation rejects an unknown live process rather than claiming cancellation while it may still publish. Persistent execution ownership and restart recovery remain necessary.
3. One uninterrupted real Patch/Scan/validation/publication/Cyber/adoption/assessment/activation flow has not passed. Local package mirrors, deployed validation and offline scanner resources must be bound and exercised. No success records should substitute for those stages.
4. Full disconnected lifecycle, running-worker restart during reassessment, concurrent revocation during real pulls, competing amendment activation stress, partial campaign operational recovery and comprehensive performance measurements remain unverified.
5. General orchestration of every requested attestation type and broader multi-platform/key-rotation acceptance remain incomplete as documented in the main guide.
6. Full-corpus intelligence recovery and representative production migration/rollback remain outstanding. Keep both database backups, stop dispatch and drain workers before rollback; preserve immutable history and pending jobs. Do not drop new tables to make an older image start.

No safety, VEX applicability, signature, Cyber authorization or compliance check was relaxed to obtain these results.
