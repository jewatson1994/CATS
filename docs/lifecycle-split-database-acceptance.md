# Lifecycle / split intelligence compatibility checkpoint

Date: 2026-10-21. Branch: `codex/lifecycle-main-integration`.

## Inputs and isolation

Lifecycle baseline: `802624c66ac33c6921119bf53488e22169f617fa`. Previous checkpoint: `d9a32a95edfedcb63c9ac4845ff6a36b2cdfb246`, incorporating main `c6280a1432a67df27ce4eb9ac340ed19f065e63d` via `8b72ead78a43cc41b35fa183180a0858114c5df8`.

This checkpoint integrates Discovery hotfix main `321cf1f93715a77737cffbc4fe5497065ddd9b30` through merge `b61b444f4c1238c48ae7769ea3f2dbb60e6a832d`, without textual conflicts. GitHub main was independently checked with `git ls-remote` and still points to that hotfix. Original branches and unrelated working changes remain untouched. The final checkpoint commit is the commit containing this report (`git log -1 --format=%H -- docs/lifecycle-split-database-acceptance.md`). Nothing was pushed.

## Runtime findings and corrections

The previous checkpoint corrected `container_intelligence.advisory_batch` to use RoutingSession.get_bind rather than assuming a directly bound session. It also added independent intelligence backups and split-database lifecycle harness initialization. Those fixes are retained.

The temporary disabling of native VEX exclusions in split mode is removed. `portal/app/intelligence_generation.py` provides a durable singleton generation in the intelligence database. PostgreSQL BEFORE STATEMENT triggers change it transactionally for evidence and trust mutations, including truncation. Initialization installs the table and triggers through `database.py`; operational tables remain in the operational database.

`native_vex.evaluate_service` binds evidence publication to this generation. `current_evaluation` filters dispositions against a freshly read generation; the SQL execution hook refreshes the bound token and acquires a shared generation lock. `cache_token` includes the live generation. Old evidence remains historical but cannot supply current exclusions. Unavailable intelligence fails conservatively. The fingerprint also includes database identity, table filenode and server start time, conservatively invalidating evaluations after restore/restart. Reads are constant cost and do not scan the intelligence corpus.

The shared lock is held through the outer operational transaction and checked before commit. Intelligence mutations acquire the conflicting lock before changing evidence. Five-second lock/statement timeouts bound waiting. This prevents concurrent evidence changes during a healthy fenced transaction; it is not a distributed atomic commit protocol. Connection loss between the final check and operational commit is not a two-phase commit guarantee. Subsequent effective reads require the live generation again and reject obsolete dispositions.

`native_vex_worker` queues stale-generation reassessments in bounded batches while avoiding duplicate busy jobs. `risk_routes.native_vex_policy` reports actual availability. Worker durability uses the existing job infrastructure.

## Verification

| Check | Result |
|---|---|
| Real split PostgreSQL intelligence suite | 24 passed (22 in 72.71s, 2 in 4.76s): schema routing, freshness/trust, valid exclusions, generation changes, concurrent fencing, outage, SQL token refresh, incarnation mismatch, recovery and reassessment scheduling |
| Real PostgreSQL proposed inventory suite | 23 passed in 80.48s: dispatch deduplication, evidence ingestion, stale/superseded work, cancellation, frozen Cyber evidence, active-state isolation, risk-policy and validation reassessment |
| Proposal assessment / release revision regressions | 54 passed in 4.68s |
| Native VEX, boundaries, consumers, risk-worker identity and Discovery regressions | 77 passed, 9 skipped in 6.00s; includes shared-image deployment setup, native Compose and release packaging checks |
| Real migration integration | Exit 0: PostgreSQL 16 copy/archive/retirement, foreign-key ordering, trust/content preservation and sequence continuation |
| Independent backup integration, retained previous checkpoint evidence | 6 passed in 41.303s: actual application and intelligence dump/restore, row equality, checksums, legacy and failure handling; not rerun for this generation change |
| Real TLS registry / Cosign / gateway with separate PostgreSQL | Exit 0: signed revision activation, patched tag delivery, digest integrity, service-isolated revocation and signed-manifest tamper denial |
| Compose | Configuration validation passed with placeholder configuration |
| Frontend | No frontend changes; production build not run because this worktree has no installed node_modules |

TLS run evidence: `.test-temp/split-generation-final-20261021/`. Delivered manifest digest: `sha256:6f6d13373d7ce1e4c4bdbe986b46accd63be78da5208a2a2f76aa8878ea26344`. Generated credentials and keys are not committed. TLS/Cosign/registry/database operations are real; scanner, validation and Cyber records in this harness are seeded and do not establish real Copa-to-human-approval acceptance.

## Reproduction

Use disposable PostgreSQL 16 with CREATE DATABASE privilege. From `portal`, set `CATS_TEST_SPLIT_POSTGRES_URL` to its URL and run:

```text
python -m pytest tests/test_split_intelligence_postgres.py tests/test_split_proposal_postgres.py -q -p no:cacheprovider --basetemp=../.test-temp/split-checkpoint
```

Create the basetemp parent first. Tests create and drop isolated databases. Never use production credentials or a production server. Supplemental tests: `test_native_vex.py`, `test_native_vex_boundaries.py`, `test_native_vex_consumers.py`, `test_risk_worker_vex_identity.py`, `test_discovery_deployment_setup.py`, `test_discovery_compose_native.py`, and `test_discovery_release_packaging.py`.

Run `python deploy/intelligence/integration_migrate.py` for migration acceptance. Backup tooling and independent recovery procedures are documented in `docs/database-backups.md`.

For the TLS harness, set `CATS_SPLIT_INTELLIGENCE=1` and `CATS_LIFECYCLE_RUN=split-generation-final-20261021`, run `python tests/lifecycle/prepare.py`, then:

```text
docker compose -f .test-temp/split-generation-final-20261021/compose.json up --abort-on-container-exit --exit-code-from runner
```

## Recovery, limits and incorporation decision

Operational backups remain independent of intelligence data; no consolidation or coordinated point-in-time recovery is introduced. Generation schema is additive. Older images do not enforce the new fence: rollback must retain conservative split-mode exclusions, rather than treating generation-bound evidence as current without verification. Intelligence recovery must initialize the generation schema/triggers before exclusions become available; unavailable or mismatched generations require reassessment.

The new generation recovery tests exercise physical table incarnation changes (VACUUM FULL), stale tokens and reconnect/reassessment behavior. They do not constitute a full database-restore-plus-worker-process-restart acceptance run. Previous actual backup/restore evidence is reported separately above. Complete worker restart acceptance, full intelligence corpus refresh, Docker/Helm CLI pulls in this run, a frontend production build, full release-image rebuild and the entire repository suite remain unverified.

The checkpoint is ready for review and incorporation into the lifecycle branch with approval: split PostgreSQL routing, live native VEX invalidation, proposal assessment, signed activation and gateway revocation passed the targeted checks. This is not full operational or disconnected lifecycle acceptance. Production patch-recipe binding and real disconnected Copa/scanner/validation/human Cyber acceptance remain the next work. No original branch merge or push was performed.
