# Lifecycle / split intelligence compatibility checkpoint

Date: 2026-10-21. Branch: `codex/lifecycle-main-integration`.

## Inputs and isolation

Integrated lifecycle `802624c66ac33c6921119bf53488e22169f617fa` with requested GitHub main `c6280a1432a67df27ce4eb9ac340ed19f065e63d` in merge `8b72ead78a43cc41b35fa183180a0858114c5df8`. No textual conflicts. Corrections are committed after that merge. Original branches were not changed. This checkpoint targets that exact main SHA, not subsequent main changes.

## Runtime findings and corrections

- `container_intelligence.advisory_batch`: an unbound RoutingSession has no `bind.dialect`; select the intelligence engine through `get_bind(mapper=IntelligenceRecord.__mapper__)`.
- `native_vex.current_evaluation`: portal SQL cannot atomically observe trust/revision changes committed in the independent intelligence database. Effective exclusions are disabled conservatively in split mode, including previews. Evidence remains available and findings remain actionable. `evaluate_service` reports the limitation; `cache_token` invalidates previous effective caches; `risk_routes.native_vex_policy` reports configured versus effective availability. This is a functional limitation, not full native VEX compatibility.
- `compose.yaml`: independent intelligence backup service, directory and initialization dependency. `deploy/backup/backup.py` validates five required intelligence tables. Backup documentation and real restore regression coverage updated.
- Lifecycle harness `prepare.py` optionally launches a separate intelligence PostgreSQL service; `gateway.py` uses production RoutingSession and partitioned schema initialization.

## Verification

| Check | Result |
|---|---|
| Split runtime plus native VEX/container intelligence regression | 76 passed in 136.76s; additional policy HTTP case 1 passed |
| Split-specific PostgreSQL cases within above | 17 total; separate application/intelligence databases, routing, rollback, SQL ownership, materialization, freshness, trust changes and conservative exclusions |
| Proposed inventory PostgreSQL suite | 23 passed in 110.19s; dispatch deduplication, evidence ingest, stale/superseded work, cancellation, frozen Cyber evidence, active-state isolation, risk-policy and validation reassessment |
| Real migration integration | Passed PostgreSQL 16 copy/archive/retirement checks, table ordering, trust/content preservation and sequence continuation |
| Backup integration | 6 passed in 41.303s; real application and intelligence dump/restore, row equality, checksums, legacy and failure handling |
| TLS registry / Cosign / gateway harness | Passed with separate PostgreSQL servers and production routing; signed revision activation, patched tag delivery, digest integrity, independent service revocation, tamper denial, manifest/blob/range/referrer handling |
| Concurrent lifecycle work | Same job reused, one durable row, surrounding transaction preserved |
| Compose | Configuration validation passed with placeholder configuration |

TLS harness pulled manifest digest `sha256:6f6d13373d7ce1e4c4bdbe986b46accd63be78da5208a2a2f76aa8878ea26344`. Local result evidence is under `.test-temp/split-main-compat-20261021/`; generated keys and credentials are not committed.

## Reproduction

Use a disposable PostgreSQL 16 server with CREATE DATABASE privilege; never point the test administrator URL at production. From `portal`, set `CATS_TEST_SPLIT_POSTGRES_URL` to its URL and run pytest against `tests/test_split_intelligence_postgres.py` and `tests/test_split_proposal_postgres.py`, using a writable unique `--basetemp`. Each case creates and drops its own databases. Supplemental regression modules are `test_native_vex.py` and `test_container_intelligence.py`.

Run `python deploy/intelligence/integration_migrate.py` for migration acceptance. Backup tests require the bundled backup image and PostgreSQL tooling described in `docs/database-backups.md`.

For TLS lifecycle acceptance set `CATS_SPLIT_INTELLIGENCE=1` and `CATS_LIFECYCLE_RUN=split-main-compat-20261021`, run `python tests/lifecycle/prepare.py`, then `docker compose -f .test-temp/split-main-compat-20261021/compose.json up --abort-on-container-exit --exit-code-from runner`.

## Limits and incorporation decision

This is not full operational acceptance. Native automatic exclusions remain unavailable with split databases until cross-database invalidation is safely designed. No distributed atomic commit is claimed. Risk assessments read current intelligence, but application and intelligence backup snapshots are independent; coordinated point-in-time recovery is not established.

Proposal tests use synthetic scanner payloads. The real TLS/Cosign harness seeds scan, validation and Cyber decision records; it does not establish real Copa-to-scanner-to-human-approval acceptance. Docker/Helm CLI client acceptance, full disconnected patching, production patch-recipe binding, complete production worker execution and full corpus freshness were not verified here. No full release-image build or entire repository regression suite was run for this checkpoint.

The isolated branch is ready for review and further integration testing, but cannot be recommended as full feature-parity acceptance while native VEX exclusions are disabled. Incorporation requires an explicit decision on that limitation or its resolution. No original branch merge or push was performed.
