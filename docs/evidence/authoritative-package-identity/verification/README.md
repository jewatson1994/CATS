# Verification record

Worktree: `feature/risk-profiles-vex`, based on `745ffd99172bd46ab2a67d2f5a6df54465e1b320`. Tests and release image cover the final runtime source hashes in [offline-package.json](offline-package.json). PostgreSQL fixture corrections and their baseline reproduction are recorded separately.

- [Test summary](test-summary.json) and [backend JUnit](backend.xml): 750 passed, 16 opt-in skips; all 21 classification cases passed.
- [Release identity](release.json), [packaged-source manifest](release-source-manifest.json), [offline identity/payload results](offline-package.json).
- [Bundled toolchain output](offline-toolchain.log), [offline Helm output](offline-helm.log), [actual build/check commands](release-commands.txt).
- [Final validation-order regressions](validation-order.xml): 361 focused cases passed, covering contradictory installed evidence obscured by incomplete or malformed metadata, sibling record ordering, and missing versus contradictory fields. A separate read-only review checked 327 resolver input combinations with no mismatches. The final formatting pass removed trailing blank lines only and verified identical Python syntax trees; the complete backend suite and release checks were rerun against those final bytes.
- Retained executable verification helpers: [identity/package check](offline-release-check.py), [Helm check](offline-helm-check.sh).

## Test commands

Run from the feature worktree using the existing project `.venv` Python and installed frontend dependencies; no dependency changes were made. Use a fresh temporary directory for each test run. The ordinary backend run has no opt-in PostgreSQL URL; PostgreSQL checks use an isolated disposable database separately.

```powershell
$env:PYTHONPATH = 'portal'
$taskTests = Get-ChildItem portal/tests/test_*.py | Where-Object {
    $_.Name -match '^test_(risk_|vex_|embedded_|verify_embedded|packaged_risk|container_intelligence|package_identity|finding_classification)'
} | ForEach-Object { $_.FullName }
& $python -m pytest @taskTests -q -p no:cacheprovider --basetemp $freshTemporaryPath --junitxml $junitPath
```

From `portal/frontend`, with the bundled pnpm runtime:

```text
pnpm test
pnpm typecheck
pnpm exec eslint src/features/risk_coverage.tsx src/features/risk_coverage.test.tsx
```

Full `pnpm lint` reports two existing unused variables in unchanged `src/features/remediations.tsx:242`. The edited files pass lint. Frontend tests produce existing nonfatal jsdom `scrollTo` warnings.

## Scanner verification

[Scanner JUnit](scanner.xml): 20 passed in 10.25 s. From the feature worktree, using the same project Python:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:JQ_DOCKER_IMAGE = 'catscan-base:local'
& $python -m pytest -q scanning-main/tests/test_report_to_portal.py scanning-main/tests/test_sbom_identity.py scanning-main/tests/test_sbom_formats.py scanning-main/tests/test_sbom_components.py --basetemp $freshTemporaryPath --junitxml $junitPath
```

The final run used `cats-scanner-identity-final-20261020-r2` under the Windows temporary directory. Shell syntax was checked separately.

## PostgreSQL fixture verification

[Final PostgreSQL report](postgresql.json): 30 passed on PostgreSQL 16.15 / Python 3.12.14 in a new disposable database. Risk/VEX (13), package membership/import/upgrade (9), durable-job leasing (1), export snapshot consistency (1), and service bundles (6) passed. SQLite service bundles also passed separately (6 cases in 3.67 s).

[Unchanged baseline reproduction](postgresql-baseline.json): extracted `745ffd9` produced 13 passed, two failures and one setup error. Both durable/export fixtures sent raw trigger DDL to the public schema even though SQLAlchemy tables used a translated test schema, causing `DuplicateObject` for `risk_policy_versions_immutable`. The service-bundle teardown lacked PostgreSQL-assigned names for cyclic foreign-key constraints. Relevant fixtures and production model files matched the baseline byte for byte before correction.

The three fixture-only changes set each isolated connection's `search_path`, reflect actual constraint names before teardown, and permit the explicit test database URL in the shared test setup. Original assertions remain unchanged. Both disposable databases were removed; the retained database remained at 44,013 documents and 5,773,747 statements. This smaller integration-test database is separate from the 29.2-million-statement real audit corpus.

Set `PYTHONPATH=portal` and point both `CATS_TEST_DATABASE_URL` and `CATS_TEST_POSTGRES_URL` to the same newly created disposable `postgresql+psycopg` database. These test fixtures recreate tables: never use the retained audit database. Credentials are not recorded in this evidence. With the existing project Python, run:

```powershell
& $python -m pytest -q --tb=short portal/tests/test_risk_vex_postgres.py portal/tests/test_intelligence_membership.py portal/tests/test_durable_jobs_postgres.py portal/tests/test_export_jobs_postgres.py portal/tests/test_service_bundle.py --basetemp $freshTemporaryPath
```

For the separate SQLite run, unset both database variables and run:

```powershell
& $python -m pytest -q portal/tests/test_service_bundle.py --basetemp $freshTemporaryPath
```

The actual PostgreSQL run used disposable database `cats_identity_verify_20261020_914b950420` and temporary directory `cats-identity-pg-914b950420`; the SQLite run used `cats-identity-fixture-sqlite-20261020-0630`, under the Windows temporary directory. Replays should use new names.

## Offline reproduction

Build command and exact original mount paths are in `release-commands.txt`. Its temporary helpers and manifest are retained here so the checks can be rerun by substituting this directory for those original temporary paths. Mount `offline-release-check.py` as `/checks/check.py`, `release-source-manifest.json` as `/checks/source-manifest.json`, and `scanning-main/tests/fixtures/identity/retained-installed-packages.json` as `/checks/retained-installed-packages.json`. Use the documented image tag, `--network none`, and `/opt/cats-venv/bin/python` entrypoint. The Helm helper expects the existing umbrella chart fixture mounted as `/checks/umbrella`.

The release checks verify packaged backend/scanner files; the frontend is covered by its separate tests, typecheck and release build. The existing signed corpus was verified and reused. Full corpus cold import and real Trivy vulnerability scanning were not repeated. No deployment, push or merge was performed.
