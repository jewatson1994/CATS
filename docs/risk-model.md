# Risk profile calculation and governance

Risk profiles are a visual, explanatory read model. They do not change Finding.active, scanner severity, compliance, exceptions, admission, remediation, or existing approval authority. Recommendations, delegated approvals and AO decisions are independent immutable events; none changes the calculated score.

## Calculation

The built-in model uses severity contributions unknown 40, negligible 5, low 15, medium 35, high 65, critical 85. Add EPSS probability times 15, up to 10 for episode age over 90 days, and 5 when a fix exists. A current exception multiplies by 1 by default. A precisely applicable trusted, current VEX not_affected statement multiplies by 0.25 only while catalog intelligence and complete scan evidence are current. Unknown severity, invalid or missing EPSS/KEV, missing VEX, conflicting, stale, withdrawn or unverified VEX adds 10 and applies a floor of 40. Finally KEV membership imposes a minimum of 95 regardless of VEX. Clamp to 0–100 and round to two decimals. Bands begin at 0, 30, 60 and 85. Configurations validate finite numeric bounds, increasing thresholds, labels, and exact nested keys. The calculation is reproducible from the saved configuration and observation inputs.

Each observation in the latest execution is evaluated independently, using stored exact package identity where available. No identity is invented from a package name. Only after that evaluation does a CVE aggregate take the maximum observation score. An active finding absent from the latest execution receives uncertain treatment while preserving known KEV membership and episode age. A finding cannot be suppressed across all packages/images by one matching VEX statement. VEX fixed is retained as evidence without automatically declaring a scanner observation resolved.

## Versioning and inheritance

Named policies have immutable numbered versions with content digests and optional clone ancestry. Assignment changes append history; a null assignment removes that scope's override. Resolution proceeds service, its single owning group and ancestor groups, default, then built-in model. Conflicting ownership and cycles fail explicitly. Group inheritance preserves the existing single owning-group model.

Assessments preserve exact configuration, assignment event, source execution, catalog content identity and metadata, classification build identity, VEX source/document identity, capture time, validity boundary, individual observations and grouped scores. Catalog dates are mandatory to claim fresh intelligence. The max_age_hours policy setting (default 24 hours) bounds both catalog age and scan age, as well as assessment lifetime. Missing, incomplete, future-dated or older scans force uncertainty and disable score reductions. Expiry is the earliest model maximum age, scan freshness boundary, classification exception boundary, catalog age boundary, or applicable VEX validity boundary. Historical records remain readable. Current readers mark changed execution, policy, catalogs, VEX, classification or expiry as stale. Missing/stale intelligence or scan evidence remains explicit uncertainty, never an implicit zero-risk result. No-scan summaries carry assessment_state=no_scan and must not be presented as assurance.

## Durable operation and limits

Run `python -m app.risk_worker` in the portal environment with the same database and catalog mounts as the web application. This worker claims only `risk_assessment` jobs using the existing durable queue leases/retries/heartbeats. API requests enqueue work; previews use a configuration in the job payload and are never selected as the active assessment. The result gives assessment_id, service_id, preview and summary. Import risk_models before the existing metadata creation step to install the additive tables and append-only guards.

Observation queries use keyset batches of 250 with a hard limit of 100,000 observations per service assessment. VEX batch queries are bounded by the observation batch. The final stored details JSON is bounded by that limit but is not a constant-memory format. This release does not claim million-observation service support. Summary readers should call latest_assessment(include_details=False), which defers the details JSON. Explicit assessment detail and historical export reads may load the complete bounded document. Configuration/classification refresh costs depend on existing classification machinery. No remote intelligence fetch occurs during calculation.

## Manual decisions

A decision references a saved non-preview assessment and records recommendation/delegated_approval/ao_decision separately, plus accept/mitigate/reject/reassess, mission impact, controls, justification, evidence references, reviewer, authenticated actor and future expiry. The policy's configurable authority label is frozen in the decision payload. HTTP callers enforce distinct role permissions; an authority label does not grant permission. Expired decisions and decisions based on stale or superseded assessments require reassessment. Record a new decision to supersede one; never edit history. ORM and SQLite/PostgreSQL database triggers reject updates/deletes on policy versions, assignments, assessments and decisions. Administrative database privileges can always alter/drop schema; these guards are application integrity, not a cryptographic audit ledger.

## Verification

Focused tests cover malformed configurations, KEV precedence, conservative uncertainty, group inheritance, assignment history, direct SQL immutability, decision evidence/service isolation, and mixed applicability across two observations of one CVE. A local pure-function benchmark evaluated 10,000 observations in 0.015 seconds. This excludes SQL, VEX queries, queueing, storage and rendering, and is not a fleet-scale performance claim. PostgreSQL trigger execution is covered by the opt-in integration checks below; end-to-end production workload performance remains unmeasured.


### SQL-backed batch benchmark

Run `python scripts/benchmark-risk-vex.py` with the portal environment. The script creates and disposes an isolated in-memory SQLite database; it does not use the application database, fetch feeds or modify findings outside its synthetic fixture. It verifies result counts/applicability and prints timing/query counts without timing assertions.

Measured locally on 2026-10-19 (Windows 11, Python 3.12.14, SQLite 3.53.1): 10 signed OpenVEX documents, 10,000 stored statements, 1,000 distinct CVEs/findings and 1,000 observations. Each CVE has 10 version-specific statements, exactly one matching the observation. Signed snapshot verification/ingestion of the 2,243,293-byte envelope took 0.4305 seconds, separately from fixture setup and the measured assessment loop.

Three fresh-session runs read observations in four 250-row keyset batches, query VEX in the database, perform exact matching and scoring, then serialize and commit one assessment. Elapsed times were 0.7376, 0.9031 and 1.0890 seconds. Each run executed 13 SELECTs (five observation queries including the terminal empty batch, and eight VEX queries) plus one assessment INSERT. The stored details payload was approximately 764 KB. This demonstrates bounded query count across these batches, including SQL/ORM matching and JSON persistence, beyond the pure-function microbenchmark.

This is a small synthetic core-path measurement, not an end-to-end worker or production capacity claim. It excludes classification rebuilds, catalog loading, queue/lease coordination, HTTP rendering, network access, disk-backed database I/O and concurrent writers. SQLite in-memory timing does not establish PostgreSQL performance or worst-case behavior for many source revisions, skewed CVE distributions or 100,000 observations. The benchmark deliberately reports those limits rather than extrapolating fleet throughput.

### PostgreSQL integration verification

`portal/tests/test_risk_vex_postgres.py` is opt-in: set `CATS_TEST_POSTGRES_URL`
to a PostgreSQL test database URL using the `postgresql+psycopg` driver and run
that test file from `portal`. The database user must be able to create schemas;
each case creates a randomly named schema and drops only that schema afterward.
Without the variable, these tests skip.

Verified on PostgreSQL 16 (isolated `postgres:16-alpine` container): ten cases
passed, including repeated `create_all`, policy inheritance/version writes,
manual decisions, assessment materialization for fresh/stale/incomplete scans,
VEX exact matching and conflict handling, authenticated snapshot import and
idempotency, and raw SQL UPDATE/DELETE rejection on all six immutable history
tables. Test schemas and the temporary container were removed afterward.
