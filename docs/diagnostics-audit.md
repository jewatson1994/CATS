# Diagnostics overhaul: boundary audit and verification

This audit covers application failure boundaries and their presentation/persistence paths. Existing business policy and security checks remain authoritative. Not every defensive parser fallback is an operational failure requiring an event.

## Plan and audit findings

Implementation follows five layers: portable schema/redaction/classification; HTTP correlation and bounded database history; retained worker diagnostics and recovery; reusable GUI details and the administrative center; regression/security tests and operating documentation.

| Area | Previous gap | Implemented boundary / evidence |
| --- | --- | --- |
| Portal API/frontend | HTTP details collapsed into generic request failures | Common middleware/exception handlers, `api.ts`, `ErrorDetails`, bounded notifications and error boundary |
| Ingestion/ownership | Existing ownerless service returned 409 whose explanation was lost | Missing/multiple-owner messages, resource/stage context, real pipeline regression and frontend 409 tests |
| Scan worker | Tool/protocol errors and lease loss lacked common retained evidence | Authenticated failure envelope, scan payload diagnostic, lease recovery and public result projection |
| Patch worker | Stage/tool context remained in logs or volatile state | State/result-file diagnostics, stage/tool metadata and portal result projection |
| Risk worker | Generic handler failures required worker logs | Durable execution captures original exception, worker/job/stage/correlation and terminal/retry state |
| Remediation | Nested delivery, image patch and validation failures lost context | Durable execution plus retained validation/delivery diagnostics and report projections |
| Provisioning | Operation errors and recovered leases lacked common evidence | Attempt JSON records phase, worker identity and last successful phase; public DTO projection |
| Validator | Setup/transport/scheduling exceptions became generic failed runs | Retained run diagnostic, terminal phase, configuration-test events and service validation display |
| OCI proxy | Public denial intentionally opaque; admin decisions hard to locate | Separate administrative policy evidence and opaque client references for both enforcement modes |
| Publication/export | Optional catalog/attachment/reference failures could be swallowed | Partial-failure events linked to resources/jobs; workflow outcomes preserved |
| Discovery | Partial inventory lacked common troubleshooting evidence | Existing adapter inventory retained, partial-result events and durable failures |
| Database | Raw SQL exceptions can include statements and parameters | Type-aware classification and safe chain projection without SQL parameters |
| Background jobs | Crashes and stale/null leases lacked actionable evidence | Durable/scan/provisioning recovery, bounded retry exhaustion and opt-in runtime ceiling |
| Registries | TLS/auth/missing-content errors scattered across strings | Common deterministic classification, connection-test events, tool/proxy diagnostics |
| Authentication/authorization | Generic or sensitive provider failures | Permission checks preserved; OIDC stage/reason allowlists; two global capabilities required for center |
| Ownership/approvals | Constraint failures inconsistently explained | Ownership classification and approval guidance; approval guards unchanged |
| Replica/offline bundles | Per-release failures and unavailable items difficult to inspect | Partial-failure events, bounded embedded reports, durable terminal failures and export/verification evidence |
| Maintenance | Optional cleanup/monitoring failures discarded | Failure capture without replacing the primary operation outcome |

Deliberate fallbacks remain for malformed optional metadata, existing structured validation/cleanup results, and reporting failure itself. Reporting never recursively diagnoses its own storage failure. Authentication omits raw provider responses and claims. Existing detailed validation evidence is preserved; the new envelope follows the common public/admin policy.

## Verification and limits

Tests exercise classification, redaction, bounded inputs, exception chains, database parameter exclusion, migration/index idempotence, retention, storage failure, middleware exceptions, successful streaming, public/admin projections, scoped authorization, ownership 409 handling, refresh persistence, worker failures/recovery, OCI policy evidence, replica failures, validation/remediation reports, copy/export and frontend request handling.

Recorded verification on 2026-11-16 (overlapping suites; counts are not additive):

- Backend integration, request/ownership, OIDC, deployment validation, remediation delivery/validation and frontend projection regressions: **212 passed**.
- Updated HTTP/administrative configuration and OIDC diagnostics: **85 passed**.
- Updated daily security-data refresh, diagnostic model, deployment validation and integration: **105 passed**.
- Final portable model checks, including distinguishing exhausted disk capacity from an unavailable disk measurement: **22 passed**.
- Final durable worker/concurrency, scan coordination/security/disk-budget, provisioning, managed validator, patch, remediation projection/delivery suites: **227 passed, 1 skipped**.
- OCI proxy, replica synchronization, release export/publication and new diagnostic boundary suites: **133 passed**; strengthened policy-mode checks: **6 passed**.
- Complete frontend suite: **604 passed across 76 files**. After live GUI testing identified an incorrect outer-frame source label, the display was corrected to select the deepest originating exception frame; focused diagnostic suites: **19 passed**.
- Frontend production build/typecheck and touched-file ESLint passed. Python compilation and scoped whitespace checks passed.

The initial automated run used isolated temporary databases. Its skipped test requires `TEST_DATABASE_URL` pointing to PostgreSQL for the existing scan-job additive migration; live acceptance results are recorded below.

## Live acceptance follow-up

An isolated current-source portal and compiled frontend were run against
PostgreSQL 16 at `http://127.0.0.1:18089`. Browser verification passed for real
administrator/viewer login, center navigation, persisted HTTP 409 ownership
details, reload persistence, worker reports and job links, recurrence, combined
filters, correlation links, empty results, copy/paste, and filtered JSON export.
The fake secret sentinel was absent from copied and exported reports; redaction
markers and useful stage/tool evidence remained. An ordinary viewer was denied
the center and did not receive administrative context.

The ownership failure came from a real pipeline ingestion HTTP request. The
three worker records used for the browser checks are explicitly synthetic GUI
fixtures, not evidence of successful scanner or patch executions. Source display
now identifies `service_ownership.py:10` in the originating exception instead of
the outer framework handler. The fix passed 19 focused frontend tests, touched-file
ESLint, and production build/typecheck.

Reproduction scripts and fixture boundaries are documented in
[`tests/diagnostics/README.md`](../tests/diagnostics/README.md). Browser evidence,
sanitized export, and screenshot are retained under
`.test-temp/diagnostics-gui-20261116/` locally.

Additional live and regression results:

- **124 live PostgreSQL tests passed in 180.82 seconds**, with no skips, after
  correcting two test fixtures. PostgreSQL 16 exercised additive migrations and
  index repair, retention, persistence independent of request rollback, concurrent
  durable-job claims and recovery, scan coordination, authorization, and
  correlation. This includes the scan-job migration previously skipped without
  a PostgreSQL URL. Final JUnit evidence is
  `.test-temp/pg-live-a7d3-final.xml`.
- **16 real HTTP checks passed** after restarting the current-source portal with
  the final fixes. Ordinary form-login sessions exercised the center and all
  diagnostic APIs, administrator/viewer/anonymous access, filters, pagination,
  recurrence, public projection, redaction, no-store headers, correlation, and
  persistence across a new session.
- **12 real external-tool cases passed**, with networking disabled and no Docker
  socket. Syft 1.31.0, Grype 0.98.0, Trivy 0.69.3 (secret scanner), and Dockle
  0.4.15 successfully processed the local Alpine archive. Actual missing input,
  missing Trivy vulnerability database, Copa 0.14.1 offline patch timeout, and
  Syft subprocess timeout failures produced terminal jobs and retained
  diagnostics. All eight expected failures preserved stage, worker, correlation,
  attempt, tool, exit/timeout evidence and cleared leases. The harness exercises
  the command adapter and durable-worker boundary, using temporary SQLite.
- **96 model, durable-job, and patching regressions passed** after the final
  changes. Tool exit/timeout metadata now survives command exceptions; explicit
  missing-input and scanner-database evidence receives specific guidance.
  Subprocess exception projections omit argv and captured output, preventing
  list-form command arguments from leaking credentials. Tests cover both direct
  and wrapped exceptions. The public projection continues to omit technical
  exception details.

Tool evidence is `.test-temp/diagnostics-tools-live/report.json`; regression
JUnit evidence is `.test-temp/diagnostics-final-model-worker.xml`. The initial
tool run lacked a Trivy vulnerability database and BuildKit. The successful
scan and patch paths were subsequently verified below.

### Successful Copa patch and Trivy vulnerability scans

Completed on 2026-11-16 local time (2026-11-17 UTC). A dedicated BuildKit 0.21.1
daemon and Docker 28.5.2 daemon were started in isolated acceptance containers,
with Unix sockets shared only with the test runner. Neither mounted the host
Docker socket nor published a port. Trivy 0.69.3 downloaded the official schema-2
database from `mirror.gcr.io/aquasec/trivy-db:2`, updated
`2026-11-16T18:50:18.311537747Z`. Its SHA-256 was
`c4c65516369d80d1fe4a9ae8667f2721393630107d8d2277a9222def00efd19d` and remained
unchanged between the before/after scans.

**All 6 successful-tool acceptance cases passed:** tool/database preflight,
source image export, Trivy vulnerability scan, Copa 0.14.1 patch, patched image
export, and Trivy rescan of the exported archive. Each case ran through the
current command adapter and durable-job executor, committed `completed` with
100% progress, cleared its lease, and had no error or diagnostic history event.

The fixture was Linux/amd64 Alpine 3.20.0, pinned to manifest-list digest
`sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd`.
Trivy found **72 fixable OS package/CVE findings before patching and 0 after**.
All 14 installed package names remained present; eight affected packages changed:

| Packages | Before | After |
| --- | --- | --- |
| busybox, busybox-binsh, ssl_client | 1.36.1-r28 | 1.36.1-r31 |
| libcrypto3, libssl3 | 3.3.0-r2 | 3.3.7-r0 |
| musl, musl-utils | 1.2.5-r0 | 1.2.5-r4 |
| zlib | 1.3.1-r1 | 1.3.2-r0 |

The output image ID changed. Every removed finding was checked by package/CVE
identity and tied to a package-version change. No synthetic reports,
`--ignore-errors`, or vulnerability suppression were used. **Two additional
scans with `--network none` passed**, reproducing the same 72-to-0 findings and
identical package inventories from the saved archives and cached database.
The patched image also started successfully without networking and ran its
shell and package manager.

The first preflight exposed a harness-only dependency mistake: this CATS image
contains `buildkitd`, but no `buildctl`. The check now records the installed
daemon binary version; the actual Copa patch proves daemon connectivity.
The harness also requires a digest-pinned source and rejects an existing output
tag, preventing stale images from satisfying the success assertions. No
application business logic or security controls required changes. Python
compilation, CLI checks, and PowerShell example parsing passed.

Evidence is retained locally under
`.test-temp/diagnostics-tools-success-20261116/`: `success/report.json`, sanitized
before/after Trivy reports, both image archives, `offline-validation.json`,
`setup.json`, and `buildkit.log`. The initial failed preflight is retained as
`preflight-missing-buildctl.json`. Reproduction and scoped cleanup commands are
in [`tests/diagnostics/README.md`](../tests/diagnostics/README.md).

The disposable BuildKit/Docker containers, their private Docker data, and their
socket volumes were removed after acceptance. The database volume
`cats-diag-success-20261116-trivy-cache` and all host evidence were retained for
reuse. The running GUI acceptance stack was left intact. Work was completed in
the local `main` checkout of the Cyber Hygiene repository; this follow-up changed
the acceptance harness and documentation only. These results preceded publication
to remote `main`. No requested successful-tool checks remain
pending.

Scope: this verifies real Trivy/Copa processes and the diagnostic/durable-job
boundary, using a temporary SQLite store. Copa consumes the real Trivy report;
this does not exercise the complete application patch worker, its Grype-to-native
report conversion, or registry publication. Patch preparation used network
access for the image and package repositories; the two additional vulnerability
scans were fully offline. Trivy correctly warns that this old Alpine fixture is
end-of-life, so zero detected findings is an acceptance result against this
database, not a production security endorsement.

These checks are not a production load test or qualification of site-specific
identity, certificates, worker volumes, registry policy, or validator services.
See [operating and upgrade guidance](diagnostics.md).

## Publication verification — 2026-11-19

The diagnostics implementation, additive migration, regression tests, live
acceptance harnesses, and this report were reconciled onto remote `main`
commit `ec1dd8f` in an isolated checkout. Existing OCI changes were preserved;
unrelated local runtime-agent work was excluded. The original working tree was
left unchanged.

The exact publication candidate passed:

- **272 backend regressions**, with one PostgreSQL-only migration check skipped
  in the SQLite run.
- **124 live PostgreSQL checks**, with no skips, including that migration check.
  The disposable PostgreSQL 16 container was removed after completion.
- **135 OCI proxy, replica synchronization, release export/publication, and
  diagnostic boundary checks**.
- **600 frontend tests across 75 files**, TypeScript checking, the production
  build, and ESLint. This candidate excludes the unrelated runtime feature tests.
- Staged whitespace validation and a dependency/scope review.

Initial native-test attempts encountered Windows test-environment restrictions:
the sandbox blocked the TestClient loopback socket pair, and the existing system
pytest temporary directory was inaccessible. Running with loopback access and a
fresh workspace-local temporary directory resolved both without application
changes. JUnit evidence is retained locally in the publication checkout under
`.test-temp/publish-backend-final.xml` and
`.test-temp/diagnostics-postgres-474e375afa6e/pytest.xml`.

The earlier GUI, HTTP, offline-tool, and successful Trivy/Copa acceptance results
above remain the recorded live acceptance; they were not rerun during publication.
Their application and harness code is included in this candidate. Generated
reports, image archives, caches, credentials, and temporary containers are not
part of the commit.
