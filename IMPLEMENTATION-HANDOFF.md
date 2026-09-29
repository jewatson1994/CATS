# CATS implementation handoff — 2026-09-28

Later work supersedes the portable-bundle limitations below. See [SERVICE-DEFINITION-IMPLEMENTATION.md](SERVICE-DEFINITION-IMPLEMENTATION.md) for the current input-only portability contract, service-definition implementation, and local acceptance checklist. This file records the earlier batch.

## Status

Repository: `C:\Users\lil-j\Projects\Cyber Hygiene`; branch: `fix/helm-classification`.
Changes remain uncommitted. Previous working-tree changes were preserved. No remote fetch, pull, push, or commit was performed during this implementation batch.

Ready for targeted local testing, **not full feature acceptance**. The spreadsheet workflow and Helm fixes are implemented. Historical evidence browsing is deliberately read-only. The portable bundle is an evidence transfer, **not the complete service backup requested**. See remaining limitations before relying on it.

## Already existed

Reused execution raw payloads, service identities, evidence normalization, canonical POA&M entries/history, scoped authorization, audit logs, CSRF protection, ingestion, SQLAlchemy, Jinja, and openpyxl. Existing remediation, dashboard, watchlist, validation, OIDC, and scanner discovery were not replaced. Previous OIDC fixes and scanner archive-limit/hash changes remain in the working tree.

## Implemented

- Shared declarative XLSX engine and PPSM, POA&M, and Asset List templates.
- Catalog-constrained custom templates, ordering, defaults, required-field previews, and presentation settings.
- Reusable service metadata and version-tagged manual inventory.
- Upload/validate/preview/confirm workbook imports with explicit conflict choice, expiration, replay protection, permissions, and audit.
- Historical execution-evidence selection and version-specific spreadsheet exports.
- All-version portable evidence ZIP with validated preview and transactional new-service import.
- Bounded multipart request handling and disk-spooled chart extraction.

## Fixed

The portal's chart downloader dispatched only explicit `oci://` references to Helm. The legitimate shorthand `registry-1.docker.io/bitnamicharts/postgresql:15.5.38` therefore reached HTTP-only validation. The service acquisition route also required a literal OCI prefix.

Both now normalize explicitly supplied chart sources. Registry-qualified shorthand becomes OCI; the trailing tag is passed to Helm as `--version`. HTTP/HTTPS retain their own path, and unsupported schemes are rejected. This does not broaden generic YAML discovery or turn arbitrary registry-looking values into discovered charts. No registry host is hard-coded. Regression coverage includes the exact supplied reference.

Chart extraction rejects traversal, absolute paths, ambiguous paths, duplicate paths, links, malformed archives, and configured limits. Each package stages separately, so a rejected package cannot partially overwrite a valid sibling. Retained-source overflow now raises an explicit error instead of silently returning no sources.

## Large Helm investigation

| Layer | Current behavior / ceiling |
| --- | --- |
| Browser / multipart | No new browser-side size blocker. Framework file spooling is passed directly to extraction rather than reading the whole uploaded chart into bytes. |
| Application request | `CATS_UPLOAD_REQUEST_MAX_BYTES`: 1 GiB total on scan/artifact upload paths; Content-Length and actual received bytes checked. This is aggregate request size, not per chart. |
| Portal archive | `CATS_PUBLIC_MAX_CHART_BYTES`: 512 MiB compressed; `CATS_PUBLIC_MAX_CHART_EXPANDED_BYTES`: 1 GiB expanded; `CATS_PUBLIC_MAX_CHART_MEMBERS`: 10,000. |
| Scanner archive | `HELM_DISCOVERY_MAX_ARCHIVE_BYTES`: 512 MiB; `HELM_DISCOVERY_MAX_ARCHIVE_EXPANDED_BYTES`: 1 GiB; `HELM_DISCOVERY_MAX_ARCHIVE_MEMBERS`: 10,000. Previous streaming hash retained. |
| Temporary storage | Upload spool and extracted chart need disk space. Concurrent requests multiply disk usage; no global quota was added. |
| Remote download | HTTP downloads still use bounded byte buffers. OCI Helm pull writes to disk, then checks size before reading. Oversized OCI downloads can consume disk before the post-pull check. |
| OCI timeout | `CATS_PUBLIC_HELM_PULL_TIMEOUT`: 180 seconds. Existing whole-job timeouts still apply. |
| Editable retained sources | `CATS_ARTIFACT_SOURCE_MAX_BYTES`: 100 MiB total; individual editable text validation remains 2 MiB. Archive acceptance does not imply every source can be retained/editable. |
| Evidence ingestion | `CATS_INGEST_MAX_SOURCE_FILES`: 5,000; `CATS_INGEST_MAX_SOURCE_BYTES`: 100 MiB. Pipeline JSON request limit `CATS_PIPELINE_MAX_REQUEST_BYTES`: 16 MiB. These remain separate from archive size. |
| Deployment validation | Existing separate source/render/command-output limits remain, including 100 MiB sources and 20 MiB render output. |
| Reverse proxy / infrastructure | Deployment-specific limits were not verified. Configure any proxy/body/time limits and temporary-volume capacity consistently. |

A synthetic on-disk archive exceeding 183 MiB passed default extraction. A real ~183 MB chart **should pass the archive upload/extraction limits** if expanded size and member count are safe. This is **not proof of end-to-end ingestion/rendering/results**: retained text size, individual text size, JSON evidence size, Helm execution, timeouts, storage, and external proxy settings can still prevent completion. Helm and Docker were not found on this PC's command path; the real archive was not supplied.

The total request ceiling also applies to other files submitted through these shared scan/artifact routes; it can be stricter than a separate image-archive limit. Adjust deliberately when testing combined uploads.

## Export architecture

`ExportTemplate` stores custom definitions; built-ins use the same interpreter. Definitions select a dataset and catalog field mappings, metadata mappings, import/export direction, defaults, required flags, column order/width, sheet name, banner, colors, and row height. No template code or expressions execute.

Resolution favors selected-version scan data, then reusable metadata/manual supplements, then configured defaults. Generated identity fields are authoritative. Missing required fields are shown before export; templates may block export or require explicit acknowledgement. Workbooks use title/metadata rows, styled headers, wrapping, frozen panes, filters, and landscape print settings. Formula-looking strings are emitted as literal strings.

Reusable metadata is current service-level metadata, **not a historical snapshot**; the UI states this. Template and metadata management currently use validated JSON editors rather than a visual form designer.

## Built-in templates

- **PPSM:** port, protocol, data service, boundary, FQDN, purpose, row number. Normalized network evidence supplies known ports/protocols; unknown descriptive fields need manual inventory or future richer adapters.
- **POA&M:** 22 columns covering identifier, description, controls, ownership/resources, milestones/dates, source/status, severity, mitigation, threat/likelihood/impact, residual risk, recommendations. Findings and policy evidence populate available scanner facts. Version-tagged canonical POA&M entries supply manual supplements. Imported status never grants approval.
- **Asset List:** 19 columns covering identity/type, addresses, public exposure, virtualization, manufacturer/model/serial, version/memory/location, approval/POC, and critical information. Explicit asset evidence and discovered images provide available facts; unknown operational asset properties remain unresolved.

Service name/version, owner/POC when present, export time, and exporting user auto-populate. Classification, phone/email when unavailable, organizational registration, review details, costs, and other unavailable fields depend on reusable metadata/defaults. No missing values are fabricated. Spreadsheet validation and physical Excel presentation still need manual review.

## Import architecture

XLSX parsing uses read-only openpyxl without evaluating formulas. Limits: 20 MiB compressed, 100 MiB expanded, 2,000 ZIP members, 10,000 worksheet rows, 100 columns, and 8,000 characters per cell. Required headers/values, duplicate identities, formulas, PPSM ports/protocols, and POA&M dates are checked. Extra columns are reported, not silently mapped.

Preview stores a 30-minute user/service/version-bound token and current dataset fingerprint. Confirmation rejects invalid, expired, replayed, or stale previews and requires explicit skip/update conflict choice. No canonical rows are changed during preview. Confirmation writes all rows and audit in one database transaction. Scan evidence stays authoritative; manual values fill gaps. POA&M writes use existing canonical entries/history and reset changed entries to pending approval. Inventory records are version-scoped.

There is not yet exhaustive semantic validation for every optional asset field. Concurrent confirmations and retention/cleanup of expired workbook previews warrant additional hardening before broad deployment.

## Service versions

Version membership comes from each immutable execution payload's `service.version`. Historical views select only matching executions. Spreadsheet datasets use the latest full service execution in that version, falling back to a matching execution if no full service scan exists. Manual inventory/POA&M imports include an explicit version.

Open **History & Versions** from the service page, select a version, and use its exchange link. The historical page shows read-only execution evidence; it is not a complete recreation of every current-service tab. Explicit historical requests to the old current-state XLSX exporter are rejected rather than silently exporting current state.

Legacy unversioned POA&M records are preserved but omitted from version-specific spreadsheets. Their historical membership cannot safely be inferred. More recent incremental image scans are not merged into a selected full execution snapshot. Historical approvals/remediation/artifact revisions require additional versioned storage, not inference from present-day state.

## Service bundle

Format: ZIP containing exactly `manifest.json` and `evidence.json`; format ID `cats-evidence-bundle`, schema version 1. Manifest describes service, versions, exclusions, byte count, and SHA-256. Limits: 100 MiB compressed/expanded, 64 KiB manifest, 1,000 executions.

Transfers validated scan payloads across versions, including finding/policy/SBOM evidence. Excludes source files, values files, entire service overview, freeform finding evidence, editable revisions, approval/remediation history, manual metadata/inventory, templates, account/role/session data, and global configuration/credentials. Remaining assessment text can still contain sensitive information: **this is not a secret-free guarantee**. Review content before moving it. Hashes detect corruption, not authenticity.

Importer rejects unexpected members, unsafe paths, duplicate members/execution IDs, malformed/unsupported schema, and checksum mismatch. Preview writes no service. Confirmation requires explicit acknowledgement, imports chronologically with new execution IDs, and commits as one transaction. An injected second-execution failure verified rollback. Existing target keys are rejected; choose a new key. Merge/replace/version-conflict resolution against existing services is not implemented.

**Do not use this bundle as a full backup or disaster-recovery mechanism.** The requested complete service transfer remains unfinished.

## Permissions

Added `template.view`, `template.manage`, `metadata.view`, `metadata.edit`, `ppsm.import`, `ppsm.export`, `poam.import`, `poam.export`, `assets.import`, `assets.export`, `bundle.import`, `bundle.export`.

Dataset/metadata/bundle-export routes enforce service-scoped authorization; history requires service viewing. Template administration and new-service bundle import are global permissions. Mutating forms require CSRF; actions record audit events. Administrators receive the new capabilities; other built-in roles were not automatically broadened. Assign granular permissions intentionally for non-admin testing.

## Migrations/configuration

Startup follows the existing create-all deployment model: new template, metadata, inventory, and preview tables are created; an additive migration adds nullable `service_version`, `exchange_key`, and `supplemental_fields` to `poam_entries`. Existing rows remain intact. Idempotence and preservation are tested on SQLite; PostgreSQL upgrade execution was not tested here. Back up the database and test upgrade in a copy before production, especially with simultaneous worker startup.

New Helm/request settings and defaults are exposed in `.env.example` and `compose.yaml`; see the size table above. No public-network fallback or new online dependency was added to exchange. Workbook/bundle structural limits currently live in code, not environment settings. Database preview storage needs an operational retention policy; automated expiry deletion was not added.

## Tests

New files: `portal/tests/test_helm_ingestion.py`, `portal/tests/test_exchange.py`, and `portal/tests/test_service_bundle.py`. Existing previous-pass OIDC/scanner test changes were preserved, not weakened.

PowerShell commands (from repository root except the first, run from `portal`):

```powershell
$env:DATABASE_URL='sqlite://'; ..\.venv\Scripts\python.exe -m pytest tests -q -rs
.\.venv\Scripts\python.exe -m pytest scanning-main/tests/test-helm-graph.py -q
.\.venv\Scripts\python.exe -m pytest scanning-main/tests -q
node --test portal/tests/elapsed_time.test.js portal/tests/deployment_validation_live.test.js
git diff --check
```

Final results: portal **476 passed, 1 skipped** (52.65 seconds); explicit Helm graph **9 passed**; default scanner collection **10 passed**; JavaScript **2 passed**; whitespace check passed (only an existing Windows line-ending conversion warning). Portal emitted two FastAPI startup-event deprecation warnings. The skipped test requires `CATS_TEST_COSIGN` for real Cosign key validation.

The explicit Helm graph command matters because the default scanner collection does not pick up its hyphenated filename. Scanner shell/integration tests and real registry/container scans were not run on this Windows environment.

## Manual local testing

Use a disposable database/storage copy first. Keep a database and artifact backup before startup migration.

- [ ] Start the updated application and check startup/migration logs. Confirm existing services, roles, findings, remediation, watchlist, and OIDC behavior remain intact.
- [ ] Upload the real ~183 MB `.tgz` through the browser. Follow upload, extraction, scanner, Helm rendering, and final findings/SBOM/network evidence. Record archive size, expanded size, member count, retained text size, duration, memory/disk peaks, and any proxy limit. Do not count extraction alone as success.
- [ ] Test an intentionally over-limit chart, a malformed chart, and mixed valid/invalid siblings. Confirm useful rejection messages and intact valid results.
- [ ] Pull `registry-1.docker.io/bitnamicharts/postgresql:15.5.38` and its explicit `oci://` equivalent using available registry credentials/network policy. Confirm Helm receives the version correctly. If upstream no longer serves that tag, distinguish registry availability from classification failure.
- [ ] Test HTTP/HTTPS repository/chart inputs and local charts. Confirm unrelated documentation, API, OIDC, and registry-looking YAML values do not become discovered charts.
- [ ] In a real service, open spreadsheet exchange. Preview PPSM, POA&M, and Asset List; verify known data is populated and missing fields are visible. Configure reusable metadata once and confirm reuse.
- [ ] Open all three exported workbooks in Excel or LibreOffice. Check columns/order, literal formula-looking text, metadata, classification/banner, wrapping, filters, and print layout.
- [ ] Create a custom template from a built-in. Reorder columns, change widths/defaults, require a missing field, test warning versus blocked export, and disable it.
- [ ] Import each workbook. Review mapped/ignored columns, new rows, conflicts, and validation errors. Cancel once and verify no data change; then confirm skip/update deliberately. Verify replay rejection and pending POA&M approval status.
- [ ] Try invalid port/protocol/date, missing headers, extra columns, and duplicate rows. Verify unrelated services are unchanged.
- [ ] Scan versions 1.4 and 1.5 with intentionally different findings, SBOM, and ports. Switch history and all three exports. Verify no 1.5 scan evidence appears in 1.4. Note that reusable metadata remains current and historical approvals are not represented.
- [ ] Export a multi-version evidence bundle. Inspect manifest versions/exclusions and sensitive contents. Do not expect source files or governance history.
- [ ] In a clean/disposable CATS environment, preview and import under a new key. Verify both versions and their scan evidence. Reuse an existing target key and tamper with the ZIP to verify rejection without partial services.
- [ ] Test non-admin users: allowed service, another service, group scope, missing import/export capability, template admin, metadata edit, and invalid CSRF. Confirm denied operations do not mutate data.

## Remaining limitations / next work

1. Full service bundle completeness and existing-service merge/version-conflict workflows remain unimplemented. The shipped evidence-only subset is explicitly labeled throughout.
2. Historical views are isolated evidence views, not full historical UI/approval/remediation/artifact reconstruction. Legacy POA&M version attribution needs an explicit migration policy.
3. Real 183 MB end-to-end and real OCI acceptance remain unverified. Large retained text/evidence can hit independent limits even when archive extraction succeeds.
4. Asset discovery adapters and optional-field validation are basic; richer network/asset fields are not always available from normalization. Incremental scans are not merged into full version snapshots.
5. Template/metadata editing is functional JSON UI, not a polished visual designer. Excel appearance needs human verification.
6. PostgreSQL migration/concurrency, simultaneous confirmations, preview cleanup, global temporary-storage quotas, and HTTP/OCI buffering need further hardening and operational tests.

Next step: run the manual checklist on a disposable local deployment, then complete full bundle/history semantics before accepting the entire requested batch.
