# CATS follow-up implementation and local testing

Date: 2026-09-28. Repository: `C:\Users\lil-j\Projects\Cyber Hygiene`.
Branch: `fix/helm-classification`. Changes remain uncommitted; earlier changes were preserved. No fetch, pull, push, or commit was performed. This report supersedes the earlier handoff where they differ.

## Status and next step

This is an earlier batch handoff. The portable-service objective and its acceptance criterion have changed; see [SERVICE-DEFINITION-IMPLEMENTATION.md](SERVICE-DEFINITION-IMPLEMENTATION.md) for the current implementation and local checklist. Generated filesystem outputs are intentionally not part of portable service input.

Earlier proposed generated-output transfer is superseded. The current next step is local acceptance against real Helm/OCI, PostgreSQL, browser, and disconnected destination environments.

## Already complete / preserved

The previous XLSX engine, built-in PPSM/POA&M/Asset List exports, immutable historical evidence pages, Helm source classification/shorthand normalization, large archive extraction protections, OIDC changes, scanner discovery, and existing remediation/watchlist/dashboard/validation workflows remain. Historical versions were not expanded into editable operational clones. Current service state remains operational; historical data is retained evidence.

## Implemented

- Version 2 service-state bundle covering 23 explicitly selected relational categories, with ID remapping rather than re-ingestion against current policy.
- Explicit new-service, missing-history, and reusable-metadata replacement import strategies.
- User-bound previews, transactional confirmation, atomic replay prevention, existing-service locking, stale-baseline detection, and bounded expired-preview cleanup.
- Catalog-driven template designer, categorized metadata form, and export population/missing-field preview.
- Semantic spreadsheet validation for IPs, FQDNs, HTTP(S) URLs, boolean fields including critical information, and severity/risk values.
- Serialized additive startup migration and authentication seeding; PostgreSQL advisory-lock paths and SQLite write-lock paths.
- Disk-streamed HTTP Helm downloads, owned-stream cleanup, and OCI temporary-space checks/cleanup.
- Export-side record limits and self-validation, manifest size checking, and validation-artifact reference checks before import confirmation.

## Full service bundle: exact coverage

The ZIP contains `manifest.json` and `service.json`, not thousands of separate evidence files. Manifest version 2 records the application label, exact relational schema fingerprint, exporter/time, service/current version/retained versions, category counts, exclusions/redactions, content byte count, and SHA-256. Checksums detect corruption, **not authenticity**.

Included relational categories:

- Service identity/current settings; executions and retained raw scan payloads.
- Findings, policy findings, finding observations, exceptions, and policy exceptions.
- Service images, editable artifact metadata/revisions, and retained source/value text after sanitization.
- POA&M entries/history, workflow requests, and POA&M change requests.
- Patch/remediation execution records and deployment-validation records.
- Service archive events, reusable metadata, and manual asset/network inventory.
- Service watchlist matches and referenced watchlist entries, plus transfer provenance.

SBOM, dependency, Helm, image, network, and other scan evidence travel where retained in those execution/evidence records. Service-targeted audit events travel as provenance, not newly issued local approvals. This is not a reconstruction of evidence that was never retained.

Excluded:

- Passwords, tokens, detected secret fields/content, private keys, authentication/session material, accounts, role/group assignments, global settings/templates, and unrelated services.
- Worker directories, generated remediation download ZIPs, patched image archives/layers, and worker-only raw reports/files.
- Live processes, cluster ownership, and global watchlist enforcement configuration.

Required local creator references map to the importing user; nullable foreign user references are cleared. Original actors remain provenance. Foreign running jobs are made non-running evidence; validation cluster/cleanup ownership is cleared. Imported watchlist definitions are disabled. Retained approval/status records are not a new authenticated approval by the original actor in the receiving installation.

**Export -> Import does not yet faithfully reconstruct all material service-owned state.** It reconstructs the included sanitized relational state, subject to the deliberate identity/runtime changes above. It does not restore working download links for omitted binaries. Sensitive free text may still remain; heuristic redaction is not a guarantee that arbitrary assessment/source text is secret-free.

## Conflict handling

- **Create:** requires an unused target key; restores included categories with local IDs. Key races fail safely.
- **Add history:** imports missing immutable execution payloads only. Fingerprints prevent repeat imports. Missing executions must precede the target's latest execution, so the target's operational current state is unchanged. No general merge of findings, workflows, or artifacts is attempted.
- **Replace metadata:** replaces the selected category of reusable manual metadata, not arbitrary service state. Existing manual values absent from the bundle are removed. Requires metadata-edit permission, explicit confirmation, and an unchanged preview baseline.
- Legacy version 1 evidence bundles remain new-service-only.

## Template and metadata UI

Open the exchange/template screen, duplicate a built-in or edit a custom template, select a dataset, and configure fields through catalog dropdowns. Add/remove/reorder fields and configure labels, required flags, directions, defaults, column width, sheet/banner, and supported presentation settings. Validate/save, reset/cancel, and enable/disable use the existing declarative backend; no expressions execute.

Reusable metadata is edited through categorized forms. Generated service/execution/export identities are read-only and authoritative. Export previews distinguish automatic, configured, default, and missing values, with required/optional missing information and metadata navigation. Current reusable metadata is not portrayed as a historical metadata snapshot.

## Import hardening and security

Preview does not change domain records. Confirm rechecks ownership, permissions, CSRF, expiration, and target identity. A conditional consumed transition and transaction protect against replay/concurrent confirmation; a service write lock serializes edits and baseline checks. Errors roll back relational changes and preview consumption. Imported workbooks do not grant approval: POA&M remains pending approval.

ZIP validation rejects unexpected/duplicate members, unsafe names/special members, encryption, malformed structure, incompatible schema, bad hashes, oversized content, duplicate IDs, dangling/cross-service references, and invalid field shapes/types. Strict JSON rejects duplicate keys/nonfinite values and enforces depth/node limits. Retained source paths reject traversal/absolute paths. No bundle content is executed or unpickled.

Cleanup deletes only expired preview rows in bounded batches, after the first interval rather than during startup migration. Concurrent-worker cleanup is safe because active previews do not match the delete condition. Concurrency tests use independent SQLite connections and real confirmation routes; they are not a live PostgreSQL substitute.

## PostgreSQL and migrations

Startup schema work is protected by a PostgreSQL transaction advisory lock; SQLite uses `BEGIN IMMEDIATE`. Authentication seed work has a separate serialized transaction. Tests cover SQLite upgrades/rollback and PostgreSQL SQL compilation/advisory-lock calls. **No live PostgreSQL server or multi-process PostgreSQL upgrade was exercised.**

Across the feature batch, new tables include export templates, service metadata, inventory records, workbook/bundle previews, and transfer provenance. POA&M receives nullable `service_version`, `exchange_key`, and `supplemental_fields`. Preview expiry/token indexes support cleanup. A partial unique POA&M exchange-identity index is created only if existing data has no duplicate identities; duplicates are preserved and a warning defers index creation for administrator reconciliation. Back up the database before testing upgrades.

## Helm/resource handling

HTTP archives stream to private temporary files in at most 1 MiB chunks, including responses without Content-Length. Consumers close owned streams on success/failure. Repository index YAML remains bounded in memory.

OCI still uses Helm with existing authentication/custom CA behavior. It uses isolated temporary directories, pre/post free-space checks, compressed-size validation, timeout handling, and cleanup. These checks are not an in-flight disk quota: Helm or concurrent writers can still exhaust a temporary volume. Use deployment-level storage limits for strict enforcement. See `HELM-TRANSFER-NOTES.md`.

Preserved defaults: 512 MiB compressed chart, 1 GiB expanded chart, 10,000 archive members, 180-second Helm pull timeout. Other retained-source/render/evidence/proxy limits still apply. Real large-chart end-to-end behavior and external registries were not tested here.

## Configuration

The following are documented in `.env.example` and passed through `compose.yaml`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `CATS_PUBLIC_HELM_TEMP_RESERVE_BYTES` | `0` | Additional free-space reserve; not a quota |
| `CATS_WORKBOOK_MAX_BYTES` | `20971520` | Workbook upload bytes, 20 MiB |
| `CATS_BUNDLE_MAX_BYTES` | `104857600` | Bundle compressed/service JSON ceiling, 100 MiB |
| `CATS_BUNDLE_MAX_RECORDS` | `100000` | Domain record cap; separate activity cap |
| `CATS_BUNDLE_MAX_JSON_NODES` | `2000000` | Parsed JSON complexity bound |
| `CATS_PREVIEW_CLEANUP_INTERVAL_SECONDS` | `300` | Cleanup interval |
| `CATS_PREVIEW_CLEANUP_BATCH_SIZE` | `100` | Expired rows per table per pass |

Manifest remains bounded to 64 KiB and JSON depth to 40. Bundle export/parse still materializes bounded JSON in memory; this is not a fully streaming relational backup. A single large database JSON field can consume memory before the encoded-byte rejection. Concurrent uploads/imports multiply memory/storage use; there is no global resource quota.

## Automated verification

Previous baseline: 476 portal passed / 1 skipped; 9 explicit Helm graph passed; 10 scanner passed; 2 JavaScript passed.

Final portal result: **543 passed, 1 skipped, 2 existing warnings in 74.56 seconds**. This is 67 additional passing tests over the 476-test baseline, with no failed tests. Run from the repository's `portal` directory:

```powershell
$env:DATABASE_URL='sqlite://'
..\.venv\Scripts\python.exe -m pytest -q --tb=short
```

Additional commands run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest scanning-main/tests -q --tb=short
.\.venv\Scripts\python.exe -m pytest scanning-main/tests/test-helm-graph.py -q --tb=short
node --test portal/tests/elapsed_time.test.js portal/tests/deployment_validation_live.test.js
node --check portal/app/static/exchange-designer.js
git diff --check
```

Scanner: 10 passed. Explicit Helm graph: 9 passed. JavaScript: 2 passed; designer syntax check passed. Targeted final transfer/semantic set: 35 passed. The optional Cosign portal test remains skipped; validator API has two existing lifespan-deprecation warnings. These are automated checks, not a browser or real-infrastructure acceptance run.

## Local acceptance checklist

Use disposable instances/database copies and non-sensitive fixtures. Keep a separate backup; do not test destructive metadata replacement against your only live service.

- [ ] Confirm the intended branch and preserve the uncommitted work before synchronizing with another PC. Remote freshness has not been verified in this batch.
- [ ] Start a fresh instance and an upgraded database copy; check startup/migration logs, then restart with multiple workers. Repeat on your supported PostgreSQL deployment; confirm no duplicate seed identities, partial DDL, or duplicate-identity warnings requiring reconciliation.
- [ ] In the browser, duplicate each built-in template, edit labels/mappings/defaults/order/presentation, add/remove fields, cancel/reset, save, and disable/re-enable. Confirm keyboard usability and that switching datasets offers valid mappings.
- [ ] Edit reusable metadata. Confirm authoritative service/version/export identity cannot be overridden; inspect automatic/configured/default/missing preview categories and required-field behavior.
- [ ] Open generated PPSM, POA&M, and Asset List workbooks in your actual Excel/LibreOffice version. Inspect banners, widths, wrapping, pagination, frozen headers, and literal formula-looking text.
- [ ] Import representative organizational workbooks with real IP/FQDN/URL/date/severity/boolean conventions. Confirm useful field errors, explicit duplicate/conflict choices, and no workbook-driven approval escalation.
- [ ] Export a representative service with multiple executions, manual inventory/metadata, POA&M/workflows, exceptions, artifact revisions, watchlist matches, and validation/remediation records. Review manifest exclusions and inspect sanitized test secrets before moving it offline.
- [ ] Preview/import that bundle into a second compatible disposable installation with a new key. Compare retained relational/evidence counts, current fields, historical views, artifact source text, POA&M/history, and provenance. Expect runtime credentials/group access to require local configuration and omitted generated downloads not to be available.
- [ ] Repeat add-history import twice; confirm deduplication and unchanged current findings/version. Verify newer execution data is rejected by this history-only mode.
- [ ] Preview metadata replacement, inspect the deletion warning, then change target metadata in another browser session; confirmation should reject the stale preview. Re-preview before deliberately replacing.
- [ ] Test with administrator, scoped importer, read-only, and unrelated-service users. Confirm inaccessible services stay inaccessible, revoking permission after preview prevents confirmation, and refreshing/replaying confirmation does not apply twice.
- [ ] Leave a preview past its 30-minute expiry and the cleanup interval in a multi-worker deployment; confirm it cannot be used and expired rows are removed while active previews remain.
- [ ] Test the real large chart through upload, HTTPS, and OCI/shorthand paths, including custom CA/private registry authentication. Verify extraction, retained sources, scan completion, results UI, and memory/temp-disk use—not just successful upload.
- [ ] On an isolated quota-limited temporary volume, exercise interrupted downloads, OCI timeout, and low disk space; confirm useful errors and cleanup. Check reverse-proxy body/time limits separately.
- [ ] Smoke-test existing OIDC login, dashboard, watchlist, remediation, and cluster validation with your actual integrations. Imported historical/runtime evidence must not launch foreign jobs or clean up an unrelated cluster.

## Remaining limitations

This earlier limitation statement is superseded by the input-only portability contract in `SERVICE-DEFINITION-IMPLEMENTATION.md`. Generated output is not required for service portability; real-infrastructure validation and disconnected image supply remain outstanding.
