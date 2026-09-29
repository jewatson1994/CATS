# Service definitions and portable inputs — current implementation

This document supersedes the portable-bundle status and acceptance criteria in `IMPLEMENTATION-HANDOFF.md` and `FOLLOWUP-IMPLEMENTATION-HANDOFF.md`. A portable service is authoritative input for a fresh assessment, not a backup of generated CATS output.

## Architecture and use

The service-scoped **Service definitions / chart catalogs** page accepts a YAML/YML source through a 30-minute preview and explicit confirmation. The retained original is an immutable `ServiceArtifactRevision`; `ServiceArtifact.source_metadata` records adapter, every declared component, per-component state, and a processing run ID. Reprocessing reads that retained original, never silently refetches an updated definition. The parser's `Adapter`/`SourceMapping` registry supports future trusted declarative providers without executing expressions from source documents.

The first adapter is Singularity. It visits every `services.*` member regardless of `enabled`; `enabled` has no effect on CATS ingestion scope or deployment-state inference. Each component is classified as normalized, unsupported, or unresolved. Helm uses `helmRepo.url`, `chartName` (falling back to `repoName`), and exact `version`. OCI uses `ociRepo.url`, `repoName`, and exact `tag`. No fallback to `latest` is allowed. Unsupported and malformed siblings remain visible without stopping usable siblings.

Normalized Helm references feed existing repository discovery and exact chart-version acquisition. OCI references feed the existing Helm OCI pull path. Existing URL classification, bounded chart handling, TLS/custom CA, and scanner code remain the enforcement points; no second registry client or public fallback was added. Acquired original chart sources are retained as chart artifacts. Definition artifact ID, revision, component index, declared source, and chart artifact ID connect definition → component → chart. Scan jobs carry that context into their local result; rendered resource/image source mappings and execution payload connect chart → workload/image → evidence. Reprocess creates a new run and fresh chart acquisition; older retained artifacts/evidence remain historically identifiable.

The page supports upload, non-mutating preview, per-component statuses, search/filter, scan-job links, and deliberate reprocessing. Acquisition, chart identity, render, and scan failure are isolated per component. A failed component does not abort its siblings. A full successful local service scan may mark the service assessed; chart-evidence scans alone do not convert Assessment Pending into an authoritative full-service assessment.

## Portable service contract

Schema v3 bundles include service identity/configuration, image references, retained chart and definition sources/revisions, reusable metadata, manual inventory, human-maintained POA&M/history, and service archive information. Legacy v2 relational bundles are projected onto the same input-only model. Legacy v1 evidence bundles create a pending service and retain old assessment only as informational provenance, never current findings.

Derived findings, scanner executions, observations, dependency/watchlist matches, runtime validation and patch records, worker directories, generated remediation ZIPs, raw reports, and generated image layers are excluded from v3 current-state restoration. Those generated artifacts are not portability blockers. If an image is now an authoritative deployment input, its reference is portable; its image bytes/layers are **not** bundled and must be supplied at the destination when disconnected. Prior imported historical evidence is also not re-exported by default. Imported service/image scan statuses reset to pending/never scanned; foreign job IDs and definition component completion states are cleared. No old finding becomes current. A destination full-service scan using its local databases, policies, watchlists, trust, and scanner versions produces the current assessment.

Import preview and confirmation retain service authorization, CSRF, audit, expiry/replay protection, schema/hash checks, relational reference validation, and transactional rollback. Source YAML is safely parsed with duplicate-key, alias/cycle, depth/node/string/byte limits. Source filenames and source paths are constrained; source content is screened/redacted conservatively. Inspect bundles for sensitive content before transfer. Hashes detect corruption, not authenticity. Runtime credentials, private registry access, and custom trust must be configured locally.

## Configuration and upgrade

New `.env.example` and Compose settings: `CATS_SERVICE_DEFINITION_MAX_BYTES=10485760`, `CATS_SERVICE_DEFINITION_MAX_NODES=200000`, `CATS_SERVICE_DEFINITION_MAX_DEPTH=64`, `CATS_SERVICE_DEFINITION_MAX_STRING_BYTES=1048576`, and `CATS_SERVICE_DEFINITION_MAX_COMPONENTS=1000`. Existing Helm acquisition/retention and bundle limits continue to apply.

No new definition table is required: service artifacts/revisions and bundle previews already model retention and confirmation. The new `services.assessment_status` column defaults to `assessment_pending`; the startup migration marks pre-existing services with executions as assessed. Back up the database before testing upgrades. A live PostgreSQL migration/concurrency run is still required; SQLite automated tests are not a substitute.

## Local acceptance checklist

Use disposable instances and non-sensitive examples.

- [ ] Open a service's **Service definitions / chart catalogs** page. Preview Singularity YAML with Helm, OCI, unsupported, malformed, and `enabled: false` components. Verify all entries appear and that preview alone changes no service artifacts.
- [ ] Confirm once; verify original text retained, second confirmation rejected, exact chart versions acquired, chart artifacts linked, and per-component status/job links visible. Search/filter and reprocess; ensure failed siblings do not stop healthy ones.
- [ ] Test real public Helm repositories and OCI registries, then private repositories with local authentication and custom CA. Check missing versions, digest/name mismatches, render failures, scanner failures, and temporary-file cleanup. Do not infer success from upload alone.
- [ ] Run a full local assessment. Verify evidence source mappings back to chart/component, current findings derived locally, and Assessment Pending clears only after a complete full-service scan.
- [ ] Export a representative service and inspect manifest/source redactions. Import into a second compatible disposable instance; verify definitions, chart sources, image references, manual inventory/metadata/POA&M, and Assessment Pending. Verify no imported current findings, jobs, approvals, or remediation output.
- [ ] Configure destination registry access, custom CA, policies, databases, and any disconnected image bytes separately. Run a fresh destination full-service assessment and compare current results under destination configuration.
- [ ] Exercise legacy v1/v2 bundles. Old evidence may be viewed as informational provenance; it must not populate current findings. Verify role boundaries, CSRF, expired previews, replay, and rollback.
- [ ] Test browser layout/accessibility and real PostgreSQL fresh/upgrade/multi-worker behavior. Smoke-test OIDC, workbook exchange, dashboards, watchlists, remediation, and deployment validation.

## Remaining limitations

No live external Helm/OCI/private-CA, disconnected second-instance, browser UX, or PostgreSQL acceptance run was available here. Bundle compatibility remains exact-schema rather than arbitrary cross-version migration. Secret screening is conservative, not a guarantee that all user-authored source is non-sensitive. Bundles contain image references, not container layers; disconnected imports must supply authoritative image bytes separately. Historical evidence export is not an optional checkbox in v3, and existing-service import remains limited to metadata replacement/read-only history rather than a general service merge.
