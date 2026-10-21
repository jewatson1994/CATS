# Discovery local acceptance — 2026-10-20

Branch: `feature/universal-deployment-discovery`. No push or merge. Singularity artifacts were unavailable.

## Result

Ready for controlled testing in the disconnected environment, subject to importing the matching worker image and qualifying the sandbox on that host. This is not full Singularity acceptance or full Flux-controller parity.

## Implemented in this increment

- Group-authorized supplemental upload UI/API and durable worker processing for missing non-secret values, charts and dependency files.
- Encrypted, bounded, add-only overlays; immutable parent inventory and per-file hash provenance; supplemental retention cleanup.
- Dependency-scoped render reuse across supplemental jobs. Unchanged Helm/Kustomize renders can be reused; Compose uses conservative full-visible-input invalidation.
- Bounded encrypted approved-HTTPS artifact caching with current authorization and digest revalidation.
- Native Compose include/extends/interpolation/profile results take precedence over fallback parsing; preferred default override and canonical custom-tag handling corrected.

## Verification

- All Discovery Python tests: **169 passed, 1 skipped**. The skipped test requires its separate PostgreSQL environment variable; PostgreSQL was exercised by the deployed harness below.
- Existing Compose ingestion/architecture, scanner coordination/security, offline schema and Compose frontend compatibility: **160 passed**.
- Discovery frontend: **5 tests passed**, TypeScript check passed.
- Worker image `cats-discovery:incremental` built successfully from this branch.
- Frontend production build and changed-file lint passed. Existing bundler warnings concern runtime app.css and a mixed static/dynamic Risk Intelligence import.
- Reproducible deployed harness: `scripts/test-discovery-deployed.ps1 -Image cats-discovery:incremental`.
- Real non-root, read-only, capability-dropped worker with approved seccomp, CPU/memory/PID limits and disposable PostgreSQL: passed.
- Native renderer versions: Helm v4.2.3, Kustomize v5.8.1, Compose 2.39.4.
- Missing Compose env_file produced incomplete evidence. Real multipart supplemental submission created a separate worker job and a complete inventory using native include, extends, env_file and selected profile semantics. Sensitive sentinel was absent from evidence.
- Original content hash remained unchanged. PostgreSQL rejected inventory UPDATE and DELETE.
- Supplemental run: 8 files, 3 roots, 6 nodes, 5 image records; **2 cache hits** for unchanged Helm/Kustomize and **1 miss** for affected Compose; 2 dependency-scoped renders.
- Confirmation produced the existing durable Scan job and its input archive with ownership/inventory linkage. Repeated handoff was idempotent.
- Disposable containers, network and volume were removed after testing.

## Verification boundaries and remaining limits

- The harness supplies an authenticated context and initially submits through the durable queue. It exercises the actual multipart supplemental route, worker, database and Scan admission, but not browser login or the initial HTTP upload.
- Scan handoff was verified; downstream vulnerability scanning, registry pulls, SBOM generation and remediation were not executed in this acceptance run.
- No real Singularity archive, its two unresolved charts, enterprise mirrors, credentials or disconnected-host TLS were available.
- Caching is opt-in, freezes potentially nondeterministic native output, and uses temporary worker storage. Parsing/dependency traversal still rerun; there is no persistent minimal dependency scheduler.
- Supplemental inputs are add-only, with a maximum of eight steps. Replacing an input requires a new source bundle. Non-secret acknowledgement is not a secret detector.
- Unknown Flux/controller semantics remain incomplete. Native custom tags in noncanonical included Compose filenames may still cause conservative incomplete diagnostics.
- Local measurements above demonstrate selective work reuse, not production-scale throughput or capacity.

## Disconnected test next step

Import/build the matching Discovery worker and deploy with the approved sandbox profile, encryption key, upload storage and exact-version local artifact manifest. Enable render caching only if preserving prior native output is acceptable. Upload Singularity, review detected roots/environment selection, supply missing artifacts as needed, and verify actual chart/image provenance before confirmation. Exercise a real Scan and compare with the existing Helm ingestion baseline; do not treat partial discovery as complete coverage.

