# Universal deployment discovery

Discovery produces reviewable deployment evidence before Scan assesses its security. It does not deploy, build images, execute repository scripts, or authorize remediation. The existing direct-scan and Service Definition routes remain supported.

## Baseline and architecture audit

This implementation starts from `1946ce775c6eb19f9fe49860a27cac60a148cc25`, which includes the current accounts/access, Risk Profiles, VEX and ownership behavior. Work is isolated on `feature/universal-deployment-discovery`; main, OCI and Risk branches were not modified.

The earlier `service_definitions.py` adapter registry normalizes recognized values/catalog structures into components. It is not a general repository model: component/chart keys and service-specific confirmation precede acquisition. `definition_acquisition.py` preserves chart source files and recursive acquisition; `definition_routes.py` manages service-scoped preview and confirmation. Those workflows, OCI/chart acquisition and historical definition provenance remain intact. They are reused as compatibility inputs, not used as the universal inventory schema.

Existing safe archive staging in `compose_ingestion.py`, legacy definition detection, durable jobs/leases, owning-group authorization, the existing scan admission path and scanner result ingestion are reused. Helm rendering is retained through the native executable. Discovery uses a separate bounded renderer rather than exposing acquisition credentials or executing repository code.

New modules separate responsibilities:

- `discovery_routes.py`: group-scoped upload, progress, retry/cancel, review, confirmation, comparison and scan admission.
- `discovery_sources.py`: authenticated encrypted upload storage and bounded temporary decryption.
- `discovery_engine.py`: format detection, local resolution, native rendering coordination, canonical graph and diagnostics.
- `discovery_renderer.py`: restricted native command allowlist, Bubblewrap isolation and child syscall filter.
- `discovery_worker.py`: durable leasing, progress, cancellation checkpoints and immutable result persistence.
- `discovery_models.py`: additive inventory, confirmation and scan-association tables.
- `discovery_retention.py`: terminal-source expiry integrated with portal maintenance.

## Canonical inventory and versioning

Schema `1.0` contains `roots`, `nodes`, `edges`, `images`, `diagnostics`, `metrics`, `tool_versions`, `selection`, `archive_hash` and aggregate `completeness`.

| Entity | Fields and meaning |
| --- | --- |
| Root | Stable ID, relative path, detected technology, completeness. A candidate boundary, not an automatically created CATS service. |
| Node | Stable ID, root ID, kind, name, namespace, state, completeness, provenance. Represents resources, components and unresolved references. |
| Image | Reference, root ID, component ID, completeness and provenance. Preserves declared tags/digests without claiming a mutable tag was resolved to a digest. |
| Edge | Source ID, target ID and relationship kind: rendering, configuration, volumes/storage, selectors, dependencies, networks, sources or values. |
| Provenance | Source path/hash and, when rendered, rendered-content hash and tool identity. Raw configuration/Secret bodies are not inventory data. |
| Database version | Immutable inventory ID, job/group IDs, archive hash, content hash and timestamp. Confirmations retain selected roots, service, actor and partial acknowledgement separately. |

IDs derive from source-relative identities; content hashes permit version comparison. Rediscovery creates a new job/result. ORM guards and SQLite/PostgreSQL triggers reject inventory updates/deletes. A confirmation never overwrites an existing service inventory or historical scan evidence. One discovery can expose multiple candidate deployments; the operator selects boundaries for an existing service with exactly one owning group.

`complete`, `partial`, `blocked` and `invalid` describe interpretation coverage, not security compliance. Nodes distinguish declared, selected, rendered and unresolved evidence. No runtime-observed claim is generated. Component/image completeness conservatively inherits unresolved root diagnostics. Unknown controller semantics, missing references and unavailable renderers are reported rather than interpreted as complete coverage.

## Adapters and supported semantics

`DiscoveryAdapter` defines technology, filenames/detector, native tool/prefix and an optional trusted handler. `register_adapter` accepts installed server code only; uploads cannot install plugins. Handlers return bounded canonical fragments. Built-in adapters share local dependency indexing, graph extraction and diagnostics.

| Input | Implemented behavior | Limits |
| --- | --- | --- |
| Repository ZIP/TAR, chart TGZ, directories | Safe staging, mixed-format detection, source hashes, multiple candidate roots, LFS/submodule diagnostics | A GitLab project export containing only a Git bundle is not a source checkout. Direct Git fetching is unavailable. |
| Helm | Native root/umbrella/vendored chart rendering, default values, ordered override files, native helper/conditional/hook semantics, generated-resource inspection | External/unvendored dependencies require local artifacts. Values files alone cannot identify a missing chart. No dependency-update network fallback. |
| Flux HelmRelease | Parent-generated resources, local chart mapping, ordered ConfigMap valuesFrom, inline values, supported targetPath, release/namespace, dependencies; child rendering and declarative Kustomize postrendering | Secret values are unresolved. targetPath uses native Helm --set semantics; only inline patch/image postrenderers are supported. Source declarations do not imply artifacts are fetched. |
| Other Flux resources | Source and dependency evidence with explicit unresolved/controller diagnostics | Local/mirrored Git and OCI sources and local Flux Kustomization builds are supported. Bucket and full controller reconciliation remain unavailable. |
| Kustomize | Native build for local bases/overlays/components/patches/images/generators | Remote bases and executable plugins/extensions unavailable. Raw pre-transform images are not passed off as final output. |
| Docker Compose | Native config with ordered files, profiles, interpolation/env_file; images, dependencies, networks, volumes, build contexts | No builds. Build-only outputs remain unresolved. Restricted fallback parsing is explicitly partial. |
| Kubernetes | Standard Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob containers/init/ephemeral containers; configuration/storage/selectors | Custom controller behavior requires a reviewed adapter. NetworkPolicy and live reachability are not evaluated. |
| Image references | Declared OCI/container image references | No registry digest lookup. OCI chart references without local artifacts are unresolved. |
| Legacy Service Definition | Existing recognized catalogs mapped into the new review model with local chart mappings | Original direct workflow remains available; new adapter does not replace recursive legacy acquisition. |

Resolution never silently accesses public networks. Local files must be inside the submitted source or an administrator-configured, integrity-verified mirror snapshot. Missing dependencies, unavailable Secrets and unsupported semantics remain visible. Configuration bodies are not persisted in the inventory; known Secret-derived values are redacted. Operators must still submit sanitized deployment configuration: source metadata and image names are evidence and cannot be reliably classified as secret automatically.

## Worker and source security

The portal streams an upload into AES-GCM encrypted storage using a domain-separated key derived from `CATS_CONFIG_ENCRYPTION_KEY`; source identity is authenticated and plaintext SHA-256 is verified after decryption. There is no plaintext fallback. Retain the encryption key; changing it makes retained retry sources unreadable. Sources expire after terminal jobs by default at 24 hours (`CATS_DISCOVERY_SOURCE_RETENTION_HOURS`, clamped 1–168). Active sibling jobs prevent deletion. Manual source removal preserves inventory evidence but prevents retry. Portal multipart scratch and worker plaintext staging use bounded tmpfs in Compose; encrypted sources use the shared upload volume.

The dedicated worker runs UID/GID 10003, read-only root, no capabilities, no-new-privileges, CPU/memory/PID limits, a private temporary filesystem and a read-only upload mount. It has database access to lease/persist jobs; the renderer does not. Bubblewrap clears environment and exposes only the selected static tool, read-only job source, private tmp/proc/dev, and separate network/PID/user/mount namespaces. Child BPF blocks further namespace/mount operations and validates syscall architecture. No Docker socket, application directory, database credentials or other uploads enter the renderer. Shell commands, Helm executable postrenderers, Kustomize plugins and arbitrary executables are rejected.

Native invocation limits: 60 seconds and 16 MiB combined output. Archive limits: 500 files, 32 MiB expanded total and 4 MiB per file; traversal, links, duplicates, malformed archives and excessive YAML structure are rejected. YAML is capped at depth 50 and 30,000 structural nodes. Downstream resource processing is bounded at 2,000 queue entries. These conservative limits intentionally reject some large projects; they are not a claim of support for unlimited repositories.

**Container sandbox policy:** Following explicit operator approval, Compose applies `deploy/discovery-seccomp.json` only to the Discovery worker. This default-derived policy permits Bubblewrap setup, which Docker's default profile blocked on the tested host. Do not use privileged mode, seccomp-unconfined or writable host `/proc` as a workaround. Hosts must also permit unprivileged user namespaces. The container policy permits sandbox setup; the stricter child filter applies after setup.

## Workflow, RBAC and Scan

See [operator walkthrough](discovery-workflow.md). Discovery is a dedicated navigation item, independent of Scan. Upload/reference input supports owning-group selection and environment/ordered-file options. Progress shows available stage/count metrics. Review includes roots, images, source evidence, graph JSON and diagnostics. Retry/rediscovery preserve earlier results; comparison lists stable IDs added, removed or changed.

Group-level `service.edit` or `config.manage` authorizes Discovery management. Service-scoped grants do not imply group-wide access. Confirmation and scanning additionally require `scan.ingest` for the selected service and revalidate its single owning group. Confirmation can stage a new service with exactly the discovery owning group, using the existing Accounts staging authority plus group scan permission. Service management alone cannot stage services. CSRF and object-scope checks apply to mutations. Partial confirmation needs explicit acknowledgement; blocked/invalid inventories cannot be confirmed.

`Confirmed Discovery → Scan` calls `main._prepare_public_scan` and the existing durable scanner infrastructure. The scan carries the exact inventory/confirmation IDs, source/content hashes, selected roots, completeness and image provenance. Repeated requests reuse the recorded scan association. Existing scan limits still apply (including the configured maximum image count); Discovery does not silently truncate the inventory. Retries recover a previously admitted scan by its confirmation ID if the portal stopped before recording the association. Mutable tags remain mutable and are not used as immutable reuse evidence.

Existing SBOM, VEX, risk/classification, patch, remediation, validation and publication behavior is unchanged. Discovery's image-only handoff does not itself supply retained chart packages for existing Helm runtime validation. Inventory evidence can be referenced, but Discovery does not claim deployment validation or a second scanning/remediation implementation.

## Offline build and operation

Build the main CATS image first, then `docker build --build-arg CATS_TOOL_IMAGE=cats:<version> -f Dockerfile.discovery -t cats-discovery:<version> .`. Set `CATS_DISCOVERY_IMAGE` to that tag. Transfer both images plus existing PostgreSQL/runtime dependencies into disconnected environments. The worker image includes Helm/kubectl from CATS, Compose 2.39.4, Bubblewrap and Python dependencies; no runtime package download is required. Connected image construction needs the declared base images/package repositories. Pin approved base-image digests in release packaging; current Dockerfile defaults use version tags.

Configure the source encryption key and supply local charts/configuration in the uploaded bundle. Native rendering additionally requires the approved container sandbox policy described above. Worker source mounts are read-only; portal writes and retention own the encrypted source volume. Durable leasing/recovery/cancellation reuse CATS infrastructure. One worker processes bounded work; scale only within database and storage capacity.

## Verification and performance

Recorded on 2026-10-20:

- Docker worker image build succeeded. Native Helm 4.2.3, Kustomize 5.8.1 and Compose 2.39.4 fixtures passed under an ephemeral reviewed test policy with no network, non-root, cap-drop, read-only root and child BPF.
- Synthetic parent Helm → generated Flux HelmRelease/ConfigMap → valuesFrom → local child → declarative Kustomize postrenderer produced the expected final image, complete. Read-only source write failed; private temporary output succeeded.
- Discovery backend regression suite: 68 passed, including engine, renderer, routes/storage, PostgreSQL and real scan admission. After adding the Discovery-specific scan completion guard, the real handoff and legacy definition route suites passed all 8 tests (including the new completion regression).
- PostgreSQL tested real encrypted-source discovery, durable claim/finish, persistence and immutable-row rejection; existing lease recovery test passed.
- Real confirmation-to-durable-scan admission tested retained input archive, ownership, provenance and repeated-request association. This is queue admission, not an end-to-end vulnerability scan of registry images.
- Existing scanner/offline/release checks: 146 passed, 1 skipped. Legacy ingestion/definition checks: 133 passed, 1 failure. That 403-versus-404 no-access expectation was reproduced on unchanged baseline; it is not introduced by Discovery.
- Frontend Discovery tests, TypeScript, changed-file lint and production build passed. Full frontend lint has pre-existing unused variables in remediations.
- Synthetic 400 files / 1,200 Pods / 1,200 distinct images: 3.067 seconds wall, 2.984 seconds CPU, 4,429,131 bytes peak Python allocations with tracemalloc, 154,180 source bytes. Two simultaneous parser invocations finished in 2.035 seconds without tracemalloc. These are Windows parser measurements, not worker RSS, native render performance or database query benchmarks.

## Remaining acceptance work

The operator confirmed that actual Singularity repository/chart artifacts are available only in their isolated environment and cannot be accessed here. Its prior all-but-two-chart result has **not** been reproduced; the two unresolved charts cannot be investigated from synthetic fixtures. No real-world Singularity acceptance is claimed.

This implementation is a working local-source Discovery workflow, but does not yet fulfill the complete universal mission: live external artifact retrieval, full Flux controller semantics, incremental dependency-only rerendering, direct Git ingestion, and comprehensive hundred-chart/concurrent durable-worker resource benchmarks remain. Exact offline mirror snapshots and a verified Discovery companion release export are implemented. Environment labels and ordered file choices are explicit operator selections; automatic reliable environment inference is not claimed. Review can associate an existing service or stage a new singly owned service with the existing staging authority. No automatic scan mode is enabled. Unsupported or incomplete interpretation stays visible and cannot be advertised as complete security coverage.

## Follow-up implementation (2026-10-20)

An administrator may enable `deploy/compose.discovery-mirror.yaml` alongside the main Compose file and set `CATS_DISCOVERY_MIRROR_DIR` to an absolute, administrator-controlled directory. The directory is mounted read-only only in the worker. Renderers see only the verified artifact staged into their job source. The worker reads `/opt/discovery-mirror/manifest.json`; uploaded files cannot supply this configuration. Example:

```json
{"version":1,"artifacts":[{"kind":"helm","reference":"oci://registry.internal/charts/example","version":"1.2.3","path":"example-1.2.3.tgz","sha256":"REPLACE_WITH_64_HEX_SHA256"}]}
```

Entries match exact kind (`helm`, `git`, `oci`), reference and version. Flux HelmRepository references use repository URL plus `/` plus chart name; Git/OCI snapshots use their declared URL and explicit commit/tag/branch or digest/tag. Hashes are verified before extraction; symlinks, traversal and duplicate identities are rejected. There is no floating-version selection or network fallback. Mirror provenance records artifact hash and identity hash without local paths or credentials.

The resolution panel supports retry with revised non-secret configuration. `source_map` maps `Kind/namespace/name` to a source directory within the upload. Flux Kustomizations use native Kustomize for that local source and support simple `${NAME}` postBuild substitution from inline values and ConfigMaps. Secret substitutions and unsupported expressions remain unresolved. Candidate environment paths are review hints, never automatic environment selection. Retry currently reruns discovery as a new immutable version; it does not claim incremental dependency caching.

The unified build script builds the matching Discovery worker. `--discovery-offline-output <directory>` exports its Docker archive, approved seccomp profile, optional mirror overlay, checksums and import instructions. This is a companion to the main CATS release, not a complete installation bundle. A real local export of the acceptance image produced a 610,633,216-byte archive with 13 layers in 9.122 seconds; all manifest checksums and the non-root image configuration were verified. Import/redeployment was not tested.

`python scripts/benchmark-discovery-renderers.py` provides a synthetic native benchmark. In the hardened, network-disabled worker with 1 CPU/1 GiB/128 PIDs, 12 jobs each rendering 100 objects across Helm/Kustomize/Compose took 0.619 seconds serial and 0.762 seconds with concurrency four (0.256-second median job, 0.307-second maximum). These small fixtures exclude database, queue and upload costs and do not establish production throughput.

Follow-up verification: 105 Discovery backend checks passed across engine, mirror security, renderer, routes, PostgreSQL and Scan handoff (run in focused batches); 4 frontend tests, TypeScript, changed-file lint and production build passed. An additional 49 scanner/offline/release regression checks passed. Scan admission covers both existing services and newly staged singly owned services. Hardened native tests additionally verified Helm targetPath list indices/escaped dots and mirrored Flux Kustomization ConfigMap substitution with inline precedence. Main-plus-mirror Compose configuration validated. These checks do not constitute a real registry vulnerability scan or Singularity acceptance.

The updated worker image `cats-discovery:followup` also built successfully. Repeating the native benchmark inside that image with the same restrictions passed all three renderers: 0.556 seconds serial and 0.746 seconds at concurrency four. This validates the packaged renderer execution path, not production throughput.


### Follow-up: Flux sources, approved retrieval, and render reuse

Flux HelmRelease `chartRef` can resolve OCIRepository archives and HelmChart indirection. Kustomization namespace, name prefix/suffix, image transformations, and inline patches are applied through a native Kustomize overlay before supported post-build substitution. Unsupported controller options still report incomplete resolution. These additions have automated fixture coverage; they are not a claim of full Flux-controller parity or Singularity acceptance.

HTTPS dependency retrieval remains opt-in. Administrators configure `CATS_DISCOVERY_HTTPS_ARTIFACT_MANIFEST` with an absolute path outside the uploads directory. Its version-2 JSON has `allowed_origins` and `artifacts`; each artifact specifies `kind`, exact `reference`, exact `version`, HTTPS archive `url`, and `sha256`. The existing version-1 local mirror takes precedence for matching identities; a failed local artifact does not silently fall back to the network. `CATS_DISCOVERY_ARTIFACT_CA_FILE` optionally adds a trusted CA bundle. URLs cannot contain credentials, queries, or fragments. Redirects and environment proxies are disabled. Certificate and hostname verification remain required. Downloads have compressed-size, socket-timeout, elapsed-budget, checksum, and subsequent extraction checks. The administrator must configure worker egress/DNS restrictions for approved enterprise mirrors; renderer networking remains disabled. This retrieves approved archives, not arbitrary Git clones or authenticated registry sessions.

Set `CATS_DISCOVERY_RENDER_CACHE=true` to enable worker-private encrypted render reuse in temporary storage. It is disabled by default because templates may intentionally produce time-dependent or random output. Reuse freezes the prior successful output only when the source/group identity, native tool version, arguments, and hashes of every renderer-visible file match. Encryption uses the configured source-storage key with authenticated cache identity. Storage is capped at 64 MiB, corruption causes a fresh render, and unknown tool versions disable reuse. Hit/miss counts are recorded in inventory metrics. Retry still creates a separate immutable inventory and revalidates/resolves sources. This is conservative render reuse, not a minimal dependency-subgraph scheduler: unrelated visible file changes invalidate results, generated temporary paths may prevent reuse, and worker restarts lose the scratch cache. No historical inventory is overwritten.

Follow-up verification: 123 combined engine, artifact-retrieval, cache, renderer, route, Scan handoff, and release-packaging tests passed. The Discovery image rebuilt successfully, and native Kustomize transformations plus encrypted render reuse passed inside the non-root, network-disabled, read-only renderer container. HTTPS tests exercise transport configuration and bounded mocked responses; deployment-specific live mirror authentication/TLS and real Flux controller parity still need environment testing. Singularity artifacts remain unavailable.
