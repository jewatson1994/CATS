# Discovery values and patch publication repair

## Scope and baseline

Branch: `fix/discovery-values-and-patch-publication`. Based on verified origin/main `c11b89d9d1ac4ee44b64884fc1de73404c3a12c0`. Existing checkouts and uncommitted work were preserved. No deployment, push, or merge was performed.

## Verified Discovery defect

`portal/app/discovery_engine.py` checked all prior diagnostics for a parent root when deciding whether a generated Flux release could render. Generated sibling releases share that root. A missing values reference in one release therefore blocked otherwise valid siblings. A native Helm regression reproduces this and verifies release-local failure handling.

The existing pipeline already renders parent charts with Helm, processes generated Flux definitions and ConfigMaps, resolves chart sources, combines Flux values, applies supported post-renderers, and extracts rendered workload images. These mechanisms remain in use; declared image strings are not promoted to successful rendered evidence.

Component values are now an ordered `component_values` mapping keyed by stable chart/release identity. Native chart defaults and the parent configuration remain primary. For generated releases, explicit component files follow generated effective values; Flux targetPath arguments retain their existing highest Helm precedence. Component files do not apply to siblings. Selections persist in inventory configuration and rediscovery. Missing or invalid selected files produce diagnostics rather than silently disappearing. Template definitions are excluded from ordinary values candidates.

Kustomize was already routed to its native renderer. Its failure text incorrectly described Helm configuration. Diagnostics and the UI now identify Kustomize and direct operators to bases, resources, components, and patches.

The actual Singularity project is unavailable locally. The historical “all but two charts” result cannot be verified. Representative native Helm fixtures verify a broken sibling, two successful releases, parent default/override values, isolated ordered component overrides, repeat discovery, and missing-file behavior. No Singularity names or paths are hardcoded.

## Verified publication defect

`resolve_registry_image` previously treated the colon in a short tagged reference such as `cats:tag` as a registry-port separator. This bypassed the selected registry. Docker can normalize that reference to `docker.io/library/cats:tag`.

`portal/app/patch_publication.py` now resolves short references against the explicitly selected registry and namespace. Qualified references must match that registry. Invalid endpoints and ambiguous single-label registry hosts are rejected before expensive patch work. Explicitly selecting Docker Hub remains supported. The UI previews the resolved destination and results retain it; the same resolved reference enters the worker payload, tagging, and push.

A registry “read-only file system” response is now prominently classified as a storage failure. Detailed sanitized output remains available. Failed push does not run signing or mark publication complete. Existing patched TAR and scan results remain accessible.

The reported storage path does not establish the actual network endpoint or storage owner. Registry/proxy routing can differ from the image name. No local configuration identifies `/repostorage/containers_registry` as CATS-managed storage. No external filesystem was repaired.

Publication-only resume is not implemented by the existing patch worker. Ordinary retry may repeat patching and scanning; this change does not pretend it can safely resume an expired worker artifact. The retained archive can still be downloaded.

## Operator diagnostics for the external storage failure

On the actual registry/storage host, collect read-only evidence, substituting the registry container name:

```sh
docker inspect <registry> --format '{{json .Mounts}}'
docker logs --tail 100 <registry>
findmnt -T /repostorage/containers_registry
df -h /repostorage/containers_registry
```

Also record the selected registry endpoint, resolved destination, and sanitized proxy/daemon routing. Do not include credentials. The registry administrator must establish why storage is read-only before retrying. Do not weaken TLS, broaden robot permissions, remount storage, or prune artifacts as a CATS workaround.

## Validation

- Discovery engine, routes, and cache regression suite including native Helm: **114 passed**.
- Discovery cache, Helm network policy, Kustomize inputs, Scan handoff, and supplements: **58 passed**.
- Publication, patch-worker, and signing regression suite: **105 passed, 1 skipped**; final destination validation suite: **12 passed**.
- Full frontend suite: **421 passed across 61 files**.
- TypeScript checking and Vite production build: passed.
- Initial broader backend setup encountered a Windows pytest temporary-directory permission error. Re-running with a fresh explicit writable `--basetemp` passed; this was not an application failure.
- Native rendering uses representative fixtures. External registry storage failure classification uses controlled error responses; no access to the affected external registry was available.
- Browser testing against the user's deployed instance was not performed.

## Deployment

No Compose or environment setting changes are required for these fixes. Build the application image from the completed branch after review and update portal and affected workers together using the normal deployment procedure. Existing discovery versions remain immutable; rerun as a new version to obtain corrected results. Select parent environment values first and component overrides only when required. Existing source allowlists, credentials, CA trust, sandboxing, and archive safety controls remain in force.

