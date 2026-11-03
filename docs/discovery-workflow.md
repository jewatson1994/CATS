# Deployment Discovery

Open **Discovery** next to Scan. Discovery inspects deployment configuration and preserves evidence; starting discovery does not start a vulnerability scan.

1. Select an owning group and upload a deployment file or repository source archive. Supported configuration includes Helm, Kubernetes, Kustomize, Compose, GitOps definitions and image lists. For a project hosted in Git, upload the checkout or source archive for the intended revision. Discovery does not clone a pasted Git URL. You can also submit an OCI image reference or an OCI chart reference with an exact version.
2. Optionally name the environment and enter relative values-file paths, one per line in override order. Use non-secret configuration. Later files override earlier files.
3. Review each deployment root, its components, image references, completeness and diagnostics. Expand **Source evidence** to inspect provenance or **Complete inventory and relationships** for the full graph. Discovery treats inputs as untrusted and does not execute application scripts, build images or deploy workloads.
4. Select the roots belonging to one service. Choose an existing service, or **Stage a new service** if your group staging authority permits it. New services receive exactly the selected owning group. Only services in the owning group for which you have scan permission appear. Explicitly acknowledge a partial inventory after reviewing its gaps. Blocked or invalid inventories cannot be confirmed.
5. Choose **Confirm inventory**. This records the reviewed service association without scanning. Choose **Start scan** separately when ready, then follow **View scan progress**.

Running work can be cancelled. Retry or **Rediscover as new version** preserves prior evidence. Under **Compare immutable versions**, select an earlier completed discovery from the same group to inspect added, removed and changed component IDs. Comparison reports inventory changes, not vulnerability changes.

If discovery is incomplete, review diagnostics and candidate environment paths. In **Resolution assistance**, adjust non-secret options (including ordered files or a `source_map` from Flux source identity to an uploaded directory), then retry as a new version. This reruns discovery and preserves earlier evidence. To add missing source files, submit a corrected archive. Administrators can also supply exact-version, SHA-256-verified archives through the optional [offline mirror](universal-deployment-discovery.md#follow-up-implementation-2026-10-20). The page never silently treats an unknown or partial result as a complete deployment.

## Helm charts declared in values.yaml

A parent `Chart.yaml` can contain only chart metadata while its sibling `values.yaml` declares child charts under `services`. For example, `services.prometheus.helmRepo` can declare the chart `kube-prometheus-stack`, its repository and its version. Discovery follows recognized Helm and OCI entries, including entries with `enabled: false`, so the inventory covers every declared component. When a resolved child's values also declare services, Discovery follows that catalog in turn. [Example catalog](../scanning-main/examples/services-values.yml)

For offline discovery, place each child under the parent's `charts/` directory as an unpacked chart or a `<chart>-<version>.tgz` package. Discovery checks the name and version against the catalog. You can also use a local `chart_map` for another uploaded directory or an administrator-configured mirror for the exact version. Direct retrieval requires `HELM_ALLOW_NETWORK=true` and an approved repository or registry namespace. [Worker source and registry configuration](universal-deployment-discovery.md#helm-network-retrieval-and-live-archive-acceptance-2026-10-21)

Each child starts with its own chart defaults. Its `valuesFiles` (also spelled `values_files`) are applied in declaration order using paths relative to the source root. Files selected for that child in **Resolution assistance** apply last. Later files override earlier ones. A parent's values selection configures the parent, and each child's selection applies only to that child.

Review each child under **Complete inventory and relationships**. A successfully rendered workload provides image evidence. If a chart or a required values file is unavailable, the inventory retains the child and its diagnostic while Discovery continues with its siblings. Supply the missing input and retry as a new version to verify the rendered images.

## Native rendering isolation

The dedicated Linux worker runs as UID 10003. Bubblewrap exposes only the selected static renderer binary and the job source directory (read-only), creates fresh user, network, process and mount namespaces, clears the environment, drops capabilities, and supplies private temporary storage. Plugins, executable post-renderers and Kustomize exec extensions are rejected. A child seccomp filter blocks subsequent namespace creation/entry and mount changes, checks the syscall architecture, and fails closed on unsupported architectures. The worker records trusted build-time Helm, Kustomize and Compose versions. Wall-clock limits apply to every render. Combined output limits are optional and default to unlimited (see the resource settings below).

Docker's built-in seccomp policy can prevent Bubblewrap namespace setup. The implementation fails closed in that case. Compose applies the explicitly approved `deploy/discovery-seccomp.json` profile only to the Discovery worker, permitting Bubblewrap setup; no privileged mode, unconfined profile or writable host `/proc` is supported. The container policy is separate from the stricter child filter applied after namespace setup.

Acceptance on Docker Desktop Linux used an ephemeral default-derived policy with `unshare`, `clone` constrained to `CLONE_NEWUSER`, and `mount`, `umount2`, `pivot_root` additions. The worker retained no network, a read-only root, all capabilities dropped, no-new-privileges, process/memory/CPU limits and private `/tmp`. Helm 4.2.3, Kustomize 5.8.1 and Compose 2.39.4 rendered fixtures successfully. A parent Helm chart generating Flux configuration, ConfigMap `valuesFrom`, a local child chart and a declarative Kustomize image post-renderer produced the expected complete inventory. A Helm write to `/source` failed; private `/tmp` output succeeded. Source ownership and worker identity were UID 10003. These results do not establish compatibility with every Linux host security policy.

## Singularity acceptance in the isolated environment

The real project is available only to the operator. Upload the complete source archive with local chart dependencies, select the intended root values files in deployment order, and compare the reviewed image inventory against the previous all-but-two-chart result. Inspect each generated Flux release, effective ConfigMap values, downstream chart and image provenance. For the two previously unresolved charts, retain the exact missing-reference diagnostics and check whether their required values exist in the source archive. Missing external artifacts remain unresolved. Record the archive hash, selected configuration, tool versions, inventory ID, component/image counts and unresolved diagnostics. Confirm service boundaries and use the existing Scan handoff only after review. Synthetic renderer tests are not Singularity acceptance.

The installed worker-only profile was also verified with Compose configuration validation, all 11 renderer regression tests, and an offline non-root Helm smoke render using the committed profile path.


### Discovery input capacity

Discovery defaults to unlimited upload bytes, per-file bytes, extracted bytes,
file counts, and renderer output bytes. Operators can set positive values for
`CATS_DISCOVERY_MAX_UPLOAD_BYTES`, `CATS_DISCOVERY_MAX_FILE_BYTES`,
`CATS_DISCOVERY_MAX_EXTRACTED_BYTES`, `CATS_DISCOVERY_MAX_FILES`, and
`CATS_DISCOVERY_MAX_RENDERED_BYTES`; zero disables the respective budget. There
is no hidden upper clamp. Direct Compose ingestion retains its separate budgets.
Supplemental inputs use the Discovery budgets and have no fixed chain-count cap.

Uploads and supplemental copies stream in chunks. Native renderer output spools
to disk before parsing; parsing still requires memory proportional to document
size. The Discovery worker uses the `discovery_scratch` disk volume for temporary
inputs instead of a 512 MiB tmpfs. Provision and monitor that volume and the
upload volume for source, decrypted, extracted and rendered data. Container
memory (`CATS_DISCOVERY_MEMORY`, default 1 GiB), CPU, process and execution-time
budgets still apply. A process killed by the operating system cannot emit its own
resource diagnostic; inspect worker/container logs in that case. Configure any
external reverse proxy request-body limit and request timeout for the intended
upload sizes; application settings cannot override an external proxy rejection.

Archive extraction, repository hashing, and approved mirror/Helm artifact downloads
use file-backed streaming. Archive buffers do not grow with the combined archive
and extracted payload. ZIP directory metadata, inventory data, parsed documents,
and final renderer text still occupy memory. Structural YAML protections and
inventory complexity limits remain; these are distinct from uploaded file-count
budgets. Helm metadata and administrator mirror manifests remain bounded. Network
socket/deadline limits remain in force. Render input scoping and encrypted cache
size thresholds only skip optimizations; they do not reject larger sources.
