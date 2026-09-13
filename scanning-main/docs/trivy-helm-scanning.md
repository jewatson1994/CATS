# Trivy, Dockle, and Helm scanning

CATScan uses separate scanners for separate evidence types. Trivy handles
source configuration and Helm-rendered Kubernetes manifests. Dockle handles
container-image hardening and its normalized records are merged into the same
`portal-policy-findings.json` contract with `scanner: "Dockle"`.

Set `DOCKLE_IMAGE_CONFIG_SCAN_ENABLED=true` to enable Dockle image checks.
Unavailable images remain in the existing skipped-image/missing-evidence flow
and are not duplicated by Dockle. Dockle scans images available to the Docker
daemon, so an image must be pulled or loaded locally before hardening checks
can run.

## Outcome

The configuration path is additive to the existing Syft/Grype image workflow.
It produces raw Trivy evidence, rendered Helm manifests, a scan-completeness
record, and a normalized `policy_findings` list for CATS. It does not replace
SBOM generation or vulnerability scanning.

Every emitted portal item uses one of the two agreed finding types:

- `Vulnerability` for the existing Grype/CVE records.
- `Configuration` for Trivy configuration, Kubernetes, Dockerfile, IaC, and
  rendered Helm findings.

Scanner-native IDs remain visible in `finding`, for example `KSV014`, `DS002`,
or `AVD-KSV-*`. `framework` preserves the scanner category, while `scanner` is
always `Trivy` for this path.

## Pipeline flow

```text
Service source / optional upstream artifact
        |
        +--> prepare_inputs --> Helm render --> image references --> Syft SBOM --> Grype fixable CVEs --+
        |                                                                            |
        +--> Trivy config (Dockerfile, Kubernetes, IaC) ----+   |
        |                                                   |   |
        `--> Helm root/umbrella discovery                  |   |
              --> dependency verification                 |   |
              --> helm template                           |   |
              --> Trivy config on rendered manifests -----+   |
                                                          |   |
                     normalized policy_findings -----------+---+
                                                          |
                     CATS pipeline-results API <-----------+
```

`prepare_inputs` runs before `generate_sboms`, so Helm-discovered images are
available to the normal Syft/Grype path. `scan_configurations` runs in the
existing `scan` stage, in parallel with
`scan_sboms`. `report_to_portal` downloads both jobs' artifacts and sends
one service execution containing `findings` and `policy_findings`.

Before SBOM generation, the pipeline renders submitted Helm charts and extracts
workload image references from `containers`, `initContainers`, and
`ephemeralContainers`. Those references are deduplicated into the service's
`images.yml`, so they follow the same Syft/Grype path as explicitly listed
images. Chart image extraction is best-effort; failed chart renders are written
to `skipped_charts.txt` and do not fail the pipeline.

Image discovery is automatic whenever `charts/`, `charts.yml`, or a values-file
catalog is present. Values catalogs are supplied with `HELM_VALUES_FILES` or
the `values_files`/`valuesFiles` key in `charts.yml`. `HELM_SCAN_ENABLED`
controls the separate Trivy configuration finding scan; it is not required for
chart image references to enter SBOM scanning.

### Recursive Helm chart graph

The scanner performs a bounded graph walk over the complete uploaded artifact.
It inventories every directory containing `Chart.yaml` and every valid packaged
chart (`.tgz`, `.tar.gz`, or `.zip`), then parses every YAML/YML document for
local paths, packaged paths, OCI references, and chart/repository metadata
combinations. Local and vendored charts are resolved without network access;
remote candidates remain unresolved evidence unless the existing Helm
network/repository configuration permits materialization.

Each graph edge records its parent chart, discovery method, source file, YAML
path, reference, confidence, and resolution status. A chart plus its values,
release, namespace, and set context is a render instance, so the same chart can
be rendered more than once when the artifact declares distinct contexts.
Standard vendored subcharts remain in the graph but are skipped as independent
render targets because the parent Helm render already contains them. The graph
is written to `.cats-helm-graph.json` and render entries to
`.cats-helm-entries.jsonl`; unresolved candidates are merged into Missing
Evidence for the portal.

## Enabling the jobs

Source and Helm configuration scanning are opt-in until the
`cyber-tools/catscan` image includes Trivy and Helm. Image configuration
scanning is enabled by default:

```yaml
variables:
  TRIVY_CONFIG_SCAN_ENABLED: "true"
  HELM_SCAN_ENABLED: "true"
```

The standalone CATScan worker also checks pulled images for image/Dockerfile
configuration misconfigurations by default. Set
`TRIVY_IMAGE_CONFIG_SCAN_ENABLED=false` to disable that pass. In a multi-job
GitLab pipeline, set the variable to `true` only when the configuration job
has access to the pulled images (or an image archive handoff). The image scan
uses the local Docker image loaded during SBOM generation; unavailable images
remain recorded as incomplete evidence.

The following defaults are intentionally disconnected-safe:

```yaml
variables:
  TRIVY_OFFLINE: "true"
  TRIVY_CACHE_DIR: "/opt/catscan/trivy-cache"
  HELM_DEPENDENCY_MODE: "vendored"
  HELM_ALLOW_NETWORK: "false"
```

To scan only non-Helm source configuration, set
`TRIVY_CONFIG_SCAN_ENABLED=true` and leave `HELM_SCAN_ENABLED=false`. To scan
only rendered charts, invert those values.

When Helm scanning is enabled but a service has no `charts/` directory, no
discoverable `Chart.yaml`, and no entries in `charts.yml`, the Helm portion is
treated as not applicable. The source configuration scan still runs, and the
execution is not marked incomplete just because that service does not use Helm.
If a chart is present but cannot render or scan, that is still recorded as
incomplete evidence.

## CATScan image requirements

The `cyber-tools/catscan` image must contain:

- `trivy`
- `helm`
- Existing `bash`, `jq`, `yq`, `coreutils`, and `sha256sum` utilities
- An existing, writable cache directory at `TRIVY_CACHE_DIR`
- Docker daemon access for image configuration scanning

The packaged Trivy 0.72 configuration checks are embedded, so a populated
vulnerability database or downloaded check bundle is not required for
configuration-only scanning. The cache directory may begin empty, but it must
exist and be writable by the pipeline user. If future Trivy versions externalize
configuration checks, package the version-matched bundle into CATScan rather
than allowing a production job to retrieve it. Validate the finished image in
an isolated network with:

```bash
trivy --version
helm version --short
trivy config --skip-check-update --skip-version-check \
  --disable-telemetry \
  --cache-dir /opt/catscan/trivy-cache \
  /path/to/known-fixture
```

Do not enable online chart or check retrieval to mask a scanner-image problem.
An unwritable cache or failed offline invocation is incomplete evidence and
should be fixed in the CATScan image supply process.

## Chart input contract

The simplest service layout is:

```text
images.yml
charts/
  service-umbrella/
    Chart.yaml
    values.yaml
    templates/
    charts/
      api/
        Chart.yaml
        templates/
      worker-0.4.0.tgz
```

When `charts.yml` is absent, the scanner discovers every root `Chart.yaml`
below `HELM_CHART_ROOTS` (default `charts`). It deliberately excludes any
`Chart.yaml` below a parent `charts/` directory. Rendering the umbrella chart
already renders all vendored child and nested child charts; separately scanning
them would create duplicate findings.

Use `charts.yml` when a service needs explicit releases, namespaces, values, or
multiple root charts. See `examples/charts.yml` for the complete contract:

```yaml
charts:
  - name: service
    path: charts/service
    release: service-prod
    namespace: service-prod
    # Optional; when omitted, Trivy's native rule type is preserved.
    framework: Kubernetes Security Check
    values:
      - charts/service/values.yaml
      - charts/service/values-production.yaml
    set:
      global.environment: production
    include_crds: true
    dependency_mode: vendored
```

`values` paths are resolved from the CI project root. `set` can be a mapping or
an array of `key=value` strings. Keep secrets out of committed values files and
CI artifacts; use safe representative values for static analysis.

### Values-file application catalogs

Services that already maintain an application catalog can point the scanner at
one or more values files with `HELM_VALUES_FILES` (colon-separated paths), or
with a top-level `values_files`/`valuesFiles` list in `charts.yml`:

```yaml
services:
  dashboard:
    enabled: false                 # metadata only; it is still rendered
    sourceType: helm
    helmRepo:
      repoName: example
      repoUrl: https://example.invalid/charts
      chart: dashboard
      version: 1.2.3
    valuesFiles: []
```

Every `services.*` entry with `sourceType: helm` is processed regardless of
its `enabled` value. Missing repositories, unavailable charts, and unavailable
dependencies are recorded in `skipped_charts.txt` and continue the scan. Remote
catalog entries require `HELM_ALLOW_NETWORK=true`; vendored chart inputs remain
the preferred offline path. See `examples/services-values.yml`.

### Nested and umbrella charts

`dependency_mode: vendored` recursively verifies dependencies declared by the
umbrella chart and by every unpacked child chart. A dependency is considered
present when the owning chart contains either:

- `charts/<dependency-or-alias>/Chart.yaml`, or
- `charts/<dependency>-<version>.tgz`.

The scanner then runs one `helm template` against the umbrella. This covers all
templates produced by direct and nested dependencies.

### Dependency modes

| Mode | Network | Behavior |
|---|---:|---|
| `auto` | Optional | Use vendored packages when present; otherwise resolve dependencies when `HELM_ALLOW_NETWORK=true`. This is the default self-service mode. |
| `vendored` | Never | Verify recursively and render existing dependencies. |
| `local` | Never | Permit only `file://` dependencies, run `helm dependency build --skip-refresh`, then verify. |
| `online` | Allowed | Run `helm dependency build`; also requires `HELM_ALLOW_NETWORK=true`. |

Remote entries in `charts.yml` also require `HELM_ALLOW_NETWORK=true`:

```yaml
charts:
  - name: cert-manager
    reference: cert-manager
    repository: https://charts.jetstack.io
    version: v1.18.2
```

Remote mode is intentionally unsuitable for a disconnected production runner.
Prefer committing or transferring a reviewed chart package and its dependency
packages into the service repository.

## Patching-triggered pipelines

When scanning is directly included by a service project, its source tree is
already available. When patching triggers the central scanning project, only
upstream job artifacts are available. The patching artifact must therefore
carry forward these optional paths:

```text
charts.yml
charts/
configuration/
```

`generate-sboms.sh` extracts these paths when present and republishes them for
`scan_configurations`. Put non-Helm Dockerfiles, Kubernetes files, Terraform,
and other IaC intended for a triggered scan below `configuration/`.

If configuration scanning is enabled in triggered mode but `configuration/` is
absent, the execution is marked incomplete. This prevents an empty artifact
from being mistaken for a clean assessment.

## Source configuration paths

Direct-include mode scans the project root by default. Override with a
space-delimited set of paths:

```yaml
variables:
  TRIVY_CONFIG_PATHS: "deploy terraform docker"
```

The scanner skips `.git`, its cloned pipeline repository, SBOM/results
directories, and rendered Helm evidence. When Helm scanning is enabled, it also
skips `HELM_CHART_ROOTS` during the source scan because rendered chart output is
authoritative.

Add project-specific exclusions with:

```yaml
variables:
  TRIVY_CONFIG_SKIP_DIRS: ".git .cats sboms results trivy-results helm-rendered vendor testdata"
```

## Artifacts

`scan_configurations` retains:

| Artifact | Purpose |
|---|---|
| `trivy-results/raw/` | Unmodified Trivy JSON per source/chart target |
| `trivy-results/normalized/` | Portal-shaped findings per target |
| `helm-rendered/` | Exact manifest stream assessed by Trivy |
| `.cats-helm-graph.json` | Bounded recursive chart graph, relationships, and unresolved references |
| `.cats-helm-entries.jsonl` | Render instances with values/release/namespace context |
| `helm-images.txt` | Deduplicated image references handed from Helm to SBOM generation |
| `portal-policy-findings.json` | Deduplicated service-level `policy_findings` |
| `results/grype/` | Native Grype JSON grouped for manual import |
| `results/trivy/` | Native Trivy JSON grouped for manual import |
| `results/dockle/` | Native Dockle JSON grouped for manual import |
| `results/cats/cats-findings.json` | CATS-normalized configuration report for Generic Findings Import |
| `results/manifest.json` | Report paths, checksums, and DefectDojo scan types |
| `results-export.tar.gz` | Complete manual-import results bundle |
| `configuration-scan-status.json` | Requested/succeeded counts and completeness |
| `configuration-skipped.txt` | Target and reason for every incomplete scan |
| `skipped_charts.txt` | Chart target and reason for every skipped chart; chart skips never fail the job |

Raw and rendered artifacts make findings reproducible and reviewable. Treat
rendered files as potentially sensitive because values can be expanded into
them; avoid rendering live secrets.

## Portal contract

Each normalized finding contains exactly the fields currently accepted by
CATS:

```json
{
  "type": "Configuration",
  "finding": "KSV014",
  "severity": "High",
  "scanner": "Trivy",
  "framework": "Kubernetes Security Check",
  "target": "payments (payments-prod) :: Deployment/payments-api",
  "namespace": "payments-prod",
  "title": "Root file system is not read-only",
  "description": "The container can write to its root file system.",
  "remediation": "Set readOnlyRootFilesystem to true.",
  "fingerprint": "trivy:<64-character-sha256>"
}
```

The fingerprint hashes scanner ID, rendered target, namespace, and Trivy cause
resource. It remains stable across identical scans and is bounded even when a
target path is long.

The overall execution `complete` flag is true only when both conditions hold:

1. Every requested image produced a Grype result and no image was skipped.
2. Every enabled source/chart configuration target rendered and scanned.

Configuration findings do not change the existing vulnerability data. A
configuration failure can still make the service evidence incomplete.

## Controls and failure behavior

`TRIVY_CONFIG_STRICT=false` is the default. Source/configuration target failures
are retained as incomplete evidence while the job succeeds so the portal
submission can still deliver partial results. Helm chart render, dependency,
and normalization failures are always non-blocking: they are written to
`skipped_charts.txt`, mark the execution incomplete, and never fail the job.
Set `TRIVY_CONFIG_STRICT=true` if source/configuration failures should also fail
the GitLab job; artifacts use `when: always`, and the portal job also runs with
`when: always`.

Common failures that mark evidence incomplete:

- Trivy or Helm missing from CATScan.
- Trivy cache directory absent or not writable.
- A configured source path does not exist.
- A Helm dependency is not vendored.
- Remote dependency mode requested while network use is disabled.
- `helm template` fails or renders no resources.
- Trivy execution or JSON normalization fails.

## Tests

The committed fixture includes a failing Trivy Kubernetes check, a failing
Dockerfile check, a passing check that must be ignored, and an umbrella chart
with a vendored child chart.

Run the dependency-free fixture check anywhere Python is available:

```bash
python tests/validate-fixtures.py
```

Run the real jq/shell normalizer contract inside CATScan or another environment
with Bash, jq, base64, and sha256sum:

```bash
bash tests/test-normalize-trivy.sh
```

Run the end-to-end disconnected toolchain test inside the finished CATScan
image. It verifies nested Helm rendering, invokes Trivy with update/network
behavior disabled, and validates the normalized output:

```bash
bash tests/test-trivy-helm-toolchain.sh
```

Finally, copy the fixture umbrella beneath a temporary `charts/` directory,
set both scan flags, and run `scripts/scan-configurations.sh` to exercise the
same orchestrator used by a service pipeline.
