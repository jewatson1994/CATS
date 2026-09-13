# CATS scanner runtime

`scanning-main` contains the scanner orchestration bundled into the unified
CATS image. It is the source for the `cats` and `cats-scan` commands used by
the portal, local Docker jobs, and thin CI wrappers.

The scanner:

1. Normalizes image, service, and Helm inputs.
2. Recursively discovers and renders Helm chart instances.
3. Extracts and canonicalizes workload image references.
4. Generates a reusable Syft inventory for each image.
5. Serializes that inventory as Syft JSON, CycloneDX JSON/XML, or SPDX JSON.
6. Scans SBOMs with Grype and configuration with Trivy and Dockle.
7. Normalizes findings and service architecture evidence.
8. Produces raw reports, a portable results archive, Excel output, and a
   self-contained HTML overview.
9. Optionally submits the normalized assessment to the portal.

Image patching, registry pushing, and Cosign signing are owned by the portal
patch worker. Signing keys are uploaded and encrypted through Portal
Configuration. This directory does not contain signing keys or perform direct
registry publication. DefectDojo-compatible scanner files are exported for
manual ingestion; the scanner does not require DefectDojo credentials.

## Commands

The unified image exposes two interfaces.

The portable CLI separates preparation, evaluation, optional patching, and
authenticated delivery:

```text
cats version
cats prepare --source SOURCE_DIR --output PREPARED_DIR
cats evaluate --source PREPARED_DIR --output RESULTS_DIR
cats patch --input RESULTS_DIR --output PATCH_DIR [--config PATCH_CONFIG]
cats push assessment --input RESULTS_DIR/portal-result.json
cats push patch --input PATCH_DIR/patch-result.json
```

The standalone runner performs a complete temporary scan in one container:

```text
cats-scan INPUT_DIR OUTPUT_DIR
```

Set `CATS_JOB_MODE=sbom` to generate SBOMs without vulnerability or
configuration scanning. The normal mode is `scan`.

## Active layout

```text
scanning-main/
├── .gitlab-ci.yml                 # thin optional GitLab entry point
├── docs/
│   └── trivy-helm-scanning.md     # Helm/configuration scan contract
├── examples/                      # sample service, image, and Helm inputs
├── scripts/                       # image-owned scanner implementation
├── templates/
│   ├── cats_preparation.yml       # thin CLI dispatch jobs
│   ├── cats_evaluation.yml
│   ├── cats_push.yml
│   ├── cats_patch.yml
│   └── cats_patch_push.yml
└── tests/                         # scanner and export regression coverage
```

The image build copies `scripts/` to `/opt/cats/scanning/scripts`, installs
`scripts/cats` as `/usr/local/bin/cats`, and links `run-scan.sh` as
`/usr/local/bin/cats-scan`.

## Input contract

An assessment may provide an `images.yml`, a service definition, Helm charts,
or a combination of them.

```yaml
service:
  id: payments-api
  name: Payments API
  version: 2.4.1
  owner: Payments Engineering
  poc: payments@example.invalid

images:
  - docker.io/library/nginx:1.27
  - docker.io/library/redis:7.2
```

`charts.yml` can describe local, packaged, repository, and OCI charts. When it
is absent, CATS discovers roots under `HELM_CHART_ROOTS`. Values files may also
contain application catalogs whose entries instantiate the same chart more
than once. Each chart instance retains its values path, parent, render status,
and source provenance.

See `examples/` and `docs/trivy-helm-scanning.md` for complete examples.

## Outputs

The evaluation directory contains normalized portal evidence and native tool
reports. The manual export uses this layout:

```text
results/
├── grype/                         # native Grype JSON
├── trivy/                         # native Trivy JSON
├── dockle/                        # native Dockle JSON
├── cats/                          # normalized configuration findings
├── manifest.json
└── README.txt
```

Common top-level artifacts include:

- `portal-result.json` — normalized portal ingestion contract.
- `service-overview.json` — architecture and data-flow evidence.
- `helm-discovery.jsonl` — chart-instance discovery and render provenance.
- `helm-render-warnings.json` — sanitized partial/failure diagnostics.
- `sboms/` — source Syft inventories and selected alternate formats.
- `results-export.tar.gz` — portable raw-results bundle.
- `scan-overview.html` — self-contained, locally navigable report.
- `scan-summary.json` and `scan-status.txt` — completion summary.

The result manifest identifies the corresponding DefectDojo parser for each
native report so the files can be manually uploaded without conversion.

## SBOM formats

`SBOM_FORMATS` accepts a comma-separated list:

```text
syft-json,cyclonedx-json,cyclonedx-xml,spdx-json
```

Syft JSON is the reusable inventory and remains the source scanned by Grype.
Other formats are serialized from that inventory without rescanning the image.
Use `SBOM_CYCLONEDX_SPEC_VERSION` when the installed serializer supports an
explicit CycloneDX version.

## Offline operation

The published CATS image contains the scanner binaries and a prepared Grype
database. Runtime update checks are disabled. Local Docker archives can be
placed in `image-archives/`; the standalone runner loads every tag from those
archives before scanning.

Helm network access is disabled by default. Set `HELM_ALLOW_NETWORK=true` only
when repository or OCI retrieval is explicitly permitted. Vendored and
uploaded charts work without network access.

Policy datasets are maintained once under `cats-image/policy/` and copied into
the unified image. Portal settings determine compliance; the scanner preserves
complete raw evidence rather than applying a second local policy gate.

## CI integration

`.gitlab-ci.yml` and the `cats_*` templates are intentionally small. They use
the published CATS image, transport the `.cats/` workspace between stages, and
invoke the same CLI used locally. They do not clone scanner source or reinstall
tools at runtime.

Portal delivery is explicit and non-blocking. A failed delivery does not erase
the generated JSON or raw results.

## Important settings

| Variable | Purpose |
|---|---|
| `CATS_OFFLINE` | Keeps scanner and chart resolution disconnected by default |
| `CATS_HELM_ENABLED` / `HELM_SCAN_ENABLED` | Enables Helm discovery and rendering |
| `HELM_ALLOW_NETWORK` | Allows approved remote Helm retrieval |
| `HELM_CHART_ROOTS` | Limits automatic chart-root discovery |
| `HELM_VALUES_FILES` | Selects values/application catalog inputs |
| `SBOM_FORMATS` | Selects one or more SBOM serializations |
| `SBOM_CYCLONEDX_SPEC_VERSION` | Requests a supported CycloneDX version |
| `TRIVY_CONFIG_SCAN_ENABLED` | Enables source and rendered-manifest scanning |
| `TRIVY_IMAGE_CONFIG_SCAN_ENABLED` | Enables Trivy image configuration checks |
| `DOCKLE_IMAGE_CONFIG_SCAN_ENABLED` | Enables Dockle image hardening checks |
| `CATS_PORTAL_URL` | Portal base URL for explicit assessment submission |
| `CATS_PORTAL_TOKEN` | Bearer token for assessment submission |
| `CATS_PORTAL_CA_FILE` | Optional CA file for a private portal endpoint |

## Tests

Python tests cover the CLI contract, recursive Helm discovery, SBOM formats,
portal result creation, and exported artifacts:

```text
python -m pytest scanning-main/tests
```

Shell fixtures under `tests/` exercise Helm rendering, image evidence,
configuration normalization, and offline scanner behavior when their required
tools are installed.
