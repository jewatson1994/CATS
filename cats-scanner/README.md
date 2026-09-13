# CATScan

CATScan is the reusable tool image for the CATS scanning pipeline. It keeps
scanner installation out of application pipelines and provides a consistent,
reviewable toolchain:

- Syft for SBOM generation (Alpine-packaged version, existing behavior)
- Grype for offline vulnerability scanning (Alpine-packaged version, existing behavior)
- Trivy `0.69.3` for configuration and rendered Kubernetes manifest scanning
- Dockle `0.4.15` for container-image hardening checks
- Helm `4.2.3` for linting, dependency handling, and deterministic rendering
- Docker CLI, `jq`, `yq`, Bash, curl, wget, git, Miller, zstd, and supporting tools

The image does not contain service data, credentials, or Copa. Copa remains in
the existing patching job and is not changed by this scanner-image update.

## Integrity and version policy

Trivy, Dockle, and Helm are installed from version-specific release archives.
Their reviewed SHA-256 values are pinned in the Dockerfile and CI
configuration. A build fails before installing a binary if its archive does
not match.

Current amd64 pins:

| Tool | Version | SHA-256 |
| --- | --- | --- |
| Trivy | `0.69.3` | `1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75` |
| Dockle | `0.4.15` | `8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad` |
| Helm | `4.2.3` | `e9b88b4ee95b18c706839c28d3a0220e5bc470e9cd9262410c90793c45ff8b7c` |

Update a version and checksum together after reviewing the corresponding
official release. The build deliberately rejects non-amd64 targets until a
second architecture and its checksum are explicitly approved.

## Build and test locally

```bash
docker compose build
docker compose run --rm catscan
```

The Compose command runs `catscan-self-test`, which verifies tool versions,
lints and renders the bundled smoke-test chart, scans the rendered manifest
using Trivy's embedded checks, and validates the JSON report shape.

To inspect versions only:

```bash
docker compose run --rm catscan catscan-version
```

## Disconnected image builds

If the Docker builder cannot reach GitHub or `get.helm.sh`, download the
official archives on an approved connected system and place them under
`tool-archives/` before building:

```text
tool-archives/
  trivy_0.69.3_Linux-64bit.tar.gz
  dockle_0.4.15_Linux-64bit.tar.gz
  helm-v4.2.3-linux-amd64.tar.gz
```

The same pinned checksum verification runs for local archives. The Docker build
still requires access to the configured Alpine package repositories unless the
base image already contains or internally mirrors those packages.

## Offline Trivy behavior

Use the supplied wrapper for configuration and rendered-manifest scans:

```bash
catscan-trivy-config --format json --output trivy-config.json ./manifests
```

`catscan-trivy-config` disables checks updates, version checks, telemetry, and
progress output. Trivy `0.69.3` embeds a release-time checks bundle, so
configuration scanning works with no external database or registry access.

The runtime cache path is:

```text
/opt/catscan/trivy-cache
```

It is exposed as `TRIVY_CACHE_DIR` and is writable for CI jobs. To bundle an
approved vulnerability database for future Trivy vulnerability use, place the
reviewed files here before rebuilding:

```text
trivy-cache/
  db/
    trivy.db
    metadata.json
```

Those DB files are not needed for the planned configuration/Helm scans. Avoid
sharing one writable Trivy cache between concurrent scanner processes because
the local cache uses file locking; copy it per job when parallel scans are
required.

## Offline Helm and umbrella charts

Helm uses these in-image paths:

```text
HELM_CACHE_HOME=/opt/catscan/helm/cache
HELM_CONFIG_HOME=/opt/catscan/helm/config
HELM_DATA_HOME=/opt/catscan/helm/data
```

For reliable offline operation, vendor every dependency archive under the
umbrella chart's `charts/` directory and commit `Chart.lock`. Rendering the
umbrella chart then includes nested subcharts in one manifest stream:

```bash
helm lint charts/my-service
helm template my-service charts/my-service \
  --namespace my-service \
  --include-crds \
  --values charts/my-service/values.yaml \
  > rendered.yaml

catscan-trivy-config \
  --format json \
  --output trivy-helm.json \
  rendered.yaml
```

`helm dependency build --skip-refresh` prevents repository index refreshes,
but it can still need a dependency archive. Vendoring dependencies under
`charts/` is therefore the dependable air-gapped method. A service with several
subcharts should point the pipeline at its top-level umbrella chart; Helm will
render enabled nested dependencies using that chart's values.

## Grype database

The scanner image refreshes the Grype vulnerability database during the Docker
build and carries that cache into the final image. The default endpoint is
Anchore's v6 distribution URL. To use an approved internal mirror, override
the build argument:

```bash
docker build \
  --build-arg GRYPE_DB_REFRESH="$(date -u +%Y%m%d%H%M%S)" \
  --build-arg GRYPE_DB_UPDATE_URL=https://mirror.example/grype/v6/latest.json \
  -f Dockerfile .
```

Change `GRYPE_DB_REFRESH` for each rebuild (or use `--no-cache`) so Docker
does not reuse a previously downloaded database layer. The final all-in-one
image must always be built from the freshly rebuilt scanner base; it cannot
recover a database that is absent from an already-cached base image.

For a connected build from the repository root:

```bash
docker build --pull \
  --build-arg GRYPE_DB_REFRESH="$(date -u +%Y%m%d%H%M%S)" \
  -f cats-scanner/Dockerfile -t catscan-base:local cats-scanner
```

The build fails unless it finds a non-empty `vulnerability.db`, validates its
Grype metadata, and successfully runs `grype db status` with automatic updates
disabled. A prepared cache directory or `grype-vuln-db.tar.zst` may be placed
in `grype-db/`; the Dockerfile uses/imports that content and performs the same
checks without needing network access.

The runtime image disables Grype's automatic network update and database-age
failure checks, so scans remain usable in an air-gapped environment. Rebuild
the image when a newer vulnerability snapshot is approved.

After building, verify the bundled database and an offline scan explicitly:

```bash
docker run --rm --network none cats-tool:local \
  sh -ec 'du -sh /opt/catscan/grype-db; GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_REQUIRE_UPDATE_CHECK=false GRYPE_DB_VALIDATE_AGE=false GRYPE_CHECK_FOR_APP_UPDATE=false grype db status && grype dir:/usr --output json >/tmp/grype-offline.json'
```

The `--network none` test uses files already present in the image and will fail
if Grype tries to update or cannot read the bundled cache.

To explicitly prepare the build-context cache on a connected build host, run:

```bash
./cats-scanner/scripts/prepare-grype-db.sh
```

This updates `cats-scanner/grype-db/` using the installed Grype client, then
validates the database structure and status. The directory's `.gitkeep` is not
considered database content and cannot satisfy the image build validation.

For an explicitly approved offline archive, the existing import helper remains
available. Place the archive and metadata in `grype-db/` before building:

```text
grype-db/
  grype-vuln-db.tar.zst
  latest.json
  import.json
```

Import it in a scan job with:

```bash
catscan-import-grype-db
```

If no archive exists, the helper safely does nothing. Existing Syft, Grype, and
patching/Copa workflows are otherwise unchanged.

## Enterprise certificates

Place a PEM bundle containing the trusted roots and intermediate at:

```text
certs/host-ca-bundle.crt
```

Separate public `.crt` files are also supported. Never place private keys in
this project or image. Rebuild CATScan whenever the enterprise trust chain
changes.

## Publish from GitLab CI

The optional GitLab pipeline builds an immutable commit/tag image plus
`latest`. By default it publishes to the current GitLab project's container
registry:

```text
$CI_REGISTRY_IMAGE
```

The job accepts these neutral overrides:

- `CATSCAN_IMAGE` — complete destination repository
- `CATS_REGISTRY` — registry host; defaults to `CI_REGISTRY`
- `CATS_REGISTRY_USERNAME` — defaults to `CI_REGISTRY_USER`
- `CATS_REGISTRY_PASSWORD` — defaults to `CI_REGISTRY_PASSWORD`
- optional `CATSCAN_BASE_IMAGE` (defaults to `alpine:latest`; set this to an approved internal base when required)

Use a narrowly scoped robot or workload identity with pull/push access only to
the scanner image repository.

After building, CI runs `catscan-self-test` before either tag is pushed.

## Use from a scanning template

```yaml
default:
  image: "registry.example.invalid/security/cats-scanner:latest"
```

Because GitLab pulls the job image before `before_script`, configure registry
authentication on the runner or through `DOCKER_AUTH_CONFIG`. Scan jobs can
then verify the installed toolchain with:

```bash
catscan-version
catscan-self-test
```
