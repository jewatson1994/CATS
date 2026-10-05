# CATS unified portal/scanning image

This project builds the deployable CATS image. The unified image contains the
application and the versioned risk-intelligence snapshot used for optional
Risk Based KEV and EPSS policy evaluation, plus the standalone scanner worker.
Raw mode uses administrator-defined severity-specific due dates. The PostgreSQL
database remains external and persistent.

The image exposes the stable `cats` CLI for both GitLab and non-GitLab runs:
`cats version`, `cats prepare`, `cats evaluate`, optional `cats patch`, and
explicit authenticated `cats push assessment|patch` commands. It also keeps
`cats-scan INPUT_DIR OUTPUT_DIR` for backwards compatibility. Publish, sign,
and DefectDojo stages are not included in the image-owned workflow.

## Build locally

From the repository root, build the CATS runtime:

```text
python scripts/build-cats-release.py --cats-version 1.3 --tag cats:1.3
```

On Windows, `build.bat` builds this runtime and then deploys the image. The
runtime profile retains scanner and validator tools without preparing Ubuntu
packages or the offline host installation bundle. Existing validator API
connections remain available; the offline SSH installer is unavailable unless
its separately verified payload is configured. Container-based VM provisioning
is not yet wired into the managed provisioning flow.

To explicitly prepare the optional self-contained offline host installer, use
`--profile release`. That profile downloads and qualifies trusted release inputs.

Save the versioned image as a Docker archive for transfer or offline import:

```text
docker save --output cats-1.3.tar cats:1.3
```

Verify or restore it with:

```text
docker image inspect cats:1.3
docker load --input cats-1.3.tar
```

The scanner build pulls the current Grype database from Anchore. Always rebuild
that scanner layer with a new cache-busting value before building the final
image; rebuilding only `Dockerfile.all-in-one` can reuse a binary-only base and
produce an image with an empty Grype cache:

```bash
docker build --pull --no-cache \
  --build-arg GRYPE_DB_REFRESH="$(date -u +%Y%m%d%H%M%S)" \
  -f cats-scanner/Dockerfile -t catscan-base:local cats-scanner
python scripts/build-cats-release.py --scanner-base catscan-base:local \
  --cats-version 1.3 --tag cats-portal:local
```

Both stages now fail if `/opt/catscan/grype-db` does not contain a real
non-empty Grype `vulnerability.db` and valid metadata. The final image runs
the same offline validation, so `.gitkeep` cannot satisfy the release build.
The image also disables Grype's application-version update check so runtime
scans do not contact Anchore in a disconnected environment.

The root `compose.yaml` runs the versioned image for both the portal and patch
worker. Set `CATS_IMAGE=cats-portal:local` in the root `.env` to run an
unversioned local build instead.

## Refresh policy data

`scripts/refresh-policy-data.sh` downloads the current CISA KEV catalog and
EPSS snapshot into `policy/`. The scanner base image refreshes the Grype
database during its Docker build; the final all-in-one image carries that
database for offline runtime scans and patch jobs.

In an isolated environment, replace the files in `policy/` from your approved
transfer process, then rebuild and publish the image.

## GitHub image build

`.github/workflows/build-cats-tool.yml` builds a fresh scanner base, builds the
unified image from `Dockerfile.all-in-one`, runs an image smoke test, and pushes
both the immutable commit tag and `latest` to:

```text
ghcr.io/<github-owner>/cats-tool
```

The workflow runs for pushes to `main`, on its maintenance schedule, and by
manual dispatch. Deployment remains separate so an image can be promoted by
immutable digest according to the destination environment's release process.
