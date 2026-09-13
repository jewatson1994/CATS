# Standalone scan image

The unified image runs the portal and the non-persistent scanner without
GitLab. The image-owned `cats` CLI is the stable interface:

```text
cats version
cats prepare --source /job/source --output /job/.cats
cats evaluate --source /job/.cats --output /job/.cats/results
cats push assessment --input /job/.cats/results/portal-result.json
```

The legacy scanner worker command remains available:

```text
cats-scan /job/input /job/output
```

Standalone scans retain raw vulnerability matches in `portal-result.json` so
the read-only results page is not narrowed by the authenticated portal's
fixable-only policy. Authenticated GitLab ingestion keeps the existing
fixable-only contract.

Input may contain `images.yml`, `images.txt`, `service.yml`, `charts/`,
`charts.yml`, and `configuration/`. `images.txt` is converted to a minimal
`images.yml` automatically. Missing/unavailable images and charts are recorded
as incomplete evidence; they do not prevent the remaining work from running.

The public portal Scan page accepts the same chart input without requiring a
service name: upload a `.tgz`, `.tar.gz`, or `.zip` chart bundle, or provide a
chart URL (one per line). Direct archive URLs, Helm repository/index URLs, and
public OCI references (`oci://...`) are supported; repository URLs discover the newest listed version of each
chart (bounded by `CATS_PUBLIC_MAX_REPOSITORY_CHARTS`, default 25). Append
`#chart-name` to a repository URL to select one chart. Multiple chart archives
may be selected in one submission. A local Docker `.tar`/`.tar.gz`/`.tgz` archive may also be uploaded;
all tags loaded from a multi-image archive are added to the scan automatically.
Uploaded archives are kept only in the job's temporary workspace and discarded
with the job. A chart-only submission is valid; the worker creates an empty
`images.yml`, skips SBOM phases, and still renders and scans the chart
configuration.

The orchestrator runs these phases in order:

1. `cats prepare` / `prepare_inputs`
2. `cats evaluate` (SBOM generation, Grype, configuration, and reporting)
3. optional `cats patch` and `cats push patch`

It intentionally does not publish images, sign images, upload DefectDojo, or
call portal ingestion. The portal/API can expose the output as a temporary
job artifact, and authenticated users can explicitly submit a completed result
to CATS.

Runtime defaults are offline-safe (`TRIVY_OFFLINE=true`, no Helm network
access, and disabled database auto-updates). A connected deployment may
override those variables for updates or remote chart dependencies.
