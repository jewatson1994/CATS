# Live diagnostics acceptance

These checks supplement the diagnostic unit/integration suites with PostgreSQL,
real HTTP sessions, actual tool processes, and browser verification. Use disposable
fixtures only. No production database, registry, or existing deployment is needed.

## PostgreSQL

From the repository root, with Docker and portal test dependencies available:

```powershell
.venv/Scripts/python.exe tools/test_diagnostics_postgres.py
```

The runner creates a uniquely named PostgreSQL 16 container on a random loopback
port, runs the selected suites, then removes only its own container. It sets
`CATS_TEST_DATABASE_URL`, `CATS_TEST_POSTGRES_URL`, and `TEST_DATABASE_URL` to that
disposable instance. Never point the scan migration tests at a shared database:
they intentionally recreate fixture tables. The diagnostic-specific PostgreSQL
tests use temporary schemas and drop only those schemas.

## Running GUI and HTTP sessions

The recorded acceptance stack uses an existing local `cats:remaining-20261107`
image for Python dependencies and mounts the current portal source and compiled
frontend read-only. Build the frontend first:

```powershell
Push-Location portal/frontend
npm run build
Pop-Location
.venv/Scripts/python.exe tests/diagnostics/prepare_gui.py
docker compose -f .test-temp/diagnostics-gui-20261116/compose.json up -d --pull never
docker compose -f .test-temp/diagnostics-gui-20261116/compose.json exec -T portal /opt/cats-venv/bin/python /acceptance/gui_seed.py --allow-isolated-fixtures --url http://127.0.0.1:8000
docker compose -f .test-temp/diagnostics-gui-20261116/compose.json exec -T portal /opt/cats-venv/bin/python /acceptance/live_http.py --url http://127.0.0.1:8000 --output /evidence/live-http.json
```

`prepare_gui.py` refuses to overwrite the existing evidence directory. It creates
an isolated database, dedicated networks, and a portal exposed only at
`http://127.0.0.1:18089`. Its static credentials are disposable test values, not
deployment defaults. The fixture seeder rejects unrelated application data.
The image must already be present; no image pull is required.

The seeder creates three explicitly synthetic worker failures with a fake secret
sentinel, then submits a real pipeline ingestion request against an ownerless
service. That request must return HTTP 409 and persist its diagnostic. The HTTP
runner uses ordinary login/session handling, without dependency overrides, to
check administrator access, anonymous/viewer denials, all query filters,
pagination, recurrence, redaction, public projection, correlation, and no-store
headers. Credentials come from the fixture environment and are omitted from
evidence.

Browser acceptance covers real login, navigation, history/detail inspection,
refresh persistence, source/cause/resolution, combined filters, empty results,
job links, correlation links, Copy Diagnostics via actual paste, JSON export,
and viewer denial. Evidence is under `.test-temp/diagnostics-gui-20261116/`.
The GUI stack is intentionally left running for review. To stop this fixture
stack after review:

```powershell
docker compose -f .test-temp/diagnostics-gui-20261116/compose.json down
```

This removes only the named acceptance stack. It does not target other CATS
containers or volumes.

## Installed external tools

The offline harness uses the installed Trivy, Grype, Syft, Dockle, and Copa
binaries. It mounts the current source read-only, uses a disposable SQLite job
store, has no Docker socket, and runs with `--network none`:

```powershell
New-Item -ItemType Directory -Path .test-temp/diagnostics-tools-live -Force | Out-Null
docker image save --output .test-temp/diagnostics-tools-live/alpine.tar alpine:3.20.0
$repo = (Get-Location).Path
$evidence = Join-Path $repo '.test-temp/diagnostics-tools-live'
docker run --rm --pull never --network none --mount "type=bind,source=$repo,target=/workspace,readonly" --mount "type=bind,source=$evidence,target=/evidence" --workdir /workspace/portal --entrypoint /opt/cats-venv/bin/python cats:remaining-20261107 /workspace/tests/diagnostics/live_tools.py --output /evidence
```

Each case uses `patching.run_command` and durable-job submit/claim/execute. The
harness checks committed terminal state, cleared leases, error history,
correlation, current/last successful stage, worker identity, attempts, and
tool/exit/timeout metadata. Successful runs must return structured JSON;
expected failures must preserve useful evidence and omit administrative details
from the public projection. Results and diagnostics are saved in
`.test-temp/diagnostics-tools-live/report.json`.

The local image has a Grype vulnerability database. Its Trivy cache has no
vulnerability database, so the offline Trivy success cases use its secret scanner
and separately verify the missing offline database failure. Copa failure
reporting is exercised; a successful patch needs a functioning BuildKit service
and the required image/package sources. These checks cover real processes and
the command/durable-worker boundaries, not the complete scan/patch pipelines or
publication to a live registry.

## Successful Trivy vulnerability scan and Copa patch

`live_tools_success.py` runs real Trivy vulnerability scans and a Copa patch
through `patching.run_command` and the durable-job boundary. It requires a genuine
Trivy database, a vulnerable image, and running Docker and BuildKit services.
The following setup creates disposable services with unique names. Docker runs
inside its own container and image store; neither service mounts the host Docker
socket or publishes a port. Both services require privileged containers. Their
default bridge network allows external egress for image and package downloads.
This is command/worker acceptance, not the production retained-input isolation
contract or the complete application patch/publication pipeline.

The setup follows Copa's [custom BuildKit address support](https://project-copacetic.github.io/copacetic/website/custom-address)
and Trivy's [database connectivity guidance](https://trivy.dev/docs/latest/guide/advanced/air-gap/).

Run from the repository root in PowerShell. The tools image must already exist;
the Docker service image, source image, and Trivy DB are downloaded explicitly.
Use a fresh suffix and evidence directory for each run:

```powershell
function Invoke-DiagnosticsDocker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed with exit code $LASTEXITCODE" }
}
$repo = (Get-Location).Path
$run = 'cats-diag-success-' + (Get-Date -Format yyyyMMddHHmmss) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$evidence = Join-Path $repo ".test-temp/$run"
$toolsImage = 'cats:remaining-20261107'
$sourceImage = 'docker.io/library/alpine@sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd'
New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
Invoke-DiagnosticsDocker image inspect $toolsImage
Invoke-DiagnosticsDocker pull docker:28.5.2-dind
Invoke-DiagnosticsDocker volume create --label "cats.acceptance=$run" "$run-docker-socket"
Invoke-DiagnosticsDocker volume create --label "cats.acceptance=$run" "$run-buildkit-socket"
Invoke-DiagnosticsDocker volume create --label "cats.acceptance=$run" "$run-trivy-cache"

Invoke-DiagnosticsDocker run -d --pull never --name "$run-docker" --label "cats.acceptance=$run" --privileged --network bridge --mount "type=volume,source=$run-docker-socket,target=/var/run" --entrypoint dockerd docker:28.5.2-dind --host unix:///var/run/docker.sock --storage-driver overlay2
Invoke-DiagnosticsDocker run -d --pull never --name "$run-buildkit" --label "cats.acceptance=$run" --privileged --network bridge --mount "type=volume,source=$run-buildkit-socket,target=/run/acceptance-buildkit" --entrypoint buildkitd $toolsImage --addr unix:///run/acceptance-buildkit/buildkitd.sock --oci-worker-net host --oci-worker-snapshotter native --containerd-worker=false

for ($attempt = 0; $attempt -lt 30; $attempt++) {
    & docker exec "$run-docker" docker --host unix:///var/run/docker.sock info *> $null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 2
}
if ($LASTEXITCODE -ne 0) { throw 'Disposable Docker daemon did not become ready' }
Invoke-DiagnosticsDocker run --rm --pull never --network bridge --mount "type=volume,source=$run-docker-socket,target=/var/run" --entrypoint docker $toolsImage --host unix:///var/run/docker.sock pull $sourceImage
Invoke-DiagnosticsDocker run --rm --pull never --network bridge --mount "type=volume,source=$run-trivy-cache,target=/trivy-cache" --entrypoint trivy $toolsImage image --cache-dir /trivy-cache --download-db-only --no-progress

Invoke-DiagnosticsDocker run --rm --pull never --network bridge --mount "type=bind,source=$repo,target=/workspace,readonly" --mount "type=bind,source=$evidence,target=/evidence" --mount "type=volume,source=$run-docker-socket,target=/var/run" --mount "type=volume,source=$run-buildkit-socket,target=/run/acceptance-buildkit" --mount "type=volume,source=$run-trivy-cache,target=/trivy-cache" --workdir /workspace/portal --entrypoint /opt/cats-venv/bin/python $toolsImage /workspace/tests/diagnostics/live_tools_success.py --image $sourceImage --patched-tag "$run-patched" --docker-host unix:///var/run/docker.sock --buildkit-addr unix:///run/acceptance-buildkit/buildkitd.sock --cache-dir /trivy-cache --output /evidence/success
```

The source digest identifies the Alpine 3.20.0 multi-platform image used for this
fixture. BuildKit resolves the pinned source from its registry independently of
the Docker service's local image store. Do not substitute a daemon-local image
tag that BuildKit cannot resolve. Keep the same downloaded Trivy DB for both
scans; the harness verifies its bytes remain unchanged. Package repositories and
the current DB may change, so a future run can require another digest-pinned
image with fixable OS vulnerabilities.

Inspect `success/report.json` for the complete outcome, image identities, DB
metadata/hash, commands, committed job states, and package/CVE comparisons.
`before.trivy.json` and `after.trivy.json` retain sanitized scanner reports;
`before.tar` and `after.tar` retain the scanned image archives. A successful
result requires actual fixable source findings, changed image/package versions,
and removal of at least one original package/CVE finding. It does not assert
that every vulnerability was fixed. Copa consumes the real Trivy report using
`--scanner trivy`; this does not exercise the application's Grype-to-native Copa
report conversion.

To verify the saved archives with networking disabled, use the same cache:

```powershell
foreach ($stage in @('before', 'after')) {
    Invoke-DiagnosticsDocker run --rm --pull never --network none --mount "type=bind,source=$evidence,target=/evidence" --mount "type=volume,source=$run-trivy-cache,target=/trivy-cache" --entrypoint trivy $toolsImage image --input "/evidence/success/$stage.tar" --cache-dir /trivy-cache --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --pkg-types os --list-all-pkgs --format json --output "/evidence/offline-$stage.trivy.json"
}
```

Compare these reports' image IDs, package inventories, and package/CVE findings
with the accepted reports. The recorded follow-up passed all six durable-job
cases and both offline scans; see the [acceptance report](../../docs/diagnostics-audit.md)
for exact results and retained evidence.

After inspecting the evidence, remove only the objects created with this run's
suffix. These commands retain the host evidence directory:

```powershell
Invoke-DiagnosticsDocker rm --force --volumes "$run-buildkit" "$run-docker"
Invoke-DiagnosticsDocker volume rm "$run-buildkit-socket" "$run-docker-socket" "$run-trivy-cache"
```
