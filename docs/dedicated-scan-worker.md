# Dedicated scan worker

The Portal accepts scan submissions, stores durable jobs and immutable input envelopes, and coordinates execution in PostgreSQL. The separate `scan-worker` claims jobs over authenticated HTTP, downloads verified inputs, acquires declared Helm charts, runs the existing scanner phases, and returns a verified evidence envelope. The Portal performs authoritative evidence ingestion. The worker has no database credentials or Docker socket.

## Deploy

Build the unified CATS image using the existing release workflow. Set `CATS_SCAN_WORKER_TOKEN` to a distinct random secret of at least 32 characters in `.env`; the same value is required by Portal and worker. Keep `.env` private. Compose requires the variable; the protocol rejects short tokens. Rotate it on both services together. `build.ps1` recreates and checks the image identity of Portal, patch-worker, and scan-worker.

Before starting Compose, manually create `scan-registry-auth` next to the selected Compose file, or set `CATS_SCAN_REGISTRY_AUTH_SOURCE` to an existing absolute directory. An empty directory supports public registries; private registries require a scoped Docker `config.json` readable by UID 10001. The bind is read-only and refuses to create a missing directory. Run `docker compose up -d --wait`. The default worker endpoint is `http://portal:8000`: 8000 is the container listener, while `CATS_PORT=8080` publishes the Portal on the host. Worker APIs under `/internal/scan-worker` require the worker bearer token and per-attempt credentials for input, heartbeat, and result operations. Use HTTPS or a trusted private network when separating hosts.

## Controls

| Setting | Compose default | Purpose |
| --- | --- | --- |
| `CATS_SCAN_CONCURRENCY` | 1 | Active scans per worker process |
| `CATS_SCAN_LEASE_SECONDS` | 90 | Claim lease; worker renews approximately every third of this interval |
| `CATS_SCAN_JOB_TIMEOUT` | 3600 | Whole attempt execution deadline, in seconds |
| `CATS_SCAN_QUEUE_CAPACITY` | 100 | Portal admission bound for nonterminal jobs |
| `CATS_SCAN_MAX_ATTEMPTS` | 3 | Maximum claimed attempts before lease recovery ends in error |
| `CATS_SCAN_DISK_BYTES` | 21474836480 | Application input, output, and result transfer budget |
| `CATS_SCAN_CPUS` | 2 | Container CPU limit |
| `CATS_SCAN_MEMORY` | 4g | Container memory limit |
| `CATS_SCAN_PIDS` | 256 | Container process limit |
| `CATS_SCAN_TMP_BYTES` | 536870912 | `/tmp` tmpfs size |

The worker runs as UID/GID 10001 with a read-only root filesystem, all capabilities dropped, and no new privileges. `/tmp` is a scoped tmpfs; `/var/lib/cats-scan` is its persistent writable workspace. Scanner image access is daemonless. The image installs `/usr/local/bin/cats-scan` as a symlink to `/opt/cats/scanning/scripts/run-scan.sh`; Compose explicitly sets `CATS_IMAGE_SOURCE=daemonless`, and image scanning uses the existing Syft registry/archive path. `DOCKER_CONFIG=/run/cats-registry-auth` points scanner tools at the read-only credential directory. Use registry-specific, pull-only credentials scoped to approved repositories; avoid broad personal or administrative credentials. Credential helper configurations require the helper executable inside the image, so verify the chosen authentication format on the target host. The application disk budget is checked periodically and does not impose a filesystem quota; provision a host volume quota when a hard storage bound is required. Cache copies and concurrent jobs consume additional space, so size the volume accordingly.

The worker joins only the internal `scan_control` network shared with Portal and its dedicated `scan_egress` network. Portal also retains its default network for database and patch-worker communication; the worker has no direct membership in that network. `scan_egress` supplies outbound connectivity, but Compose does not enforce a destination allowlist. Enforce approved registry/chart destinations and block private infrastructure access with deployment firewall or equivalent network policy, then verify actual routing and DNS behavior on the target host.

## Offline databases and trust

Policy data and baked Grype/Trivy databases are mounted read-only from the existing shared volumes. On first initialization the worker copies databases into writable workspace caches, allowing scanner lock/cache writes while preserving the source. Existing workspace caches are retained on restart and are not automatically refreshed from a changed source. When updating offline databases, stop the worker, replace only its copied cache directories after preserving any required data, then restart to seed the new source. Helm cache/config/data directories also live in the workspace.

Uploaded image archives can be scanned without a Docker daemon. Registry scans and declared remote Helm charts still require reachable sources and suitable trust. Submission trust bundles are passed to scanner tools. `HELM_ALLOW_NETWORK=false` remains the default for Helm dependency operations; declared chart acquisition is a separate worker preparation step. A chart acquisition failure is recorded in skipped-chart evidence.

## Recovery, cancellation, and evidence

Job status and attempt identity survive Portal restarts. Expired running claims are recovered with bounded retry backoff. Every new claim receives a fresh attempt ID and token; the Portal rejects stale, expired, or unrelated attempts. A worker stops its scanner process group when shutdown, timeout, or lease loss occurs. Cancellation uses the existing job cancellation API (`POST /api/public/jobs/{job_id}/cancel`); the next heartbeat fails the attempt fence, so termination follows heartbeat detection rather than being instantaneous.

A successful transfer is validated against job identity, input digest, manifest file checksums, allowed output paths, and scanner exit status. The Portal records evidence before ingestion; identical completed transfers are accepted as duplicates and conflicting replacements are rejected. Portal maintenance ingests ready evidence using a PostgreSQL advisory lock. Service scan ingestion uses the existing `public:<job>` execution identity for replay protection. Required-phase failures retain diagnostics and finish as errors; ingestion failures retain results for review.

Temporary worker attempt directories are removed after execution. Portal job artifacts and database history provide retained evidence. Preserve both the Portal artifact volume and PostgreSQL backups. Review worker logs, Portal job status, and retained phase logs when an attempt repeatedly expires. The worker healthcheck tests a local heartbeat file younger than 120 seconds; it confirms process-loop activity, not scanner tool health or Portal connectivity.

## Verification limits

Both Compose configurations were parsed and validated, and the updated PowerShell build script passed syntax validation. Runtime Docker build, nonroot scanner execution, container health behavior, and resource enforcement have not been verified in this workspace because Docker daemon access was denied. Perform those deployment checks on the target host before relying on these controls operationally.

## Upgrade and rollback

Back up PostgreSQL and the Portal `public_jobs` artifact volume together before upgrading. Stop scan admission and allow active scans to finish, or cancel them through the existing endpoint and confirm terminal status. Deploy Portal and worker from the same image version; the release script checks their image identities. The new coordinator creates durable scan tables through the existing application database initialization. Old in-memory active jobs do not migrate into the durable queue automatically: complete or resubmit them during the maintenance window.

For rollback, stop admission and the worker first, preserve database and artifact backups, and select the previous Portal image and Compose configuration together. Existing durable jobs will not be serviced by an older Portal; reconcile or resubmit them after rollback. Do not delete retained evidence to make a rollback start. The coordinator automatically retries expired attempts up to the configured maximum; terminal errors require review and a new submission, rather than an assumed operator retry command. Forced container termination can leave incomplete attempt directories in the worker volume; clean only confirmed inactive directories after stopping the worker. Do not remove its database caches as part of routine job cleanup.

## Static review and measured test evidence

The unified image installs the pinned `requests==2.32.5` dependency from `portal/requirements.txt`. Worker chart size/member limits, Helm acquisition timeout/reserve, discovery limits, and service-definition limits mirror Portal configuration. Offline Grype/Trivy behavior comes from the unified scanner image; writable cache paths and Grype metadata path are explicitly overridden for the worker. Copied cache files belong to the nonroot copying process, while a fresh named workspace receives UID/GID 10001 ownership from the image. Existing or restored volumes must independently have compatible ownership and readable source caches.

Reviewed scanner shell temporary-file usage writes data beneath `/tmp` and executes bundled tools/scripts from the image; no direct execution of a temporary binary was found in those scripts. The `/tmp` noexec setting is therefore retained. Scanner tool internals, custom runner overrides, and private credential helpers still need a real nonroot container test. A process-loop healthcheck can remain healthy while Portal is unreachable; worker logs and queue age must also be monitored. Lease loss prevents authorized submission and terminates the scanner after detection. HTTP calls have finite connection/read timeouts, and the attempt timeout starts before acquisition. Deadline detection fences submission and stops scanner execution; an in-progress acquisition or transfer may return only when its own finite request timeout expires. End-to-end deadline behavior has not been measured in a container.

| Verification performed in this workspace | Result |
| --- | --- |
| Root and template Compose parsing with example environment | Passed |
| Rendered worker user, root read-only flag, mounts and network membership | Matched configured isolation |
| Registry bind read-only and missing-path creation disabled | Confirmed in rendered Compose |
| Updated PowerShell build script syntax parsing | Passed |
| Whitespace validation | Passed |
| Docker daemon/build/container execution | Unavailable: daemon access denied |
| VM latency, responsiveness, throughput, peak disk/memory, actual egress policy | Not measured |

These checks establish configuration consistency only. Record deployment-host measurements for simultaneous Portal requests and representative scans, cancellation and restart recovery, private/offline registry access, mounted-cache permissions, noexec behavior, and actual CPU/memory/PID/firewall enforcement before claiming operational performance or isolation.
Normal submission routes never schedule the former Portal scanner executor. That retained diagnostic function rejects execution unless `CATS_ENABLE_LEGACY_PORTAL_SCANNER=true` is explicitly set; the flag does not reroute production submissions. Leave it unset in production. Worker evidence includes `worker-provenance.json` with tool versions, available vulnerability-database metadata, resolved image digest files, and execution timestamps. Unsupported or unavailable metadata is recorded explicitly rather than inferred.

The regression suite completed **201 tests in 27.95 seconds**, covering coordinator fencing, checksum/path validation, authentication, cancellation, subprocess termination, retries, duplicate ingestion, incomplete results, definition history, Helm compatibility, and existing artifact query behavior. After final credential-isolation and Windows publication changes, the 70 affected checks passed in 7.98 seconds, including two additional assertions for definition notification and Helm credential isolation. These use local SQLite and simulated scanner processes; PostgreSQL advisory locking and concurrent container behavior still require target-host validation. No runtime throughput or Portal latency improvement is claimed.
