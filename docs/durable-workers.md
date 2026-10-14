# Durable workers and managed provisioning

HQ accepts expensive work into PostgreSQL and returns a job identifier. The same
CATS image runs the portal and each worker under different startup commands.
No message broker is required. Runtime validation remains on the separate
validator VM; image patching remains in the existing patch-worker.

## Ownership and recovery

| Process | Work and boundary |
| --- | --- |
| portal | Authorizes and persists requests; serves status and authorized downloads. No Docker socket. |
| remediation-worker | Plans, expensive previews, source resolution, candidate orchestration, validation coordination and delivery. Calls patch-worker for image patching. |
| export-worker | Spreadsheet, diagram, evidence and ZIP generation. Uses existing export builders; does not assemble remediation candidates a second time. |
| provisioning-worker | Privileged SSH/Docker provisioning with the existing managed-validator operation and attempt records. Has the HQ Docker socket; exposes no HTTP port. |
| scan-worker / portal-control | Existing scan queue and private control protocol, unchanged. |

The shared Jobs page projects the existing scan and provisioning records together
with the new `durable_jobs` table. List, counts and details respect current scope
permissions. Export jobs are visible only to their requester with every original
permission still present. Provisioning remains administrator controlled.

Remediation/export claims use database leases, heartbeats, claim tokens and
bounded retries (three by default). A dead worker's expired claim becomes eligible
after backoff. A stale worker cannot commit status or publish through the guarded
worker path. Remediation side effects retain domain receipts: interrupted candidate
or delivery work is safely terminalized for explicit domain retry; it is not
blindly re-published. Remote validation resumes its retained validation identifier.
Plan/export cancellation is supported before execution starts; Jobs exposes only
supported actions. Failed or cancelled plans/exports can be retried while their
attempt budget remains. Errors use sanitized diagnostics and correlation IDs.

Plans retain exact service version, execution, selected findings, and digest.
Execution still requires **Plan → Review → Confirm → Remediate → Validate → Deliver**.
Worker authorization is checked again. Retained-secret filtering and approval
checks remain in the shared remediation code. Navigation/restart does not lose
the persisted work.

## Export contract

Generation is queued for portfolio/service workbooks, Export All, purpose exports
(findings, mitigations, diagrams, SBOM, PPSM, POA&M, asset list), Helm diagrams,
portable service bundles and spreadsheet exchange. Existing downloads of already
generated scan results or retained signed delivery artifacts remain direct.

API callers receive HTTP 202 with `job_id` and `status_url`. Browser download links
redirect to `/jobs?job=<id>`. Poll `/api/v1/jobs/<id>` and follow `download_url`
after completion. Existing synchronous export clients must adopt this protocol.
Remediation plan/preview responses likewise contain a persisted job identifier
and pending state; the wizard waits for its result.

Submission captures service/version/execution identities without loading assessment
evidence. If these change before generation begins, the job fails and asks for a
new export. PostgreSQL generation uses one REPEATABLE READ snapshot, including
lazy evidence reads; template and other metadata are captured when the worker
starts. Historical exchange retains its explicitly selected version. Permissions
are checked at submission, execution, publication and download; new grants cannot
broaden a queued portfolio. Files publish by atomic rename only after completion.
Export All signing and OCI documentation retain the existing shared builders.

One cross-process export slot bounds disk contention. Completed files expire after
24 hours. Cleanup removes expired outputs and abandoned scratch directories.
An expired download returns HTTP 410; submit a new export. Default per-file limit
is 256 MiB, with a 4 GiB export directory budget and a conservative three-file-size
reservation for scratch. Linux also limits individual scratch files through
`RLIMIT_FSIZE`. Oversized exports fail with a diagnostic; increase budgets when
the deployment supports larger artifacts. Job metadata remains for audit.

## Provision without staging a release

The normal image build produces the unified CATS runtime. It does not prebuild a
final validator release. In **Administration → Validators**, enter the Ubuntu
VM's connection details, verify the SSH host fingerprint through the trust
workflow, supply SSH/sudo credentials and click **Provision**. No Build Payload
step or release directory is required.

The provisioning worker:

1. Connects with the explicitly trusted host key and checks OS, architecture,
   capacity and runtime prerequisites.
2. Resolves the immutable image ID of its own running unified CATS container
   (or configured immutable runtime) and the application's pinned Kind node image.
3. Acquires missing inputs only from approved internal digest references, prepares
   image archives and the isolated node recipe on demand, verifies checksums and
   records provenance. A matching verified cache can be reused.
4. Transfers assets, configures the supported container runtime from approved
   pinned packages if required, and provisions the containerized validator.
5. Configures mTLS and enrollment, runs the actual self-test and cleanup, and only
   then reports **Healthy**.

The cache identity includes runtime image, node image, architecture and recipe
hash. Changing any of them requires preparation again. Attempts persist the chosen
runtime identity before lengthy work; retries do not silently select another
image. The existing per-validator operation guard prevents simultaneous actions.
On recovery, the worker reconciles the target and enrollment before continuing.
Provisioning uses a one-hour lease (longer than bounded external operations),
10-second heartbeats, and up to three attempts with 30/60-second retry delays.
A process death can therefore take up to an hour to reclaim safely.

SSH credentials are encrypted with `CATS_CONFIG_ENCRYPTION_KEY` and cleared from
terminal attempts. They are not placed in command-line arguments or logs. Keep
this key stable and protect the database, shared validator data and Docker host.

### Disconnected inputs

The exact unified image and pinned Kind node can already be in HQ's Docker cache.
Otherwise configure internal sources:

```dotenv
CATS_PROVISIONING_INTERNAL_REGISTRIES=harbor.internal.example
CATS_PROVISIONING_CATS_SOURCE=harbor.internal.example/cats/runtime@sha256:<digest>
CATS_PROVISIONING_NODE_SOURCE=harbor.internal.example/cats/kindest-node@sha256:<required-digest>
```

These are configuration examples; replace the placeholders with actual immutable
identities. The node mirror must preserve the application's required digest.
The Docker daemon needs internal registry TLS trust. The provisioning worker
uses the existing read-only registry authentication directory through
`DOCKER_CONFIG`; configure its `config.json` for authenticated internal pulls.
`CATS_PROVISIONING_CATS_IMAGE` is normally blank (use the worker's exact image);
an override must be an immutable image ID or repository digest.

For targets without Docker 28+, configure
`CATS_PROVISIONING_INTERNAL_PACKAGE_HOSTS` and
`CATS_PROVISIONING_DOCKER_PACKAGES`. The latter is a JSON object keyed by
`ubuntu-22.04-amd64` or the supported target Ubuntu version, with a list of
`{"url":"https://packages.internal.example/path/package.deb","sha256":"<64 hex>"}`
records covering Docker and its full dependency closure. HTTPS redirects and
URL credentials are rejected. Packages are fetched into the managed cache,
verified, transferred, and checked with `dpkg --dry-run` before installation.
There is no public APT fallback. A target with suitable Docker installed needs
no package catalog. Missing images/packages report the missing dependency and
supported acquisition path before installation modifies the target.

The archive/package cache defaults to 32 GiB with seven-day expiry and stale
preparation cleanup after two hours. Set `CATS_PROVISIONING_CACHE_MAX_BYTES` for
larger runtimes. Docker image/build storage is separate from this archive budget:
monitor the daemon filesystem and provision host capacity for it. Preparation is
serialized through a cache lock. Probe containers have explicit 0.5 CPU, 256 MiB
and 64 PID limits; the isolated node recipe only copies its pinned entrypoint
(no build-time workload execution). The final self-test runs on the validator VM
under the existing strict runtime resource controls.

Existing verified staged releases remain supported through the optional
`CATS_MANAGED_VALIDATOR_RELEASE_SOURCE` bind mount. Leave it blank for automatic
on-demand preparation. The legacy build script flag `--prepare-validator-release`
is optional; it is not part of the normal managed flow.

## Upgrade an existing installation

Back up PostgreSQL and the existing encryption key. Upgrade the image and Compose
files together, preserving your environment values and existing volumes. Add the
three worker services and their named volumes from this revision. Remove the old
mandatory staged-release setting unless deliberately retaining that path.

```sh
# Select the newly built/imported image in the existing .env first.
docker compose config --quiet
docker compose up -d --force-recreate --wait portal portal-control scan-worker patch-worker remediation-worker export-worker provisioning-worker
docker compose ps
docker compose logs --tail=100 remediation-worker export-worker provisioning-worker
```

Portal startup creates the new job table and applies additive provisioning-attempt
columns. New workers wait for portal health. No manual data migration or scan-job
conversion is needed. Preserve `validator_payloads`; new `validator_data` stores
shared managed-validator state/cache and `export_jobs` stores worker outputs.
Do not use `down --volumes` during an upgrade. If a prior deployment stored custom
validator state only in a container's `/app/data`, copy it into the persistent
volume before replacing that container.

| Worker | Concurrent work | CPU | Memory | PIDs | Database pool |
| --- | --- | --- | --- | --- | --- |
| remediation-worker | 1 | 1 | 2 GiB | 256 | 2 main + 2 background; no overflow |
| export-worker | 1 shared export slot | 1 | 1 GiB | 128 | 2 main + 2 background; no overflow |
| provisioning-worker | 1 per process; per-validator exclusion | 1 | 2 GiB | 256 | 2 main + 2 background; no overflow |

Compose exposes `CATS_REMEDIATION_CPUS`/`CATS_REMEDIATION_MEMORY`,
`CATS_EXPORT_CPUS`/`CATS_EXPORT_MEMORY` and
`CATS_PROVISIONING_CPUS`/`CATS_PROVISIONING_MEMORY` settings.
New workers use 30-second shutdown grace periods. Remediation/export queue capacity
defaults to 200 and their leases to 120 seconds (`CATS_JOB_QUEUE_CAPACITY`,
`CATS_JOB_LEASE_SECONDS`). Budget the existing scan/patch engines, Docker child
workloads and database in addition to these processes. Do not scale provisioning
workers without capacity planning; host-level Docker work shares the portal VM.

## Verification scope

`portal/tests/test_durable_jobs_postgres.py` is an opt-in real PostgreSQL test
using a disposable schema (`CATS_TEST_POSTGRES_URL`). It verifies eight competing
claims, recovery receipts and stale-owner fencing. The remaining durable-job,
remediation, export and provisioning suites exercise permission revocation,
source drift, restart boundaries, artifact completeness and failure diagnostics.
On the local Docker Desktop daemon (29.6.2), on-demand preparation used the
already cached exact unified CATS image and pinned Kind base without network
access. Fresh preparation completed in 97.53 seconds; fully verified cache reuse
completed in 23.09 seconds. The disposable real-runtime smoke then finished
VERIFIED: actual Helm installation passed, the release was DEPLOYED, its one
expected pod became Ready, and cluster/network cleanup completed. Public egress
was blocked by the runtime container's network-none setting and the node's
verified isolated internal bridge. This exercised the Docker 29 empty-port
compatibility fallback using trusted clients inside the owned node. An initial
fixture under /tmp hit Docker's tmpfs copy visibility limitation; the successful
run used persistent /var/lib storage, matching managed provisioning. No dedicated
SSH target was supplied, so offline Docker package installation, target enrollment
and the complete remote readiness workflow still require deployment validation.
The Desktop smoke disabled node resource enforcement for this disposable fixture;
it does not verify configured production CPU, memory and PID enforcement.

The complete backend run recorded 2,448 passes, 15 skips and one obsolete
preflight-message assertion already loaded before its correction. The corrected
case passed separately; the bootstrap/provisioning selection passed 46 tests.
The Docker 29 isolated-port compatibility correction passed 92 deployment and
isolation tests, including its new regression case. The frontend suite passed
all 274 tests across 45 files, and the production build passed. Both Compose
configurations and PowerShell build-script syntax checks passed.
Two opt-in tests also passed against a real disposable PostgreSQL server:
the concurrent lease/recovery test described above and an export snapshot test
with a second connection changing source metadata and evidence during generation.
The generated archive retained its original, internally consistent snapshot.

Synthetic fixtures containing 95 charts and 1,700 findings measured about 8 ms
for remediation enqueue plus preview and 10 ms (12 SQL statements) for export
admission on the development machine. These are request-boundary measurements,
not production benchmarks or full export timings. The remediation worker then
generated the fixture's complete 95-chart, 1,700-finding plan. Linux file-size
enforcement and a full multi-worker Ubuntu deployment remain deployment checks;
Windows unit tests do not establish those operating-system guarantees.
