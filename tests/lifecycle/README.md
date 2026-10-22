# Local signed lifecycle integration

This fixture uses a private Docker network, Distribution registry with an explicitly trusted temporary TLS certificate, PostgreSQL, real Cosign, and actual Uvicorn HTTP requests. It uses existing local `cats:1.2`, `registry:2.8.3`, and `postgres:16-alpine` images. No ports are published and no public artifacts are pushed. The source mount is read-only. Do not run if another project named `cats-lifecycle-test` already exists.

From the repository root, with Python cryptography installed:

```powershell

python tests/lifecycle/prepare.py

docker compose -f .test-temp/lifecycle-repro/compose.json up --abort-on-container-exit --exit-code-from runner runner

docker compose -f .test-temp/lifecycle-repro/compose.json down --volumes

```

Preparation refuses to overwrite an existing fixture directory; use a fresh directory/database for each run. The generated directory contains disposable private keys and must remain ignored. The fixture runs no patch scanner or deployment validation: scan receipts, Cyber decisions and deployment validation records are explicitly synthetic. Signature creation/verification, database constraints, authorization, upstream registry traffic and gateway HTTP responses are real; no authorization or transport functions are mocked.

Verified on 2026-10-21 with Docker Engine 29.6.2:

- Encrypted-key Cosign signing, pinned-key verification and tamper rejection.

- TLS registry upload and gateway tag/digest/blob/range/referrers reads.

- Revocation denies manifest, cached blob and referrers access.

- A missing active pointer denies tag/digest/cached blob access without legacy fallback.

- Two services activate real signed revision manifests over a shared patched artifact.

- Their stable tags return the patched digest while the upstream stable tag still points to original bytes.

- Direct original-digest requests are denied rather than substituted.

- Revoking one service leaves the other service operational.

- Tampering with the other service's signed manifest denies its tag request.

The runner writes `proxy-results.json`, `active-results.json` and `concurrency-results.json`. The concurrency check uses separate PostgreSQL sessions to verify same-key durable dispatch serialization and preservation of unrelated caller writes. This is integration coverage of fixture evidence, not certification of patch correctness or a complete human approval journey.

## Real Docker and Helm clients

Optional host-client mode exposes only `127.0.0.1:18083`. Requires host Docker and Helm binaries. It stores temporary client authentication in the ignored fixture directory, without changing the user's client configuration. Select a fresh run name and ensure the test project and loopback port are unused:

```powershell

$env:CATS_CLIENT_PROBE='1'

$env:CATS_LIFECYCLE_RUN='lifecycle-clients-fresh'

python tests/lifecycle/prepare.py

docker compose -f .test-temp/lifecycle-clients-fresh/compose.json up -d runner

python tests/lifecycle/host_clients.py .test-temp/lifecycle-clients-fresh

docker compose -f .test-temp/lifecycle-clients-fresh/compose.json down --volumes

docker image rm 127.0.0.1:18083/clients/image:stable

```

On 2026-10-21 the runner exited successfully and actual host clients passed:

| Operation | Result | Elapsed |

|---|---|---|

| Docker image pull, valid OCI config and tar layer | Downloaded and unpacked | 658 ms |

| Helm OCI chart pull | Downloaded chart version 0.1.0 | 475 ms |

| Docker pull after approval revocation | HEAD rejected, 403 | 252 ms |

| Helm pull after approval revocation | GET rejected, 403 `approval_not_current` | 166 ms |

Ten sequential actual authenticated gateway manifest reads measured 39.02-54.21 ms (median 42.05 ms). These are local, single-client fixture measurements including database authorization and registry traffic, not load-test results or production latency guarantees. Host-client pulls exercise legacy nonrevision approvals; the separate signed active revision checks still run through real HTTP. The gateway-to-registry link uses TLS with the generated trusted CA; host-client-to-gateway HTTP is confined to loopback. The tiny image contains a file and valid filesystem layer but no executable; this is pull/unpack verification, not workload execution. Chart pull does not establish Kubernetes installation readiness. Approval, scan and validation fixture records remain synthetic.

`client-results.json` records actual command results; `clients-ready.json` records gateway lookup timings. The test only removes its dedicated project resources and unique image tag. No existing deployment containers or volumes are modified.

## Continuation run

On 2026-10-21, `CATS_LIFECYCLE_RUN=lifecycle-continue-20261021` completed successfully, including concurrent PostgreSQL deduplication checks. This run did not repeat host Docker/Helm client checks. The private bridge allows external egress; this is not disconnected acceptance. Preserve the ignored run directory for local evidence; never commit its generated signing keys. Only remove volumes belonging to the dedicated disposable fixture when cleanup is intended.
