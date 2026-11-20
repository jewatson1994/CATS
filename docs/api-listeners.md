# CATS HTTP listeners outside the portal

Use the [portal integration guide](api-integration.md) for CI ingestion, its bearer token and the portal's OpenAPI document. The five applications below have separate route tables. Ports shown are the listener defaults. Deployment templates and ingress determine the client-facing addresses.

## OCI distribution gateway

Use the registry hostname configured for consumers. Compose runs the gateway on port 5000 internally. A private image pull uses a CATS machine account with a grant on its repository mapping. A public service can allow anonymous image pulls. The offline evidence download requires machine authentication and a verified published approval. [OCI operations](oci-proxy.md) · [Evidence retrieval](oci-evidence.md)

| Method | Path | Returns |
| --- | --- | --- |
| GET, HEAD | `/v2/` | Registry protocol probe |
| GET, HEAD | `/v2/{repository:path}/manifests/{reference}` | Manifest by tag or digest |
| GET, HEAD | `/v2/{repository:path}/blobs/{digest}` | Blob or headers |
| GET | `/v2/{repository:path}/referrers/{digest}` | OCI referrers |
| GET | `/api/oci/evidence/{repository:path}/manifests/{digest}/offline` | Offline ZIP for the authorized digest |
| GET | `/.well-known/cats/signing-keys` | Public signing key inventory |
| GET | `/healthz` | Gateway database readiness |

The repository parameter includes the mapped project, local numeric service ID and image path. **Pull from CATS** supplies this path and the digest. A push to a release destination uses the destination registry's own API.

## Scan control

The dedicated scan worker calls the private `portal-control` listener on port 8001. The worker protocol takes `Authorization: Bearer …` and a worker identity in `X-Worker-Id` (default `scan-worker`). Claimed attempts use `X-Attempt-Token` as well. [Scan worker setup and credentials](dedicated-scan-worker.md)

| Method | Path | Operation |
| --- | --- | --- |
| POST | `/internal/scan-worker/claim` | Claim scan work |
| POST | `/internal/scan-worker/{job_id}/{attempt_id}/heartbeat` | Renew an attempt and report progress |
| GET | `/internal/scan-worker/{job_id}/{attempt_id}/input` | Download the attempt's input archive |
| PUT | `/internal/scan-worker/{job_id}/{attempt_id}/results` | Submit an attempt's results |
| POST | `/internal/scan-worker/{job_id}/{attempt_id}/failure` | Report a failed attempt |
| GET | `/health` | Database readiness |

## Patch worker

The portal contacts `patch-worker` on port 8010. The internal operations require `X-CATS-Worker-Token` configured with `CATS_PATCH_WORKER_TOKEN`.

| Method | Path | Operation |
| --- | --- | --- |
| POST | `/internal/patch-bindings/prepare` | Prepare a patch binding |
| DELETE | `/internal/patch-bindings/{binding_id}` | Release a binding |
| POST, GET | `/internal/patch-jobs/{job_id}` | Start or inspect a patch job |
| POST | `/internal/patch-jobs/{job_id}/cancel` | Cancel a patch job |
| POST, GET, DELETE | `/internal/candidate-verifications/{attempt_id}` | Start, inspect or clean up candidate verification |
| GET, HEAD | `/openapi.json` | Worker schema |

## Validator execution

The appliance uses port 8443 and requires a trusted TLS client certificate with an allowed fingerprint. An accepted validation returns HTTP 202 and a job ID. Poll with the same client identity that submitted the job. [Validator deployment](validator-appliance.md)

| Method | Path | Operation |
| --- | --- | --- |
| GET | `/health` | Validator health and capabilities |
| POST | `/api/v1/validations` | Submit a JSON validation package |
| GET | `/api/v1/validations/{job_id}` | Read job state |
| POST | `/api/v1/validations/{job_id}/cancel` | Request cancellation |
| POST | `/api/v2/validations` | Submit an OCI declaration or stream an artifact with its declaration |
| GET | `/api/v2/validations/{job_id}` | Read job state |
| POST | `/api/v2/validations/{job_id}/cancel` | Request cancellation |
| GET, HEAD | `/openapi.json`, `/docs`, `/docs/oauth2-redirect`, `/redoc` | Schema and documentation |

## Validator administration

The appliance's administration UI runs on HTTPS port 8444. It uses a local administrator session and CSRF-protected forms. The login form is served by the root page.

| Method | Path | Operation |
| --- | --- | --- |
| GET | `/` | Login form or administration page |
| POST | `/login` | Start a local administrator session |
| POST | `/readiness` | Check appliance readiness |
| POST | `/settings` | Save execution and trust settings |
| POST | `/password` | Change the local password |
| POST | `/logout` | End the session |
