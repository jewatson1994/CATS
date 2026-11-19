# Integrate with CATS

Use the **portal HTTPS hostname** for submitting scan evidence and the **OCI HTTPS hostname** for pulling a container or chart. CATS exposes two machine-authenticated CI operations. Service dashboards, release management, approvals, and most other portal JSON operations use a signed-in user's session and permissions.

## Choose an interface

| Consumer | Host and routes | Identity and contract |
| --- | --- | --- |
| CI evidence producer | Full portal, `POST /api/v1/pipeline-results` and `POST /api/v1/amendment-assessments/{proposal_id}` | Deployment pipeline bearer token. Both accept an `ExecutionPayload`. The live pipeline schema includes nested evidence types and receipts. |
| Monitoring | Portal, `GET /health` and `GET /readyz` | No credential required. Health returns `{"status":"ok"}`. Readiness checks database connectivity and returns 200/ready or 503/unavailable. |
| Docker, containerd, Helm, OCI clients | OCI host, `/v2/`, manifest and blob GET/HEAD, referrers GET | A private service requires an authorized CATS OCI machine principal. Public pulls require the owning group's configured release/compliance policy to pass as well. See [OCI operations](oci-proxy.md). |
| Self-service scan submitter | Portal, `POST /api/public/jobs`, then the returned status and results URLs | Normally a portal session. An operator can enable anonymous submissions with `CATS_SCAN_ALLOW_ANONYMOUS`. Such a submission returns an `access_token` specific to that job. Supply it in `X-Scan-Access-Token` on subsequent requests. |
| Portal UI / signed-in operator | Portal, including `/api/dashboard/*`, `/api/services/*`, `/api/approved-releases*`, `/api/risk/*`, `/api/oci/*` and `/api/v1/jobs*` | Local or OIDC login creates a `cats_session` cookie. Permissions depend on the action and resource. For example, approval writes require a matching `X-CSRF-Token`. Several legacy operations take HTML forms, and an expired session can redirect to login. |
| Scan / patch workers and validator | Private control or appliance listener | Scan workers use `/internal/scan-worker/*` with a worker credential and attempt token on attempt-specific calls. The patch service uses `X-CATS-Worker-Token` on its internal operations. Validation submission and polling use the mTLS appliance at `/api/v2/validations`, with v1 routes for the legacy protocol. See [scan workers](dedicated-scan-worker.md) and [validator setup](validator-appliance.md). |

The pipeline credential grants evidence-write authority across services on its full portal. Reserve it for trusted producers. A private OCI pull uses the machine principal's registry credentials. An OIDC access token from the provider cannot substitute for either credential or the portal session.

## Inspect the exact routes on your installation

Download the schemas from the CATS version you deploy. The pipeline schema is small enough to use offline and contains the two CI operations. The full FastAPI schema includes the documented portal handlers, including browser pages and forms. The OCI and worker processes have separate listeners. Some portal handlers parse a request body themselves, so the full schema can list a route without describing its body or its internal authorization checks.

```sh
export CATS_PORTAL_URL=https://cats.example.org
curl -fsS "$CATS_PORTAL_URL/api/v1/pipeline/openapi.json" -o cats-pipeline.json
curl -fsS "$CATS_PORTAL_URL/openapi.json" -o cats-portal.json

# Print the exact documented method and path from either downloaded schema.
jq -r '.paths | to_entries[] | .key as $p | .value | keys[] |
  select(test("^(get|put|post|delete|patch|head|options|trace)$")) |
  "\(ascii_upcase) \($p)"' cats-portal.json | sort
```

On PowerShell 7, this prints the same inventory using the built-in JSON parser.

```powershell
$portal = 'https://cats.example.org'
$schema = (Invoke-WebRequest "$portal/openapi.json").Content | ConvertFrom-Json -AsHashtable
foreach ($path in $schema.paths.Keys | Sort-Object) {
    foreach ($method in $schema.paths[$path].Keys) {
        if ($method -in 'get','put','post','delete','patch','head','options','trace') {
            '{0} {1}' -f $method.ToUpperInvariant(), $path
        }
    }
}
```

The interactive portal views are `/docs` and `/redoc`. On a disconnected network, use the downloaded JSON directly if their browser assets are unavailable. Operations listed in the schema are subject to deployment mode. Replica mode rejects CI submissions with HTTP 403. The [non-portal listener inventory](api-listeners.md) lists the exact routes on the OCI, worker and appliance applications.

## Pull the containers in an approved release

Open the approved release in the portal and use **Pull from CATS** on each container. A client with a signed-in portal session can look up the same pull references through these routes.

| Step | Method and path |
| --- | --- |
| Find the service's approved releases | `GET /api/approved-releases?service={service_key}` |
| Read the selected release and its artifact inventory | `GET /api/approved-releases/{identity}` |
| Resolve a container by its zero-based index in that release's snapshot | `GET /api/approved-releases/{identity}/artifacts/{artifact_index}/pull` |
| Resolve a container from an imported release on this instance | `GET /api/replica/releases/{identity}/artifacts/{artifact_index}/pull` using the local imported release ID |

For an available route, use the returned `routes[].reference` as the argument to `docker pull` or as a Kubernetes container image. It includes the service-specific repository and approved digest. If `login_required` is true, authenticate to the indicated registry with an authorized OCI machine principal. An unavailable response gives a `reason`. Each registry fetch checks the current pull policy. These release lookups use the saved artifact inventory, so a scheduled rescan can replace the current container row without changing which digest the release requests. [OCI operations and evidence retrieval](oci-proxy.md)

## Submit one execution

Have the deployment administrator configure `PIPELINE_API_TOKEN` on the full portal and provision that value as a masked CI secret. For an existing custom deployment that relied on the development default, set an explicit secret and recreate the portal. Clients that previously sent the token alone in `Authorization` must add the `Bearer` prefix.

Use the portal's trusted HTTPS certificate chain. For a private CA, configure your runner's trust store or give curl the CA file with `--cacert`. The example below creates a service and retains an incomplete image-scoped execution. Use a test instance and supply your actual service key, owning group, scan time, and evidence for production.

Save this example as `execution.json`.

```json
{
  "schema_version": "1.0",
  "execution_id": "ci:integration-demo:build-42:scan-1",
  "scanned_at": "2026-11-19T12:00:00Z",
  "complete": false,
  "fixable_only": true,
  "artifact_type": "image",
  "scan_scope": "image",
  "scope_image": "registry.example.org/demo/web:1.2.3",
  "service": {
    "id": "integration-demo",
    "name": "Integration Demo",
    "version": "1.2.3",
    "groups": ["Integration Test"]
  },
  "findings": []
}
```

```sh
curl --fail-with-body -sS -X POST "$CATS_PORTAL_URL/api/v1/pipeline-results" \
  -H "Authorization: Bearer $PIPELINE_API_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @execution.json
```

The first successful submission returns HTTP 201. A typical response for the example is `{"accepted":true,"duplicate":false,"execution_id":42,"deployment_validation_run_id":null}`. The numeric response `execution_id` identifies the CATS database row. Keep your own **string** execution ID and the submitted JSON together for retries. Sending the same execution again returns HTTP 201 with `duplicate:true` and the same numeric ID. Reusing that ID with different scan evidence returns 409. Each new scan needs a globally unique producer ID, even when two services scan the same digest.

| Input | What the producer supplies |
| --- | --- |
| `service` | A stable key, display name and version. A new service requires exactly one owning group. Ingestion can create that group. An existing service may omit the group or supply its existing owner. Ownership changes require authorized administration. |
| `scanned_at`, `complete`, `fixable_only` | Include a timestamp with its UTC offset. Set `complete` according to the actual scan and report skipped inputs. The portal accepts fixable-only assessments through this route. |
| `scan_scope` | Defaults to `service`. Use `image` with `scope_image` for a single container, or `evidence` for supplemental observations. Only a current complete service scan can resolve omitted service-wide findings. A current complete image scan reconciles vulnerability findings within its image scope. Supplemental evidence leaves omitted findings open. Distribution scans go through the workflow bound to their saved selection. |
| Evidence | Findings, policy findings, SBOM components, retained scanner/SBOM documents, and optional deployment inputs are defined under `components.schemas` in the pipeline contract. Follow document encoding, byte length, and SHA-256 requirements when attaching original output. |

For an amendment, post its whole-service assessment to `/api/v1/amendment-assessments/{proposal_id}` with the same bearer header and payload structure. Use the numeric ID of an existing proposal for that service. This workflow validates the active base revision, current scan dispatch where present, evidence freshness, and proposed inventory. It requires a complete, fixable-only service scan with no skipped charts/images. A successful 201 contains `proposal_id`, `assessment_id`, `accepted:true`, and `active_release_changed:false`. Cyber approval and release activation have their own lifecycle. [Approved releases](cyber-approved-releases.md)

## Handle failures and retries

Read the HTTP status first. Portal errors normally include a `detail` string, object or validation list and a `diagnostic` object. Record the response's `X-Correlation-ID` with the producer execution ID. The portal checks the declared and received body sizes before route authentication, so an oversized request can return 413 even when its credential is invalid. A proxy or ingress can return its own error format.

| Result | How to handle it |
| --- | --- |
| 400 or 422 | Check the JSON, length header, schema, owning group, scope and fixable-only flag. Validation errors can identify the failing field under `detail[].loc`. |
| 401 | Check the bearer scheme and pipeline secret. An operator must distribute the replacement if the deployment token has rotated. |
| 403 | Verify the target is the authoritative full portal. For a session or OCI operation, check the specific permission and pull policy. |
| 409 | Inspect the detail. Common causes include an execution key reused with changed evidence, mismatched ownership, an archived/imported service, or a stale amendment. |
| 413 | The default JSON request ceiling is 16 MiB on both pipeline operations. Operators configure `CATS_PIPELINE_MAX_REQUEST_BYTES` in bytes. Original evidence documents also have encoded/decoded size limits, and ingress may impose a lower ceiling. |
| 503 or transient transport/5xx failure | If the portal reports unconfigured pipeline credentials, fix the configuration. For a transient failure, retry the same persisted payload with bounded backoff. Serialize retries for a given execution key. |

## Priorities for further API hardening

1. **Scope machine identities to services and actions.** Introduce separately revocable CI credentials with ownership scope, expiry and audit identity before giving independent teams direct write access. The deployment currently shares one pipeline secret.
2. **Publish a versioned read contract for release consumers.** The portal already serves release details and jobs to authorized sessions. A managed read-only machine permission with explicit response models for active release, image digests and evidence would let automation consume this data without a browser login.
3. **Guard contract compatibility in CI.** Generate a diff of the pipeline OpenAPI contract against the last released schema, check breaking changes, and run an ingestion-and-retry test against a disposable PostgreSQL deployment. Include overlapping deliveries for the same execution key to qualify concurrent retry behavior.
