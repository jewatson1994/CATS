# Integrate with CATS

Point your project's CI runner at the **authoritative portal's HTTPS URL**. Give the runner a CATS project token for the service it builds. If CATS should run the scanners, send the built artifact or its registry reference. If your pipeline already ran the scanners, send the resulting execution evidence. A workload pulling an approved release connects to the **OCI gateway hostname** with its own registry access.

## Choose an interface

| Consumer | Host and routes | Identity and contract |
| --- | --- | --- |
| Project CI, CATS runs the scan | Full portal, `POST /api/v1/artifact-submissions` and `GET /api/v1/artifact-submissions/{submission_id}` | Project bearer token with `artifacts.submit`. The POST queues the work. Poll with the issuing credential for scan and ingestion status. |
| Project CI, external scanner produced the evidence | Full portal, `POST /api/v1/pipeline-results` and `POST /api/v1/amendment-assessments/{proposal_id}` | Project bearer token with `evidence.write`. Both operations accept an `ExecutionPayload` and return an ingestion receipt. An explicitly configured deployment token also supports these two legacy operations. |
| Monitoring | Portal, `GET /health` and `GET /readyz` | No credential required. Health returns `{"status":"ok"}`. Readiness checks database connectivity and returns 200/ready or 503/unavailable. |
| Docker, containerd, Helm, OCI clients | OCI host, `/v2/`, manifest and blob GET/HEAD, referrers GET | A private service requires an authorized CATS OCI machine principal. Public pulls require the owning group's configured release/compliance policy to pass as well. See [OCI operations](oci-proxy.md). |
| Self-service scan submitter | Portal, `POST /api/public/jobs`, then the returned status and results URLs | Normally a portal session. An operator can enable anonymous submissions with `CATS_SCAN_ALLOW_ANONYMOUS`. Such a submission returns an `access_token` specific to that job. Supply it in `X-Scan-Access-Token` on subsequent requests. |
| Portal UI / signed-in operator | Portal, including `/api/dashboard/*`, `/api/services/*`, `/api/approved-releases*`, `/api/risk/*`, `/api/oci/*` and `/api/v1/jobs*` | Local or OIDC login creates a `cats_session` cookie. Permissions depend on the action and resource. For example, approval writes require a matching `X-CSRF-Token`. Several legacy operations take HTML forms, and an expired session can redirect to login. |
| Scan / patch workers and validator | Private control or appliance listener | Scan workers use `/internal/scan-worker/*` with a worker credential and attempt token on attempt-specific calls. The patch service uses `X-CATS-Worker-Token` on its internal operations. Validation submission and polling use the mTLS appliance at `/api/v2/validations`, with v1 routes for the legacy protocol. See [scan workers](dedicated-scan-worker.md) and [validator setup](validator-appliance.md). |

## Connect a project

**CATS operator or service manager**

1. On the full portal, open **Services → the target service → Overview → Project integrations**. Verify its service key and single owning group. Each project credential is bound to that existing local service and owner. A repository name, chart name, image path or CI project ID does not select or create a destination service.
2. Open **Manage credentials → New credential**. Enter a project label, select the scopes your pipeline needs, choose the lifetime, and issue the credential. The default is 30 days. The range is 1–365 days. An issuer needs both `service.edit` and `scan.ingest` on the target service. The built-in Service Manager role provides both. A user with only the Administrator role needs an additional service-scoped ingestion grant to issue tokens. Listing and revoking credentials requires `service.edit`.
3. Copy the one-time token into the CI system's masked secret **CATS_PROJECT_TOKEN**. Supply the service key and full portal URL to the project team. Check that a dedicated scan worker can reach the artifact source and trusts its TLS certificate. Project scans acquire registry references anonymously. For a private source, have CI pull or package the artifact using its own registry access and upload that file to CATS.

For administrative automation, an authorized **portal session** can list or create credentials via `GET` or `POST /api/services/{service_key}/project-credentials`. Creation accepts JSON with `project_label`, `scopes`, `expires_in_days` and the session's `csrf_token`. Only the creation response includes `token`. Revoke one credential with `POST /api/services/{service_key}/project-credentials/{credential_id}/revoke` and the session CSRF token.

**Project team**

1. Configure `CATS_PORTAL_URL` (for example `https://cats.example.org`, without a trailing slash) and the masked `CATS_PROJECT_TOKEN`. Install your site's CA on the runner or supply it with curl's `--cacert` option. The examples use Bash, curl and jq.
2. Choose an input below. For artifact submissions, supply a stable `Idempotency-Key` for each distinct build output and save the receipt with your CI job. For evidence, retain the exact execution payload and string execution ID.
3. Rotate by issuing a replacement, updating the CI secret, and revoking the old credential. Finish polling outstanding jobs with the original credential before revocation. An expired, revoked or inactive credential stops authorizing requests. Transferring the service to another owning group disables its existing credentials and prevents pending scans from writing evidence under the new owner. Removing the issuer's required permissions also disables the credential.

### Choose an artifact

| Input | `kind` | What to send |
| --- | --- | --- |
| Container in a registry the worker can read anonymously | `image` | JSON `reference`, preferably pinned by digest. |
| Private or disconnected image | `docker-archive` | Multipart `file`. For example, have CI run `docker image save --output web.tar "$IMAGE_TAG"` against a locally available tagged image, then upload `web.tar`. Tagged OCI-layout archives are also supported. |
| Helm chart | `helm-chart` | Upload a chart archive containing `Chart.yaml`, or send JSON such as `{"kind":"helm-chart","reference":"oci://registry.example.org/charts/web:1.2.3","version":"1.2.3"}` for an anonymously readable chart. Use a chart version tag for a specific chart version. The chart package must contain the values and dependencies needed for the intended render. |
| Docker Compose deployment | `compose` | Upload a Compose YAML file or a tar, gzip-compressed tar or ZIP containing a detectable Compose file or conventional base/override pair. |

Omitting `kind` uses `auto` detection. For automation with a known artifact type, set it explicitly. The optional `version` labels evidence for the service. If omitted, CATS uses the service's current/manual version, falling back to `Unversioned`. It does not select a registry tag or choose the service. Project submissions add evidence for the artifact to the service and preserve the service's other inventory.

The examples below work with curl alone for submission. With the CATS scanner CLI installed, `cats submit --reference "$IMAGE_REF" --key "$BUILD_KEY" --version "$RELEASE_VERSION"` or `cats submit --file "$CHART_PACKAGE" --key "$BUILD_KEY" --version "$RELEASE_VERSION"` uses the same project token and portal URL. For a private CA, set `CATS_PORTAL_CA_FILE` when using the CLI.

### Submit a registry image

Capture the full image reference from the build that pushed it. A digest reference pins the exact image. This GitLab-style example uses a stable key across retries of the same pipeline. Set an equivalent immutable build identifier in other CI systems.

```bash
set -euo pipefail
: "${CATS_PORTAL_URL:?}" "${CATS_PROJECT_TOKEN:?}" "${CI_PIPELINE_ID:?}" "${IMAGE_REF:?}" "${RELEASE_VERSION:?}"
key="pipeline-${CI_PIPELINE_ID}-web-image"
jq -n --arg ref "$IMAGE_REF" --arg version "$RELEASE_VERSION" \
  '{kind:"image", reference:$ref, version:$version}' > cats-image.json
curl --fail-with-body -sS -o cats-receipt.json \
  -H "Authorization: Bearer $CATS_PROJECT_TOKEN" -H "Idempotency-Key: $key" \
  -H 'Content-Type: application/json' --data-binary @cats-image.json \
  "$CATS_PORTAL_URL/api/v1/artifact-submissions"
```

### Submit a packaged Helm chart

For example, `helm package ./charts/web --destination dist` produces a versioned `.tgz`. Set `CHART_PACKAGE` to that file. Include chart dependencies and the intended `values.yaml` in the package. Each submission accepts one source. A standalone values file does not identify a chart. The worker still needs access to the images referenced by the rendered workloads for their image scans. A private image can be submitted separately as a tagged image archive.

```bash
set -euo pipefail
: "${CATS_PORTAL_URL:?}" "${CATS_PROJECT_TOKEN:?}" "${CI_PIPELINE_ID:?}" "${CHART_PACKAGE:?}" "${RELEASE_VERSION:?}"
curl --fail-with-body -sS -o cats-receipt.json \
  -H "Authorization: Bearer $CATS_PROJECT_TOKEN" \
  -H "Idempotency-Key: pipeline-${CI_PIPELINE_ID}-app-chart" \
  -F "file=@${CHART_PACKAGE}" --form-string 'kind=helm-chart' \
  --form-string "version=${RELEASE_VERSION}" \
  "$CATS_PORTAL_URL/api/v1/artifact-submissions"
```

### Wait for retained evidence

The first accepted POST returns **202**. Replaying the same request with the same credential and key returns **200** and the same submission and job IDs. A changed input under that key returns **409**. Keep the original reference or uploaded file, filename, kind and version for retries. New inputs get a new key. Keys begin with a letter or digit and contain up to 128 letters, digits or the characters `._:-`.

The status URL in `cats-receipt.json` belongs to the portal. A CI job can use the following polling step after either submission above. Configure its timeout to match the queue and expected scan time.

```bash
set -euo pipefail
status_path=$(jq -er '.status_url' cats-receipt.json)
deadline=$((SECONDS + ${CATS_POLL_TIMEOUT_SECONDS:-10800}))
while (( SECONDS < deadline )); do
  curl --fail-with-body -sS --connect-timeout 10 --max-time 30 --retry 3 --retry-max-time 60 \
    -H "Authorization: Bearer $CATS_PROJECT_TOKEN" \
    "$CATS_PORTAL_URL$status_path" -o cats-status.json
  jq '{id, job_id, service_key, scan_status, ingest_status, execution_id}' cats-status.json
  if jq -e '.scan_status == "complete" and .ingest_status == "ingested" and .execution_id != null' cats-status.json >/dev/null; then
    exit 0
  fi
  if jq -e '(.scan_status | IN("incomplete","error","cancelled","expired")) or
            (.ingest_status | IN("failed","expired"))' cats-status.json >/dev/null; then
    exit 1
  fi
  sleep 15
done
echo "Timed out waiting for CATS submission at $status_path" >&2
exit 1
```

This example requires a complete scan and retained evidence. A partial scan can retain evidence and still fail this CI step. A successful execution records the scan under its mapped service. Cyber review, signed activation, expiry, distribution and the OCI pull policy govern release publication and consumption separately. [Approved release workflow](cyber-approved-releases.md)

## Inspect the exact routes on your installation

Download the schemas from the CATS version you deploy. The pipeline schema contains the four CI operations above and can be used offline. The full FastAPI schema includes the documented portal handlers, including browser pages and forms. The OCI and worker processes have separate listeners. Some portal handlers parse a request body themselves, so the full schema can list a route without describing its body or its internal authorization checks.

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

## Send evidence from an external scanner

Use a project token with `evidence.write` when your build already has scanner output. This operation ingests results directly. It accepts JSON describing an execution. To have CATS fetch and scan a built artifact, use the artifact submissions above.

The example retains an incomplete, image-scoped execution on the existing service with key `integration-demo`, owned by the group `Integration Test`. Substitute your credential's service key, service name, owning group, version, actual image reference and scan time. Include the evidence your scanner collected.

Save this example as `execution.json`.

With the CATS scanner image, run `cats push assessment --input execution.json` to send this file. The command uses `CATS_PROJECT_TOKEN` first and posts to `$CATS_PORTAL_URL/api/v1/pipeline-results` over HTTPS. Existing CI jobs can continue to use `CATS_PORTAL_TOKEN` for legacy assessment delivery. The optional patch push uses its separately configured destination and legacy credential.

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
  -H "Authorization: Bearer $CATS_PROJECT_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @execution.json
```

The first successful submission returns HTTP 201. A typical response for the example is `{"accepted":true,"duplicate":false,"execution_id":42,"deployment_validation_run_id":null}`. The numeric response `execution_id` identifies the CATS database row. Keep your own **string** execution ID and the submitted JSON together for retries. Sending the same execution again returns HTTP 201 with `duplicate:true` and the same numeric ID. Reusing that ID with different scan evidence returns 409. Each new scan needs a globally unique producer ID of up to 240 characters, even when two services scan the same digest. Pick a producer prefix such as `ci:`. CATS reserves `public:` and `proposal:` for its own job and proposal dispatches.

| Input | What the producer supplies |
| --- | --- |
| `service` | `service.id` is the mapped string service key. The numeric service ID returned by artifact submission is a different field. Include the service name and version. For a project credential, use the existing service and omit `groups` or supply its current owning group. CATS preserves the service's recorded name, description, owner and POC. |
| `scanned_at`, `complete`, `fixable_only` | Include a timestamp with its UTC offset. Set `complete` according to the actual scan and report skipped inputs. The portal accepts fixable-only assessments through this route. |
| `scan_scope` | Defaults to `service`. Use `image` with `scope_image` for a single container, or `evidence` for supplemental observations. Only a current complete service scan can resolve omitted service-wide findings. A current complete image scan reconciles vulnerability findings within its image scope. Supplemental evidence leaves omitted findings open. Distribution scans go through the workflow bound to their saved selection. |
| Evidence | Findings, policy findings, SBOM components, retained scanner/SBOM documents, and optional deployment inputs are defined under `components.schemas` in the pipeline contract. Follow document encoding, byte length, and SHA-256 requirements when attaching original output. |

For an amendment, post its whole-service assessment to `/api/v1/amendment-assessments/{proposal_id}` with the same bearer header and payload structure. Use the numeric ID of an existing proposal for that service. With a project credential, a proposal scan must already have been dispatched. Use the execution ID `proposal:<dispatched scan job ID>` and version from the current dispatch. This workflow validates the active base revision, dispatch, evidence freshness and proposed inventory. It requires a complete, fixable-only service scan with no skipped charts/images. A successful 201 contains `proposal_id`, `assessment_id`, `accepted:true`, and `active_release_changed:false`. Cyber approval and release activation have their own lifecycle. [Approved releases](cyber-approved-releases.md)

### Existing deployment-wide evidence producers

Operators can retain an explicitly configured `PIPELINE_API_TOKEN` for trusted legacy evidence writers. New installations can use project tokens without configuring this secret. The deployment token is shared across services and has broader authority over evidence, including creating a service with one owning group through pipeline ingestion. Reserve it for producers that need that authority. Send it using `Authorization: Bearer <token>` on the two evidence routes. Artifact submissions and status polling require a project credential. Project pipeline tokens, worker credentials, OIDC identities and OCI machine principals serve different interfaces.

## Handle failures and retries

Read the HTTP status first. Portal errors normally include a `detail` string, object or validation list and a `diagnostic` object. Record the response's `X-Correlation-ID` with the artifact submission ID or producer execution ID. On the two evidence routes the portal checks the declared and received body sizes before route authentication, so an oversized request can return 413 even when its credential is invalid. A proxy or ingress can return its own error format.

| Result | How to handle it |
| --- | --- |
| 400 or 422 | Check the JSON, length header, schema, owning group, scope and fixable-only flag. Validation errors can identify the failing field under `detail[].loc`. |
| 401 | Verify the bearer scheme, secret, expiry and revocation status with the credential owner. |
| 403 | Verify the full portal, required scope, owning group and issuer's current permissions. For a session or OCI operation, check the specific permission and pull policy. |
| 404 on status | Check the saved status URL, portal instance and original project credential. A different project credential cannot retrieve that submission. |
| 409 | Inspect the detail. Common causes include an idempotency key or execution ID reused with changed input, mismatched ownership, an archived/imported service, or a stale amendment. |
| 413 | The JSON limit on the two evidence-ingestion operations defaults to 16 MiB (`CATS_PIPELINE_MAX_REQUEST_BYTES`). Original evidence documents also have encoded/decoded size limits. The artifact route allows 16 KiB of reference JSON. The default scan upload limits are 512 MiB for charts (`CATS_PUBLIC_MAX_CHART_BYTES`) and 2 GiB for image archives (`CATS_PUBLIC_MAX_IMAGE_ARCHIVE_BYTES`). The worker's scan workspace or portal ingress can impose a lower ceiling. |
| 415 on artifact submission | Use `application/json` for a registry reference or `multipart/form-data` with one `file` for an upload. |
| 429 | Queue capacity is exhausted. Retry the same artifact submission and key after a delay. |
| 503 or transient transport/5xx failure | If the portal reports the deployment-wide token is unconfigured, check which token the evidence producer is using. For a transient failure, check portal readiness and retry with bounded backoff. Preserve the idempotency key for artifacts and the string execution ID and exact payload for completed evidence. |

## Priorities for further API hardening

1. **Publish a versioned read contract for release consumers.** The portal already serves release details and jobs to authorized sessions. A managed read-only machine permission with explicit response models for active release, image digests and evidence would let automation consume this data without a browser login.
2. **Guard contract compatibility in CI.** Compare the pipeline OpenAPI contract against the last released schema and exercise representative projects against PostgreSQL, including concurrent retries and credential rotation.
