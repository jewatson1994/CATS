# OCI compliance proxy

The CATS OCI facade is included in the main Compose stack and serves approved artifacts from configured upstream registries. It is a read-only Distribution API endpoint, not a second registry or an upload destination. Upstream Harbor remains the source of content. CATS owns authorization, current policy decisions, and the local verified-content cache.

## Deployment

Build or load the CATS image containing this feature and configure the normal deployment environment. Both `compose.yaml` and `templates/compose.main.yaml` include `oci-proxy` by default. From the repository root, start the main stack normally:

```sh
docker compose config --quiet
docker compose up -d --wait
```

For the main deployment template, use the ordinary [template startup commands](../templates/README.md#main-cats). No overlay is required. `compose.oci-proxy.yml` remains a no-op compatibility file so existing commands that include it continue to work with the main Compose file.

The proxy uses the same `CATS_IMAGE`, database, and `CATS_CONFIG_ENCRYPTION_KEY` as the portal. Its separate named `oci_proxy_cache` volume survives restarts and service recreation. It has no Docker socket, privileged execution, or registry storage backend. The application listens on port 5000; Compose publishes it only on host loopback at `127.0.0.1:5000` by default (`CATS_OCI_PORT` changes the host port). Terminate HTTPS at a trusted reverse proxy and forward only over the trusted local/container network. Configure clients to trust that HTTPS certificate. Do not send machine credentials over a public HTTP connection.

Configure an upstream HTTPS registry origin and its read-only upstream credentials through the CATS administration interface. Add private CA PEM certificates when needed. Delegated token service origins and blob redirect origins require explicit allowlisting. Keep the allowlists narrow: token services receive upstream credentials. Redirects to another origin lose Authorization headers; signed CDN URLs can still work. No insecure TLS bypass exists.

Cyber release publication runs in `remediation-worker` and has a separate redirect policy. If its source registry or destination redirects blob GET/HEAD requests to object storage, configure `CATS_OCI_BLOB_REDIRECT_ORIGINS` in the deployment environment and recreate the worker. Same-origin redirects need no setting; registry credentials are never forwarded cross-origin, and cross-origin writes and manifest redirects remain blocked. The upstream allowlists above and `CATS_OCI_TOKEN_REALMS` do not grant this permission. See [publication configuration](signed-release-documentation.md#configuration-and-boundaries).

Issue separate scoped machine credentials for consumers. Use those credentials with `docker login`, Helm registry login, or an equivalent OCI client against the CATS hostname. Portal browser sessions are not registry login credentials. Limit each machine identity to the explicitly mapped repositories it needs; rotate or revoke it without changing upstream credentials.

## Content and policy behavior

Every delivery must pass the current authorization and compliance decision, including a content-cache hit. Cached bytes are never evidence of approval. Mutable tags resolve to immutable upstream manifest digests before policy evaluation. Child manifests, configs, layers, and referrers must remain within the authorized approved graph; knowing a blob digest does not grant access to it. Multi-platform indexes require all exposed children to be eligible. Unknown, stale, blocked, revoked, and out-of-scope artifacts fail closed.

Manifest responses preserve upstream bytes and their SHA-256 identity; retained manifest JSON is stored in PostgreSQL. The configurable disk quota applies to cached blobs, not database metadata. Blob downloads stream to temporary files in bounded chunks, verify SHA-256, and atomically enter the cache only after success. Cache hits are rehashed; corrupted entries are removed and fetched again. Writers use an interprocess lock. Older entries are evicted to enforce the byte quota. Interrupted temporary files are removed by a subsequent writer. Repository pushes, deletes, and uploads are unsupported.

Referrers are fetched with bounded pagination restricted to the same upstream repository and subject. Legacy cosign `sha256-<subject>.sig` discovery verifies that every simple-signing payload names the exact authorized subject digest before exposing its manifest or blobs. This establishes an association, not cryptographic trust: consumers must still verify signatures using their own approved public keys or identity policy. The facade filters returned references according to its current graph/policy rules. Clients that require registry-specific APIs beyond OCI Distribution must use Harbor directly through separately authorized workflows.

Cache configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CATS_OCI_CACHE_DIR` | `/var/cache/cats-oci` in the main stack | Persistent content directory |
| `CATS_OCI_CACHE_MAX_BYTES` | 10737418240 | Total cached content quota (10 GiB) |
| `CATS_OCI_MAX_BLOB_BYTES` | 4294967296 | Maximum individual blob (4 GiB) |
| `CATS_OCI_PORT` | 5000 | Loopback host port |

Provision free space for the configured quota and filesystem overhead. Cache eviction can require refetching content; upstream availability remains necessary for fresh tag/policy resolution. This is a cache, not offline registry replication.

## Harbor acceptance checklist

Run these checks against a staging Harbor instance and a staging CATS database before production. Real local Harbor transport and proxy checks passed as recorded in the implementation review; full scanner, consumer-client and deployment acceptance still requires this checklist.

1. Configure a read-only Harbor robot account, trusted CA, and any delegated token endpoint. Confirm authenticated pull succeeds and an untrusted CA or unapproved realm fails.
2. Import and approve a digest-pinned image through the normal CATS workflow. Pull its tag and digest via the CATS endpoint; compare the manifest digest and layer digests with Harbor. Pull it again to exercise the cache.
3. Test an OCI Helm chart and a multi-platform image. Verify each exposed child manifest and blob is authorized and the aggregate index is denied when any required child lacks approval.
4. Move a tag to an unknown or blocked digest. Verify the next request is denied and does not reuse approval attached to the former digest.
5. Revoke the machine credential or remove its repository grant. Verify cached manifests and blobs are denied. Repeat with a known digest from an unrelated repository.
6. Change policy or introduce overdue findings for the approved digest. Verify subsequent GET and HEAD requests fail closed despite a populated cache.
7. Verify subject-bound referrers and pagination; no unrelated or disallowed artifact may appear. Attempt write/delete operations and verify rejection.
8. Interrupt a large download and restart the proxy. Verify no partial blob is served, subsequent download succeeds, and cache use stays within the configured content quota.

## Startup database locks

The proxy initializes the shared schema before opening its HTTP listener. Older
images recreated installed triggers and repeated index/default DDL during every
startup. An open portal transaction could block that DDL, with Services, the Cyber
dashboard, and Administration then waiting behind it. A healthy portal container
does not rule out this database lock chain.

If PostgreSQL activity shows proxy startup waiting on schema DDL and blocking page
queries, stop `oci-proxy` to release its migration transaction. Keep it stopped
until an image containing the startup migration fix is deployed; a normal
`docker compose up` will start the old image again. Updated images retain existing
triggers, defaults, and indexes. Actual schema changes have a five-second lock
timeout after acquiring the migration advisory lock. A timeout rolls back the
whole migration and fails startup, rather than serving with a partially upgraded
schema. If it recurs, inspect long-running/open transactions and schedule the
upgrade during a quiet period before restarting the affected service.

## Rollback

To take the proxy out of service immediately, stop it:

```sh
docker compose stop oci-proxy
```

When using the deployment template, include your existing `--env-file` and `-f templates/compose.main.yaml` arguments. Stopping or removing the container does not disable this default service: a later normal `docker compose up` starts it again. Keep it stopped during the rollback and account for it in subsequent deployment commands.

Remove its reverse-proxy route and revoke its machine credentials. Preserve the cache volume for investigation or later reuse; deleting it is optional and only removes reproducible upstream content. The normal portal, workers, database, and Harbor remain in place. Do not use `docker compose down -v` as a proxy rollback because it can remove unrelated persisted services and data. Reverting clients to direct Harbor access requires an explicit access-policy decision; do not automatically bypass compliance enforcement.


## Reassessment, renewal and verification

Keep the normal remediation worker running: its maintenance loop creates durable `oci_reassessment` jobs and reconciles completed scans. Schedule state, dispatch receipts, scanner job state, and renewal records survive application restarts in PostgreSQL. Scan outputs must also remain available on the normal scanner storage until ingestion finishes.

Open an approved Cyber request and use its **Scheduled reassessment** section to set the interval, enable or disable scheduling, refresh progress, and follow a new renewal request. A scoped Service Manager can also configure an approved release with `PUT /api/cyber-approvals/{id}/reassessment`, sending JSON `{"interval_days":7,"enabled":true}` and the session CSRF token in `X-CSRF-Token`. The interval accepts 1–365 days. A new schedule is due immediately, then repeats at that interval. Send `enabled:false` to stop future dispatches. This action requires `service.view`, `service.edit`, `service.export`, `approval.request`, and `scan.ingest` for the service. The Administrator role deliberately excludes pipeline ingestion; use an appropriately scoped Service Manager assignment instead of widening that role.

Scheduling currently supports approvals containing only registry-backed images pinned to SHA-256 digests. Charts, uploaded archives, and mixed releases require a full assessment through the existing workflow. The worker submits the exact retained image identities through the existing scanner and imports the completed results into the original service/version. It rechecks the schedule owner's current permissions before submission and ingestion.

Inspect `GET /api/cyber-approvals/{id}/reassessment` for events: `queued`, `scanning`, `failed`, `review_required`, or `pending_review`. Failed/incomplete scans never extend approval. An interrupted submission without a persisted scan receipt fails closed and requires investigation; it is not blindly retried. A successful, fresh, complete assessment with unchanged artifact identities creates a new pending Cyber approval. Only the normal Cyber decision can grant its validity period. The prior approval and its frozen evidence remain unchanged. A competing newer assessment causes review rather than silently substituting evidence. Manual renewals use the existing approval request endpoint with `renews_approval_id` and the same fresh-evidence checks.

Revoke a grant through the existing Cyber action (`POST /api/approved-releases/{id}/revoke`). Revocation disables future scheduled dispatch for that approval and prevents in-flight work from granting a renewal. Consumer requests still evaluate current grant, credential, and policy state, including cached content; schedule success itself never authorizes delivery.

Public verification keys are available at `GET /api/oci/approval-keys`. Signing configuration rotation retains both old and new public keys with SHA-256 fingerprints; discovery never returns private keys. Establish the expected fingerprint through a trusted channel before verifying downloaded evidence. Retention starts with this feature: import/retain any older verification keys needed for approvals issued before deployment through the existing signing configuration process before rotating away from them.

Use the existing evidence and offline bundle downloads at `/api/cyber-approvals/{id}/download/evidence` and `/api/cyber-approvals/{id}/download/offline` when available. They reuse retained snapshots, checksums, signatures, and verification material from the release publication workflow. Offline signature verification establishes evidence authenticity; it cannot prove that the approval remains unrevoked or permitted by today's policy. Check current authorization online before consuming through the proxy.
