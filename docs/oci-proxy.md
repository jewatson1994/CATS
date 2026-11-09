# OCI compliance proxy

The CATS OCI facade is included in the main Compose stack and serves approved artifacts from configured upstream registries. It is a read-only Distribution API endpoint, not a second registry or an upload destination. Upstream Harbor remains the source of content. CATS owns authorization, current policy decisions, and the local verified-content cache.

## Deployment

Build or load the CATS image containing this feature and configure the normal deployment environment. Both `templates/compose.local.yaml` and `templates/compose.main.yaml` include `oci-proxy` by default. For a shared deployment, use the [main deployment template](../templates/README.md#main-cats) with Docker Compose v2 (`docker compose`): it includes Nginx and its configuration in one Compose file, with the portal and OCI proxy on distinct HTTPS hostnames sharing host port 443. Set the required `CATS_PORTAL_HOSTNAME` and `CATS_OCI_HOSTNAME`, configure DNS, and provide matching certificates before startup. Follow [HTTPS setup and migration](nginx-ingress.md) when upgrading an existing installation.

The local `templates/compose.local.yaml` remains the local HTTP stack. From the repository root, start that stack with:

```sh
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml config --quiet
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml up -d --wait
```

No OCI overlay is required for either file. The former `compose.oci-proxy.yml` was a no-op and has been removed. Remove it from existing `COMPOSE_FILE` settings and `-f` lists.

The proxy uses the same `CATS_IMAGE`, database, and `CATS_CONFIG_ENCRYPTION_KEY` as the portal. Its separate named `oci_proxy_cache` volume survives restarts and service recreation. It has no Docker socket, privileged execution, or registry storage backend. In the deployment template, the application serves HTTPS privately on port 5000 and Nginx passes through TLS from host port 443; neither backend publishes a host port. Clients use `registry.example.com` (replace with your configured hostname), without `:5000`, and must trust its certificate. The root local stack instead publishes HTTP only on host loopback at `127.0.0.1:5000` by default (`CATS_OCI_PORT` changes that host port). Do not send machine credentials over a public HTTP connection.

For this upgrade, use the updated shared `CATS_IMAGE` for `portal`, `portal-control`, and `oci-proxy`. Both integrated Compose definitions provide a writable 64 MiB `/tmp` tmpfs for startup while retaining the read-only remediation volume. Keep that tmpfs entry when adapting the template; shared startup code creates `/tmp/cats-patch-jobs`.

For older deployments retaining the root Compose file, the [legacy Nginx override](nginx-ingress.md#legacy-root-stack-override) enables the same TLS passthrough routing and removes backend published ports. The integrated deployment template needs no Nginx override or separate Nginx configuration files. No CATS image rebuild is needed for either routing setup.

Configure an upstream HTTPS registry origin and its read-only upstream credentials through the CATS administration interface. Add private CA PEM certificates when needed. Delegated token service origins and blob redirect origins require explicit allowlisting. Keep the allowlists narrow: token services receive upstream credentials. Redirects to another origin lose Authorization headers; signed CDN URLs can still work. No insecure TLS bypass exists.

Cyber release publication runs in `remediation-worker` and has a separate redirect policy. If its source registry or destination redirects blob GET/HEAD requests to object storage, configure `CATS_OCI_BLOB_REDIRECT_ORIGINS` in the deployment environment and recreate the worker. Same-origin redirects need no setting; registry credentials are never forwarded cross-origin, and cross-origin writes and manifest redirects remain blocked. The upstream allowlists above and `CATS_OCI_TOKEN_REALMS` do not grant this permission. See [publication configuration](signed-release-documentation.md#configuration-and-boundaries).

Issue separate scoped machine credentials for consumers. Use those credentials with `docker login`, Helm registry login, or an equivalent OCI client against the CATS hostname. Portal browser sessions are not registry login credentials. Limit each machine identity to the explicitly mapped repositories it needs; rotate or revoke it without changing upstream credentials.

## Map a Harbor project

On the **Approved Release Destinations** page, open **Approved artifact distribution** and choose **Add mapping**. Select the Harbor upstream and enter `cyber-approved/*` for both **Public repository** and **Upstream repository**. This exposes `cyber-approved/team/api` under the same name in CATS. To use a different public name, enter `approved/*` on the public side. CATS keeps the entire path below the project name. Both patterns must consist of one project name followed by `/*`.

Grant the new mapping to a CATS machine account. The grant covers current and future repositories in the project. CATS uses scan or verified publication evidence to identify the service for each repository and digest, then checks current approval and compliance. If two services claim the same repository and digest, use an exact mapping to select the intended service. Exact mappings take precedence and require their own grant. A suspended exact mapping blocks the pull. For services using signed release revisions, pulls by tag also require the tag and digest to match the active signed release.

To test registry access, choose **Test connection**, enter an existing tag or digest, then enter a concrete public repository such as `cyber-approved/team/api`. To verify the full pull, log in to the CATS proxy with the CATS machine credentials and run `docker pull cats.example/cyber-approved/team/api:v1` with an approved image and tag from your project.

## Content and policy behavior

Every delivery must pass the current authorization and compliance decision, including a content-cache hit. Cached bytes are never evidence of approval. Mutable tags resolve to immutable upstream manifest digests before policy evaluation. Child manifests, configs, layers, and referrers must remain within the authorized approved graph; knowing a blob digest does not grant access to it. Multi-platform indexes require all exposed children to be eligible. Unknown, stale, blocked, revoked, and out-of-scope artifacts fail closed.

An approved saved service distribution uses its own retained scan and frozen component selection. Its approval does not authorize excluded images. Current policy, finding deadlines, and exception validity still apply to the selected findings; a pending or newer distribution scan requires approval of the current evidence before pulls resume.

Manifest responses preserve upstream bytes and their SHA-256 identity; retained manifest JSON is stored in PostgreSQL. The configurable disk quota applies to cached blobs, not database metadata. Blob downloads stream to temporary files in bounded chunks, verify SHA-256, and atomically enter the cache only after success. Cache hits are rehashed; corrupted entries are removed and fetched again. Writers use an interprocess lock. Older entries are evicted to enforce the byte quota. Interrupted temporary files are removed by a subsequent writer. Repository pushes, deletes, and uploads are unsupported.

Referrers are fetched with bounded pagination restricted to the same upstream repository and subject. Legacy cosign `sha256-<subject>.sig` discovery verifies that every simple-signing payload names the exact authorized subject digest before exposing its manifest or blobs. This establishes an association, not cryptographic trust: consumers must still verify signatures using their own approved public keys or identity policy. The facade filters returned references according to its current graph/policy rules. Clients that require registry-specific APIs beyond OCI Distribution must use Harbor directly through separately authorized workflows.

Approved releases can also contain a signed immutable attestation inventory. The proxy serves its `sha256-<subject>.att` tag, manifest digest, DSSE payloads and inert config, and includes the descriptor in `/referrers/<subject>`. The signed manifest digest is authoritative even if the upstream `.att` tag moves. Every envelope must match the exact subject, typed CATS predicate and evidence receipt in the granting release; arbitrary upstream referrers cannot authorize additional content. Publication and replica import verify the DSSE signature with the release's authenticated signing key. Relocation preserves the original signed source reference inside the predicate.

Attestation manifest and blob cache hits require current authorization for the root image or chart and membership in the exact release granting that request. Referrers repeat this check after fetching content. Supersession, expiry, revocation or a changed inventory can therefore deny previously cached attestations; a Local Cyber override grants only its retained release and digest scope. Historical releases without the optional attestation inventory remain valid but expose no attestation graph through this path.

The publisher retains each pinned signature and attestation graph under a `cats-signature-<manifest-sha256-hex>` or `cats-attestation-<manifest-sha256-hex>` registry tag. Replicate and retain those tags so an older approval remains complete after another approval moves the same artifact's native attachment tags. These retention tags support registry transport; proxy consumers use the authorized native tag or immutable digest.

Cache configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CATS_OCI_CACHE_DIR` | `/var/cache/cats-oci` in the main stack | Persistent content directory |
| `CATS_OCI_CACHE_MAX_BYTES` | 10737418240 | Total cached content quota (10 GiB) |
| `CATS_OCI_MAX_BLOB_BYTES` | 4294967296 | Maximum individual blob (4 GiB) |
| `CATS_OCI_PORT` | 5000 | Loopback host port in the root local stack only; unused by the HTTPS deployment template |

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
9. With one `cyber-approved/*` mapping and one machine grant, pull approved images from two services, including a nested repository. Confirm an unapproved digest and a revoked approval fail with cached layers present. Add an exact repository mapping and confirm the project grant cannot access it until the machine receives the exact mapping's separate grant; suspending the exact mapping must block that repository.

## Startup database locks

The proxy initializes the shared schema before opening its HTTP listener. Older
images recreated installed triggers and repeated index/default DDL during every
startup. An open portal transaction could block that DDL, with Services, the Cyber
dashboard, and Administration then waiting behind it. A healthy portal container
does not rule out this database lock chain.

If PostgreSQL activity shows proxy startup waiting on schema DDL and blocking page
queries, stop `oci-proxy` to release its migration transaction. Keep it stopped
until an image containing the startup migration fix is deployed; a normal
`docker compose --project-directory . --env-file .env -f templates/compose.local.yaml up` will start the old image again. Updated images retain existing
triggers, defaults, and indexes. Actual schema changes have a five-second lock
timeout after acquiring the migration advisory lock. A timeout rolls back the
whole migration and fails startup, rather than serving with a partially upgraded
schema. If it recurs, inspect long-running/open transactions and schedule the
upgrade during a quiet period before restarting the affected service.

## Rollback

To take the proxy out of service immediately, stop it:

```sh
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml stop oci-proxy
```

When using the HTTPS deployment template, replace `--project-directory . --env-file .env -f templates/compose.local.yaml` with your existing `--env-file /secure/cats.env -f templates/compose.main.yaml` arguments, substituting your environment path. Stopping or removing the container does not disable this default service: a later normal `docker compose --project-directory . --env-file .env -f templates/compose.local.yaml up` starts it again. Keep it stopped during the rollback and account for it in subsequent deployment commands.

Remove its reverse-proxy route and revoke its machine credentials. Preserve the cache volume for investigation or later reuse; deleting it is optional and only removes reproducible upstream content. The normal portal, workers, database, and Harbor remain in place. Do not use `docker compose --project-directory . --env-file .env -f templates/compose.local.yaml down -v` as a proxy rollback because it can remove unrelated persisted services and data. Reverting clients to direct Harbor access requires an explicit access-policy decision; do not automatically bypass compliance enforcement.


## Reassessment, renewal and verification

Keep the normal remediation worker running: its maintenance loop creates durable `oci_reassessment` jobs and reconciles completed scans. Schedule state, dispatch receipts, scanner job state, and renewal records survive application restarts in PostgreSQL. Scan outputs must also remain available on the normal scanner storage until ingestion finishes.

Open an approved Cyber request and use its **Scheduled reassessment** section to set the interval, enable or disable scheduling, refresh progress, and follow a new renewal request. A scoped Service Manager can also configure an approved release with `PUT /api/cyber-approvals/{id}/reassessment`, sending JSON `{"interval_days":7,"enabled":true}` and the session CSRF token in `X-CSRF-Token`. The interval accepts 1–365 days. A new schedule is due immediately, then repeats at that interval. Send `enabled:false` to stop future dispatches. This action requires `service.view`, `service.edit`, `service.export`, `approval.request`, and `scan.ingest` for the service. The Administrator role deliberately excludes pipeline ingestion; use an appropriately scoped Service Manager assignment instead of widening that role.

Scheduling currently supports approvals containing only registry-backed images pinned to SHA-256 digests. Charts, uploaded archives, and mixed releases require a full assessment through the existing workflow. The worker submits the exact retained image identities through the existing scanner and imports the completed results into the original service/version. It rechecks the schedule owner's current permissions before submission and ingestion.

Inspect `GET /api/cyber-approvals/{id}/reassessment` for events: `queued`, `scanning`, `failed`, `review_required`, or `pending_review`. Failed/incomplete scans never extend approval. An interrupted submission without a persisted scan receipt fails closed and requires investigation; it is not blindly retried. A successful, fresh, complete assessment with unchanged artifact identities creates a new pending Cyber approval. Only the normal Cyber decision can grant its validity period. The prior approval and its frozen evidence remain unchanged. A competing newer assessment causes review rather than silently substituting evidence. Manual renewals use the existing approval request endpoint with `renews_approval_id` and the same fresh-evidence checks.

Revoke a grant through the existing Cyber action (`POST /api/approved-releases/{id}/revoke`). Revocation disables future scheduled dispatch for that approval and prevents in-flight work from granting a renewal. Consumer requests still evaluate current grant, credential, and policy state, including cached content; schedule success itself never authorizes delivery.

Public verification keys are available at `GET /api/oci/approval-keys`. Signing configuration rotation retains both old and new public keys with SHA-256 fingerprints; discovery never returns private keys. Establish the expected fingerprint through a trusted channel before verifying downloaded evidence. Retention starts with this feature: import/retain any older verification keys needed for approvals issued before deployment through the existing signing configuration process before rotating away from them.

Use the existing evidence and offline bundle downloads at `/api/cyber-approvals/{id}/download/evidence` and `/api/cyber-approvals/{id}/download/offline` when available. They reuse retained snapshots, checksums, signatures, and verification material from the release publication workflow. Offline signature verification establishes evidence authenticity; it cannot prove that the approval remains unrevoked or permitted by today's policy. Check current authorization online before consuming through the proxy.


## Standalone disconnected replica

`CATS_MODE=full` remains the default for existing installations. Deploy a replica with a separate database and storage; do not change an authoritative installation into a replica by toggling its environment. The replica is a read-only evidence browser and OCI distribution service. Its local accounts, source configuration, machine credentials and explicitly approved Cyber overrides are writable; imported services, findings, approvals, POA&Ms and evidence remain immutable through the API, including for administrators.

Copy `templates/replica.external-ingress.env.example` to `.env.replica`, set unique database and bootstrap passwords, and generate a persistent Fernet encryption key (for example, `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`). Keep this key with the backup secrets. Load the same published full Linux amd64 image used for main CATS and select it with `CATS_IMAGE`. Existing replica settings can use `CATS_REPLICA_IMAGE` as a fallback when `CATS_IMAGE` is unset or blank. Load `postgres:16` too, then use the standalone file:

```sh
docker compose --project-directory . --env-file .env.replica -f templates/compose.replica.external-ingress.yaml up -d --wait --pull never
```

Do not merge this file with the full Compose stack. It fixes `CATS_MODE=replica` and starts only PostgreSQL, the portal and the OCI proxy. It does not start scan, patch, discovery, deployment-validation, intelligence refresh, maintenance or export workers; it does not mount the Docker socket or require scanner databases. Database migrations and authentication still run. Synchronization runs in the background and does not block portal startup on registry availability. The shared image contains the full scanner/validator toolset and checksum-pinned Cosign verifier, while replica runtime mode skips assessment and intelligence initialization. The replica Compose file has no build context; no separate replica image build is needed.

The portal and proxy bind to loopback ports 8080 and 5000 by default. Publish them through the installation's TLS reverse proxy using the proxy routing guidance above. Session cookies are secure; access the portal over HTTPS. Retain local login or configure a reachable local Keycloak/OIDC realm through the `CATS_OIDC_*` settings; replicas do not bypass authentication. Use **Administration > Settings** for the local OIDC mapping and CA configuration. A replica must not depend on the authoritative system's identity provider if that provider is unreachable in the disconnected environment.

### Registry and source setup

1. Log in with the bootstrap administrator and complete the password change. Open **Administration > Replica synchronization**. Configure a local Harbor/OCI registry connection with its HTTPS endpoint, a pull-only robot credential when required, and the appropriate CA certificate. Credentials are encrypted using `CATS_CONFIG_ENCRYPTION_KEY`; returned API responses never contain saved passwords.
2. Independently obtain the publishing system's root public-key SHA-256 fingerprint through a trusted administrative channel. Add a source using the local registry, an exact `project/service/releases` repository or `project/*` discovery scope, the trusted `sha256:<64 lowercase hexadecimal characters>` fingerprint(s), and a polling interval. An unchained package must match a configured pin directly. A rotated signer must authenticate a complete succession chain from the original pinned root, with every transition signed by both predecessor and successor. Keep the original pin during authenticated rotation; a successor key does not need a separate pin. Never trust a new fingerprint merely because it appears in the downloaded archive. Use **Edit source** to update polling and trusted fingerprints; removing the root pin denies its successor chain. An imported source keeps its registry/repository binding; configure a separate source for a different scope.
3. Enable the source or choose **Sync now**. The page shows last success, errors and job stages. Invalid signatures, incomplete evidence, graph/digest mismatches and stale or replayed versions leave the last valid imported state intact. Fix the registry/trust problem and retry; a synchronization failure does not grant access. Exact repositories avoid relying on registry catalog permission; project discovery requires listing permission within that scope.
4. Open an imported service and **Releases** to inspect the publisher, signed manifest digest, validity and artifact inventory. Each artifact lists its local proxy pull path. Download **immutable release evidence** for the original captured evidence; queued spreadsheet/bundle generation is intentionally unavailable because the replica has no export worker.
5. Open **Release destinations** to review the imported service-scoped repository mappings and create a local machine principal with explicit grants to the required repositories. Automatic mapping creation does not create consumer credentials or grant access. Configure clients to pull the displayed local proxy path by digest using that principal. The proxy requires current credentials and checks the imported release state on every request, including cache hits. Edit a repository mapping to set **Local maximum release age (days)** when local policy requires earlier expiry. This limit only shortens the signed release validity; it never extends the publisher’s expiry or requires a local rescan. Leave it blank to use the signed validity period.

Only the local registry must be reachable for synchronization and uncached distribution; the replica does not query the authoritative CATS instance. Expiry is evaluated locally. Revocations and superseding releases take effect when their verified update arrives through the local registry. Monitor synchronization freshness as part of disconnected operations. The signed publication format and replication requirements are described in [Portable approved releases](portable-approved-releases.md).

### Local Cyber mission-continuity decisions

Assign the **Local Cyber** role to a named local Cyber reviewer with the intended service scope. The default Administrator role deliberately excludes `local_override.create`, `local_override.revoke` and `local_override.view_audit`; ordinary administration does not authorize mission risk acceptance. Existing role and scope checks, session authentication, CSRF protection and audit recording remain active.

Use the service's **Cyber Overrides** view, or follow the guidance returned by a denied proxy pull. Select the exact imported release and optionally an exact manifest digest, the specific denial condition (expired, superseded or revoked), mission impact, justification and explicit risk acceptance. An empty expiration/review date is permitted for an indefinite decision. Revoked-release decisions require explicit elevated-risk acknowledgment. The override cannot allow an unknown artifact, invalid signature, missing or corrupted evidence, untrusted publisher, disabled credential or unrelated digest.

The service and release pages show an active mission-continuity exception separately from the original approval. An override never changes that approval's status, expiry, revocation or captured evidence. Review creator, timestamps, conditions and last usage; reviewers with audit permission can inspect individual uses. Revoke the local override with a reason when no longer justified. Each subsequent distribution request reevaluates the current override and release state.

### Persistence and recovery

Back up `replica_db`, `replica_evidence`, and the encryption key together. PostgreSQL retains source pins, imported release high-water marks, users, grants, overrides, audit records and synchronization jobs. Evidence storage retains verified archives required for integrity checks. The `replica_cache` volume is disposable upstream content and never establishes authorization by itself. Restarting portal/proxy preserves committed configuration and evidence and resumes background synchronization; no in-memory approval or override cache is authoritative. Do not delete database/evidence volumes as a routine retry or upgrade step.
