# OCI approved-release replica deployment runbook

System A is the authoritative, full CATS installation: it assesses, patches and obtains Cyber approval. System B is a separate CATS replica and local OCI registry: it verifies the replicated release, reconstructs its retained evidence, and enforces local pull authorization. System B does not require a connection to System A after the complete release graph has reached its local registry.

This is an operating procedure, not a qualification result. See [portable approved releases](portable-approved-releases.md), [signed release documentation](signed-release-documentation.md), and [OCI proxy behavior](oci-proxy.md) for the underlying formats and interfaces. Use the qualification report for the exact versions, commands, evidence and observed outcomes of a particular deployment.

## 1. Prepare System A and registry replication

1. Keep System A in its existing full mode, with its durable database, artifact storage and publication worker. Configure a release destination under **Administration → Release Destinations**, including its HTTPS registry, namespace, publishing credentials and CA trust. Configure the signing key under **Settings** and deliver its SHA-256 public-key fingerprint to System B administrators through an independently trusted channel.
2. Use the ordinary scan, remediation, Release Distribution and Cyber approval workflow. Publish the approved snapshot and wait for successful publication. Retain the signed manifest, complete evidence, receipt and artifact inventory. A legacy approval without complete portable evidence needs a new review; retrying it cannot manufacture the missing frozen evidence.
3. Replicate the complete approved namespace from the System A registry into System B's registry. Preserve immutable manifest and blob bytes, all image-index children, chart packages, configs, layers, explicit Cosign `.sig` and `.att` manifests and blobs, and the service's `releases` repository. Discovery tags use `release-<sequence>-<release-id>` and `revocation-<sequence>-<release-id>`. Image-only tag filters are insufficient.
4. Preserve repository paths where possible. Configure retention so every referenced artifact and signature remains available while its release or history is required. Verify the actual registry replication product and version; ordinary OCI graph copying is not evidence that a Harbor replication rule works.
5. Keep the publisher signing identity and approved destination available for later signed revocation publication. Copying a release or changing a registry tag never extends its signed expiration.

Use a read-only registry identity on System B. TLS/registry credentials establish transport access; the independently delivered publisher fingerprint establishes release trust. These are separate controls.

### Integrated attestation routing

New approved publications include a native Cosign `cyber-approval` attestation for every image and chart. Its signed predicate binds the artifact digest, approval snapshot and evidence archive. The signed release inventory pins its immutable manifest, blobs and verified receipt. Replica import requires the complete declared graph and verifies the DSSE signature with the release's authenticated signing key. Legacy releases without an attestation inventory remain readable; import does not invent attestations for them.

Replicate and retain the digest-derived `cats-signature-<manifesthex>` and `cats-attestation-<manifesthex>` tags as well as native `.sig` and `.att` tags. These immutable tags preserve earlier approvals when the same artifact is approved again before replication. Current offline imports create them too. Older publications and embedded import scripts are not retroactively updated; use the current importer or explicitly backfill retained graphs before relying on delayed replication.

For an older complete signed inventory without optional `retention_tag` metadata, derive each retention tag from its pinned signature or attestation manifest digest and tag that exact retained graph. Preserve all signed bytes. The current reviewed `verify-import.py` can replace an older bundle's embedded importer without changing the signed contents; it creates these tags during import. Its destination repository layout is the offline artifact import layout, so preserve or explicitly map the original release repositories when configuring replica discovery. Backfill requires the complete pinned graphs: a tag cannot recover deleted manifests or blobs, and an approval missing frozen `replica-service.json` evidence requires a new approval. The compatibility fixture qualifies this older CATS inventory shape, not arbitrary third-party attestations or all historical release formats.

Consumers use the displayed proxy repository to request the subject's `sha256-<digest>.att` tag, its retained manifest digest, envelope blobs or OCI referrers. These routes enforce the same live release approval and exact-root Local Cyber override as the image. Expiration, supersession, revocation, removed trust or a revoked override denies access even when the envelope is cached. Mutable upstream tags cannot replace a retained release's pinned attestation.

Registry relocation preserves the original signed source reference, subject digest and predicate. Verify that original claim against the signed inventory; do not rewrite it to the target registry name. The integrated qualification helper is `portal/tests/harbor_continuity_qualification.py`; it exercises publication, authenticated rotations, normal replica synchronization, proxy pulls and Local Cyber overrides. Its fixtures are explicitly synthetic and do not replace a real scan-and-approval qualification.

The optional full-mode `verify_attestation` convenience helper expects the supplied reference inside the predicate. Supplying a relocated target reference does not reinterpret the original source-bound predicate. Verify the native signature at the target and check the original signed source subject, without rewriting that claim.

To repeat the optional synthetic transport check, run the following in a verification environment with the application dependencies, Cosign and `<repository>/portal` on `PYTHONPATH`. Replace every placeholder with the deployment's actual path or credential-free HTTPS registry authority. Use a fresh private workspace and a unique literal `qualification/<unique-run>` subtree; the helper retains its generated private signing key there. The Docker configuration directory must contain authorized source/target registry credentials in `config.json`; keep it private.

```text
python <repository>/portal/tests/harbor_attestation_qualification.py publish --workspace <new-private-workspace> --source https://<source-registry> --target https://<target-registry> --namespace qualification/<unique-run> --ca <ca-bundle.pem> --docker-config <docker-config-directory>
```

Run the actual Harbor replication policy for that exact subtree, retain its successful execution/task evidence, and stop or isolate the source registry. The helper does not copy between registries. Then verify using the same retained workspace and explicit trust:

```text
python <repository>/portal/tests/harbor_attestation_qualification.py verify --workspace <new-private-workspace> --source https://<source-registry> --target https://<target-registry> --namespace qualification/<unique-run> --ca <ca-bundle.pem> --docker-config <docker-config-directory>
```

Retain `expected.json`, `verification.json`, `target-cosign-verified.jsonl`, the Harbor execution evidence and the observed source-offline state. This optional direct-transport check does not exercise the replica proxy; use the integrated qualification for that path.

### System A environment and publication prerequisites

Start from the full deployment's existing [templates/local.env.example](../templates/local.env.example) and [templates/compose.local.yaml](../templates/compose.local.yaml), preserving its persistent storage and configured services. The publication-related settings below supplement that deployment; they are not a replacement environment file for System A.

| Setting | Required configuration / default |
| --- | --- |
| `CATS_MODE` | `full` (the default); keep System A authoritative |
| `POSTGRES_PASSWORD`, `CATS_BOOTSTRAP_PASSWORD` | Required by full Compose; supply real secrets through the existing deployment secret process |
| `CATS_CONFIG_ENCRYPTION_KEY` | Required persistent Fernet key protecting saved registry credentials and signing configuration; preserve the existing value |
| `CATS_PATCH_WORKER_TOKEN`, `CATS_SCAN_WORKER_TOKEN`, `PIPELINE_API_TOKEN` | Required by full Compose; preserve the deployment's authenticated worker/integration configuration |
| `CATS_RELEASE_DOC_MAX_BYTES` | `268435456`; generated documentation archive and expanded content limit |
| `CATS_BUNDLE_MAX_BYTES` | `104857600`; portable service/evidence bundle limit |
| `CATS_OCI_TOKEN_REALMS` | Empty by default; allow only independently approved HTTPS token-service origins when the registry uses another origin |
| `CATS_OCI_BLOB_REDIRECT_ORIGINS` | Empty by default; allow only approved HTTPS origins for blob read redirects, never copy signed URLs or credentials into this setting |

Store the signing private key/password and destination credentials in their authorized CATS configuration interfaces. `CATS_SIGNING_PRIVATE_KEY` and `CATS_SIGNING_PASSWORD` are transient internal job material, not required deployment secrets to add to `.env`. Keep destination CA certificates configured and TLS verification enabled. Publisher trust on System B remains an independently provisioned public-key fingerprint.

The full deployment's `remediation-worker` executes release publication and must have the same encryption key, retained release storage and publication environment as the portal. After an intentional publication environment change, use the same Compose files/project/env-file as the existing deployment. For the local Compose deployment, these commands validate configuration and recreate the affected services without printing secrets:

```powershell
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml config --quiet
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml up -d --no-deps --force-recreate --wait portal portal-control remediation-worker
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml ps portal portal-control remediation-worker
```

Expect healthy running services and a successful signed publication receipt before treating the release as ready for registry replication. For a deployment template, use that deployment's actual files and environment path instead.

## 2. Prepare the separate System B deployment

Use Docker Compose v2 and a separate project, database and volumes. The [replica Compose file](../templates/compose.replica.external-ingress.yaml) is standalone. Do not combine it with the full `templates/compose.local.yaml` or the full deployment template: those deploy assessment infrastructure that a replica does not need.

For deployment with built-in HTTPS ingress, use the dedicated [replica template and environment example](../templates/README.md#cats-replica). That template requires an explicit image and has no build context; it can be deployed without a source checkout. It adds a fourth service, Nginx, for built-in HTTPS routing with private TLS backends. Prepare the pinned Nginx image, two DNS names and matching certificate directories as described there. It preserves the external-ingress file's `cats-replica` project, volume names and replica settings. The commands below use the external-ingress file, which also consumes a prebuilt image.

The external-ingress replica file has exactly three services, ordered `portal`, `oci-proxy`, then `db`. Both variants use the same full `CATS_IMAGE` as main CATS, with `CATS_MODE=replica` fixed by Compose. The image contains the full scanner/validator toolset and signature verifier, but neither replica stack starts assessment workers, validator services or intelligence initialization, mounts a Docker socket, or requires scanner databases. Main and replica remain separate deployments with independent databases and storage.

Deliver the published, verified full Linux amd64 CATS image into the disconnected environment, using the same release artifact as System A. Prepare the `postgres:16` image too. No lightweight replica image build is required. Historical ARM64 qualification applies only to the legacy `portal/Dockerfile.replica` image; it does not qualify the shared full image for ARM hosts. Deployment capacity and performance still require qualification on the intended host.

From the repository root:

```powershell
Copy-Item templates/replica.external-ingress.env.example .env.replica
# Replace YOUR_CATS_IMAGE with the full release image already loaded on this host.
docker run --rm --pull never --entrypoint python YOUR_CATS_IMAGE -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set `CATS_IMAGE` to that full image reference and put the generated key into `CATS_CONFIG_ENCRYPTION_KEY` in the private `.env.replica`. Set unique `POSTGRES_PASSWORD` and `CATS_BOOTSTRAP_PASSWORD` values; the example passwords are placeholders. Keep the environment file and encryption key in your secret-management/backup process and out of source control. Existing encrypted credentials depend on the same encryption key after restart or restore.

| Setting | Deployment use |
| --- | --- |
| `CATS_IMAGE` | Explicit published full CATS image loaded for this release; required unless the legacy fallback is set |
| `CATS_REPLICA_IMAGE` | Legacy replica image setting; used only when `CATS_IMAGE` is unset or blank |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Dedicated replica database; do not point at System A |
| `CATS_BOOTSTRAP_USERNAME`, `CATS_BOOTSTRAP_PASSWORD` | Initial local administrator; changing these is not a password-reset procedure for an existing account |
| `CATS_CONFIG_ENCRYPTION_KEY` | Persistent secret encryption/integrity key; preserve with backups |
| `CATS_PORT`, `CATS_OCI_PORT` | Host loopback backend ports, default 8080 and 5000 |
| `CATS_OCI_CACHE_MAX_BYTES` | Proxy blob-cache quota, default 10 GiB; budget database/evidence storage separately |
| `CATS_OIDC_*` | Optional locally reachable OIDC issuer, client and redirect configuration |

Compose fixes `CATS_MODE=replica`, production mode, disabled development-auth bypass, secure session cookies and disabled deployment validation. Do not turn the replica into full mode against its imported database.

### HTTPS and names

Select your actual portal and OCI hostnames, DNS records and trusted certificates. The deployment template includes TLS passthrough routing on port 443, with certificates mounted in the private portal and proxy backends; no forwarded-header trust is needed for that path. Both full and replica templates use port 443, so use separate hosts or adapt ingress/port mappings when sharing a host. Neither variant creates DNS records or issues certificates.

When using the external-ingress replica file instead, place a TLS ingress in front of its loopback portal and proxy ports. Preserve the original Host and HTTPS forwarding information; configure the ingress/forwarded-header trust for your topology. Do not expose those plain HTTP backend ports to consumer networks. The root file does not include ingress.

The portal sets secure cookies, so use its HTTPS address for browser login. The external-ingress file's local health probes use loopback HTTP; the deployment template verifies backend certificates over HTTPS. OCI clients must trust the ingress certificate; the replica must separately trust the local upstream registry certificate. Use your actual hostnames in client commands, not the examples from other deployment documents. Do not layer a full-stack ingress template onto this replica merely to obtain TLS.

For disconnected use, keep a tested local login or configure an OIDC/Keycloak issuer reachable within System B's environment. A login that depends on an unreachable external identity provider cannot provide offline access.

## 3. Start and configure the replica

Validate and start only the replica project:

```powershell
docker compose --project-directory . --env-file .env.replica -f templates/compose.replica.external-ingress.yaml config --quiet
docker compose --project-directory . --env-file .env.replica -f templates/compose.replica.external-ingress.yaml up -d --wait
docker compose --project-directory . --env-file .env.replica -f templates/compose.replica.external-ingress.yaml ps
```

For an offline start with both images already loaded, use `up -d --wait --pull never` in place of `up -d --wait`. This makes a missing image fail clearly without attempting a registry pull; the replica Compose file has no build context. Keep the same Compose project name on subsequent starts so the deployment retains its volumes; choose different host ports when another installation already uses the defaults.

Log in through the HTTPS portal and open **Replica administration** at `/admin/replica`.

1. **Local registries → Add local registry:** enter System B's registry HTTPS origin and read-only credentials. System roots and CATS's configured trusted CA certificates are used by default; add registry-specific CA PEM only when additional trust is required. Use **Registry access and proxy** for advanced connection settings, repository mappings, machine accounts and connection tests. Explicitly allowlist any required delegated token-service or blob-redirect origin; do not broadly trust unrelated origins.
2. **Release sources → Add release source:** select that local registry; enter an exact repository ending in `/releases`, or a single project scope such as `<approved-project>/*`; add the independently trusted `sha256:` publisher fingerprint(s); set the polling interval and save.
3. Prefer exact release repositories if the registry does not permit catalog discovery. Wildcard discovery requires `/v2/_catalog`; both forms require paginated tag access and read access to every referenced artifact/signature.
4. Select **Synchronize now**, or let scheduled synchronization run. Initial sync runs in a background thread after portal startup. Empty local evidence is expected until a complete verified release activates; startup does not wait for the registry or ingest public risk feeds.
5. Watch **Synchronization history and import failures**. It reports stage, status and discovered/activated/revoked/unchanged/failed counts. Source health shows the last attempt/success and a correlation reference on failure. The page refreshes every five seconds while open.

Registry synchronization, upstream connection tests and OCI proxy retrieval use the global **Trusted CA certificates** configured under **Authentication and trust**, in addition to system roots. The optional per-registry CA field adds certificates for that registry; it does not replace the inherited bundle. Configure shared environment CAs once on System B, and use the registry field for any extra CA required only by that registry. Publisher fingerprints remain separate release-signing trust anchors.

Polling defaults to 300 seconds and accepts 10–86400 seconds. The worker checks for due work about every five seconds. Manual and scheduled admission share a durable per-source job; repeated requests do not intentionally create parallel imports of the same source. Interrupted work is recovered through durable job leases and retries.

A source with imported services is bound to its registry and repository scope. Do not rebind it to another location. Plan a separate source/deployment migration with verified identity continuity.

### Separate local permissions

| Responsibility | Permission/scope |
| --- | --- |
| Registry credentials, machine principals and repository access | `release.destination.manage` |
| Publisher pins and source configuration | `replica.admin` |
| Manual synchronization and sync health | `replica.sync` or the administration permission for viewing health |
| Read imported service pages | `service.view` for the intended service/group |
| Read retained signed context/download evidence | `evidence.view` plus service visibility |
| Grant/revoke mission-continuity exceptions | Dedicated `local_override.create` / `local_override.revoke` for the intended service/group |
| Inspect exception usage | `local_override.view_audit` for the intended service/group |

Use local accounts/roles and locally managed scopes on `/admin`; source actors remain historical attribution, not imported login accounts or grants. A source administrator can select existing registries without receiving registry credentials. The built-in Administrator role alone does not confer Local Cyber override authority. Assign Local Cyber responsibility deliberately and separately.

## 4. Verify retained evidence and enable consumer pulls

After synchronization, inspect the imported service from `/`. Check its overview, artifacts, findings, activity, dependencies, remediations/POA&M and history. The service's version/history selector and **Approved Releases** (`/approved-releases?service=<service-key>`) expose retained versions, signed expiry/status, digest inventory and evidence download. Evidence is the captured authoritative assessment; importing does not start a new scan or recalculate it under local intelligence.

Check the original actors, timestamps, findings/observations, risk/approval context and documents in the retained evidence. Source account IDs are not local authorization identities. History/downloads may remain available after an approval stops authorizing pulls.

Activation creates exact service-specific proxy routes. **Approved Releases → Signed artifact inventory** shows the local pull paths. The usual route is `services/<local-service-id>/<upstream-repository>`; very long names have a deterministic shorter form. Use the displayed path instead of guessing it.

Under **Registry access and proxy**, create a scoped machine principal and grant only the required repository mappings. Browser sessions are not OCI login credentials. Use the real proxy origin, machine identity and displayed path:

```text
docker login <proxy-host> --username <machine-user> --password-stdin
docker pull <proxy-host>/<displayed-public-repository>@sha256:<approved-digest>
helm registry login <proxy-host> --username <machine-user> --password-stdin
```

Supply secrets through the client prompt or approved secret input; do not paste credentials into a command log. Use the retained chart's recorded source-to-target mapping for environment-specific values. Approved chart bytes are not rewritten on import.

Verify a complete consumer pull, including all requested image platforms or chart layers. Test an unrelated digest and a disabled/ungranted mapping and expect denial. Proxy cache hits still undergo current authorization; cache contents do not establish approval. Mapping suspension, disabled upstreams/principals, signature/inventory integrity and publisher trust remain enforcement boundaries.

## 5. Updates, expiry, revocation and Local Cyber exceptions

For an update, System A publishes a newly approved signed sequence. Replicate its entire graph, then synchronize System B. A complete valid successor replaces the active view transactionally while prior releases remain retained. Incomplete candidates, invalid signatures, altered bytes, replay and conflicting identity/sequence cannot become a valid successor. Existing valid evidence remains available when a new candidate fails.

Signed expiration is evaluated against System B's trusted UTC clock. Importing, retrying or copying never renews it. Expired/revoked/superseded release status is separate from evidence retention. A local mapping policy may impose additional constraints; configuration cannot forge an authoritative approval.

System A revocation publishes a separate signed, sequenced event through the same release repository. Replicate and sync that event. System B cannot enforce a publisher revocation it has not received. Retention and replication rules must carry revocation events as well as approvals.

For mission continuity, an authorized Local Cyber user opens `/services/<service-key>/cyber-overrides` and selects the exact imported release and denial condition (`superseded`, `expired` or `revoked`). The user must record mission impact, justification and explicit risk acceptance, and may restrict the exception to one signed digest. A blank digest selects only that release's signed inventory. An expiration is optional; a blank expiration is explicitly indefinite, and a review date alone does not end authorization. Overriding a revoked release requires elevated-risk acknowledgment.

An override changes only local enforcement for its scope. It cannot bypass a bad signature, corrupt evidence, an untrusted publisher, an unrelated digest or disabled access mapping. Normal approval remains visibly unchanged. Inspect usage history after a pull; revoke with a reason when the exception is no longer justified. Subsequent requests recheck authorization, including warm-cache requests. Another valid independent override can still authorize its own scope. Existing running workloads and bytes already delivered are not remotely withdrawn.

### Registry credential rotation

Create the replacement registry identity/token with the same intended repository scope while the old identity is still valid. On System A, update the affected approved publication destination's credentials through its authorized administration interface. On System B, update the existing local registry entry under **Registry access and proxy** with `release.destination.manage`; its authenticated, CSRF-protected API is `PUT /api/oci/upstreams/<id>` with `username` and `password`. Preserve the registry ID, endpoint, CA trust and repository mappings. Omitted credential fields are retained; an explicit empty string clears that field. Do not put secrets into recorded commands or reports.

Verify a new signed publication and replication on System A, then synchronize and perform an uncached authorized pull on System B using the replacement credentials. A known release's unchanged sync alone may not exercise registry authentication, so also prove a fresh referenced object is readable. Revoke the old registry identity only after the new path succeeds; if validation fails, keep the old identity available, restore its configured credentials and investigate the transport/scope error. Registry credential rotation does not change publisher identity or signing trust.

### Authenticated publisher key rotation

Keep the original publisher fingerprint configured on System B. On System A, finish or retry every reserved release and revocation publication, then upload the replacement private/public key pair and password through the existing signing configuration form. CATS validates the replacement and creates a transition certificate signed by both the current and replacement keys before saving it. Concurrent changes are serialized; unfinished publications or a stale configuration prevent replacement with an actionable error.

The certificate binds the original trust root, both public keys, the preceding transition, generation and each service's next publication sequence. Subsequent releases and revocations carry the complete chain. System B verifies it from the original pin, retains a sealed continuity record and preserves service identity, history, local grants and overrides. The actual signer remains separately recorded. A fresh replica can authenticate a later successor directly from the original pin; old signed releases remain valid within their certified sequence intervals. Keys cannot authorize events beyond their cutover, and conflicting chains, rollback and altered certificates fail closed.

Publish and replicate a new approved release, synchronize System B, and verify a cold artifact and attestation pull. Check that the service identity and original trust pin are unchanged and the release shows the replacement signer. The authenticated current key can publish a revocation for an earlier key's release, so previous private keys are not needed for that operation after a successful transition. Retain normal encrypted backups of publisher settings and replica state. Never clear identity, sequence or trust records to bypass validation.

Removing the original pin denies its entire successor chain; adding an unrelated fingerprint does not establish continuity. Rotation supports at most 32 transitions, at most 10,000 service cutovers per certificate, and at most 4 MiB for the complete canonical serialized chain. These limits apply together: large certificates can reach the aggregate byte bound before either count limit, so 32 certificates containing 10,000 cutovers each are not guaranteed to fit. Plan a separately authorized trust migration before exhausting these bounds; never truncate the authenticated chain.

A lost current private key cannot create a dual-signed transition. Restore an authorized backup of that same current key, its password and the configuration encryption key as required, preserving the existing authenticated chain and publisher identity; validate the restored key before proceeding with the normal replacement workflow. The tested configuration path re-uploads the same backed-up key, retains the chain and then completes a successor transition. It does not recover an absent backup or qualify a deployment's backup custody. If the key is irrecoverably lost, use a separately authorized trust migration with independently provisioned trust; do not delete replica identity, sequence or trust records to force continuity.

## 6. Persistence, upgrade and disconnected operation

`replica_db` stores identities, release state, local configuration, jobs, mappings, accounts and audit. `replica_evidence` stores retained evidence. `replica_cache` stores the OCI blob cache. Compose uses `restart: unless-stopped` and health checks. Container recreation preserves named volumes; `down --volumes` removes them and is not an upgrade procedure.

Back up PostgreSQL and the retained evidence consistently, and protect the matching encryption key. Retain registry data independently: the proxy cache is evictable and is not a replacement for a fully replicated registry. Back up local identity-provider configuration and TLS material through their owning systems. Test restoration into an isolated environment before relying on a backup.

For a quiesced backup drill, stop the portal and proxy writers before capturing the database and evidence. Either take a consistent PostgreSQL logical dump while writers remain stopped or snapshot a stopped database volume and start only its isolated clone to create the dump. Restore the dump with error checking into fresh PostgreSQL storage and restore the matching evidence before starting the isolated portal. Preserve the matching encryption key through the secret store. Compare every retained table, sequence and evidence-file digest with the captured state, then verify login, scoped access, signed evidence downloads and an uncached graph pull through restored registry credentials. A successful local restore does not establish off-host backup durability, a recovery-time target or recovery from loss of the encryption key.

For an application update, preserve project/volume names, review schema compatibility, take the backups, load the chosen full release image, update `CATS_IMAGE`, then run the same Compose `up -d --wait` command. The legacy `CATS_REPLICA_IMAGE` fallback remains supported, but an explicit `CATS_IMAGE` takes precedence. Upgrade portal and proxy together. Verify login, source health, retained release IDs/history, local role separation, a complete pull and persisted override audit after restart. Rollback involving a schema change may require the consistent backup; do not assume an older image can read a newer schema.

To qualify independence, first prove System A is reachable, then stop/isolate System A and its registry while leaving System B's registry, database, portal, proxy and local authentication available. Synchronize a completely replicated successor and make a fresh full pull through System B. Verify no successor content was already in the proxy cache before the first pull. Retained evidence browsing must also work. A DNS/TLS configuration error is not proof that the source was disconnected.

System B needs its own local registry for discovery and uncached bytes. Losing that registry can block new pulls or tag resolution even with some cached content. Disconnection from System A does not freeze signed expiry or convey future revocations. Keep a trustworthy local clock and a procedure for delivering signed updates/revocations into the disconnected environment.

## 7. Failure recovery and resource limits

Inspect `/admin/replica`, the audit page and service logs. Keep correlation IDs and secret-free diagnostics with the incident record:

```powershell
docker compose --project-directory . --env-file .env.replica -f templates/compose.replica.external-ingress.yaml ps
docker compose --project-directory . --env-file .env.replica -f templates/compose.replica.external-ingress.yaml logs --tail 100 portal oci-proxy
```

Portal `/health` is process liveness and deliberately remains successful during a database outage. Anonymous `/readyz` executes a database query: it returns `200 {"status":"ready"}` when the database is available and a redacted `503 {"status":"unavailable"}` when it is unavailable. Readiness responses are not cached. The standalone Compose portal health check uses `/readyz`; the proxy uses its database-aware `/healthz`. Neither probe establishes registry connectivity or validates a complete retrieval, so monitor source synchronization and a scoped artifact retrieval separately.

Qualify outage recovery only in an isolated deployment: stop its database, verify portal liveness remains `200`, both readiness probes return `503`, and both application containers become unhealthy; restart that database, then verify readiness and container health return to normal and an authenticated release read succeeds without restarting the applications. Compose probe intervals and retry counts delay the unhealthy transition; measure that delay against the site's detection target. Configure external monitoring, alert destinations and escalation for the deployment. Container health alone does not deliver alerts, and local failure injection does not qualify production alert delivery.

| Symptom | Recovery |
| --- | --- |
| Database readiness unavailable | Check the database, its storage and connection configuration; restore connectivity, then verify both readiness probes, container health and an authenticated release read recover |
| Registry unreachable / TLS / unauthorized | Check connectivity from System B, correct origin, CA chain, read credentials and explicitly permitted token/redirect origins; retry synchronization |
| Wildcard source fails discovery | Confirm catalog permission and valid same-origin pagination, or use exact release repositories |
| Missing child/layer/chart/signature/evidence | Finish registry graph replication and retention repair; retry the same release without inventing a new sequence |
| Publisher trust or service identity conflict | Compare independently provisioned fingerprints and signed service identity; correct the source/trust provisioning or plan a controlled migration, never bypass verification |
| Sequence conflict / rollback | Investigate publisher receipts and event order; preserve the current high-water mark and audit history |
| Source changed during verification | Recheck the intended configuration and synchronize again; an obsolete verification cannot activate under changed trust |
| Retained evidence missing/corrupt | Stop unsafe storage changes and restore from a verified consistent backup. Sync can refetch missing evidence from the complete trusted local registry, but an existing corrupt content-addressed file is rejected and requires storage repair; never edit integrity metadata to make it pass |
| Pull denied after successful sync | Check effective release expiry/revocation/supersession, local clock, publisher pins, service route, upstream/mapping/principal status and grants; use Local Cyber exceptions only where justified |
| Interrupted or failed sync | Correct the cause and use Synchronize; durable retry/lease recovery is idempotent, and the last valid active release is retained |

Public sync diagnostics intentionally avoid registry response secrets. Preserve the failure reference and inspect authorized logs/audit rather than exposing tokens or private material in support screenshots.

For disposable qualification fault injection, holding one repository's layer link may still leave its blob available through a cached registry descriptor. The caller must also quarantine and restore only the exact repository-scoped cached descriptor, preserving global blob data and unrelated cache entries; never flush a shared cache. Restore both the link and descriptor in cleanup, and prove missing content through the normal target HTTP route before treating the injection as effective. A storage-link change alone is not that proof.

One discovery budget spans catalog pages and every discovered release repository during a source sync. These variables are forwarded by `templates/compose.replica.external-ingress.yaml`; set positive values in `.env.replica` and recreate the services after an intentional change:

| Variable | Default | Limit |
| --- | --- | --- |
| `CATS_REPLICA_DISCOVERY_MAX_PAGES` | 100 | Total catalog/tag-list pages |
| `CATS_REPLICA_DISCOVERY_MAX_ENTRIES` | 10000 | Total catalog/tag entries examined |
| `CATS_REPLICA_DISCOVERY_MAX_RELEASES` | 10000 | Matching release/revocation references |

Exceeding a budget fails discovery; it does not silently accept a truncated first page. Narrow the source scopes or size the budgets to the registry's known inventory and operational capacity. Pagination rejects cycles and cross-origin/cross-repository continuation.

Verification also bounds total fetched release graph bytes (default 20 GiB, `CATS_CYBER_RELEASE_MAX_BYTES`), individual graph blobs (default 1 GiB, `CATS_CYBER_RELEASE_BLOB_MAX_BYTES`), graph nesting and archive expansion. These graph-byte variables require an explicit Compose environment override if changed; adding them only to `.env.replica` does not forward them. Proxy blob limits are separate from verification limits. Provision memory, disk and time for the complete graphs and retained evidence; raising limits does not create that capacity.

The image build requires its package/base-image sources unless images are prepared ahead of time. Exact repository discovery avoids catalog dependency but does not remove read access to referenced repositories. The replica authorizes retrieval; cluster admission and the treatment of already running workloads remain deployment responsibilities. It does not reassess retained findings, patch software, run validators, or refresh public risk intelligence.
