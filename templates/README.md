# CATS deployment templates

For prompted setup and a small installer bundle without container images, start with the [guided main and replica installer](../docs/guided-setup.md). It uses these templates and images already loaded on the target host, preserves existing settings and secrets on upgrades, and selects the worker AppArmor overlay when required.

Choose the appropriate deployment below. The example commands run from the repository root; the replica template can also be copied to its host as described below. Copy the matching environment example to a protected file outside Git and replace all placeholders. Do not replace an existing environment file or encryption key during an upgrade.

| Deployment | Compose file | Environment example |
| --- | --- | --- |
| Full CATS: assessment, remediation, approval and OCI access | [compose.main.yaml](compose.main.yaml) | [main.env.example](main.env.example) |
| Replica: retained evidence and local OCI access | [compose.replica.yaml](compose.replica.yaml) | [replica.env.example](replica.env.example) |
| Separate validator sandbox | [compose.validator.yaml](compose.validator.yaml) | [validator.env.example](validator.env.example) |

Main and replica use the same published full CATS image, selected with `CATS_IMAGE`, on Linux amd64. The replica is its own stack, with `CATS_MODE=replica` fixed in its Compose file. Do not combine its Compose file with the main or validator templates. Existing replica environment files may use `CATS_REPLICA_IMAGE` as a fallback when `CATS_IMAGE` is unset or blank; when both are set, `CATS_IMAGE` takes precedence.

## Main CATS

The main template runs PostgreSQL, portal, the private portal-control listener, oci-proxy, patch-worker, scan-worker, remediation-worker, export-worker, provisioning-worker, and Nginx under the project name `cats`. All CATS services use the same already-built application image; Nginx uses a pinned official image. This template does not build either image. Local accounts are enabled by default; configure an external OIDC provider only when needed. No identity provider is deployed by this stack.

Use Docker Compose v2 (`docker compose`). Set the required, distinct `CATS_PORTAL_HOSTNAME` and `CATS_OCI_HOSTNAME` values, configure their DNS, and provide matching `tls.crt` and `tls.key` files in `/opt/cats/certs/portal` and `/opt/cats/certs/oci-proxy` (or your configured certificate directories). See [HTTPS setup and migration](../docs/nginx-ingress.md) before startup. Nginx and its configuration are included in this one Compose file; no `compose.nginx.yml` or separate Nginx configuration files are needed.

Prepare the built `CATS_IMAGE`, `postgres:16-alpine`, and the pinned Nginx image selected in Compose. Replace the environment example's image, passwords, worker/pipeline tokens and Fernet key before startup. For offline startup, preload every image and append `--pull never` to `up`. Main CATS also needs this checkout's `deploy/discovery-seccomp.json` and `deploy/discovery-mirror/` files. Its bundled paths resolve relative to `templates/`; keep the checkout layout or use explicit absolute paths when relocating it.

Declare the Kind node image once as `CATS_KIND_NODE_IMAGE` in `.env`, including its approved registry manifest/index digest. Compose forwards it to the portal and background workers using the application's existing runtime setting. Older `.env` files using `CATS_DEPLOYMENT_KIND_NODE_IMAGE` remain supported when the new name is unset or blank. The scan attempt timeout defaults to three hours (`CATS_SCAN_JOB_TIMEOUT=10800`); explicit existing values still take precedence.

Create the scan registry-auth directory before startup (it may be empty for public registries). The commands below create the default auth and backup directories at the repository root; create your chosen paths instead if you change `CATS_SCAN_REGISTRY_AUTH_SOURCE` or `CATS_DB_BACKUP_DIR`. Preserve existing absolute storage paths when upgrading.

Earlier template defaults placed auth and backups under `templates/scan-registry-auth` and `templates/backups/postgres`. If your installation used those locations, keep their absolute paths in your existing environment file; these changes do not move stored files.

For a new deployment:

```powershell
Copy-Item templates/main.env.example C:/secure/cats.env
notepad C:/secure/cats.env
New-Item -ItemType Directory -Force scan-registry-auth, backups/postgres | Out-Null
docker compose --env-file C:/secure/cats.env -f templates/compose.main.yaml config --quiet
docker compose --env-file C:/secure/cats.env -f templates/compose.main.yaml up -d --wait
```

On Linux, use `cp templates/main.env.example /secure/cats.env`, `mkdir -p scan-registry-auth backups/postgres`, and the corresponding `--env-file` path. Protect that file with appropriate filesystem permissions.

To enable GitLab Discovery, approve the project URLs or instance origins in `CATS_DISCOVERY_GITLAB_SOURCES`. The optional private CA override applies to the public portal. [GitLab Discovery configuration](../docs/discovery-workflow.md#allow-projects-in-compose)

Required values include the built `CATS_IMAGE`, unique database/bootstrap passwords, pipeline and worker tokens, and a stable Fernet encryption key. `CATS_MANAGED_VALIDATOR_RELEASE_SOURCE` is optional; leave it blank for automatic preparation when Provision is clicked. See [durable workers and on-demand provisioning](../docs/durable-workers.md) for upgrade commands, internal dependencies and resource defaults.

Generate the encryption key with the portal Python environment:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Nginx serves the portal and OCI proxy on their separate HTTPS hostnames through host port 443. TLS terminates in the backends on private ports 8000 and 5000; neither backend publishes a host port. Secure session cookies are enabled. Keep `CATS_DEV_AUTH_BYPASS=false`. Upgrade the image and Compose file together; retain database volumes and the encryption key. For an existing installation, merge template changes into your current Compose file while preserving credentials, customizations, unrelated overrides and the existing project name. Follow the [migration sequence](../docs/nginx-ingress.md#apply-when-certificates-and-dns-are-ready) to release port 443 before starting Nginx. Once that migration is complete, after selecting a new application image in your existing environment file, recreate the CATS application services:

```sh
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml config --quiet
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml up -d --force-recreate --wait portal portal-control oci-proxy discovery-worker scan-worker patch-worker remediation-worker export-worker provisioning-worker
```

Discovery uses the same `CATS_IMAGE`. Its image must contain any newly enabled feature, and changes to its environment settings require recreating `discovery-worker`.

The read-only OCI compliance proxy starts with the main stack. It shares the portal image, database, and encryption key, and retains verified content in the `oci_proxy_cache` volume. Consumers use the configured registry hostname on HTTPS port 443 without `:5000`; `CATS_OCI_PORT` does not apply to this template. Configure upstream registries and scoped machine credentials before use. No overlay is needed; the legacy `compose.oci-proxy.yml` is a no-op compatibility file. See [OCI proxy operations](../docs/oci-proxy.md) for policy behavior, cache limits, acceptance checks, and rollback.

The three new workers share common Compose settings through YAML anchors and wait for portal health before starting. PostgreSQL stores their durable jobs; no message broker or additional published ports are needed. Preserve `validator_payloads`, `validator_data` (managed-validator state and preparation cache), and `export_jobs` (generated downloads). `validator_staged_release` is an empty fallback volume when no legacy release directory is selected. See the [upgrade guide](../docs/durable-workers.md#upgrade-an-existing-installation) before replacing a deployment that kept validator state only inside the portal container.


The scan-worker requires its own random `CATS_SCAN_WORKER_TOKEN` of at least 32 characters, shared with the control listener. Scan-worker APIs are available only on `http://portal-control:8001` inside the private network; do not publish this port. The scan-worker has no PostgreSQL credentials or Docker socket. Its root broker has only the capabilities needed to launch isolated scanner subprocesses under a separate UID/GID (base 10002), with a read-only root filesystem and a disk workspace for large artifacts. The three new workers use PostgreSQL directly; only provisioning-worker has Docker-host access for preparing validator payloads. The existing patch-worker also retains Docker-host access.

The portal itself does not mount the Docker socket. It queues work and calls the patch service or configured validator; scanning reads images from registries without a Docker daemon. Docker operations run in the patch/provisioning workers and on the validator's own host. Keeping the socket out of the public portal prevents that web process from directly controlling host containers.

The registry-auth bind is read-only and missing-path creation is disabled. The default `../scan-registry-auth` is relative to the Compose file, resolving to the repository-root directory created above. Use an absolute path for a custom directory. An empty directory supports public sources; private sources require pull-only Docker `auths` entries scoped to approved repositories. Credentials are copied only for referenced hosts in authorized authenticated service scans. Anonymous submissions are disabled by default; enabling `CATS_SCAN_ALLOW_ANONYMOUS` does not grant service credentials.

Scan inputs/results use plain tar envelopes; bounded submission preparation and evidence upload work run off the async request thread. Offline database imports publish immutable generations; each attempt receives a verified private snapshot. Durable PostgreSQL jobs survive restart, failed attempts follow bounded category-specific retry rules, and eligible unreferenced terminal scan evidence/history has a default 30-day retention; service/execution/image/definition references and output-bearing orphan directories are retained conservatively. Remediation candidate security checks run in patch-worker and fail closed when valid evidence is unavailable; Schrödinger remains independent.

Follow [the dedicated worker guide](../docs/dedicated-scan-worker.md) for controls, credential rotation, storage/generation lifecycle, retention, and the target-host validation checklist. Compose rendering proves configuration consistency; validate actual scanner tools, large disk-backed artifacts, private OCI, offline imports, restart/cancellation, resource/network enforcement, and Portal latency on the deployment host before claiming operational readiness.

The root `compose.yaml` remains a local HTTP stack: portal port 8080 and the OCI proxy's loopback port 5000 are published by default. The [legacy Nginx override](../docs/nginx-ingress.md#legacy-root-stack-override) remains available for that stack. This deployment template includes HTTPS ingress and requires an explicit image selection; the root file defaults to `cats:local`. Both share volume names, support optional staged validator release directories, and use project `cats`, so they operate on the same main stack when run against the same Docker host.

## Signed release documentation

The main environment and Compose templates include `CATS_RELEASE_DOC_MAX_BYTES` (256 MiB default). If your registry delegates authentication, configure its approved token-service origins in `CATS_OCI_TOKEN_REALMS`. If it redirects publication blob downloads to object storage, configure the approved storage origins in `CATS_OCI_BLOB_REDIRECT_ORIGINS`. Both origin lists default to empty. For worker recreation and verification commands, see [release documentation operations](../docs/signed-release-documentation.md#configuration-and-boundaries).

## OIDC clock skew and remediation validation

`OIDC_CLOCK_SKEW_SECONDS=60` configures OIDC token timestamp tolerance. It is an environment-only setting, with no Administration field. Use an integer from `0` through `300` seconds; `0` disables tolerance. An omitted value defaults to `60`; blank or invalid values are rejected. Keep the host clock synchronized.

After editing your existing environment file, recreate the Portal services to load the value. No image rebuild is needed:

```sh
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml config --quiet
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml up -d --no-deps --force-recreate --wait portal portal-control
```

For the repository-root stack, use `docker compose up -d --no-deps --force-recreate --wait portal portal-control` after editing `.env`. For direct Portal development, restart the process with the updated environment.

`CATS_REMEDIATION_REQUIRE_VALIDATION=true` requires validation bound to the candidate before OCI or deployable bundle delivery. Keep this default unless your deployment deliberately permits skipping validation. This delivery policy is separate from `CATS_DEPLOYMENT_VALIDATION_ENABLED`; see [the remediation wizard guide](../docs/remediation-wizard.md) for the workflow and deployment requirements.

For changes to remediation policy or other settings shared with background workers, recreate the full CATS service list shown above so every process receives the updated environment.

## CATS replica

[compose.replica.yaml](compose.replica.yaml) runs four services under project `cats-replica`, in this reading order:

1. `portal`: view retained evidence and administer synchronization, trust and local access.
2. `oci-proxy`: authorize consumer pulls and serve verified content from the local registry/cache.
3. `nginx`: route the two HTTPS hostnames on port 443; its configuration is included.
4. `db`: store local accounts, replica state and authorization records.

Health dependencies determine startup order. The full image contains scanner and validator tools, but this stack starts no assessment workers or validator services and mounts no Docker socket. Replica runtime mode skips assessment and intelligence initialization. This template uses prebuilt images and has no build context, so it can also be copied to a replica host without the source checkout.

Before starting, load the selected full `CATS_IMAGE`, `postgres:16`, and pinned Nginx image selected in Compose onto that host. Set two distinct DNS hostnames pointing to the replica, and provide their readable full-chain `tls.crt` and `tls.key` files in the configured certificate directories. The built-in HTTPS routing works like [main CATS ingress](../docs/nginx-ingress.md); no extra proxy configuration is needed. Only Nginx publishes a host port; the portal and OCI backends stay private. Main and replica both use port 443, so deploy them on separate hosts or adapt ingress/port mappings if sharing a host.

Set `CATS_IMAGE`, unique database/admin passwords and a stable Fernet key in the environment file. Generate a new key with the loaded full image (replace `YOUR_CATS_IMAGE` with its actual tag):

```sh
docker run --rm --pull never --entrypoint python YOUR_CATS_IMAGE -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

For disconnected release access, provide a local OCI registry containing the complete replicated release graphs. Registry replication and publisher trust are configured after startup; see [the deployment runbook](../docs/oci-replica-deployment-runbook.md#2-prepare-the-separate-system-b-deployment).

For a new deployment:

```powershell
Copy-Item templates/replica.env.example C:/secure/replica.env
notepad C:/secure/replica.env
# Set image, passwords, Fernet key, both DNS names and certificate directories.
docker compose --env-file C:/secure/replica.env -f templates/compose.replica.yaml config --quiet
docker compose --env-file C:/secure/replica.env -f templates/compose.replica.yaml up -d --wait --pull never
docker compose --env-file C:/secure/replica.env -f templates/compose.replica.yaml ps
```

On Linux, use `cp templates/replica.env.example /secure/replica.env` and the corresponding `--env-file` path. If you copied the Compose file elsewhere, substitute its actual path. `--pull never` makes a missing image fail locally without contacting a registry. Protect the environment file and preserve the encryption key, credentials, project name and volumes during upgrades. Portal and proxy must use the same full image version.

Once healthy, use **Replica administration** to configure the local registry, independently trusted publisher fingerprint and synchronization. Follow [startup and trust configuration](../docs/oci-replica-deployment-runbook.md#3-start-and-configure-the-replica) before enabling consumer pulls; starting the containers alone does not import or trust a release.

The repository-root [compose.replica.yaml](../compose.replica.yaml) remains a three-service option with loopback HTTP backends and separately supplied HTTPS ingress. It uses the same full `CATS_IMAGE`. The deployment template adds built-in HTTPS while sharing its replica settings, project and volume names, so both address the same replica when used on the same Docker host. For an existing replica, retain its original credentials, encryption key and project name. When switching to this template, provision certificates and release port 443 from any existing ingress before startup; the old `CATS_PORT`/`CATS_OCI_PORT` settings do not apply here.

## Validator sandbox

Use a dedicated **Linux amd64 VM** with Docker; this host-networked template is not a Docker Desktop deployment. It builds `portal/Dockerfile.validator` from the checkout. The root file uses context `.` and the template uses `..`, relative to their Compose-file directories.

```sh
cp templates/validator.env.example /secure/validator.env
# Edit and protect /secure/validator.env before running:
docker compose --env-file /secure/validator.env -f templates/compose.validator.yaml -p cats-validator config --quiet
docker compose --env-file /secure/validator.env -f templates/compose.validator.yaml -p cats-validator up -d --build --wait
```

Supply:

- A TLS directory containing `server.crt`, `server.key`, and `client-ca.crt`.
- A shared PEM CA bundle at the configured absolute path.
- Trusted production client-certificate SHA256 fingerprints.
- A unique local administrator password and the verified Docker archive checksum.
- An approved digest-pinned Kind image available to the sandbox.

The validation API uses mTLS on `CATS_VALIDATOR_PORT` (default 8443); administration uses HTTPS on `CATS_VALIDATOR_ADMIN_PORT` (default 8444). These ports are configurable and used directly through host networking. `CATS_VALIDATOR_IMAGE` selects the locally built image tag. The commands select project `cats-validator`, separate from main CATS. For an existing validator, retain its original project name so its state volume remains attached.

The Docker socket grants control of the sandbox host. Restrict the validation API to main CATS and administration to your management network. Prevent submitted workloads from reaching production networks. A started container is not proof of validation readiness: configure endpoint, client trust, and server CA in CATS administration, then perform the connection and readiness checks.

CATS submits and polls validation jobs; the validator does not call back into production. Follow [the appliance guide](../docs/validator-appliance.md) for enrollment, trust, execution modes, and readiness evidence.

## Maintaining the templates

Keep shared root and template Compose service settings synchronized, including the worker anchors. Their intended differences are the main template's required image selection, integrated HTTPS ingress and template-relative host paths; the replica template's required image selection, integrated HTTPS ingress and absence of a local build; and the validator template's relative build context. Keep common settings aligned across the matching environment examples while preserving those deployment differences. Environment examples contain placeholders only; do not commit live settings, credentials, or private keys.

### Discovery storage and optional limits

Discovery uses the disk-backed `discovery_scratch` volume at `/tmp`, replacing its previous 512 MiB tmpfs. The five `CATS_DISCOVERY_MAX_*` settings in `main.env.example` default to `0` (unlimited); positive values impose administrator ceilings. Keep the portal and Discovery worker settings aligned. Other services retain their existing tmpfs settings.

When upgrading, retain your existing credentials and encryption key, update the Compose template and optional settings, then recreate the portal and discovery-worker using your existing Compose project name. Do not remove existing volumes. Available Docker host disk space, worker memory/CPU, execution timeouts, and reverse-proxy request limits still constrain processing; provision and monitor storage for retained uploads and expanded repositories.
