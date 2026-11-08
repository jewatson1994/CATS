# Portal and OCI pulls on HTTPS port 443

Both `templates/compose.main.yaml` and `templates/compose.replica.yaml` include Nginx, its startup command, and its routing configuration in one Compose file. The startup command validates the hostnames and writes the configuration into the container's writable `/tmp` area. No Nginx override or companion configuration files are needed. Use Docker Compose v2 (`docker compose`). This routing change needs no CATS image rebuild. For replica startup, use the [dedicated replica instructions](../templates/README.md#cats-replica); the commands below address main CATS.

All hostnames in this guide are placeholders. Replace `portal.example.com` and `registry.example.com` with your own distinct DNS names. Set `CATS_PORTAL_HOSTNAME` and `CATS_OCI_HOSTNAME` in your deployment environment; Compose requires both and supplies no hostname defaults.

Nginx publishes host port 443 and reads the hostname at the start of each TLS connection to route the encrypted connection:

| Client address | Internal destination | Certificate served |
| --- | --- | --- |
| `https://portal.example.com` | `portal:8000` | Certificate covering `portal.example.com` |
| `registry.example.com/cyber-approved/...` | `oci-proxy:5000` | Certificate covering `registry.example.com` |

Neither backend publishes a host port. Clients use port 443 without adding `:5000`. Authentication, approval checks, repository mappings and Harbor credentials remain in CATS.

## Prepare certificates, DNS and settings

Keep your existing environment file, credentials, database volumes and encryption key when upgrading.

1. Place the portal certificate at `/opt/cats/certs/portal/tls.crt` and its private key at `/opt/cats/certs/portal/tls.key`, or retain the existing directory through `CATS_PORTAL_CERT_DIR`.
2. Place the issued registry certificate at `/opt/cats/certs/oci-proxy/tls.crt` and its private key at `/opt/cats/certs/oci-proxy/tls.key`. Create that separate directory first. Each `tls.crt` must contain the leaf certificate followed by any intermediate certificates. The service user inside its container must be able to read its key; do not make private keys world-readable. Missing files or unreadable keys prevent startup.
3. In the DNS used by client machines, point **both hostnames to the VM's reachable IP**, not `127.0.0.1`. Allow inbound TCP 443 through the VM firewall/network rules from those clients. Configure an AAAA record only if IPv6 connectivity to that VM is available. Remove any earlier `registry.example.com -> 127.0.0.1` hosts entry on remote clients.
4. Add these settings to your existing deployment environment file, replacing the example hostnames:

```dotenv
CATS_PORTAL_HOSTNAME=portal.example.com
CATS_OCI_HOSTNAME=registry.example.com
CATS_PORTAL_CERT_DIR=/opt/cats/certs/portal
CATS_OCI_CERT_DIR=/opt/cats/certs/oci-proxy
```

The existing portal certificate can cover both services only if its Subject Alternative Names include **both** hostnames. In that case both certificate directory settings can point to the same directory. A certificate that only covers `portal.example.com` cannot authenticate `registry.example.com`. For an internal CA, install its CA certificate in client trust stores, including Docker's registry trust configuration; do not mark the registry insecure. DNS ownership and certificate issuance are outside Compose.

Nginx uses TLS passthrough: certificates and private keys stay mounted in the backend containers. The portal receives HTTPS requests and uses secure session cookies. No certificate is mounted into Nginx.

## Use the integrated deployment template

For a new installation from the checkout, follow the [main template setup](../templates/README.md#main-cats). Run from the repository root with your protected environment file:

```sh
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml config --quiet
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml up -d --wait
```

For an existing installation in `/opt/cats`, back up its current Compose file and merge the updated `templates/compose.main.yaml` into `/opt/cats/compose.yaml`, preserving deployment customizations. Do not replace a customized file wholesale. Keep your existing `.env`, credentials, encryption key, volume names and project name; do not introduce a new `-p` value or `COMPOSE_PROJECT_NAME`. Check the merged configuration for any previously customized backend port mappings and remove them so only Nginx publishes port 443.

The embedded Nginx configuration has no paths relative to the Compose file, so moving the template needs no extra Nginx files or `--project-directory` workaround. Other existing relative bind mounts retain the template's path assumptions: review and preserve their intended host paths when relocating the Compose file.

If `COMPOSE_FILE` or explicit `-f` arguments currently include `compose.nginx.yml`, remove **only that obsolete override** for the integrated template. Preserve unrelated overrides and their ordering. With no other overrides, `/opt/cats/compose.yaml` is selected by ordinary `docker compose` commands; an existing `COMPOSE_FILE` can be reduced to `compose.yaml`. Explicit `-f` arguments replace `COMPOSE_FILE`, so update deployment scripts too. Do not append the legacy Nginx override to the integrated template.

Use the staged migration below when updating an existing deployment, especially if the portal currently owns host port 443.

## Apply when certificates and DNS are ready

These commands assume the integrated file is `/opt/cats/compose.yaml`, settings are in the existing `/opt/cats/.env`, and any other required overrides remain selected. If using the file in the checkout, retain your existing `--env-file` and `-f templates/compose.main.yaml` arguments on every command instead.

```sh
cd /opt/cats
docker compose config --quiet
docker compose pull nginx
```

Proceed only if both succeed. There is a short interruption while port 443 transfers from the portal to Nginx. First recreate the two backends to release their published ports and load their certificates:

```sh
docker compose up -d --no-deps --force-recreate --wait --wait-timeout 180 portal oci-proxy
```

Only after that succeeds, start or update Nginx:

```sh
docker compose up -d --no-deps --wait --wait-timeout 60 nginx
docker compose ps portal oci-proxy nginx
```

Nginx should be the only one of these three services publishing a host port: `443->8443`. Portal port 8000 and OCI port 5000 stay inside the Compose network. Existing database and worker containers are not recreated by these commands. If a backend fails, inspect `docker compose logs --tail 80 portal oci-proxy` before starting Nginx; do not bypass certificate verification to make a health check pass.

Your client commands then use CATS machine credentials and the normal registry address:

```sh
docker login registry.example.com --username YOUR_CATS_MACHINE_USERNAME
docker pull registry.example.com/cyber-approved/REPOSITORY:APPROVED_TAG
```

Enter the machine account's secret at the password prompt. Replace the repository and tag with an approved image. The Harbor robot credential belongs in CATS's upstream configuration. Docker image references do not include `https://`.

## Legacy root-stack override

The repository-root `compose.yaml` remains a local HTTP stack. If keeping that file or an older deployment definition, `compose.nginx.yml` remains supported to add the same HTTPS routing. This legacy path needs Docker Compose **2.24.4 or newer** because its `!reset` entries remove previously published backend ports, including a customized `443:8000` mapping.

Copy these files from the checkout into the existing installation, preserving their relative locations:

- `compose.nginx.yml`
- `deploy/nginx/nginx.conf.template`
- `deploy/nginx/start-nginx.sh`

Use the certificate, DNS and hostname settings above. `deploy/nginx/.env.example` contains the legacy settings; merge them into your existing `.env` without replacing credentials. If no other overrides are active, set:

```dotenv
COMPOSE_FILE=compose.yaml:compose.nginx.yml
```

For older deployments that still need a separate OCI overlay, retain it:

```dotenv
COMPOSE_FILE=compose.yaml:compose.oci-proxy.yml:compose.nginx.yml
```

Merge these entries with any other active overrides, keeping `compose.nginx.yml` last. These lists use the Linux separator `:`; Windows uses `;`. Explicit `-f` options replace this selection and must also keep the Nginx override last. Follow the same [staged application commands](#apply-when-certificates-and-dns-are-ready) above. Keep this file selection for subsequent upgrades while using the legacy path.

## Operations and rollback

- Both backends have HTTPS health checks that verify the configured hostname against their mounted certificate. Nginx checks its configuration and listening socket. Nginx health alone does not prove registry authorization, DNS or trust from other machines.
- Certificates are loaded by Uvicorn at startup. After renewing certificate files, restart the corresponding backend: `docker compose restart portal` or `docker compose restart oci-proxy`. Nginx resolves container addresses again after recreation; it does not need the keys or a certificate reload.
- Hostnames must be distinct. Clients must use hostname/SNI; unknown names and connections made only to an IP address are rejected. This setup does not provide plain HTTP port 80 or certificate issuance/renewal.
- TLS passthrough preserves HTTP requests, authorization, ranges and response bytes. Backend session/audit records see Nginx's container IP rather than the original client IP. Portal login lockouts remain account-based. PROXY protocol is deliberately disabled because these Uvicorn listeners do not accept it.
- The Nginx image digest is pinned. To update it, set `CATS_NGINX_IMAGE` to a reviewed official image with the stream and SSL preread modules, pull it, and recreate only `nginx`. Use the same Compose file selection and environment file for all maintenance commands.

To roll back, first release port 443 while the current Nginx definition is still selected:

```sh
docker compose stop nginx
docker compose rm -f nginx
```

For an integrated-template migration, restore the saved previous Compose definition and previous file selection, preserving credentials and unrelated overrides. For a legacy-override rollback, remove only `compose.nginx.yml` from `COMPOSE_FILE` or the explicit `-f` list, preserving any previously required OCI and other overlays. Validate and recreate the backends with that original selection:

```sh
docker compose config --quiet
docker compose up -d --no-deps --force-recreate --wait portal oci-proxy
```

If the original deployment also used Nginx, then start it with the restored original selection after the backends are healthy. Otherwise these commands restore the backends' original published ports. Rollback does not delete volumes. Keep the original Compose files available throughout migration.

References: [Compose merge/reset behavior](https://docs.docker.com/reference/compose-file/merge/), [Nginx TLS hostname routing](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html), [Docker registry CA trust](https://docs.docker.com/engine/security/certificates/).
