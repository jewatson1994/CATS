# Portal and OCI pulls on HTTPS port 443

All hostnames in this guide are placeholders. Replace `portal.example.com` and `registry.example.com` with your own distinct DNS names. Set `CATS_PORTAL_HOSTNAME` and `CATS_OCI_HOSTNAME` in your deployment environment; Compose requires both and supplies no hostname defaults.

`compose.nginx.yml` moves the VM's published port 443 from the portal to Nginx. Nginx reads the hostname at the start of each TLS connection and routes the encrypted connection to the matching container:

| Client address | Internal destination | Certificate served |
| --- | --- | --- |
| `https://portal.example.com` | `portal:8000` | Existing portal certificate |
| `registry.example.com/cyber-approved/...` | `oci-proxy:5000` | Certificate covering `registry.example.com` |

Neither backend publishes a host port with this override. Clients use port 443 without adding `:5000`. Authentication, approval checks, repository mappings and Harbor credentials remain in CATS. This change needs no CATS image rebuild; it adds a pinned official Nginx container and Compose/configuration files.

## Prepare the VM

These instructions assume the existing installation is in `/opt/cats` and its main file is `compose.yaml`. Keep that file, its existing `.env`, database volumes and encryption key. Use Docker Compose **2.24.4 or newer** (`docker compose version`); the override uses `!reset` to remove existing published backend ports, including a customized `443:8000` mapping.

1. Copy these files from this checkout into the existing installation, preserving their relative locations:
   - `compose.nginx.yml`
   - `deploy/nginx/nginx.conf.template`
   - `deploy/nginx/start-nginx.sh`
2. Keep the portal's existing files at `/opt/cats/certs/tls.crt` and `/opt/cats/certs/tls.key`.
3. Place the issued `registry.example.com` certificate at `/opt/cats/oci-certs/tls.crt` and its private key at `/opt/cats/oci-certs/tls.key`. Create that separate directory first. Each `tls.crt` must contain the leaf certificate followed by any intermediate certificates. The service user inside its container must be able to read its key; do not make private keys world-readable. Missing files or unreadable keys prevent startup.
4. In the DNS used by client machines, point **both hostnames to the VM's reachable IP**, not `127.0.0.1`. Allow inbound TCP 443 through the VM firewall/network rules from those clients. Configure an AAAA record only if IPv6 connectivity to that VM is available. Remove any earlier `registry.example.com -> 127.0.0.1` hosts entry on remote clients.

The existing portal certificate can cover both services only if its Subject Alternative Names include **both** hostnames. In that case both certificate directory settings can point to the same directory. A certificate that only covers `portal.example.com` cannot authenticate `registry.example.com`. For an internal CA, install its CA certificate in client trust stores, including Docker's registry trust configuration; do not mark the registry insecure. DNS ownership and certificate issuance are outside Compose.

Nginx uses TLS passthrough: certificates and private keys stay mounted in the backend containers. The portal continues to receive real HTTPS requests, keeping its HTTPS redirects and secure session cookies. No certificate is mounted into Nginx.

## Add the override to the existing deployment

Add these settings to your **existing** `/opt/cats/.env`. The sample in `deploy/nginx/.env.example` contains the same settings; do not copy it over your existing credentials.

```dotenv
CATS_PORTAL_HOSTNAME=portal.example.com
CATS_OCI_HOSTNAME=registry.example.com
CATS_PORTAL_CERT_DIR=/opt/cats/certs
CATS_OCI_CERT_DIR=/opt/cats/oci-certs
```

The current main `compose.yaml` already defines `oci-proxy`. Also set:

```dotenv
COMPOSE_FILE=compose.yaml:compose.nginx.yml
```

For older deployments where the proxy is still in a separate optional overlay, instead use:

```dotenv
COMPOSE_FILE=compose.yaml:compose.oci-proxy.yml:compose.nginx.yml
```

Keep `compose.nginx.yml` last. These `COMPOSE_FILE` lists use the Linux separator `:`; Windows uses `;`. Merge these entries with any other active overrides instead of dropping them. Setting `COMPOSE_FILE` ensures subsequent plain `docker compose` commands keep Nginx routing enabled. Explicit `-f` options replace this selection: upgrade scripts using them must include this override last too.

For deployments run directly from this repository's `templates/compose.main.yaml`, use the existing protected environment file and this explicit prefix instead:

```sh
docker compose --project-directory . --env-file /secure/cats.env \
  -f templates/compose.main.yaml -f compose.nginx.yml config --quiet
```

Run that from the repository root. `--project-directory .` makes the Nginx bind paths resolve to the repository root. Use the same prefix for subsequent commands and add the hostname/certificate settings to `/secure/cats.env`.

## Apply when certificates and DNS are ready

For the `/opt/cats` deployment with `COMPOSE_FILE` set above:

```sh
cd /opt/cats
docker compose config --quiet
docker compose pull nginx
```

Proceed only if both succeed. There is a short interruption while port 443 transfers from the portal to Nginx. First recreate the two backends to release their published ports and load their certificates:

```sh
docker compose up -d --no-deps --force-recreate --wait --wait-timeout 180 portal oci-proxy
```

Only after that succeeds, start Nginx:

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

## Operations and rollback

- Both backends have HTTPS health checks that verify the configured hostname against their mounted certificate. Nginx checks its configuration and listening socket. Nginx health alone does not prove registry authorization, DNS or trust from other machines.
- Certificates are loaded by Uvicorn at startup. After renewing certificate files, restart the corresponding backend: `docker compose restart portal` or `docker compose restart oci-proxy`. Nginx resolves container addresses again after recreation; it does not need the keys or a certificate reload.
- Hostnames must be distinct. Clients must use hostname/SNI; unknown names and connections made only to an IP address are rejected. This setup does not provide plain HTTP port 80 or certificate issuance/renewal.
- TLS passthrough preserves HTTP requests, authorization, ranges and response bytes. Backend session/audit records see Nginx's container IP rather than the original client IP. Portal login lockouts remain account-based. PROXY protocol is deliberately disabled because these Uvicorn listeners do not accept it.
- The image digest is pinned in the override. To update Nginx, set `CATS_NGINX_IMAGE` to a reviewed official image with the stream and SSL preread modules, pull it, and recreate only `nginx`.

To return to the previous deployment, while the override is still selected, run:

```sh
docker compose stop nginx
docker compose rm -f nginx
```

Then remove only `compose.nginx.yml` from the `COMPOSE_FILE` setting (or your explicit `-f` list), preserving any previously required OCI and other overlays. Recreate the backends using that original selection:

```sh
docker compose up -d --no-deps --force-recreate --wait portal oci-proxy
```

This restores the commands, certificates, health checks and published ports from your original files. It does not delete volumes. Keep the original Compose files available throughout migration.

References: [Compose merge/reset behavior](https://docs.docker.com/reference/compose-file/merge/), [Nginx TLS hostname routing](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html), [Docker registry CA trust](https://docs.docker.com/engine/security/certificates/).
