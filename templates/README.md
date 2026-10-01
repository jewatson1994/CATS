# CATS deployment templates

Run these commands from the repository root. Copy the matching `.env.example`
to a protected environment file outside the repository, replace all `REPLACE`
values, and restrict its permissions. Never commit credentials or private keys.

## Main CATS (production)

`compose.main.yaml` mirrors the root `compose.yaml`: database, portal, and patch
worker. Select an already-built CATS image with `CATS_IMAGE`; this template does
not build the main image. Keep development authentication bypass disabled.

```sh
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml config --quiet
docker compose --env-file /secure/cats.env -f templates/compose.main.yaml up -d --wait
```

The portal listens on HTTP port 8080 by default. Put it behind your approved
HTTPS reverse proxy and set `SESSION_COOKIE_SECURE=true` for HTTPS deployment.
Generate a Fernet encryption key using the CATS Python environment:

```sh
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

## Validator (disposable project VM)

`compose.validator.yaml` builds the validator from this checkout. Its build
context is the repository parent of `templates`, so do not move it independently
of the source tree. Provision `server.crt`, `server.key`, and `client-ca.crt` in
the TLS directory, and your shared PEM CA bundle at the configured bundle path.
Use an approved, digest-pinned Kind image and independently verify the Docker
archive checksum; placeholders are not deployment values.

```sh
docker compose --env-file /secure/validator.env -f templates/compose.validator.yaml config --quiet
docker compose --env-file /secure/validator.env -f templates/compose.validator.yaml up -d --build
```

The validation API uses mTLS on 8443; the local administrator page uses HTTPS
on 8444. Host networking and the Docker socket grant control of the sandbox VM.
Use a dedicated Linux amd64 VM, never the production host. Restrict 8443 to
main CATS and 8444 to your management network. Block project-initiated connections
to production at the NSG/firewall; allow downloads only as deliberately approved.

Configure the validator endpoint, client certificate/key, and server CA in main
CATS administration, then test the connection. CATS submits jobs and polls their
results; the validator does not call back into production. See
[the appliance guide](../docs/validator-appliance.md) for setup, trust-store
limitations, readiness tests, execution modes, and persisted settings.

Root Compose files remain supported. Keep these templates synchronized when
changing either canonical deployment file. Both main templates use the project
name `cats`; avoid starting a second main deployment against the same project.
