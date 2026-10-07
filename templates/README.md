# CATS deployment templates

These templates deploy the current runtime and its separate validator sandbox. Run the commands from the repository root, keeping the templates in this checkout. Copy the matching environment example to a protected file outside Git and replace all placeholders. Do not replace an existing environment file or encryption key during an upgrade.

## Main CATS

The main template runs PostgreSQL, portal, and patch-worker under the project name `cats`. It uses an already-built image and does not build it. Local accounts are enabled by default; configure an external OIDC provider only when needed. No identity provider is deployed by this stack.

```powershell
Copy-Item templates/main.env.example C:/secure/cats.env
notepad C:/secure/cats.env
docker compose --env-file C:/secure/cats.env -f templates/compose.main.yaml config --quiet
docker compose --env-file C:/secure/cats.env -f templates/compose.main.yaml up -d --wait
```

On Linux, use `cp templates/main.env.example /secure/cats.env` and the corresponding `--env-file` path. Protect that file with appropriate filesystem permissions.

Required values include the built `CATS_IMAGE`, unique database/bootstrap passwords, pipeline and worker tokens, a Fernet encryption key, and **an absolute host path** for `CATS_MANAGED_VALIDATOR_RELEASE_SOURCE`. The release build prints the prepared directory. Forward-slash Windows paths such as `C:/cats/releases/validator` work well in environment files. Copy the entire prepared directory when moving hosts.

Generate the encryption key with the portal Python environment:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The portal defaults to HTTP port 8080. For shared deployments, configure your approved HTTPS reverse proxy and set `SESSION_COOKIE_SECURE=true`. Keep `CATS_DEV_AUTH_BYPASS=false`. Update the image selection and recreate portal and worker together for upgrades; retain database volumes and the encryption key.

The root `compose.yaml` and this template share the same runtime settings and volume names. The template requires explicit image and release-directory selections; the root file retains local-development fallbacks. Both use project `cats`, so they operate on the same main stack when run against the same Docker host.

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

Keep root and template Compose service definitions synchronized. Their intended differences are the main template's required image/release path and the validator template's relative build context. Environment examples contain placeholders only; do not commit live settings, credentials, or private keys.
