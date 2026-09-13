# OIDC and OCI registry configuration

CATS keeps identity-provider settings and reusable OCI registry profiles in the global **Administration → Configuration** page. Only global configuration administrators can change them. Secrets are encrypted at rest with Fernet and are never rendered back into forms, reports, logs, or patch job metadata.

## Encryption key

Set `CATS_CONFIG_ENCRYPTION_KEY` before starting CATS and keep the same value across restarts and upgrades. Generate one with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The key is intentionally an environment-level secret. If it is replaced, existing OIDC client secrets and registry tokens cannot be decrypted until they are entered again.

## Generic OIDC setup

1. Open **Administration → Configuration** and select `OIDC` (or `Both`) under Identity.
2. Enter a provider name, HTTPS issuer URL, client ID, scopes, and claim names. `openid` is added automatically when omitted.
3. Enter the client secret only when creating or replacing it. The saved configuration stores only an encrypted value.
4. Set the callback URL registered with the provider to `/auth/oidc/callback` on the CATS public URL. Set the post-logout URL to the CATS login page.
5. Save, then use **Test OIDC discovery**. The test performs discovery only and records a sanitized status.
6. Users can use the provider button on the login page. Group and role claims are mapped through the existing CATS provisioning rules.

The canonical Compose stack includes local Keycloak. Set its administrator
password in `.env`, then start the normal stack:

```powershell
docker compose up -d --wait
```

Keycloak is then available to the browser at `http://localhost:8081` and to CATS on the Compose network at `http://keycloak:8080`. Create a realm and client in Keycloak, then configure:

- **Issuer URL:** `http://keycloak:8080/realms/cats`
- **Browser issuer URL:** `http://localhost:8081/realms/cats`
- **Redirect URI:** `http://localhost:8080/auth/oidc/callback`
- **Post-logout redirect URI:** `http://localhost:8080/login`

The internal issuer prevents the CATS container from trying to reach itself through `localhost`. The browser issuer rewrites only the browser-facing authorization URL. HTTP issuers require the explicit local-development setting `CATS_OIDC_ALLOW_INSECURE_HTTP=true` and must not be used in production.

## Reusable OCI registries

Add a registry profile with an HTTPS endpoint, optional namespace, and either anonymous or credential authentication. Patch input pages expose saved profiles as optional source/destination selectors. Selecting a profile supplies its username/token to that job without copying the secret into the job configuration. Source and destination profiles are independent, so a public source can be patched and pushed to a private destination.

Use **Test** on a profile to perform a short `/v2/` reachability check. The result stores only `Reachable`/`Unavailable` and a sanitized detail. Delete a profile when it is no longer needed.
