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

## OIDC clock tolerance

Set `OIDC_CLOCK_SKEW_SECONDS=60` in the deployment environment to tolerate small differences between Portal and provider clocks. The default is 60 seconds when absent; accepted values are integer seconds from 0 through 300. Zero restores strict timing. Negative, empty, noninteger, and larger values reject OIDC authentication rather than silently falling back. Local password recovery remains available.

PyJWT applies the same native leeway to future `iat` and optional `nbf`, and to `exp`. Tokens beyond that tolerance are rejected; expiry at exactly the leeway boundary is rejected by PyJWT. ID tokens require issuer, subject, audience, issued-at and expiration claims, and timestamps must be finite JSON numbers. Signature, issuer, audience, nonce, callback state, identity linking, role mapping and account enablement checks remain enforced.

After upgrading the image, recreate the Portal container to load the setting. Both supported Compose files pass it through with the default, so existing `.env` files need no edit unless overriding it. Do not replace secrets or regenerate environment files. Keep NTP enabled on both provider and Portal hosts; leeway does not repair a badly incorrect clock.

Timestamp failures produce server-side warnings containing only category, claim name, server UTC time, safe numeric token timestamp, tolerance and signed difference (`token - server`). Malformed values are omitted; tokens, authorization codes, secrets and user claims are never included. The browser receives a generic login failure. Compare these diagnostics with the actual token issuance time: a provider HTTP Date header can come from a proxy and does not prove the token issuer's clock.

## Linking existing CATS accounts

Existing accounts require an explicit administrator binding. Username and email claims alone cannot claim a local account. Set `CATS_OIDC_ACCOUNT_LINKS` to a JSON object indexed by the configured issuer and the provider's immutable subject, for example:

```json
{"https://identity.example/realms/cats":{"provider-subject-123":"admin"}}
```

The same object can be supplied as `account_links` in administrator-managed OIDC configuration. When present, that configuration takes precedence over the environment mapping. Confirm the subject in the provider's administration interface before binding it. Each CATS account accepts one issuer/subject identity; a conflicting link is rejected. New identities can still be automatically provisioned when their username is unused and existing claim mapping rules authorize them.

CATS stores a versioned SHA-256 key of the issuer/subject pair in its existing unique identity column, preserving user IDs, local roles, scopes, ownership and audit history without a database schema migration. Accounts linked by older releases stored only the subject: add the explicit issuer/subject binding above before their first upgraded login so CATS can safely migrate the identity. The legacy subject is never automatically assumed to belong to a different provider.

Linking preserves local password recovery and account enablement. A disabled account stays disabled, retains its link and grants, and receives no session after provider authentication. Re-enable it through the existing administrative account control to restore access. Bootstrap creates an administrator only when the user table is empty; it does not replace disabled accounts.

## Reusable OCI registries

Add a registry profile with an HTTPS endpoint, optional namespace, and either anonymous or credential authentication. Patch input pages expose saved profiles as optional source/destination selectors. Selecting a profile supplies its username/token to that job without copying the secret into the job configuration. Source and destination profiles are independent, so a public source can be patched and pushed to a private destination.

Use **Test** on a profile to perform a short `/v2/` reachability check. The result stores only `Reachable`/`Unavailable` and a sanitized detail. Delete a profile when it is no longer needed.
