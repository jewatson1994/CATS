# CATS Portal + Keycloak/OIDC Integration Guide

This guide configures the CATS Portal to authenticate users with Keycloak while preserving the existing CATS authorization model. Keycloak proves who the user is; CATS determines which roles, groups, services, findings, POA&M records, and approval workflows the user can access.

The portal supports three identity modes:

- `local` — existing CATS username/password login only.
- `oidc` — Keycloak login only.
- `both` — Keycloak login plus local CATS accounts. This is recommended during rollout because it preserves administrator recovery access.

## 1. Decide the Keycloak deployment values

Before configuring Keycloak, choose the public URL users will use to reach the portal. The URL must be stable and must use HTTPS outside of an isolated local development environment.

Example values:

```text
Keycloak base URL:       https://sso.example.invalid
Realm:                   cats
Keycloak issuer:         https://sso.example.invalid/realms/cats
Portal URL:              https://cats.example.invalid
OIDC client ID:          cats-portal
```

The issuer is the realm URL, not the Keycloak administrator console URL. For the example above, the discovery document must be available at:

```text
https://sso.example.invalid/realms/cats/.well-known/openid-configuration
```

Verify that URL from the portal host before enabling OIDC. The portal must be able to reach the issuer, token endpoint, user-info endpoint, and JWKS endpoint.

## 2. Create or select the Keycloak realm

1. Sign in to the Keycloak Administration Console.
2. Create a realm named `cats`, or select the existing CATS realm.
3. Confirm the realm is enabled.
4. Confirm the realm issuer URL matches the value that will be placed in `CATS_OIDC_ISSUER_URL`.

Do not use the `master` realm for application users unless that is an intentional organizational policy decision.

## 3. Create the CATS OIDC client

In the `cats` realm:

1. Open **Clients**.
2. Select **Create client**.
3. Set **Client type** to `OpenID Connect`.
4. Set **Client ID** to `cats-portal`.
5. Leave the client authentication enabled. The portal uses a confidential client because it exchanges an authorization code server-side.
6. Use the standard authorization-code flow.
7. Disable implicit flow and direct access grants unless your organization explicitly requires them.
8. Save the client.

Configure the client URLs:

```text
Valid redirect URI:
https://cats.example.invalid/auth/oidc/callback

Valid post logout redirect URI:
https://cats.example.invalid/login

Web origin:
https://cats.example.invalid
```

For local development, add the local equivalents separately rather than replacing the production values:

```text
http://localhost:8080/auth/oidc/callback
http://127.0.0.1:8080/auth/oidc/callback
http://localhost:8080/login
http://127.0.0.1:8080/login
```

Use exact paths. Do not use a wildcard redirect URI in production.

## 4. Record the client secret

Open the client’s **Credentials** tab and copy the generated client secret. Store it in the deployment secret store, not in Git, a Dockerfile, a compose file committed to source, or a browser-visible setting.

The value becomes:

```env
CATS_OIDC_CLIENT_SECRET=the-keycloak-client-secret
```

Rotate the secret if it is exposed. After rotation, restart the portal so the new value is loaded.

## 5. Configure user claims

The portal uses these claims:

| Claim | Purpose | Default |
|---|---|---|
| `sub` | Stable external user identity | Required |
| `preferred_username` | CATS username fallback | Preferred |
| `email` | Username/display-name fallback | Optional |
| `name` | CATS display name | Optional |
| `groups` | CATS group/service scope | `groups` |
| `realm_access.roles` | CATS role mapping | `realm_access.roles` |

The ID token and user-info response should include at least `sub`, `preferred_username` or `email`, and the required role/group claims.

In Keycloak, add a **Client scope** or client-specific protocol mappers:

### Groups mapper

1. Create a mapper named `groups`.
2. Mapper type: **Group Membership**.
3. Token claim name: `groups`.
4. Add to ID token: enabled.
5. Add to access token: enabled.
6. Add to userinfo: enabled.
7. Decide whether to include the full group path. The portal strips leading and trailing `/` characters, but the CATS group name should still match the final group name.

### Username mapper

Ensure the standard `preferred_username` claim is present in the ID token or user-info response.

### Email and display-name mappers

Ensure `email` and `name` are included when your organization permits them. CATS uses them to populate a readable display name and to recover when a preferred username is unavailable.

### Role claims

Keycloak normally emits realm roles in `realm_access.roles`. Client roles are emitted under:

```text
resource_access.cats-portal.roles
```

The portal accepts both locations. Keep the role names stable and map them explicitly in the environment configuration.

## 6. Create the Keycloak groups

Create groups that correspond to the groups already used by CATS. Example:

```text
/Cybersecurity
/Assessors
/Group A
/Group B
/Platform Engineering
```

The group name must match the CATS group name after the portal removes leading/trailing slashes. Existing CATS groups are recommended for the first rollout so group service assignments remain under administrator control.

Do not enable automatic group creation initially. Set:

```env
CATS_OIDC_AUTO_PROVISION_GROUPS=false
```

If a user presents a group that does not exist in CATS, the group claim is ignored until an administrator creates and assigns that group. This prevents a spelling mistake or unapproved Keycloak group from granting service scope.

## 7. Create and map Keycloak roles

The built-in CATS roles are:

```text
Administrator
Assessor
Service Manager
Cybersecurity
```

You can use Keycloak realm roles with the same names, or use simpler names and map them. The recommended explicit mapping is:

```env
CATS_OIDC_ROLE_MAP={"cybersecurity":"Cybersecurity","assessor":"Assessor","service-manager":"Service Manager","administrator":"Administrator"}
```

The mapping is case-sensitive on the Keycloak side and case-insensitive when matching the resulting CATS role name.

Recommended role policy:

- `Administrator`: CATS administration, configuration, role management, and unrestricted service visibility.
- `Cybersecurity`: review exceptions, approve POA&M entries, manage policy, and review all scoped findings.
- `Assessor`: view and export services and audit information.
- `Service Manager`: view assigned services, request exceptions, create POA&M entries, and request archival.

Do not map every Keycloak user to `Administrator`. Use the least-privilege role required for the user’s job.

## 8. Decide how group roles are assigned

The portal can apply a default role to a user’s CATS group assignment:

```env
CATS_OIDC_GROUP_DEFAULT_ROLE=Service Manager
CATS_OIDC_GROUP_ROLE_MAP={}
```

For a more specific mapping:

```env
CATS_OIDC_GROUP_ROLE_MAP={"Cybersecurity":"Cybersecurity","Assessors":"Assessor","Platform Engineering":"Service Manager"}
```

Users can still receive global role claims from Keycloak. Group assignments add group-scoped access; they do not replace the CATS service-to-group relationships.

## 9. Configure the portal environment

Add these values to the deployment environment used by the portal container:

```env
CATS_IDENTITY_MODE=both

CATS_OIDC_ISSUER_URL=https://sso.example.invalid/realms/cats
CATS_OIDC_CLIENT_ID=cats-portal
CATS_OIDC_CLIENT_SECRET=replace-with-secret
CATS_OIDC_REDIRECT_URI=https://cats.example.invalid/auth/oidc/callback
CATS_OIDC_POST_LOGOUT_REDIRECT_URI=https://cats.example.invalid/login

CATS_OIDC_SCOPES=openid profile email groups
CATS_OIDC_GROUPS_CLAIM=groups
CATS_OIDC_ROLES_CLAIM=realm_access.roles
CATS_OIDC_ROLE_MAP={"cybersecurity":"Cybersecurity","assessor":"Assessor","service-manager":"Service Manager","administrator":"Administrator"}
CATS_OIDC_GROUP_ROLE_MAP={}
CATS_OIDC_DEFAULT_ROLE=
CATS_OIDC_GROUP_DEFAULT_ROLE=Service Manager
CATS_OIDC_AUTO_PROVISION=true
CATS_OIDC_AUTO_PROVISION_GROUPS=false
```

`CATS_OIDC_DEFAULT_ROLE` is intentionally empty in the recommended configuration. A user should receive a role from an explicit Keycloak role or group mapping. During an initial lab-only test, it can be set to `Assessor`, but do not use that as a production authorization shortcut.

The compose file passes these values to the portal container. If you deploy with Kubernetes, Helm, or another runtime, set the same names as Secret/ConfigMap values.

## 10. Configure TLS and certificates

The portal should use HTTPS, and the browser-facing hostname must match the certificate. Keycloak must also present a certificate trusted by the portal container.

If Keycloak uses a private or internal CA:

1. Place the CA certificate in the portal image or mount it as a read-only file.
2. Update the container trust store according to the base image.
3. Restart the portal.
4. Verify the discovery and JWKS URLs from inside the portal container.

Do not disable TLS verification as a workaround. The OIDC callback exchanges credentials and must not trust an unverified identity provider.

## 11. Configure the CATS identity setting

After the environment values are present:

1. Sign in with the existing local administrator account.
2. Open **Administration → Configuration**.
3. Select the intended group scope.
4. Set **Identity mode** to **Both local and OIDC**.
5. Save the configuration.
6. Sign out.
7. Confirm the login page shows **Sign in with Keycloak** and the local login form.

Use **OIDC / Keycloak** only after recovery access has been tested successfully.

## 12. Test with a non-privileged account first

Create one test user in Keycloak with:

- one known group, such as `Assessors`;
- one mapped role, such as `assessor`;
- no administrator role.

Test the following:

1. Open `/login`.
2. Select **Sign in with Keycloak**.
3. Complete the Keycloak login.
4. Confirm the browser returns to the CATS dashboard.
5. Confirm the user’s display name is correct.
6. Confirm only services assigned to the user’s CATS group are visible.
7. Confirm the user cannot open Administration unless their mapped role permits it.
8. Confirm exports, POA&M scope, exception requests, and findings use the same service scope.
9. Check CATS Audit Policy for the `auth.oidc_login` event.

## 13. Test the recovery account

Before changing the mode to OIDC-only:

1. Open a private browser window.
2. Confirm the local administrator can still sign in.
3. Confirm the administrator can return to Administration → Configuration.
4. Confirm the local administrator can change the identity mode back to `both` or `local`.

Keep one local recovery account with a long random password stored in the approved secret manager. Do not use the development bypass in production:

```env
CATS_ENV=production
CATS_DEV_AUTH_BYPASS=false
```

## 14. Move from Both to OIDC-only

Only after the previous tests pass:

1. Keep the local recovery account enabled until the organization approves OIDC-only operation.
2. Set Identity mode to **OIDC / Keycloak** in the CATS Configuration tab, or set the equivalent scoped setting through the database-management process approved for your deployment.
3. Sign out and validate Keycloak login again.
4. Confirm a local POST to `/login` is rejected with the local-login-disabled message.
5. Keep the recovery procedure documented and protected.

The recommended default for the first production rollout is still **Both local and OIDC**.

## 15. User lifecycle and role changes

OIDC users are matched by the stable Keycloak `sub` claim. Do not change a user’s identity by changing only their email address. If a user is disabled in Keycloak, the portal will not automatically revoke an already-issued CATS session until that session expires unless the identity provider or reverse proxy enforces shorter sessions.

For immediate access removal:

1. Disable the user in Keycloak.
2. Disable the corresponding CATS user in Administration → Accounts & Roles.
3. Review and revoke active sessions through the approved operational procedure.
4. Review the CATS audit trail.

For role changes, update Keycloak roles/groups and have the user sign in again. Existing role assignments may remain in the local database; review them before relying on a role removal as an immediate revocation mechanism.

## 16. Troubleshooting checklist

### The Keycloak button is not visible

- Confirm Identity mode is `oidc` or `both`.
- Confirm the saved configuration applies to the current group scope.
- Restart the portal if the environment configuration changed.

### The portal reports OIDC is not configured

- Confirm `CATS_OIDC_ISSUER_URL` is set.
- Confirm the issuer discovery URL is reachable from the portal container.
- Confirm the client ID, secret, and redirect URI are present.

### Keycloak reports an invalid redirect URI

- Compare Keycloak’s configured redirect URI with the exact browser-facing portal URL.
- Include `/auth/oidc/callback`.
- Check HTTP versus HTTPS, hostname, port, and trailing path.

### The callback reports invalid state or nonce

- Confirm cookies are enabled.
- Confirm the portal is not behind a proxy that changes host/scheme incorrectly.
- Use HTTPS in shared environments.
- Do not open the callback URL manually; begin at `/login`.

### The user signs in but sees no services

- Confirm the `groups` claim is present.
- Confirm the Keycloak group name matches an existing CATS group.
- Confirm that CATS group is assigned to the service.
- Confirm the user received a mapped CATS role.
- Confirm `CATS_OIDC_AUTO_PROVISION_GROUPS` is intentionally set for your policy.

### The user receives too much access

- Remove broad realm roles.
- Remove an unintended global CATS role assignment.
- Review `CATS_OIDC_ROLE_MAP` and `CATS_OIDC_GROUP_ROLE_MAP`.
- Disable automatic group provisioning unless explicitly required.

## 17. Rollback

To return to local login without deleting users or evidence:

```env
CATS_IDENTITY_MODE=local
```

Restart the portal, then sign in with the existing local administrator account. OIDC-created users remain in the database with `auth_source=oidc`; their evidence, service assignments, and audit records are preserved.

## 18. Deployment commands

After changing the portal source, requirements, compose values, or templates:

```powershell
docker compose up -d --build portal
docker compose logs --tail=200 portal
```

For a clean local identity-mode check:

```powershell
docker compose exec portal python -c "import os; print(os.getenv('CATS_IDENTITY_MODE', 'local'))"
```

Do not place the client secret in the repository or in a public package. Add it only in the target environment’s secret configuration.
