# Identity and remediation deployment acceptance

Deploy the rebuilt portal image against the existing persistent database after taking a backup. Startup applies the additive identity tables and OIDC mapping/scope columns; no new Compose services or environment variables are required. Rebuild worker images from the same revision so retained-source protection also runs during candidate generation. Existing global mappings retain their meaning until an administrator explicitly reviews and changes them.

## Native VEX disposition upgrade

Upgrade the portal and all workers together. Additive native VEX tables and generation triggers preserve existing evidence and leave automatic exclusions disabled by default. Keep the existing `risk-worker` running against the same database and installed local intelligence snapshot; offline evaluation needs no live feed. Direct development runs `python -m app.risk_worker` with the portal package on the Python path. Review the current preview in Configuration → General Policy before enabling, then verify mixed observations, expiry, rescan/trust invalidation and disabling. Existing jobs, POAMs and Cyber approval history remain preserved. See [native VEX operations and measured limitations](../../docs/native-vex-disposition.md) for the lifecycle, security boundary, benchmark scope and unresolved real-positive applicability gap.

## OIDC diagnostics

The callback records a structured event with `correlation_id`, `stage`, `reason` and `outcome`. The failure page displays that same reference; administrators can find `auth.oidc_failed` in the audit UI or `OIDC` events in portal logs. Stages distinguish state/cookie validation, configuration, token exchange, token validation, UserInfo, account provisioning, account status and authorization. Reasons distinguish issuer/audience/signature/time failures, identity collisions, required explicit account links and disabled accounts without serializing provider responses or exceptions.

A successful, validated login with no effective permissions creates a session and displays **Signed in successfully**, with instructions to request access. This is not a token failure. Permissions and configurable claim mappings use only the verified ID token. UserInfo cannot add authorization claims. Existing signature, issuer, audience, nonce and bounded clock-skew checks remain in force.

The portal filters callback query parameters out of Uvicorn access logs and uses no-store/no-referrer responses. If a reverse proxy, ingress or external access logger records request URLs, configure it to omit the callback query string as well: the application cannot sanitize logs already written upstream. Do not paste authorization codes, tokens, cookies or client secrets into support reports. A correlation ID and its structured diagnostic event are sufficient.

## Optional Keycloak discovery

Discovery already exists and remains separate from login and manual mapping. Enable client authentication and service accounts for the server-configured client. Grant its service account read access using realm-management `view-users`, `view-clients` and `view-realm`, or equivalent fine-grained permissions for the required directory resources. `realm-admin` is unnecessary. Exact permissions can vary with the realm's fine-grained authorization configuration; verify against that realm.

The backend fetches groups (including separately paginated children), realm roles, client roles and active protocol mappers. Credentials stay on the server. A permissions error is shown as unavailable, separately from a successful empty directory. Counts describe directory entries; suggestions require a supported mapper enabled in the login client's ID token or an applicable client scope. Custom mappers can require manual entry. Set the exact claim path and exact value; a Keycloak role does not automatically appear in `groups`. Role mappers must emit multiple values. Discovery neither grants access nor gates ordinary OIDC login.

## Acceptance checklist

- Remediation: assess a service with safe charts, a literal-secret chart and an independent image fix. Confirm the plan shows safe opportunities and sanitized chart/file/key diagnostics. Confirm original evidence remains intact. Explicitly exclude the blocked chart to build a partial candidate; verify its exclusion report and that validation/download/OCI paths still reject unsafe retained material. Repeat with templated, empty and placeholder values to check false positives.
- Scopes: map the existing exact provider claim to Service Manager using **CATS-managed scope**. Assign Alice A/B and Bob C inside CATS. Test lists, direct service URLs, exports and remediation as both users. Test no assignment, group assignment, role removal at the next login and assignment removal during an active session. Review any fixed/global mapping conversion before applying it; preserve the recovery administrator.
- Accounts: independently verify issuer and immutable `sub`, pre-link a local test account, and verify both sign-in methods reach the same account. Merge a duplicate using a different administrator, explicitly select retained grants, and verify history, ownership, disabled-account handling and revoked sessions. Update any contradictory legacy `account_links` configuration to the survivor.
- Diagnostics: induce a state failure, token validation failure and unlinked username collision. Match each displayed reference to its sanitized audit/log event. Verify callback access logs contain no query parameters and a valid but unscoped user sees the successful-login/no-access page.
- Discovery: test read-only service-account permissions, denied permissions, empty directories, nested groups and more than one page. Verify manual mappings and normal login continue without discovery.

Local regression tests use real database/session and HTTP authorization paths with mocked provider and delivery I/O. Validation passed 670 relevant backend tests, 269 frontend tests, TypeScript checking and the production frontend build. These checks do not establish production verification. A real Keycloak realm, production-size assessment corpus, actual OCI registry/Helm execution and production database concurrency must be checked in deployment acceptance.

See [account linking](account-linking.md) for the merge workflow and recovery constraints, [CATS-managed scope](../../docs/oidc-managed-scope.md) for mapping migration and permission semantics, and [remediation pipeline](remediation-pipeline.md) for partial candidate handling.
