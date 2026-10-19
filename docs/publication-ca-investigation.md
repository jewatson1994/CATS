# Publication CA investigation — 2026-10-19

Investigated repository main at b23e021bc554efe096592a7fba731a46c2c2c8b8.
Local fix branch: fix/publication-managed-ca-trust. Nothing pushed or merged.
Reported destination: https://harbor.aj.frm.project/cyber-approved.
Reported correlation ID: 09116a267f3b4c1aab6ab68cb065e82f.
No access to the disconnected deployment, its database, logs, daemon configuration, or actual certificate chain was available.

## Finding

A confirmed code defect omits portal-managed CA certificates from the destination publication environment. This reproduces a certificate verification failure when the registry requires those CAs. It is a plausible explanation for the reported incident, not proof of its exact runtime cause: the sanitized message does not identify the failing host or TLS verification reason, and artifact transfer can contact a source registry, destination registry, or token endpoint.

The certificates need not be missing or stale in the worker. Publication reads current PortalSetting rows and supplies managed certificates to source retrieval, but previously built destination trust from destination.ca_pem alone. When source and destination host match, source retrieval also uses the destination environment and therefore shared the omission. There is no certificate-download step in this publication path.

## Execution and trust paths

| Concern | Patch push | Cyber-approved Publication |
| --- | --- | --- |
| Entry | portal/app/main.py: public_patch_submit, _run_patch_job | portal/app/cyber_approvals.py: publication submission, publish_job |
| Executor | app.patch_worker subprocess, normally via dedicated patch worker API; local fallback exists | app.remediation_worker dispatches cyber_release_publish to publish_job; compose.yaml runs this worker separately |
| Registry configuration | Submitted destination_image and destination credentials; optional reuse of source credentials | ApprovedReleaseDestination record, checked against frozen endpoint, namespace and destination CA digest; separate from patch input and source oci_registries |
| Managed CAs | main.py copies trusted_ca_certificates into job configuration and sends it to patch worker | cyber_release_publication.publish reads PortalSetting directly through the worker DB session |
| Trust application | patch_worker.main builds system-plus-managed CA file and sets SSL_CERT_FILE, REQUESTS_CA_BUNDLE and Grype CA variables | Before fix: registry_environment -> destination_trust -> ephemeral_trust used only destination.ca_pem. After fix: system + current managed CAs + destination CA |
| Network transport | docker login/push via host Docker socket | release_oci._Client uses verified Python HTTPS; Skopeo for retained Docker archives; Cosign for registry signatures |

Patch worker code passes no registry TLS-disable flags. However, docker push is performed by the Docker daemon; setting a CA environment variable in the CLI process does not configure that daemon's registry trust. compose.yaml mounts /var/run/docker.sock into patch-worker. Whether the successful push actually verified Harbor must be checked on that daemon: inspect its effective insecure-registry settings and registry/system CA trust. Do not infer verification from success alone. No patch behavior was changed.

## Hostnames, authentication and redirects

- service_oci.validate_destination requires an HTTPS origin with no path; cyber-approved belongs in the namespace. cyber_release_publication.publish constructs repositories as namespace/cyber-approved/release-key/artifact. A namespace already named cyber-approved therefore produces that segment twice. This is existing naming behavior and does not itself explain TLS failure.
- Publication uses the ApprovedReleaseDestination endpoint, not necessarily the patch destination hostname. Actual saved values must be compared in the deployment.
- release_oci._Client explicitly loads the supplied CA file into a default verifying SSL context. Both registry and Bearer-token requests use that same opener and context.
- Same-origin token endpoints are accepted. Cross-origin token services require CATS_OCI_TOKEN_REALMS approval. This allowlist is separate from certificate trust.
- _NoRedirect refuses redirects. Upload Location must remain on the approved HTTPS origin. Rejected redirects normally produce an HTTP/origin failure, not this SSL diagnostic. No restriction was relaxed.
- Python's diagnostic indicates ssl.SSLError (possibly wrapped in URLError). A Skopeo process failure instead maps to a tool exit error. The supplied stage does not distinguish source, destination or authentication TLS failures.

## Fix

- service_oci.destination_trust accepts managed certificates and combines them with the destination CA through the existing ephemeral additive bundle helper.
- release_documentation.registry_environment forwards those certificates, retaining scoped credentials and cleanup.
- cyber_release_publication.publish passes current worker-read settings for every publication attempt. No cached startup bundle or frozen CA list is introduced.
- release_oci._Client consumes SSL_CERT_FILE. signing.clean_environment preserves it and signing.sign_and_verify passes it to Cosign subprocesses.
- _publish_image_archive copies the same bundle to Skopeo's --dest-cert-dir and now explicitly sets --dest-tls-verify=true.
- TLS verification and hostname checks remain enabled. No insecure fallback, redirect relaxation, or credential expansion was added.

## Regression coverage and deployment validation

Tests cover worker-side propagation and updated certificates on a subsequent attempt; real local TLS with managed root and intermediate; failure with the old destination-only trust; registry and token HTTPS; a real child process consuming the bundle; hostname mismatch rejection; destination-specific plus managed CA composition; Skopeo environment/certificate-directory/verification arguments; temporary trust cleanup. Skopeo and Cosign themselves are mocked in these tests, not executed against Harbor.

In the disconnected deployment, still verify:

1. Installed portal/worker image commit and the failed job's retained diagnostic/logs for the correlation ID above.
2. The effective patch destination and ApprovedReleaseDestination hostname, credentials, namespace and destination CA; current managed certificate fingerprints/expiry. Compare actual values without exposing passwords.
3. Harbor's presented chain and SAN for the exact hostname, system clock, and the Bearer realm's hostname/chain. The current user-facing diagnostic cannot distinguish missing issuer, expiry, hostname mismatch or protocol negotiation failure.
4. Docker daemon's effective TLS/insecure-registry configuration on the patch host. The repository cannot establish whether the successful push verified the server.
5. Rebuild/redeploy the fixed remediation-worker image and retry an approved publication. Exercise actual Skopeo archive publication, Cosign sign/verify, all five artifacts, registry readback and offline bundle completion. Existing authorization, validity and partial-publication checks still apply.

### Executed results

- Focused suites: test_publication_tls, test_cyber_release_publication, test_trusted_ca, test_service_oci, test_release_documentation and test_release_oci: **98 passed**.
- Additional test_service_oci + test_signing run: nine signing/API tests returned HTTP 503; the exact same nine failures reproduce on untouched b23e021 (49 passed, nine failed, one skipped). The skipped test requires real Cosign. These are not claimed as passing.
- git diff --check passed.
