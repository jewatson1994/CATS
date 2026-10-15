# Cyber approvals and approved releases

Cyber approval records a decision on a retained service snapshot. Registry publication is a separate operation. A release can be approved while publication is pending, publishing, or failed; consumers should retrieve artifacts only from a successfully published release.

## Request a review

Open a service and choose **Request Cyber Approval**, or use its **Approvals** tab. Select **Current Service** or a specific **CATS Remediated** candidate in the release variant selector, then submit. Candidates are associated with the current service scan and version.

Submission is gated on retained evidence completeness, not a clean vulnerability result. Missing scanner/SBOM evidence, skipped artifacts recorded as missing evidence, lost declared chart sources or dependencies, and corrupt retained files must be corrected. Remaining vulnerabilities, failed or skipped deployment verification, and absent configuration scans or Helm charts are presented for Cyber review. **CATS Remediated** identifies remediation provenance; it does not assert that every check passed or that deployment was verified.

CATS selects the eligible default OCI destination automatically (or the first eligible destination if no default exists). Destination and signing setup do not block submission. If no destination exists yet, Cyber selects an eligible destination after an administrator configures it, before approving. Submission retains the artifact and evidence snapshot, variant, version, scan date, and any available destination for review. Later scans or service edits do not rewrite the evidence.

Container tags are accepted without requiring a manually supplied digest. When the scan did not retain an image digest, Cyber sees that the tag will be resolved at publication and could identify different content from the scanned image. Publication records the resolved digest before copying, reuses it on retries, and signs the exact published content. Retained remediation image archives are copied from their checked snapshot bytes. Approved Releases and offline bundles record the final immutable references and signatures.

## Review and decide

The top-level **Approvals** queue lists pending, approved, and denied requests. Open a request to inspect its artifacts, findings, mitigations, exceptions, remediation provenance, coverage and verification notes, destination, and complete snapshot. Cyber can approve images with remaining vulnerabilities. Authorized reviewers must enter a rationale when approving or denying. Destination and signing identity are bound before approval; these publication settings must be available to approve. Denial does not require publication setup. Approval does not mean that registry publication has succeeded.

## Retrieve a release

The **Approved Releases** catalog separates the Cyber decision from publication status. Open a release to inspect the decision record, destination, immutable artifact references, signature evidence, and available evidence or offline downloads. Pull and deployment instructions are shown with the release. Deploy the immutable references recorded there instead of a mutable tag.

For a failed publication, authorized reviewers can choose **Retry publication**. Refresh the release to view publication progress and errors. A retry publishes the same approved snapshot; it does not approve new service changes.

Revoked releases and their retained artifacts remain available for audit history only and are no longer authorized for deployment. Revocation does not remove already imported artifacts or automatically enforce a policy in running clusters. Registry access controls and deployment admission policies must enforce who can retrieve or deploy those artifacts.

## Verify and import offline

Obtain the trusted signing key fingerprint independently from your Cyber approver. A public key packaged with a download cannot establish trust by itself. Download the published offline bundle and extract it into an empty directory. The included `README.txt` documents the exact commands for that bundle.

Verification requires **Python 3** and **Cosign 2.x**. Import additionally requires **ORAS 1.2 or later**, access to the target OCI registry, prior ORAS/Cosign login, and configured registry CA trust. Verify all retained evidence, OCI layers, and artifact signatures before import:

```sh
python verify-import.py --fingerprint sha256:<trusted-key-fingerprint>
python verify-import.py --fingerprint sha256:<trusted-key-fingerprint> --destination registry.example/team/release
```

The signed `release-manifest.json` maps source images and charts to their approved digest references. The import command prints each source, published reference, and new target reference. Use that source-to-target mapping to supply environment-specific Helm values and image overrides pointing to the imported immutable digests. Retained charts are not rewritten after approval. Configure registry immutability and retention, and deployment signature/admission policies separately; publication alone does not enforce approved-only deployment.

## Configure destinations

Administrators with release destination permission use **Administration → Release Destinations** to configure registry name, HTTPS endpoint, namespace, permitted group IDs, availability for new requests, default selection, registry credentials, optional custom CA, and pull/deployment instructions. Credentials are submitted to the server and never returned to the browser. When editing, leaving the password or custom CA blank preserves its existing value. Signing uses the global signing configuration under **Settings**.

Configure a reachable OCI registry and credentials permitted to publish into the selected namespace. Keep source-registry credentials and CA trust configured so the worker can retrieve all approved artifacts. Configure the global Cosign signing key before Cyber approves publication, and distribute its trusted public-key fingerprint independently to consumers. Restrict destination groups to the intended services and assign `approval.request`, `approval.decide`, and `release.destination.manage` separately; requesting a snapshot also requires service export access. Catalog reading uses service viewing access, while retained downloads require service export access.

Publication runs as a durable job on the existing **remediation-worker**. Rebuild and upgrade the portal and workers together so they use the same application version; this feature needs no additional Compose services or Compose changes. Keep the existing durable database and artifact storage volumes. Inspect the release publication error and retry the same snapshot after correcting registry, signing, or worker availability issues.

Approval history preserves service and account provenance. Services and accounts referenced by approval records cannot be deleted; archive a service or disable an account instead.

Request and decision permissions are separate. The server checks service/group access, evidence readiness, immutable snapshot identity, and publication authorization; disabled buttons are only a convenience and do not replace server enforcement.

## Frontend integration

Page envelopes use `cyber_approvals`, `approved_releases`, and `approved_release_destinations`. Their routes are `/cyber-approvals`, `/approved-releases`, and `/admin/approved-release-destinations`. Detail pages use `?id=`, and service links use `?service=`. JSON mutations use the existing same-origin request helper and `X-CSRF-Token` header. Service readiness and request creation are refreshed from the server before review.
