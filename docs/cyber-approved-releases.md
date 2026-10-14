# Cyber approvals and approved releases

Cyber approval records a decision on a retained service snapshot. Registry publication is a separate operation. A release can be approved while publication is pending, publishing, or failed; consumers should retrieve artifacts only from a successfully published release.

## Request a review

Open a service and choose **Request Cyber Approval**, or use its **Approvals** tab. Choose **Current Service** for the current retained service evidence. Choose **CATS Remediated** and select a retained remediation to request review of that candidate and its provenance.

The readiness check lists evidence blockers. Resolve missing evidence before submitting. Select an approved OCI destination and optionally explain the request context. Submission retains the artifact and evidence snapshot, variant, version, scan date, and destination for review. Later scans or service edits do not rewrite that record.

## Review and decide

The top-level **Approvals** queue lists pending, approved, and denied requests. Open a request to inspect its immutable artifacts, findings, mitigations, exceptions, remediation provenance, destination, and complete snapshot. Authorized Cyber reviewers must enter a rationale when approving or denying. Approval does not mean that registry publication has succeeded.

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

Configure a reachable OCI registry and credentials permitted to publish into the selected namespace. Keep source-registry credentials and CA trust configured so the worker can retrieve all approved artifacts. Configure the global Cosign signing key before requesting approval, and distribute its trusted public-key fingerprint independently to consumers. Restrict destination groups to the intended services and assign `approval.request`, `approval.decide`, and `release.destination.manage` separately; requesting a snapshot also requires service export access. Catalog reading uses service viewing access, while retained downloads require service export access.

Publication runs as a durable job on the existing **remediation-worker**. Rebuild and upgrade the portal and workers together so they use the same application version; this feature needs no additional Compose services or Compose changes. Keep the existing durable database and artifact storage volumes. Inspect the release publication error and retry the same snapshot after correcting registry, signing, or worker availability issues.

Approval history preserves service and account provenance. Services and accounts referenced by approval records cannot be deleted; archive a service or disable an account instead.

Request and decision permissions are separate. The server checks service/group access, evidence readiness, immutable snapshot identity, and publication authorization; disabled buttons are only a convenience and do not replace server enforcement.

## Frontend integration

Page envelopes use `cyber_approvals`, `approved_releases`, and `approved_release_destinations`. Their routes are `/cyber-approvals`, `/approved-releases`, and `/admin/approved-release-destinations`. Detail pages use `?id=`, and service links use `?service=`. JSON mutations use the existing same-origin request helper and `X-CSRF-Token` header. Service readiness and request creation are refreshed from the server before review.
