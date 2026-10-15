# Cyber approvals and approved releases

Cyber approval records a decision on a retained service snapshot. Registry publication is a separate operation. A release can be approved while publication is pending, publishing, or failed; consumers should retrieve artifacts only from a successfully published release.

## Request a review

Open a service and choose **Request Cyber Approval**, or use its **Approvals** tab. Select **Current Service** or a specific **CATS Remediated** candidate in the release variant selector, then submit. Candidates are associated with the current service scan and version.

Submission is gated on retained evidence completeness, not a clean vulnerability result. Missing scanner/SBOM evidence, skipped artifacts recorded as missing evidence, lost declared chart sources or dependencies, and corrupt retained files must be corrected. Remaining vulnerabilities, failed or skipped deployment verification, and absent configuration scans or Helm charts are presented for Cyber review. **CATS Remediated** identifies remediation provenance; it does not assert that every check passed or that deployment was verified.

CATS selects the eligible default OCI destination automatically (or the first eligible destination if no default exists). Destination and signing setup do not block submission. If no destination exists yet, Cyber selects an eligible destination after an administrator configures it, before approving. Submission retains the artifact and evidence snapshot, variant, version, scan date, and any available destination for review. Later scans or service edits do not rewrite the evidence.

Container tags are accepted without requiring a manually supplied digest. When the scan did not retain an image digest, Cyber sees that the tag will be resolved at publication and could identify different content from the scanned image. Publication records the resolved digest before copying, reuses it on retries, and signs the exact published content. Retained remediation image archives are copied from their checked snapshot bytes. Approved Releases and offline bundles record the final immutable references and signatures.

## Review and decide

Select a severity bar to see the top five container images ranked by finding observations for that severity and filter the findings table. Select a container in that ranking to filter the table to its exact image reference, together with the other active filters. Select it again or use **Clear container filter** to remove that filter. Repeated package or scanner observations count separately; this is not a count of unique CVEs or running containers. The ranking uses the complete retained snapshot, independent of the table's search and risk filters. Observations without an image are reported separately.

New requests freeze KEV/EPSS lookups from the portal's installed intelligence catalogs together with the KEV catalog version/release date and EPSS model version/score date. The review shows when this intelligence was captured at request submission; these are review-time datasets, not a claim about the original scanner's feed versions. Later feed refreshes do not change a submitted review. Original scan results remain intact, and `frozen-snapshot.json` in the evidence ZIP includes the review intelligence. Missing or invalid catalogs produce unknown intelligence, not a negative result. Older requests retain their original values and show dataset provenance as not recorded; CATS does not backfill them from today's feeds. No new environment settings are required.

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

Publication runs as a durable job on the existing **remediation-worker**. Rebuild and upgrade the portal and workers together so they use the same application version; this feature needs no additional Compose services. Keep the existing durable database and artifact storage volumes. Inspect the release publication error and retry the same snapshot after correcting registry, signing, or worker availability issues.

Approval history preserves service and account provenance. Services and accounts referenced by approval records cannot be deleted; archive a service or disable an account instead.

Request and decision permissions are separate. The server checks service/group access, evidence readiness, immutable snapshot identity, and publication authorization; disabled buttons are only a convenience and do not replace server enforcement.

## Frontend integration

Page envelopes use `cyber_approvals`, `approved_releases`, and `approved_release_destinations`. Their routes are `/cyber-approvals`, `/approved-releases`, and `/admin/approved-release-destinations`. Detail pages use `?id=`, and service links use `?service=`. JSON mutations use the existing same-origin request helper and `X-CSRF-Token` header. Service readiness and request creation are refreshed from the server before review.

## Approval expiry

New Cyber approvals expire **90 days after the approval decision** by default. Administrators can change **Settings → Image signing (Cosign) → Cyber approval lifetime (days)** to any whole number from 1 to 3650 and save the signing configuration. This setting can be saved before keys are uploaded, survives key rotation/removal, and takes effect without restarting services. Existing signing keys are preserved when only the lifetime changes.

The saved setting takes precedence over `CATS_CYBER_APPROVAL_VALIDITY_DAYS`, which remains an optional deployment default until a lifetime is saved in Settings. If neither is configured, CATS uses 90 days. No Compose or `.env` edit, database migration, or additional service is required for the Settings control; deploy the updated portal image to expose it.

Changes affect **future approvals only**. The duration is frozen when Cyber approves; retrying publication, re-signing during a retry, downloading, or copying to another OCI never renews it. Request and approve a new snapshot to renew authorization.

Approved Releases displays the expiry and distinguishes valid, expiring soon (within seven days), expired, revoked, and reapproval-required releases. Expired releases cannot be published or retried. Their historical evidence and downloads remain available for audit. Previously signed releases without a signed expiry require new Cyber approval; CATS does not invent an expiry for an old signature. Previously downloaded verification scripts are not updated retroactively.

The signed release manifest contains `approval.approved_at`, `approval.expires_at`, and `approval.validity_days`. Each published image, Helm chart, and release artifact also carries these signed Cosign annotations:

- `io.cats.approval.type`: `cyber-approved-v1`
- `io.cats.approval.release`: the release key
- `io.cats.approval.approved-at`: the UTC approval timestamp
- `io.cats.approval.expires-at`: the UTC expiry timestamp

The offline verifier/importer validates the manifest signatures, requires matching signed dates on every artifact, and rejects a missing, malformed, future, or expired window using the importing system's UTC clock. It rechecks during import; if expiry occurs mid-import, already copied artifacts can remain but authorization is not extended. Exact-byte OCI transfers preserve the signatures and dates. The evidence ZIP's detached signature remains useful for historical integrity; deployment authorization comes from the signed release manifest and artifact annotations.

### Enforce expiry in a consuming cluster

Cryptographic signatures remain verifiable after authorization expires. A generic `cosign verify` or a cluster rule that only requires a trusted signature does **not** reject an expired approval. Consumers must enforce the signed window against a trustworthy local clock. Expiry does not delete registry content, evict running Pods, or propagate later revocations into disconnected systems.

An optional [Kyverno policy example](../templates/kyverno-cyber-approval-expiry.yaml) verifies the signed annotations and checks the date at admission. It is not installed by CATS. Replace its public-key placeholder with your independently trusted CATS public key, configure registry authentication and CA trust, disable the Kyverno admission controller image-verification cache (`--imageVerifyCacheEnabled=false`), and test against your installed Kyverno version before rollout. Namespace labels selecting enforcement must be controlled by cluster administrators. Put the release key and exact signed timestamps on Pod metadata (for Deployments, `spec.template.metadata.annotations`). The example requires every image in a Pod, including sidecars, to have approval for the same release/window. It checks Pod creation and updates; already running workloads are not automatically stopped.

The example follows Kyverno's [signed annotation verification](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/) and [time comparison functions](https://kyverno.io/docs/policy-types/cluster-policy/jmespath/). Both signature binding and time validation are required: trusting an unsigned Pod expiry annotation by itself would let a deployer extend the deadline.
