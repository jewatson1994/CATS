# Signed release documentation

Release documentation travels with the immutable deployment identity. A release contains `documentation.zip`, `release-manifest.json`, verification instructions, and, when signing is enabled, `documentation.zip.sig`, `release-manifest.sig` and `release-public-key.pem`. Signing is local, uses the configured Cosign key, and does not contact a public transparency log. A successful registry upload alone does not establish a valid signature or successful deployment validation; retain each outcome separately.

## Implementation and package layout

The retained-candidate Deliver workflow uses the same permission-scoped Export All builder as the All download, including configured PPSM, POAM and Asset List workbooks. `service_exports.py` builds the exports; `release_exports.py` writes and retains the archive; `release_documentation.py` caches immutable snapshots and manifests; `release_signing.py` invokes the existing Cosign/key infrastructure; `release_oci.py` handles standard Distribution uploads and retrieval. `delivery_execution.py` provides process-safe execution locks. Existing delivery records hold checkpoints and receipts, without a new database table. The React Deliver panel shows contents, authorization, progress, references and downloads.

Standard and Offline bundles include these files under `release/`:

```text
release/
  documentation.zip
  release-manifest.json
  VERIFY.txt
  documentation.zip.sig      # signed releases
  release-manifest.sig       # signed releases
  release-public-key.pem     # signed releases
```

The documentation archive is the ZIP produced by Export All: configured `ppsm.xlsx`, `poam.xlsx`, `asset_list.xlsx`, `findings.xlsx`, `mitigations.xlsx`, available `diagrams.zip` and `sbom-components.json`, and `cats-service.zip` when the exporting user has `bundle.export`. Missing evidence is represented by explicitly named `.unavailable.txt` entries. Release metadata and the entry inventory live in the separate `release-manifest.json`, leaving the ZIP contents identical in scope to Export All.

This integration serves retained remediation candidates. There is no new standalone service-publication endpoint, and ordinary Export All remains a download workflow. Existing scan and patch-worker architecture is unchanged. Signing and registry transport are implemented, but production readiness still requires the deployment-host checks below.

## Configuration and boundaries

Set these in the main deployment environment; both shipped Compose files forward them through the shared environment to `portal`, `portal-control`, and `remediation-worker`, which executes Cyber release publication:

| Setting | Default | Purpose |
| --- | --- | --- |
| `CATS_RELEASE_DOC_MAX_BYTES` | `268435456` | Positive byte limit for the Export All documentation archive and its uncompressed generated content. OCI transport allows another 2 MiB for release metadata, signatures and its empty config. |
| `CATS_BUNDLE_MAX_BYTES` | `104857600` | Combined expanded manifest and payload limit, and compressed-size limit, for portable service/evidence bundles. There is no separate 64 KiB manifest cap. |
| `CATS_OCI_TOKEN_REALMS` | empty | Comma-separated HTTPS origins allowed to receive the destination credentials when obtaining a registry bearer token. The registry's own origin is always allowed. |
| `CATS_OCI_BLOB_REDIRECT_ORIGINS` | empty | Comma-separated HTTPS origins allowed for cross-origin publication blob GET/HEAD redirects. Registry credentials are never forwarded to another origin. Same-origin reads and HTTP 307/308 writes are supported automatically. |

For example, a registry at `https://registry.example` with a separate token service at `https://auth.registry.example/token` needs `CATS_OCI_TOKEN_REALMS=https://auth.registry.example`. This grants trust to that **origin**, including its port, rather than only the example path. Add only operator-approved token services. Empty is the safest default for registries that authenticate on their own origin.

OCI publication uses the approved service destination or administrator-approved remediation destination, its encrypted credentials, and its additive CA trust. Documents are stored in the **same repository** as their immutable subject (`registry/repository@sha256:...`). The helper reads only the supplied `DOCKER_CONFIG/config.json`; it does not invoke credential helpers or fall back to a user's Docker configuration. HTTPS verification remains enabled. Cross-origin upload locations, writes, and manifest redirects are rejected.

For a registry that redirects blob downloads to object storage, set `CATS_OCI_BLOB_REDIRECT_ORIGINS` to the storage service's approved HTTPS origin, for example `https://registry-storage.example`. This applies to both source retrieval and destination verification during publication. Use origins only, including any non-default port; do not include paths, queries, credentials, or signed URLs. The redirected storage service must accept the request without registry credentials, typically through a signed URL issued by the registry. Configure CA trust separately when needed. `CATS_OCI_TOKEN_REALMS` and the OCI proxy's upstream allowlists do not authorize publication blob redirects. Recreate `remediation-worker`, `portal`, and `portal-control` after changing these environment settings, then retry the failed publication.

The private signing key and password remain in encrypted configuration. Only the public key is exported. The public-key fingerprint is SHA-256 over DER SubjectPublicKeyInfo, recorded with the `sha256:` prefix. Obtain the expected fingerprint through a trusted administrative channel; trusting a key solely because it accompanies a signature does not authenticate the publisher.

The active delivery endpoint is `POST /services/{service_key}/remediations/{job_key}/delivery`. OCI delivery requires both service-scoped `artifact.publish` and `service.export` permissions, an approved destination and explicit authorization to disclose the release security documentation to that registry audience (`authorize_documentation=yes`). Bundle delivery uses `service.export`. Configured signing also requires the applicable `artifact.sign` permission. Existing validation and release-policy gates still apply. This endpoint delivers a retained candidate; it does not trigger a new remediation scan.

Authorized users with `service.export` can retrieve retained `documentation.zip`, `release-manifest.json`, `VERIFY.txt`, and, for signed releases, `documentation.zip.sig`, `release-manifest.sig` and `release-public-key.pem` through `GET /services/{service_key}/remediations/{job_key}/deliveries/{attempt_id}/<filename>`. The server checks ownership and retained-file integrity before serving these files. Signature/key attachments are also present in the delivered OCI artifact or bundle for independent verification.

## Identities and retained evidence

The release manifest uses schema `cats.release/v1`. It binds the documentation archive's SHA-256 and byte length to the selected service snapshot and exact deployment artifact identities. OCI image/Helm manifest digests, Helm package hashes and local archive hashes are distinct identity types. A mutable image tag is not an immutable deployment identity. The canonical release-manifest revision is retained outside that manifest to avoid a self-referential hash.

For bundles, the signed manifest binds the embedded deployment content, rendered evidence and image archive identities. The outer bundle hash is computed after packaging and retained in the delivery receipt, outside the bundle. Verify both the receipt's bundle hash and the signed internal manifest when both are available.

`documentation.zip` captures current service data and configured templates when the release snapshot is first generated, including current POAM records and inventory. Its detached signature directly authenticates those exact ZIP bytes. The separate signed release manifest binds the ZIP digest to the deployment artifacts and records its inventory, remediation baseline and deployment validation results. The source execution/version identifies the remediation baseline; it does not restrict the export to historical scan data. No new scan is performed. Explicit unavailable-evidence entries do not assert that missing evidence was generated or validation passed.

Portable bundle manifests larger than 64 KiB are accepted during export, import and OCI attachment. Existing total archive-size, expanded-size and JSON-structure limits still apply.

Retries reuse retained release bytes. A new snapshot, manifest, signature or other attachment produces a new documentation revision. A partial result preserves any known uploaded immutable reference even when later retrieval or signature verification fails. Keep these references for diagnosis and retry; do not reinterpret a partial result as a complete release.

At startup, recovery takes the same cross-process `delivery_lock` used by delivery workers. Attempts still owned by another worker are left alone. Interrupted `running`, `staged` and `publishing` attempts whose lock can be acquired become `failed`, preserving their receipts and recording the interruption for an explicit retry. Queued attempts are dispatched again after the recovery lock has been released. Recovery does not infer success from an interrupted upload.

## Independent OCI retrieval

The following Bash examples use an independently installed [ORAS CLI](https://oras.land/docs/commands/). Authenticate to the approved registry with its documented login method. For private CAs, add `--ca-file /trusted/path/ca.pem` to ORAS network commands. Do not use insecure TLS flags. Replace the example values with the subject and documentation reference from the retained delivery receipt.

```bash
SUBJECT='registry.example/team/api@sha256:SUBJECT_DIGEST'
DOC_REF='registry.example/team/api@sha256:DOCUMENTATION_MANIFEST_DIGEST'
oras discover --artifact-type application/vnd.cats.release.documentation.v1 "$SUBJECT"
oras manifest fetch --output documentation-oci-manifest.json "$DOC_REF"
oras pull --output release-documents "$DOC_REF"
```

For `association_mode=oci_referrers`, discovery should list the documentation digest. Use that digest and compare it to the retained receipt before pulling. For `association_mode=compatibility_tag`, the registry may lack referrers support or reject OCI 1.1 subject fields. The receipt's explicit `DOC_REF` still works. A deterministic tag is also retained as `sha256-<subject digest>.docs-<documentation revision prefix>`; use it for discovery only, then retrieve and verify the exact recorded digest. This compatibility tag is specific to CATS and is not the OCI referrers fallback index tag.

Hash the exact `documentation-oci-manifest.json` bytes and compare them with the SHA-256 in `DOC_REF`. Inspect its `io.cats.release.subject` annotation for an exact match to `SUBJECT`, plus its OCI `subject.digest` when present. Check each layer's digest and size against the pulled file identified by `org.opencontainers.image.title`. ORAS command details: [discover](https://oras.land/docs/commands/oras_discover/), [manifest fetch](https://oras.land/docs/commands/oras_manifest_fetch/), [pull](https://oras.land/docs/commands/oras_pull/).

## Independent offline signature verification

First confirm the included public key matches your trusted fingerprint:

```bash
cd release-documents
openssl pkey -pubin -in release-public-key.pem -outform DER -out release-public-key.der
openssl dgst -sha256 release-public-key.der
cosign verify-blob --key release-public-key.pem \
  --signature documentation.zip.sig --offline --insecure-ignore-tlog=true \
  documentation.zip
cosign verify-blob --key release-public-key.pem \
  --signature release-manifest.sig --offline --insecure-ignore-tlog=true \
  release-manifest.json
```

The transparency-log flag is required because these releases deliberately use local key signing with `--tlog-upload=false`; it does not disable TLS or the signature check. See [Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/) and [Cosign's guidance for signatures without Rekor](https://blog.sigstore.dev/cosign-2-0-released/). Retain a tested Cosign version with the offline verification environment.

After the signature passes, compare the manifest's `documentation.digest` and `documentation.bytes` with the archive, and check that its artifact identities are the exact deployment you intend to use. For example:

```bash
python - <<'PY'
import hashlib, json
from pathlib import Path
manifest = json.loads(Path('release-manifest.json').read_text())
archive = Path('documentation.zip').read_bytes()
assert manifest['documentation']['digest'] == 'sha256:' + hashlib.sha256(archive).hexdigest()
assert manifest['documentation']['bytes'] == len(archive)
print('Documentation archive matches the signed manifest.')
print(json.dumps(manifest['artifacts'], indent=2))
PY
```

Then verify the file hashes in `release-manifest.json` under `snapshot.entries` after safely extracting the archive. A supplied `SHA256SUMS` is useful for transport checks, but the signed manifest and trusted signing key are the authenticity boundary. Unsigned releases can have valid hashes while providing no publisher signature assurance.

## Internal helper contracts

- `app.release_oci.publish_documentation(files, subject, env)` accepts safe attachment basenames mapped to local paths, an immutable OCI SHA-256 subject, and the authorized destination's environment. Required files are `documentation.zip` and `release-manifest.json`; optional text/checksum/signature/public-key attachments are supported. It uploads an OCI image manifest with artifact type `application/vnd.cats.release.documentation.v1`, verifies the manifest and every blob by digest, and checks referrers discovery. Older registries receive a compatible manifest retaining explicit subject annotations.
- Successful publication returns `status=published`, `publication_status=published`, `verification_status=verified`, `reference`, `digest`, `subject`, `revision`, `association_mode`, `compatibility_reference` and file descriptors. `revision` here hashes the attachment inventory and is distinct from the canonical release-manifest revision. On failure, the sanitized result retains publication identity when known. Callers must evaluate verification and signature outcomes separately.
- `app.release_oci.verify_documentation(reference, subject, env)` re-fetches the immutable documentation manifest and blobs and checks association/inventory hashes. It verifies content integrity, not a detached signature.
- `app.release_signing.sign_release_archive(archive_path, output_dir, signing_material)` signs exact Export All ZIP bytes; `verify_release_archive(archive_path, signature_path, public_key_path, expected_fingerprint=None)` verifies that detached signature. Both use the shared release public key.
- `app.release_signing.sign_release_manifest(manifest_path, output_dir, signing_material)` signs exact manifest bytes and verifies the detached signature before reporting success. `verify_release_manifest(manifest_path, signature_path, public_key_path, expected_fingerprint=None)` supports an explicit trusted fingerprint. Disabled signing is reported as unsigned; verification failure is never reported as signed.
- `app.remediation_delivery.deliver(..., checkpoint=None)` calls an optional persistence callback with a fresh `artifact_identities` list after each established immutable artifact identity and signature outcome. Exact Helm packages are retained under the candidate's `delivery-packages` directory and checksum-checked before retry, so repackaging timestamps do not change an otherwise unchanged publication.

The OCI helper assumes the caller has already authorized the destination and selected the release. It is not an alternate permission or publication-policy API.

## Backup, retention and rollback

Before upgrading, quiesce delivery jobs and capture a consistent database backup together with the **entire retained remediation job directory tree**. In the shipped Compose layout these are the PostgreSQL data/backup and `remediation_jobs` volume mounted at `/tmp/cats-remediation-jobs`. Preserve candidates, delivery archives, documentation snapshots, manifests, signatures, public keys, receipts and retained Helm package caches together. Backing up selected ZIP files alone loses the linkage and retry evidence held elsewhere in the job tree and database.

Back up the encrypted signing configuration and the associated `CATS_CONFIG_ENCRYPTION_KEY` through the organization's secret-backup process. Protect and store the decryption key separately from the database backup. Also retain approved destination configuration, private CA certificates, and the deployed image/Compose/environment versions. A database restored without the matching encryption key cannot recover its encrypted credentials. Document key rotation and retain historical **public** keys for old releases.

Registry retention must preserve both deployment and documentation manifest digests and their blobs. Referrers discovery and compatibility tags are not substitutes for a registry backup or a retention policy. Local retention cleanup preserves the entire remediation job directory whenever it contains a `release-documentation` directory, keeping authoritative immutable release history until explicit authorized service deletion. Preserved directories still count toward the storage quota and can prevent admission of new jobs. Other inactive job directories remain subject to normal age and quota cleanup; back them up before their configured deadlines. Back up release history before deleting a service.

Rollback the application image/code and its matching Compose files together. Preserve the database and retained release directories; never remove volumes or delete release evidence as a rollback step. If a database rollback is necessary, restore a matched database/filesystem backup after evaluating schema compatibility. Older code may not expose newer release metadata, but its absence from the old UI does not justify deleting the signed releases or registry artifacts. Run the independent digest/signature checks on a retained release after restore.

## Verification scope

The automated OCI tests exercise an isolated authenticated TLS registry implemented with the Distribution HTTP protocol: uploads, immutable retrieval, bearer authentication, referrers/compatibility behavior, corruption detection, trust boundaries and retries. They are **not** a Harbor test, a vendor registry container test, or a certification of every registry implementation. Test the actual approved registry's authentication, CA, redirect behavior, upload limits, referrers support and retention policy before relying on production delivery.

An isolated local measurement on 2026-10-09 used the existing `test_release_exports.source` and `test_release_documentation.candidate` fixtures with the real `release_documentation.prepare` implementation, Windows and Python 3.12.14. The small sample contains one vulnerability, one policy finding, one SBOM component and one port, generates five worksheets, and uses unsigned releases. Across five fresh temporary directories, generation took 39.992–46.881 ms (median 44.656 ms). Five unchanged preparations per directory had median times of 5.202–5.421 ms (median of those medians 5.223 ms); every cached receipt and attachment byte matched the initial preparation. The documentation ZIP contained 13 entries and 39,224 uncompressed bytes, occupying 31,396–31,397 bytes; all three unsigned attachments totaled 39,534–39,535 bytes. Fixture setup was outside the timed interval. This measures local generation and cache checks for a small synthetic sample, excluding signing, registry transfer and deployment validation; it is not a production throughput benchmark.
