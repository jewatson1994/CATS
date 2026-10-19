# Machine retrieval of Cyber evidence

Use the same scoped machine credentials as OCI pulls to download the existing signed offline bundle:

`GET /api/oci/evidence/{public_repository}/manifests/{sha256_digest}/offline`

The repository is the configured public mapping and the manifest digest is immutable. Tags are not accepted. The endpoint authorizes the exact digest against current service policy and uses that decision's Cyber approval. Only a published bundle with a verified publication/signature receipt is available. A release that has not completed publication returns unavailable; no new signature or replacement bundle is generated.

The response is the unchanged `offline-bundle.zip`, with `X-CATS-Approval-ID` and `X-CATS-Evidence-Digest` headers. Verify the downloaded checksum and the bundle's existing signatures using its verification instructions and a separately trusted signer fingerprint. Public key history is available from `/api/oci/approval-keys`. Upstream referrers are not substituted for Cyber evidence. A bundle may contain the complete approved service evidence, not only one image; grant repository credentials only to consumers allowed to receive that evidence.

The standalone proxy needs read-only access to the existing approved-release storage at the same absolute path used by the publisher. Set `CATS_APPROVED_RELEASE_ROOT` consistently, or mount the existing remediation job storage read-only so its `approved-releases` subdirectory resolves identically. The proxy verifies path confinement and the stored bundle checksum before returning bytes and rechecks machine authorization and the selected approval immediately before delivery. It never requires a signing private key to deliver the retained bundle.

Revoked credentials, disabled mappings, stale policy evidence, expired/revoked approvals, missing files, altered bundles, and changed approvals deny retrieval. Already downloaded evidence remains usable for offline authenticity verification, but offline verification cannot establish current authorization or revocation status. Use an online authorization check before a subsequent deployment or pull.
