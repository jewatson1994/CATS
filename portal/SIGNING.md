# Portal image signing

After rebuilding the portal and patch-worker images, open **Configuration → Image signing**. Upload a Cosign private key, its password, and optionally its public key. CATS derives the public key locally and rejects a mismatched uploaded pair. Enable **Require signing for portal patch pushes**, then save.

From the repository root, build and start the local Compose services:

```sh
docker build --build-arg CATSCAN_BASE_IMAGE=catscan-base:local --build-arg CATS_VERSION=1.2.1 -f cats-image/Dockerfile.all-in-one -t cats:1.2.1 .
docker compose up -d --wait
docker compose logs -f portal patch-worker
```

The application service is named `portal`. The canonical root `compose.yaml` runs the prebuilt image and defaults to `cats:1.2.1`; if `CATS_IMAGE` is set, it must match the tag you built. Keep the database volume unless intentionally resetting all historical data.

The private key and password use the existing `CATS_CONFIG_ENCRYPTION_KEY` encryption mechanism. Preserve this server key across redeployments and database restores. Public-key downloads contain no private material. Blank upload fields preserve the configured pair; upload the private key again to replace its password or public key. Removing keys disables future signing. Already queued jobs retain their original key selection.

When enabled, signing applies to portal patch jobs that publish an image, including image patch jobs initiated by the portal's existing remediation workflow. Pipeline scans/ingestion and download-only patch jobs do not sign. Publishing requires the `artifact.sign` permission, granted by default to Administrator and Cybersecurity. Custom roles may scope it to services. Existing scan-ingest and remediation permissions are still required where applicable.

The worker patches and rescans, pushes the image, captures that push's immutable digest, signs it, and verifies the registry signature with the selected public key. A missing digest, signing error, or failed verification fails the job. The pushed image may already exist when signing fails; CATS retains its digest and the downloadable patched archive for diagnosis. It does not automatically delete a published image.

Signatures are stored alongside the image in the destination OCI registry. The configured registry account must be able to write and read these signature artifacts. Cosign uses the job's isolated Docker credentials and trusted CA bundle. CATS does not disable registry TLS verification. Signing and verification do not contact a public transparency log or require keyless identity services; the configured registry must remain reachable.

Results expose signature status, the signed digest, key fingerprint, verification time, and Cosign version. Audit history records key configuration changes and signing requests/outcomes without key contents or passwords. Temporary key files are restricted to the worker and deleted after signing, including handled failures. Secret credentials are passed to the isolated worker in memory/environment, never its durable job configuration or results.

The supported release image (`cats-image/Dockerfile.all-in-one`) and standalone portal image bundle checksum-pinned Cosign 2.6.1. Both portal and worker must be upgraded; do not deploy a new portal against an old worker. No pipeline signing scripts are enabled by this change.

For independent verification using the downloaded public key and the digest shown in results:

```sh
cosign verify --key cosign.pub --insecure-ignore-tlog=true --offline registry.example/team/image@sha256:DIGEST
```

The transparency-log option matches the private-registry signing policy. See the [Cosign signing flags](https://github.com/sigstore/cosign/blob/v2.6.1/doc/cosign_sign.md) and [verification flags](https://github.com/sigstore/cosign/blob/v2.6.1/doc/cosign_verify.md).

Regression tests: run `python -m pytest tests --import-mode=importlib` from `portal` with `PYTHONPATH=tests`. Optionally set `CATS_TEST_COSIGN` to a trusted local Cosign executable to exercise real encrypted-key validation and wrong-password rejection. Worker registry operations are mocked in the regression suite; a real patch/push smoke test requires Docker and a destination registry.
