# Connected managed-validator release build

Run from the repository root on a connected machine with a Linux-container Docker
engine and Python:

```text
python scripts/build-cats-release.py --cats-version 1.3 --tag cats:1.3
```

This is the supported normal release build. It prepares and qualifies real Ubuntu
22.04 amd64 assets, builds the scanner base, and builds the unified CATS image.
The wrapper supplies the internal BuildKit asset contexts automatically. Operators
do not stage packages, wheels, tools, images, charts, or manifests.
Use `--image portal` for the standalone portal, or `--scanner-base IMAGE` to reuse
an existing offline-capable scanner base. No deployment or VM provisioning occurs.

The release asset preparation can also be run independently for diagnosis:

```text
python scripts/prepare-managed-validator-release.py --output .release-cache/managed-validator/release --cats-version 1.3
```

## Connected preparation

`scripts/managed-validator-release/pins.json` locks official upstream binaries,
Docker packages, the Ubuntu native build image, and the Kind node image.
Downloads require independent SHA256 verification. Signed APT metadata supplies
package hashes. Wheel hashes are checked against exact PyPI release metadata.
The resolver uses an empty dpkg status to acquire the complete native runtime
closure, including Python 3.10 venv prerequisites. The deterministic local
self-test server is compiled statically and packaged as a scratch OCI image;
its chart has no dependencies or remote references.

A disposable privileged Ubuntu 22.04 harness runs with `--network none`. It
installs only local packages and wheels, checks executable versions, starts its
own isolated Docker daemon, loads the exact digest archives, and runs the
Kind/Helm self-test. It does not mount the host Docker socket or contact the
acceptance VM. Qualification failures stop publication. Successful evidence is
required before manifest qualification flags or the release seal are written.

Only Ubuntu 22.04 amd64 is published by this pipeline. The existing runtime
supports independently qualified Ubuntu 24.04 assets, but this release does not
advertise an unqualified platform.

## Sealed image and offline runtime

The image contains `/opt/cats/validator-assets/release.json`, a separate
`ubuntu-22.04-amd64/validator-assets.json`, binaries, native packages, native
wheels, node and self-test image archives, and the local chart. Both final
Dockerfiles reuse `seal-managed-validator-release.py` and the existing runtime
verifier; incomplete assets or a mismatched CATS version fail the image build.
The image trust pin is `/opt/cats/validator-assets.sha256`. Distribute the final
image through a trusted image digest.

Runtime Build Payload packages the current CATS application plus these local
assets using the existing assembler and verifier. It performs no acquisition.
Payloads retain provenance, immutable history, verification, activation, and
persistent storage under `/app/data/validator-payloads`. Provisioning uses local
`apt-get --no-download`, `pip --no-index`, and `docker load`. Self-test uses the
bundled chart and image. Docker's containerd image store is required to preserve
OCI digest identity. Fresh installations enable it; an existing runtime must
already provide it or the administrator must enable it before retrying.

## Explicit developer omission

Add `--profile development` to intentionally omit managed-validator assets.
The image carries `omitted.json` and the UI displays **Managed Validator Assets
Not Included**, disabling Build Payload. The default is the release profile;
missing production assets cannot silently fall back to a developer image.

## Acceptance after redeploy

1. Redeploy the built CATS image using the existing Compose configuration.
2. Open Settings → Validation → Validators.
3. Under Installation Payload, choose Ubuntu 22.04 amd64 and select Build Payload.
4. Wait for VERIFIED and ACTIVE; review the retained provenance and build history.
5. Manage the existing CATSchrodinger-Dev-01 validator, confirm its SSH fingerprint,
   and run Test Connection with temporary credentials.
6. Review the organized preflight results and acknowledge applicable warnings.
7. Re-enter the temporary credentials and select Provision Validator.
8. Run Self-Test after enrollment and wait for HEALTHY.

The build command does not run these provisioning actions automatically.
