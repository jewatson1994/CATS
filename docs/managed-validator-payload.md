# Building the managed validator offline payload

V1 supports Ubuntu Server 22.04 LTS and 24.04 LTS, amd64 and arm64. Build a separate payload on a connected staging VM matching each target Ubuntu version and architecture. The first real acceptance target is Ubuntu Server 22.04 LTS. Never reuse Noble (24.04) packages or wheels for Jammy (22.04). Provisioning never runs repository updates, downloads packages, pip indexes, registry pulls or installer curl commands. A payload is administrator supplied trusted executable code; SHA256 integrity is not publisher authentication. Protect the staging machine and distribute the final manifest digest through the HQ deployment configuration, independently of the payload directory.

The builder `scripts/build-managed-validator-payload.py` accepts a staging directory and a new destination. It validates local archive structure, copies only declared files, hashes them, validates the result, and prints the manifest digest. It does not acquire assets or prove dependency closure by itself. Do not fabricate placeholder assets to deploy.

1. Start an Ubuntu 22.04 or 24.04 staging VM matching the target architecture and baseline image. Use Ubuntu's signed repositories and a configured trusted Docker package repository if applicable. Acquire the complete `.deb` dependency closure for Docker Engine 28+ from the trusted Docker Ubuntu repository, its CLI/containerd, Python 3, python3-venv and openssl. The practical reproducible method is a disposable clean baseline VM: run apt update, then apt-get with `--download-only install` for the selected runtime packages, copying `/var/cache/apt/archives/*.deb` into staging `packages/`. An already configured build host can omit dependencies it has installed; its cache is not proof of a clean-VM closure. Record repository origins and exact package versions in a build record. Test installation on another clean matching VM with networking disabled. `apt-get --no-download install /path/to/packages/*.deb` must succeed without unmet dependencies. Test the oldest documented baseline too.
2. Acquire architecture-specific Kind, kubectl and Helm binaries from their official release distributions. Check upstream signatures/checksums before staging `bin/kind`, `bin/kubectl`, `bin/helm`. Record exact versions. Test those binaries on the staging platform.
3. Copy the repository's `portal/app`, `portal/validator_server.py` and `portal/requirements.txt` into an application staging directory. Create its `wheels/` with `python3 -m pip download --only-binary=:all: -r requirements.txt -d wheels` on the matching architecture and native Python platform (3.10 for 22.04, 3.12 for 24.04). Include every transitive wheel. Verify a new venv using that same native Python installs successfully using `pip install --no-index --find-links wheels -r requirements.txt`. Archive application contents at the archive root as `validator.tar.gz`; exclude credentials, local databases, caches and .env files.
4. Select and verify a Kind-compatible node image and a small self-test workload image with SHA256 registry digest references. Export images into archives supported by the installed Docker runtime. Test loading archives with registry access disabled and require `docker image inspect IMAGE@sha256:DIGEST` to succeed. Ordinary `docker save/load` may discard repository digest metadata; a tag-only archive fails this check and cannot qualify as a pinned offline payload. Use an export/import path proven to preserve the required identity on the selected runtime. This is a required release qualification step, not something the builder assumes succeeds.
5. Create a minimal Helm chart whose workload image is exactly the pinned self-test image, with `imagePullPolicy: Never`. It must reach readiness in Kind without internet access. Archive chart contents with `Chart.yaml` at the root, plus `templates/`, as `self-test-chart.tar.gz`. Run `helm lint` and a full offline Kind install/readiness/uninstall/delete test. No remote chart dependencies are permitted.
6. Write `specification.json` beside these staged files. For example (replace every version/digest with measured release values):

```json
{
  "format": 1,
  "payload_version": "2026.10.04-1",
  "os": "ubuntu",
  "os_version": "22.04",
  "architecture": "amd64",
  "node_image_reference": "kindest/node@sha256:<64 lowercase hexadecimal characters>",
  "self_test_image_reference": "your-trusted-registry/self-test@sha256:<64 lowercase hexadecimal characters>",
  "assets": {
    "kind": "bin/kind",
    "kubectl": "bin/kubectl",
    "helm": "bin/helm",
    "validator": "validator.tar.gz",
    "node_image": "images/node.tar",
    "self_test_image": "images/self-test.tar",
    "self_test_chart": "self-test-chart.tar.gz"
  },
  "versions": {
    "kind": "<release>", "kubectl": "<release>", "helm": "<release>",
    "validator": "<source revision>", "node_image": "<release/digest>",
    "self_test_image": "<release/digest>", "self_test_chart": "<chart version>"
  },
  "packages": ["packages/<every-required-package-version-architecture>.deb"]
}
```

7. Run `python scripts/build-managed-validator-payload.py STAGING NEW_PAYLOAD`. Retain the printed SHA256 in the deployment record. Configure HQ `CATS_VALIDATOR_PAYLOAD_DIR` to the read-only payload mount and `CATS_VALIDATOR_PAYLOAD_SHA256` to that digest. The HQ application packages its checked-in bootstrap scripts under `app/validator_bootstrap_assets`; no additional scripts mount is required. `CATS_VALIDATOR_BOOTSTRAP_SCRIPTS` is available only as an explicit deployment override. Mount assets read-only and supply a durable configuration encryption key using the existing HQ secret mechanism.
8. Provision a fresh disconnected Ubuntu target. Supply SSH fingerprint obtained independently from the VM console. Test Connection reads host facts and checks supplied sudo authentication; it does not create workspaces/install software. Ensure HQ can reach TCP 22 for bootstrap and the configured mTLS API port (default 8443). The installer does not replace host firewall rules; administrators must supply permitted network paths. Verify successful enrollment, runtime checks, actual Kind/Helm workload readiness, cleanup and READY. Keep provisioning evidence and manifest digest. A service that only starts is not acceptance.

Installation uses `/opt/cats-validator/app` and its offline venv; the application is readable but immutable to the service account. State and private scratch storage belong to `cats-validator` under `/var/lib/cats-validator`. Local self-test assets are installed under `/opt/cats-validator/self-test`. Docker group membership intentionally gives the dedicated worker runtime control: deploy validators on isolated VMs, separate from production workloads. Existing Docker Engine 28+ installations are reused without reinstalling runtime packages; older installed Docker versions block with an explicit upgrade requirement. Existing matching Docker installations can be reused, but supplied packages must remain compatible. Dependency/package/script failures block enrollment.

This repository does not include third-party executable payloads. Release qualification on real connected staging and disconnected clean target VMs is necessary; unit tests cannot establish Ubuntu package closure, image archive identity retention, firewall reachability or systemd/Kind behavior.

## Multiple trusted platform releases

For a single release, the existing directory plus manifest SHA256 remains supported; HQ rejects any host with a different OS/version/architecture. To support both versions in one HQ deployment, mount a catalog directory containing separately built release directories and `catalog.json`:

```json
{
  "format": 1,
  "payloads": [
    {"os": "ubuntu", "os_version": "22.04", "architecture": "amd64", "path": "ubuntu-22.04-amd64", "sha256": "<manifest SHA256 from builder>"},
    {"os": "ubuntu", "os_version": "24.04", "architecture": "amd64", "path": "ubuntu-24.04-amd64", "sha256": "<manifest SHA256 from builder>"}
  ]
}
```

Set `CATS_VALIDATOR_PAYLOAD_SHA256` to the independently retained SHA256 of **catalog.json** instead of a release manifest. Add arm64 entries only with independently qualified arm64 releases. All entries must validate before inventory marks the catalog available. HQ selects exactly the detected OS/version/architecture after Test Connection and repeats selection against live SSH preflight immediately before transfer. A missing matching release, changed authorized digest or mismatched remote OS fails closed before installation. The installer independently verifies `/etc/os-release` and dpkg architecture.

Do not hard-code package versions across releases: resolve and retain a complete `.deb` closure using the matching Ubuntu release and repository suite, and acquire wheels using that release's native Python ABI. The installer uses only the selected manifest's files. Its safe archive extraction works without requiring a particular tarfile security backport ([Python tarfile version details](https://docs.python.org/3.10/library/tarfile.html)). Qualification must include the oldest supported 22.04 baseline and current patched 22.04, followed by 24.04.
