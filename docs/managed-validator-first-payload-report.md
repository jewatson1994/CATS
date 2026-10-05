# First real managed-validator payload: inspection and build stop

2026-10-04. Target: CATSchrodinger-Dev-01, Ubuntu Server 22.04 LTS, amd64.
Repository: Cyber Hygiene. Branch: `feature/hq-managed-validator-provisioning`.
Inspected HEAD: `ddc39b6f45745a5025c91dcf8706617b9576eacb`; substantial existing uncommitted application changes must be included in any release identity.

**No usable payload was built. Required assets are missing.** No public assets were downloaded, no target VM was contacted or modified, and no commit/push was performed. Inspection finished before this report was added. Existing implementation and verification were preserved.

## Completion report

1. **Existing contract.** Format 1 is implemented by `portal/app/validator_payload.py`. The supported builder is `scripts/build-managed-validator-payload.py STAGING NEW_OUTPUT`. It copies locally supplied assets, constructs the manifest, hashes every declared file, runs the actual HQ verifier, and prints the manifest SHA256. It does not acquire assets or prove runtime dependency closure. There is no payload build/import UI or admin build endpoint in the inspected implementation.

2. **Exact structure.** The top-level payload is a directory, not a ZIP/TGZ. Names below follow the existing documented layout; manifest asset paths can use other safe relative names. Application and chart are nested tar archives; images are archives accepted by Docker load.

   ```text
   STAGING/specification.json                 # build input; not copied into output
   OUTPUT/manifest.json
   OUTPUT/bin/kind
   OUTPUT/bin/kubectl
   OUTPUT/bin/helm
   OUTPUT/packages/<safe-name>.deb            # complete native package closure
   OUTPUT/validator.tar.gz                    # root: validator_server.py,
                                             # requirements.txt, app/, wheels/*.whl
   OUTPUT/images/node.tar
   OUTPUT/images/self-test.tar
   OUTPUT/self-test-chart.tar.gz              # root: Chart.yaml, templates/, etc.
   ```

   Symlinks, unsafe paths and unmanifested output files are rejected. Tar archives must not contain links, devices, absolute paths or traversal. Do not put release records, checksum sidecars or specification.json inside OUTPUT.

3. **Manifest schema.** `format: 1`; nonempty `payload_version`; `os: ubuntu`; `os_version: "22.04"`; `architecture: amd64`; `node_image_reference` and `self_test_image_reference` containing `@sha256:` plus 64 lowercase hex characters; `assets` and nonempty `versions` entries for all seven assets; nonempty `packages` list of `.deb` paths; `files` mapping each exact relative path to positive integer `size` and 64-hex `sha256`. The trusted digest covers exact bytes of `manifest.json`. HQ requires an externally supplied trusted digest, independent of the payload. A checksum alone does not authenticate a vendor.

4. **Required component inventory.** See the table below. No complete seven-asset release, package closure, application wheel closure, specification or release manifest was found in the repository or relevant Downloads asset search. `validator-payload/` and `validator/` are empty. Old HQ image archives are not managed-validator payloads. Docker was unavailable on this shell's PATH; WSL inventory access was denied, so this inspection does not establish whether an inaccessible daemon has other images.

5. **Versions.** Managed installation requires Docker Engine **28+**, and explicit manifest-recorded versions of Kind, kubectl, Helm and images. It does not pin exact releases of those tools. Exact approved release pins, node compatibility and trusted artifact SHA256 values have not been supplied. The separate `portal/Dockerfile.validator` pins Docker CLI 27.5.1 / Kind 0.27.0 / kubectl 1.32.2 / Helm 3.17.1; those are appliance-build settings, not a qualified managed release. Docker 27.5.1 does not satisfy the managed installer's minimum. No new version/hash was invented for this report.

6. **Application packaging.** The managed design expects native application source plus offline wheels, not an application container image: current `portal/validator_server.py`, `portal/app`, `portal/requirements.txt`, and the complete runtime wheel closure. Ubuntu 22.04 needs native Python 3.10-compatible wheels. Include application schemas/resources in app/. The requirements file pins direct runtime dependencies; transitive dependencies also need a release lock. No development test dependencies need inclusion. Record source HEAD, dirty source content hashes and final artifact hash; HEAD alone does not identify this working tree.

7. **Self-test packaging.** A digest-pinned workload image archive plus a dependency-free local Helm chart, with Chart.yaml at tar root. Workload images must match the manifest and use `imagePullPolicy: Never`. Installer loads both image archives, then requires `docker image inspect` of their exact digest references. It extracts the chart and generates a checksummed local self-test manifest. `validator_operations.py` requires an actual offline Kind/Helm lifecycle, readiness, zero external pulls/fetches and verified cleanup before READY. Merely starting the service does not pass.

8. **Ubuntu 22.04 offline provisioning.** Supported in the implementation, but **not demonstrated with a real release**. Installer detects actual OS/version/architecture; checks asset hashes; installs local packages using `apt-get --no-download`; installs wheels using `pip --no-index`; installs tools, local images, service and self-test material. The missing Jammy package/wheel closures and image qualification prevent an acceptance claim. Docker is not required to be preinstalled on the target.

9. **Ubuntu 24.04.** Also supported in code, but requires a separately qualified Noble release and native Python 3.12 wheels. A 22.04 manifest does not authorize installation on 24.04. A trusted catalog can contain separate releases; do not relabel/reuse this target's Jammy packages as Noble assets.

10. **Missing assets.** All required deployable artifacts are missing or unqualified, as listed below. Repository application/bootstrap source is present. The root `alpine.tar` contains linux/amd64 Alpine 3.20; `vulnerable-test-images.tar` contains old nginx 1.19, Alpine 3.12 and Ubuntu 20.04 fixtures. Their archive metadata was read without loading/running them. They are not supplied as qualified self-test assets, and digest retention/full lifecycle has not been tested. Neither archive provides a Kind node image.

11. **Missing binary/runtime checklist.** Supply trusted exact Docker 28+ Jammy amd64 runtime packages and all dependencies, native Python/venv/OpenSSL packages, linux-amd64 Kind, kubectl and Helm, with exact versions and approved acquisition hashes. Stage them at packages/ and bin/ as below. Component SHA256 values do not exist for absent artifacts; they must come from verified acquisition, never fabricated placeholders.

12. **Missing application checklist.** Supply a current-code application tar and complete Python 3.10 linux-amd64 wheel closure at validator.tar.gz, a release identity for the dirty source, and acquisition/build records. The recipe below uses the existing source-plus-wheels design.

13. **Missing image/test checklist.** Supply a Kind-compatible digest-pinned node archive at images/node.tar, a digest-pinned tested workload archive at images/self-test.tar, and its chart at self-test-chart.tar.gz. Ordinary docker save/load can lose repository digest metadata: successful export alone is insufficient. Both digest references must survive offline load on the chosen Docker runtime or this release must stop.

14. **Connected preparation commands/process.** The appendix gives commands for a deliberately connected Ubuntu 22.04 amd64 build workstation and separate disposable offline qualification VM. They were **not executed**. Exact upstream versions/digests/package closure remain required release inputs because the existing managed architecture does not prescribe them. A fully populated turnkey command with claimed real hashes cannot honestly be given before those inputs exist.

15. **Actual verification outcome.** No output path, payload size or manifest/component hashes were generated. The real verifier rejects the existing empty `validator-payload` directory with missing manifest.json. HQ `payload_material()` rejects this shell's configuration with `A trusted CATS_VALIDATOR_PAYLOAD_SHA256 is required`. Therefore completeness/integrity/trust/platform qualification is **not achieved**. The architecture has no top-level archive SHA256 requirement.

16. **HQ consumption/selection.** `CATS_VALIDATOR_PAYLOAD_DIR` defaults to `/opt/cats/validator/payload`. Compose mounts `${CATS_VALIDATOR_PAYLOAD_HOST_DIR:-./validator-payload}` there read-only and passes `CATS_VALIDATOR_PAYLOAD_SHA256`. For a single release, pin manifest.json; for a catalog, pin catalog.json, whose entries separately pin release manifests. HQ selects exactly the detected OS/version/architecture after preflight and repeats verification immediately before transfer. Files are sent over pinned SSH; target installer independently checks platform and hashes. `CATS_VALIDATOR_BOOTSTRAP_SCRIPTS` is an optional HQ script-directory override, not the payload location.

17. **Code changes necessary.** None for inspection or an asset-missing build stop. Existing verifier must remain strict. Real qualification may reveal a runtime/export issue, but that has not been demonstrated here and was not patched speculatively.

18. **Files changed in this task.** Only `docs/managed-validator-first-payload-report.md`. Earlier dirty/untracked project files were preserved. No new builder, format, package installer or fabricated archive was created.

19. **Tests.** `.venv\Scripts\python.exe -m pytest` against `portal/tests/test_managed_validator_bootstrap.py` and `portal/tests/test_validator_operations.py`: **41 passed**, four existing FastAPI lifecycle deprecation warnings. These cover verifier/trust/platform/catalog/archive protections and bootstrap/self-test behavior. Two direct calls to the real local/HQ verification path rejected absent payload material as described in item 15. Tests do not prove real Ubuntu dependency closure or Docker digest retention.

20. **Next UI step.** Do not provision yet: unavailable is accurate. First prepare and qualify the assets on the build machines, run the existing builder and HQ verification, and supply the resulting directory and trusted manifest digest through HQ deployment configuration. Recreate/redeploy HQ using the existing deployment process to apply mount/environment changes. Then open Settings → Validation → Validators, select CATSchrodinger-Dev-01, and check that installation payload inventory includes Ubuntu 22.04 amd64. Manually continue Test Connection, any required warning acknowledgment, and provisioning with fresh temporary credentials and independently checked SSH fingerprint. No payload upload/import control is currently implemented.

## Asset inventory

Every file in the final directory needs manifest size/SHA256 protection. Independently verify vendor origin/checksums before building; the builder's newly calculated hash does not establish acquisition trust.

| Component | Required version / platform | Staged filename/path | Source/build location | Present / missing | Why required; hash treatment |
|---|---|---|---|---|---|
| Docker/runtime and closure | Docker Engine 28+; exact approved versions; Jammy amd64/all packages | packages/<safe-name>.deb | Trusted signed Ubuntu Jammy and Docker Ubuntu repositories; clean matching staging VM | Missing | Target has no runtime. Include Docker CE/CLI/containerd and selected dependencies; archive SHA256 in manifest, package metadata/version/origin in external release record. |
| Python/venv/OpenSSL closure | Ubuntu 22.04 native Python 3.10; exact distro package versions | packages/<safe-name>.deb | Matching signed Ubuntu repositories | Missing | Offline venv, TLS/enrollment and installer prerequisites; same package/hash records. |
| Kind | Exact approved linux-amd64 release, compatible with selected node | bin/kind | Official Kind release artifact or trusted internal mirror | Missing | Ephemeral cluster; upstream checksum then final file SHA256. |
| kubectl | Exact approved linux-amd64 version compatible with node Kubernetes | bin/kubectl | Official Kubernetes release distribution or trusted mirror | Missing | Resource/readiness checks; acquisition and final file SHA256. |
| Helm | Exact approved linux-amd64 release | bin/helm | Official Helm release distribution or trusted mirror | Missing | Real Helm lifecycle; verify downloaded tar and extracted executable. |
| Validator | Current source identity + exact native runtime wheel closure | validator.tar.gz | This working tree's portal source plus verified wheels | Source present; deployable tar/wheels missing | Native service/schema code; outer tar SHA256 protects nested content. Record dirty source and wheel hashes outside output. |
| Kind node | Exact compatible node release and registry digest; linux/amd64 | images/node.tar | Approved official node release/registry or trusted mirror | Missing | Offline cluster boot; digest reference plus archive SHA256; load/inspect qualification mandatory. |
| Self-test workload | Exact approved release and digest; linux/amd64 | images/self-test.tar | Trusted selected workload build/registry | Missing qualified asset; unrelated fixture archives present | Offline readiness exercise; digest reference + archive SHA256 + load qualification. |
| Self-test Helm chart | Explicit chart release matching workload/ports/readiness | self-test-chart.tar.gz | Administrator/build-maintained local chart | Missing | Chart.yaml at tar root, no remote dependencies, pinned image/Never; tar SHA256 and full lifecycle test. |
| Bootstrap installer | Current HQ source revision/content | Not a payload asset; portal/app/validator_bootstrap_assets/install.sh | Current HQ deployment | Present | HQ transfers scripts separately; payload file manifest does not cover these scripts. Keep HQ deployment trusted. |
| systemd unit | Generated by current installer | Not a payload file; installed /etc/systemd/system/cats-validator.service | install.sh | Generator present | Native service/account, Docker dependency and state permissions. |
| Schemas/configuration | Matching current application | app/ inside validator.tar.gz; runtime configuration generated during enrollment | portal/app; certificates.sh; validator_enrollment.py | Source present; packaged material missing | Protocol/schema/runtime config. Private keys, issued certificates, SSH passwords, HQ keys and enrollment secrets must not enter reusable payload. |

## Connected build preparation (instructions only)

Run on a **separate connected Ubuntu 22.04 amd64 build VM**, not CATSchrodinger-Dev-01. Use a clean baseline matching the target to resolve packages. Use another disposable VM with networking disabled for runtime qualification. Keep records outside STAGE/OUTPUT. These are commands using an administrator-reviewed release lock; no automatic unpinned fallback is permitted.

### A. Establish release inputs and matching platform

Create `release.env` outside the payload with real approved values for: `REPO`, `STAGE`, `OUTPUT`, `RECORD`, `PAYLOAD_VERSION`, `KIND_VERSION` (with v), `KIND_SHA256`, `KUBECTL_VERSION` (with v), `KUBECTL_SHA256`, `HELM_VERSION` (with v), `HELM_TAR_SHA256`, `NODE_IMAGE_REF`, `NODE_IMAGE_VERSION`, `SELF_TEST_IMAGE_REF`, `SELF_TEST_IMAGE_VERSION`, `SELF_TEST_CHART_VERSION`. Also supply reviewed full-dependency `requirements.lock` with hashes and a chart directory `SELF_TEST_CHART_DIR`. Do not invent digest values. Set OUTPUT to a new directory.

```bash
set -euo pipefail
source ./release.env                 # trusted administrator-authored file
source /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 22.04
test "$(dpkg --print-architecture)" = amd64
test "$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')" = 3.10
: "${REPO:?}" "${STAGE:?}" "${OUTPUT:?}" "${RECORD:?}" "${PAYLOAD_VERSION:?}"
: "${KIND_VERSION:?}" "${KIND_SHA256:?}" "${KUBECTL_VERSION:?}" "${KUBECTL_SHA256:?}"
: "${HELM_VERSION:?}" "${HELM_TAR_SHA256:?}" "${NODE_IMAGE_REF:?}" "${NODE_IMAGE_VERSION:?}"
: "${SELF_TEST_IMAGE_REF:?}" "${SELF_TEST_IMAGE_VERSION:?}" "${SELF_TEST_CHART_VERSION:?}" "${SELF_TEST_CHART_DIR:?}"
test ! -e "$STAGE" && test ! -e "$OUTPUT"
mkdir -p "$STAGE/bin" "$STAGE/packages" "$STAGE/images" "$RECORD/downloads"
git -C "$REPO" rev-parse HEAD > "$RECORD/source-head.txt"
git -C "$REPO" status --short > "$RECORD/source-status.txt"
```

Copy the current working-tree code to that workstation, including required untracked application files; a checkout of HEAD alone omits current work. Keep all credentials/databases/environment files out of the source artifact.

### B. Resolve and retain the complete Jammy package closure

On the clean connected baseline, configure the reviewed signed Jammy and Docker repository definitions/keys using the organization's trusted process. Inspect available versions and deliberately select Docker Engine 28+ plus its compatible CLI/containerd versions. Do not run a public installer script.

```bash
apt-cache policy docker-ce docker-ce-cli containerd.io python3 python3-venv openssl
apt-cache madison docker-ce docker-ce-cli containerd.io
# Write runtime-roots.lock outside STAGE: one exact package=version per line,
# for selected docker-ce, docker-ce-cli, containerd.io, python3,
# python3-venv, openssl and any explicitly selected runtime plugins.
mapfile -t roots < "$RECORD/runtime-roots.lock"
test "${#roots[@]}" -gt 0
sudo apt-get update                  # connected preparation ONLY
sudo apt-get --download-only -y install "${roots[@]}"
python3 - "$STAGE/packages" "$RECORD/packages.json" <<'PY'
import glob, hashlib, json, pathlib, shutil, subprocess, sys
dest = pathlib.Path(sys.argv[1]); rows = []
for name in sorted(glob.glob('/var/cache/apt/archives/*.deb')):
    p = pathlib.Path(name); digest = hashlib.sha256(p.read_bytes()).hexdigest()
    # Ubuntu version filenames often contain '+' or ':'; manifest paths forbid them.
    target = dest / (digest + '.deb'); shutil.copyfile(p, target)
    meta = subprocess.check_output(['dpkg-deb', '-f', str(p), 'Package', 'Version', 'Architecture'], text=True)
    rows.append({'source_filename': p.name, 'payload_path': 'packages/'+target.name,
                 'sha256': digest, 'metadata': meta})
if not rows: raise SystemExit('No package closure acquired')
pathlib.Path(sys.argv[2]).write_text(json.dumps(rows, indent=2)+'\n')
PY
```

Use a clean package cache/baseline so unrelated cache entries are not selected. Retain signed repository provenance with package records. Apt on an already provisioned workstation can omit installed dependencies; its cache is insufficient evidence. On the separate matching offline qualification VM, copy the packages and require `sudo apt-get --no-download -y install /qualification/packages/*.deb` to succeed, then `docker version` must show Engine 28+. A closure that fails this check must be re-resolved; do not install missing dependencies on the real validator manually to hide the failure.

### C. Acquire only the explicitly locked vendor binaries

The following deliberate downloads happen only on the connected build VM. Expected hashes come from the reviewed release record/vendor verification process, not invented values. Retain originals and acquisition provenance outside payload.

```bash
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" \
  -o "$RECORD/downloads/kind"
printf '%s  %s\n' "$KIND_SHA256" "$RECORD/downloads/kind" | sha256sum -c -
install -m 0755 "$RECORD/downloads/kind" "$STAGE/bin/kind"
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
  -o "$RECORD/downloads/kubectl"
printf '%s  %s\n' "$KUBECTL_SHA256" "$RECORD/downloads/kubectl" | sha256sum -c -
install -m 0755 "$RECORD/downloads/kubectl" "$STAGE/bin/kubectl"
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \
  -o "$RECORD/downloads/helm.tar.gz"
printf '%s  %s\n' "$HELM_TAR_SHA256" "$RECORD/downloads/helm.tar.gz" | sha256sum -c -
tar -xOf "$RECORD/downloads/helm.tar.gz" linux-amd64/helm > "$STAGE/bin/helm"
chmod 0755 "$STAGE/bin/helm"
"$STAGE/bin/kind" version > "$RECORD/kind-version.txt"
"$STAGE/bin/kubectl" version --client -o json > "$RECORD/kubectl-version.json"
"$STAGE/bin/helm" version --short > "$RECORD/helm-version.txt"
sha256sum "$STAGE"/bin/* > "$RECORD/binary-sha256.txt"
```

Compare measured versions to the approved lock and qualify the Kind/node/kubectl combination; no specific compatible combination has been established by this inspection.

### D. Build the native current-code application

Provide `RECORD/requirements.lock` containing the reviewed complete transitive runtime dependency lock, including hashes, compatible with every pinned requirement in current portal/requirements.txt. Resolve it on native Python 3.10; do not use Windows wheels or a Noble wheelhouse. The acquisition commands fail when binary wheels are unavailable rather than silently downloading source/build dependencies.

```bash
mkdir -p "$RECORD/application/app" "$RECORD/application/wheels"
rsync -r --exclude='__pycache__' --exclude='*.pyc' --exclude='.env*' \
  --exclude='*.db' --exclude='*.sqlite*' "$REPO/portal/app/" "$RECORD/application/app/"
cp "$REPO/portal/validator_server.py" "$REPO/portal/requirements.txt" "$RECORD/application/"
python3 -m pip download --require-hashes --only-binary=:all: \
  -r "$RECORD/requirements.lock" -d "$RECORD/application/wheels"
python3 -m venv "$RECORD/wheel-check"
"$RECORD/wheel-check/bin/pip" install --no-index --require-hashes \
  --find-links "$RECORD/application/wheels" -r "$RECORD/requirements.lock"
"$RECORD/wheel-check/bin/pip" install --no-index \
  --find-links "$RECORD/application/wheels" -r "$RECORD/application/requirements.txt"
"$RECORD/wheel-check/bin/pip" check
"$RECORD/wheel-check/bin/pip" freeze > "$RECORD/installed-runtime.txt"
(cd "$RECORD/application"; find app wheels -type f -print0 | sort -z | xargs -0 sha256sum;
 sha256sum validator_server.py requirements.txt) > "$RECORD/application-content-sha256.txt"
tar -czf "$STAGE/validator.tar.gz" -C "$RECORD/application" \
  validator_server.py requirements.txt app wheels
```

Review copied resources for secrets and validate archive safety with the existing builder. Repeat installation in a fresh offline Python 3.10 venv on the qualification VM. Record source content hashes as part of release identity, not only HEAD.

### E. Acquire/export and qualify pinned local images and chart

```bash
[[ "$NODE_IMAGE_REF" =~ @sha256:[0-9a-f]{64}$ ]]
[[ "$SELF_TEST_IMAGE_REF" =~ @sha256:[0-9a-f]{64}$ ]]
docker pull --platform linux/amd64 "$NODE_IMAGE_REF"       # connected preparation ONLY
docker pull --platform linux/amd64 "$SELF_TEST_IMAGE_REF"  # connected preparation ONLY
docker image inspect "$NODE_IMAGE_REF" > "$RECORD/node-inspect.json"
docker image inspect "$SELF_TEST_IMAGE_REF" > "$RECORD/self-test-inspect.json"
# Candidate exports only; save does NOT establish required RepoDigest retention.
docker image save -o "$STAGE/images/node.tar" "$NODE_IMAGE_REF"
docker image save -o "$STAGE/images/self-test.tar" "$SELF_TEST_IMAGE_REF"
"$STAGE/bin/helm" lint "$SELF_TEST_CHART_DIR"
tar -czf "$STAGE/self-test-chart.tar.gz" -C "$SELF_TEST_CHART_DIR" .
```

The supplied chart must have Chart.yaml at its root, the declared chart version, no external dependencies, correct workload ports/readiness, the exact self-test image digest, and Never pull policy. It must satisfy the validator's strict workload policy; arbitrary images/charts do not constitute a qualified self-test.

On the **separate offline qualification VM**, with the exact runtime and an initially empty image store:

```bash
docker load -i /qualification/images/node.tar
docker load -i /qualification/images/self-test.tar
docker image inspect "$NODE_IMAGE_REF"
docker image inspect "$SELF_TEST_IMAGE_REF"
```

If either inspect fails, **STOP**. Do not substitute a tag, weaken the installer, or report the payload verified. Select an export supported by this Docker load path that demonstrably retains the required digest identity. This report does not establish such an export. After identity qualification, run the current validator's real self-test on the disposable offline machine with the same local chart/images, strict sandbox settings and no-egress configuration; require VERIFIED, complete cleanup, zero pulls/fetches and a real deployed Helm lifecycle. That runtime test is separate from the builder's structural/hash verification.

### F. Assemble using the existing builder and verify through HQ

Only after A–E succeed, record measured binary versions and build identity in the specification. Commands below use the declared approved versions; verify they agree with measured output first.

```bash
export STAGE OUTPUT RECORD PAYLOAD_VERSION KIND_VERSION KUBECTL_VERSION HELM_VERSION
export NODE_IMAGE_REF NODE_IMAGE_VERSION SELF_TEST_IMAGE_REF SELF_TEST_IMAGE_VERSION SELF_TEST_CHART_VERSION
export VALIDATOR_VERSION="$(cat "$RECORD/source-head.txt")-content-$(sha256sum "$RECORD/application-content-sha256.txt" | cut -d' ' -f1)"
python3 - <<'PY'
import json, os, pathlib
e=os.environ; stage=pathlib.Path(e['STAGE'])
assets={'kind':'bin/kind','kubectl':'bin/kubectl','helm':'bin/helm',
        'validator':'validator.tar.gz','node_image':'images/node.tar',
        'self_test_image':'images/self-test.tar','self_test_chart':'self-test-chart.tar.gz'}
versions={k:e[v] for k,v in {'kind':'KIND_VERSION','kubectl':'KUBECTL_VERSION',
 'helm':'HELM_VERSION','validator':'VALIDATOR_VERSION','node_image':'NODE_IMAGE_VERSION',
 'self_test_image':'SELF_TEST_IMAGE_VERSION','self_test_chart':'SELF_TEST_CHART_VERSION'}.items()}
spec={'format':1,'payload_version':e['PAYLOAD_VERSION'],'os':'ubuntu','os_version':'22.04',
 'architecture':'amd64','node_image_reference':e['NODE_IMAGE_REF'],
 'self_test_image_reference':e['SELF_TEST_IMAGE_REF'],'assets':assets,'versions':versions,
 'packages':sorted(p.relative_to(stage).as_posix() for p in (stage/'packages').glob('*.deb'))}
(stage/'specification.json').write_text(json.dumps(spec,indent=2)+'\n')
PY
python3 "$REPO/scripts/build-managed-validator-payload.py" "$STAGE" "$OUTPUT" \
  | tee "$RECORD/manifest-sha256.txt"
export CATS_VALIDATOR_PAYLOAD_DIR="$OUTPUT"
export CATS_VALIDATOR_PAYLOAD_SHA256="$(cat "$RECORD/manifest-sha256.txt")"
PYTHONPATH="$REPO/portal" python3 - <<'PY'
from app.validator_management import payload_material
root, manifest, digest = payload_material({'os':'ubuntu','os_version':'22.04','architecture':'amd64'})
print('HQ VERIFICATION PASSED', root, manifest['payload_version'], digest)
PY
```

Run HQ verification using an environment with the current portal dependencies. Record actual results; do not confuse a successful builder with completed runtime acceptance. Preserve the trusted manifest SHA256 separately. Publish the unchanged output directory to the HQ host, configure `CATS_VALIDATOR_PAYLOAD_HOST_DIR` to that directory and `CATS_VALIDATOR_PAYLOAD_SHA256` to the actual recorded digest, then redeploy HQ through its existing process. No real values for those two deployment settings were generated during this task.
