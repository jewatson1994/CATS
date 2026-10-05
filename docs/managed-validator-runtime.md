# Docker-host validator runtime

The unified CATS image uses `CATS_ROLE=hq` by default. HQ refuses a mounted
`/var/run/docker.sock`. `CATS_ROLE=validator` launches only the existing mTLS
validator server on 8443; it does not import HQ startup/background workers.
The dedicated validator VM grants the container root-equivalent host control
through its Docker socket. Do not co-locate other workloads on that VM.

The scanner base supplies checksum-pinned Kind 0.33.0, kubectl 1.37.0 and Helm
4.2.3, Docker CLI, bash, tar, coreutils and CA certificates. The unified layer
adds the application Python environment and Docker CLI. Its build now asserts
these tools and copies `validator_server.py`, previously absent. Validator
runtime uses host networking so the core's loopback Kind API endpoint remains
reachable; Kind workloads still run on owned internal isolated bridges with
restricted admission and verified CPU/memory/PID limits. Docker 28 or newer
is required by the existing strict network isolation checks.

Prepare an already-built local CATS image using:

```
python scripts/prepare-docker-validator-release.py --cats-image cats:VERSION --output RELEASE_DIRECTORY
```

The exact pinned Kind node image from `ValidationConfig.kind_node_image` must
already exist locally. Preparation saves local images; it never pulls, downloads,
installs host packages, or invokes Ubuntu repositories. Configure HQ's
`CATS_MANAGED_VALIDATOR_RELEASE_DIR` to the prepared directory. Assets contain
CATS Docker-save archive, pinned node archive, checksummed manifest and a small
Helm self-test archive. Hashes detect corruption; preparation/distribution remains
an administrator-controlled trust boundary, not a public self-signed release.

The self-test uses the same exact CATS image as a restricted nonroot Python
sleep workload with `imagePullPolicy: Never`. HQ uploads its chart through the
normal authenticated v2 validation API. Success requires the actual Kind core,
Helm install with deployed release, workload readiness and complete cleanup.
Health alone cannot pass it. No Internet workload image is needed.

Unit tests verify startup gates and evidence requirements. Actual Docker build,
Kind/Helm execution and VM acceptance must be recorded separately; unit tests do
not establish runtime acceptance.

## HQ release configuration

Bind the prepared directory read-only into HQ at an absolute container path,
and set the release environment variable to that same path. For example, add
the following to the existing HQ Compose service (retain its existing volumes):

```yaml
environment:
  CATS_ROLE: hq
  CATS_MANAGED_VALIDATOR_RELEASE_DIR: /opt/cats/managed-validator-release
volumes:
  - /srv/cats/managed-validator-release:/opt/cats/managed-validator-release:ro
```

Do not mount the Docker socket in HQ. Run a single HQ application process for
V1 provisioning: the bootstrap lifecycle and temporary credential handoff are
process-local. Multiple independent HQ processes are not a supported V1 topology.

The administrator must supply a dedicated Docker-ready Ubuntu Server 22.04 LTS
or 24.04 LTS amd64 VM, functioning systemd/cgroup v2 and Docker Engine 28 or newer,
SSH access with the required administrative privileges, and the HQ-to-validator
mTLS API route. No host package installation is performed. Allow only trusted HQ
traffic to the configured API port; bootstrap preserves host firewall policy.
Provide at least 2 CPUs, 4 GiB memory and 20 GiB free disk; 4 CPUs, 8 GiB memory and
40 GiB free disk are recommended, with additional disk space for the saved CATS
image, temporary image archives and each concurrent Kind workload.

The validator runs with host networking, a read-only root filesystem, a small
writable `/tmp`, and a writable managed state directory mounted at the same
absolute host/container path. `TMPDIR`, `HOME` and Helm's writable cache/config/data
locations must point into managed state. In particular, Kind serializes local
workload images into temporary archives: the full CATS image will not fit in the
small `/tmp` mount. The managed state filesystem must have room for those archives.

Docker-save archives can discard source repository digests on Docker load. The
manifest retains the pinned node source digest; bootstrap verifies the loaded
image's exact configuration ID and uses its versioned local tag for Kind. This
permits disconnected execution without weakening the exact local image check.

The self-test uses one ready Pod and intentionally exercises the existing strict
Kind isolation, image preload, actual Helm installation, workload observations,
and cleanup. These are runtime acceptance requirements; preparation and unit tests
do not prove them. No actual Docker/VM acceptance has been performed in this
workspace because Docker is unavailable.
