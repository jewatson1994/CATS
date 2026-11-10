# Isolated worker actions

Discovery rendering, Scan rendering/scanning, Patch candidate rendering/scanning
and Remediation delivery/bundle rendering use the same offline action runner. Acquire images, charts and registry credentials
in the broker first; an action sees only its explicit input files and private
scratch space. The action has a separate network, PID, mount and user namespace,
no capabilities, no worker environment, no Docker socket and a child seccomp filter
that denies further namespace or mount changes. Unsupported isolation fails closed.

The final action filesystem has no `/proc` mount. The private PID namespace
remains enabled, and Docker's default masked and read-only system paths remain
intact. Creating a fresh procfs inside a nested user namespace can fail with
`Can't mount proc on /proc: Operation not permitted` when Docker has locked
submounts under its existing `/proc`. The runner avoids that unnecessary mount;
it does not bind the broker's `/proc` into the action or disable system-path
protections. This correction is part of the unified image, so older images need
the updated runner as well as the AppArmor profile corrections below.

The unified image carries Bubblewrap, static Helm 4.2.3, kubectl 1.37.0 and Compose
2.39.4 plus static Syft 1.31.0, Grype 0.98.0, Trivy 0.69.3 and Dockle 0.4.15.
Syft and Grype use checksum-pinned upstream archives because the Alpine package
binaries require a dynamic loader. The build verifies the actual executable
format and versions and records `/opt/discovery/tool-versions.json`. Rebuild the
scanner base when the unified build rejects an old tool version. No action installs
packages or retrieves dependencies at runtime. Skopeo remains a broker acquisition
tool; its Alpine package version is recorded alongside the scanners.

## Docker configuration

Each action, including a health probe, runs under its own Linux child-process
supervisor. It adopts and reaps orphaned descendants, stops remaining children
when the tool exits, and cleans up on cancellation, timeout or broker death.
It does not share child ownership with other concurrent actions. Both shipped
Compose topologies also enable `init: true` for the four action workers so
container-level orphans are reaped if an action supervisor is forcibly killed.
The image includes the per-action fix; recreate workers with the updated Compose
files to enable the additional container init. No extra capabilities are required.

Both shipped Compose topologies apply `deploy/discovery-seccomp.json` to all four
action workers. The filename is retained for compatibility. This default-deny policy
permits namespace/mount setup before the stricter child filter is applied. The
container kernel still requires the appropriate namespace-local capabilities;
no `SYS_ADMIN` host capability is added. Discovery remains UID 10003 with all
capabilities dropped. The Scan broker retains only SETUID, SETGID, CHOWN and KILL;
the runner drops identity before executing an action. Patch retains its existing
broker Docker access for acquisition and publication, but the socket and broker
identity are never included in the action. Remediation keeps its existing trusted
broker configuration and uses the same action protection for delivery and final
bundle rendering. The background-service anchor deliberately excludes the action
setup policy and renderer healthcheck. These protections do not make either
broker itself safe to run untrusted code.

Scan and Patch mount the same refreshed Grype and Trivy database volumes read-only.
The broker pins the selected database generation into each action. A required
database that has not been populated produces an incomplete result; the action
does not download it. Database refresh is performed by the security-data worker,
independently of the SQL-only intelligence schema initializer.
The offline release's explicit Grype database age-validation policy is preserved
and recorded in the result binding; database hash-integrity checks always apply.

All worker healthchecks execute `python -m app.rendering --probe` in the effective
container settings. This runs an isolated Helm version command; it validates the
namespace, mount, seccomp and executable path. Scan also checks its existing
readiness state and Patch also checks its HTTP service. A healthy probe does not
prove that a particular chart is complete or that a registry is reachable.

## Ubuntu hosts with AppArmor

Docker's `docker-default` AppArmor policy denies mount operations, including
Bubblewrap's first mount-propagation operation. Adding a seccomp exception alone
cannot resolve `bwrap: Failed to make / slave: Permission denied`.

Use the supplied named profile on Ubuntu 24.04 with AppArmor 4 or later. Perform
these steps on the Linux Docker host, from the matching release checkout:

```sh
sudo install -m 0644 deploy/cats-worker-actions.apparmor /etc/apparmor.d/cats-worker-actions
sudo apparmor_parser --replace /etc/apparmor.d/cats-worker-actions
sudo aa-status
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml config --quiet
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml up -d --no-build --pull never --force-recreate discovery-worker scan-worker patch-worker remediation-worker
```

For the TLS deployment use `--env-file /secure/cats.env -f templates/compose.main.yaml`
in place of `--project-directory . --env-file .env -f templates/compose.local.yaml`. Keep the template in `templates/`: its bundled
paths resolve relative to that directory. The [guided installer](../docs/guided-setup.md)
detects AppArmor, loads this profile and saves a launcher with the correct files.
Keep the AppArmor overlay on every deployment/recreate, including
release upgrades; a restart does not change a container's security options. The
profile file in `/etc/apparmor.d` is reloaded by the host AppArmor service at boot.
Verify that `cats-worker-actions (enforce)` is present after host upgrades/reboots.
Deploy the updated unified image, profile and Compose overlay together as one
release. Loading the profile without recreating the workers leaves the existing
containers under their original security settings.

The profile permits unprivileged user namespaces and the temporary mount paths
Bubblewrap uses. It keeps an enforcing profile, denies writes to `/proc/sys` and
`/sys`, and adds no container capabilities. Its filesystem/network access for the
broker is intentionally broader than the isolated action; isolation still relies
on the runner's explicit mounts, dropped identity and child filter. Qualify the
profile again if the Bubblewrap version or host security stack changes.

The raw-socket deny is scoped to IPv4 and IPv6. Bubblewrap creates a raw
`NETLINK_ROUTE` socket to bring up loopback in its private network namespace;
a blanket `deny network raw,` also denies that socket. Explicit AppArmor denies
are quiet by default, so an empty kernel audit log does not rule out this
failure. Replace the old blanket deny with `deny network inet raw,` and
`deny network inet6 raw,`, then reload the profile with `apparmor_parser --replace`.
The existing broad broker network allow also permits raw sockets in other
non-IP families unless denied separately; packet, vsock and alg remain denied.
The isolated action still has a separate network namespace and no capabilities.
Profile replacement applies to attached containers immediately; rerun the actual
worker health probe before resuming startup. Update the release profile too,
with its bundle manifest checksum, before rerunning setup so it cannot reinstall
the old rule. No image rebuild is needed for this profile-only correction.

Bubblewrap also temporarily binds `/oldroot/proc/` to `/proc/` after its first
pivot, so fd-based mount setup can use `/proc/self/fd`. This is a recursive bind,
not a new proc filesystem mount; the `/newroot/` mount rules do not cover it.
A denial with `name="/proc/"`, `srcname="/oldroot/proc/"` and `flags="rw, rbind"`
requires `mount options=(rw,rbind,silent) /oldroot/proc/ -> /proc/,`.
The subsequent cleanup requires `mount options=(rw,rprivate,silent) -> /oldroot/,`
before detaching that root. Both rules stay scoped to Bubblewrap's setup paths;
the existing `/proc/sys` and `/sys` write denials remain in effect. Reload the
profile and rerun the worker health probe after applying these corrections.

Before accepting work, run each preflight with the same Compose files:

```sh
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml run --rm --no-deps --entrypoint /opt/cats-venv/bin/python discovery-worker -m app.rendering --probe
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml run --rm --no-deps --entrypoint /opt/cats-venv/bin/python scan-worker -m app.rendering --probe
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml run --rm --no-deps --entrypoint /opt/cats-venv/bin/python patch-worker -m app.rendering --probe
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml run --rm --no-deps --entrypoint /opt/cats-venv/bin/python remediation-worker -m app.rendering --probe
docker inspect --format '{{.Name}} {{.AppArmorProfile}} {{json .HostConfig.SecurityOpt}}' $(docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.worker-apparmor.yaml ps -q discovery-worker scan-worker patch-worker remediation-worker)
```

On failure, inspect the worker health output and host kernel audit log
(`sudo journalctl -k --since '10 minutes ago'`). Check that user namespaces are
supported, their namespace quota is nonzero and the expected named profile is
loaded. Do not disable AppArmor globally, use `apparmor=unconfined`, disable
seccomp, add `SYS_ADMIN`, enable privileged mode or expose writable host `/proc`
as a workaround. Hosts whose policy forbids nested unprivileged namespaces are
unsupported until their operator supplies an equivalent reviewed deployment.

Docker Desktop and Linux hosts without AppArmor use the base Compose definition
without the AppArmor overlay; the same seccomp and action preflights still apply.
Do not disable an active host policy to use this path. Other LSMs, rootless Docker
and nested container hosts need their own qualification.

## Cert-manager rendering regression

Use the official cert-manager v1.20.2 chart archive. The verification script
requires SHA-256 `d2a50bd44a09d838c2576a8f3dfca1524597c7393cf8d82ab3ec8a465b9eeb79`
and rejects any other fixture. Set `CATS_IMAGE` to the updated unified release
image and `CATS_CERT_MANAGER_ARCHIVE` to the archive's absolute local path, then
run from the repository root on the Ubuntu host with the named profile loaded:

```sh
docker run --rm --network none --read-only --user 10003:10003 --cap-drop ALL \
  --security-opt no-new-privileges:true --security-opt seccomp=deploy/discovery-seccomp.json \
  --security-opt apparmor=cats-worker-actions --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777 \
  --mount "type=bind,src=$PWD/scripts/verify-worker-rendering.py,dst=/verify-worker-rendering.py,readonly" \
  --mount "type=bind,src=$CATS_CERT_MANAGER_ARCHIVE,dst=/cert-manager-v1.20.2.tgz,readonly" \
  --entrypoint /opt/cats-venv/bin/python "$CATS_IMAGE" \
  /verify-worker-rendering.py /cert-manager-v1.20.2.tgz
```

Expected result: exit code zero and JSON with
`"discovery_scan_candidate_equal": true`, one shared rendered-output SHA-256,
and exactly four `quay.io/jetstack/cert-manager-{cainjector,controller,startupapicheck,webhook}:v1.20.2`
image references, plus `"compose_kustomize": "passed"`. The script also checks
Compose global options and a local Kustomize resource through the shared runner.
It exercises production chart extraction and compares
Discovery, the scan CLI and candidate/delivery rendering byte for byte. On a
host without AppArmor, omit only that security option; that run does not qualify
the Ubuntu AppArmor deployment.

Repeat the same command for the root Scan broker, replacing
`--user 10003:10003 --cap-drop ALL` with
`--cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add KILL`.
Both runs must produce the same rendered-output hash. Mount only the verification
script and fixture so the test exercises the application packaged in the image.

## Standalone scanner and disconnected deployment

Build `cats-scanner/Dockerfile` with the repository root as context, or run
`docker compose -f cats-scanner/compose.yaml build`. This copies the same minimal
action modules into `/app/app`; it does not install the portal. A standalone
scanner container needs the shared seccomp policy and, on AppArmor hosts, the
loaded named profile, together with writable job scratch. Run its preflight as
`python3 -m app.rendering --probe` before scanning.
For example, from the repository root on a host with the profile loaded:

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add KILL \
  --security-opt no-new-privileges:true --security-opt seccomp=deploy/discovery-seccomp.json \
  --security-opt apparmor=cats-worker-actions --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777 \
  --entrypoint python3 catscan:local -m app.rendering --probe
```

Omit only the AppArmor option on a host that has no AppArmor enforcement.
Any `/tmp` tmpfs must use `mode=1777` so the dropped action identity can create
its private staging directory. Discovery's persistent scratch volume inherits
the image's `/tmp` permissions on first creation; verify those permissions when
reusing an older volume.

The release companion export includes the image, seccomp profile, AppArmor
profile, overlay and this guide with SHA-256 entries in its manifest. Verify those
hashes, copy the files into the matching deployment paths, load the host profile
where applicable, and run all four preflights after importing the image.

The Ubuntu AppArmor parser accepts this profile. Local Docker Desktop can test
nested action isolation but does not enforce AppArmor; successful target-host
preflights and representative render/scan actions remain required before release.

References: [Docker AppArmor profiles](https://docs.docker.com/engine/security/apparmor/),
[AppArmor mount and user namespace rules](https://apparmor-documentation-c38b15.gitlab.io/documentation/in-depth/profiles/core-policy-reference/),
[Bubblewrap namespace setup](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c).
