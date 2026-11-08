# Guided setup for CATS main and replica

Create a small installer directory containing setup scripts, Compose files and
instructions. Packaging includes no container images by default and needs no
Docker installation or network connection. The required images must already be
loaded on the destination host.

```sh
python3 scripts/package-cats-setup.py --mode main --output cats-main-setup
```

For a replica, select `--mode replica` with a new output directory:

```sh
python3 scripts/package-cats-setup.py --mode replica --output cats-replica-setup
```

Both packaging and setup use Python's standard library; no pip installation is
needed. Setup prompts for the full CATS image already on the host and writes it
to `CATS_IMAGE` in either mode, preserving existing environment settings during
upgrades. Optional `--image <reference>` supplies a suggested image when packaging;
it does not export an image. Existing replica settings may still supply
`CATS_REPLICA_IMAGE` when `CATS_IMAGE` is unset or blank; `CATS_IMAGE` takes
precedence when both are set.

Transfer that whole directory through your approved ingress process. On the
Linux destination, prepare the TLS files and prerequisites listed below, enter
the directory, and run the matching command:

```sh
sudo bash setup-main.sh
# On a replica host instead:
sudo bash setup-replica.sh
```

The guided setup asks for the deployment settings, protects the environment file,
checks the supplied files and local images, and starts the selected stack. It
checks file hashes against `manifest.json`; retain this inventory with the
transfer record. The manifest is an inventory, not a signature.

To prepare settings without starting services, add `--configure-only`. To defer
the final registry connection, add `--skip-registry`. To use an existing protected
environment file, provide its absolute path:

```sh
sudo bash setup-main.sh --env-file /etc/cats/cats.env
```

`--extra-compose /absolute/path/override.yaml` includes a reviewed deployment
override. Keep the same override on subsequent runs. The replica is a separate
stack: never combine its template with the main template. Its Compose file sets
`CATS_MODE=replica`; although the shared image contains the full toolset, the
replica starts no assessment workers and mounts no Docker socket.

## Exactly what to ingress

`INGRESS.txt` lists the included files, required local images, prerequisites, and
actual runtime mounts for the selected template. The default bundle contains:

| Item | Main | Replica |
| --- | --- | --- |
| Matching entry point | `setup-main.sh` | `setup-replica.sh` |
| Setup helpers | `scripts/setup-cats.py`, `scripts/cats_setup_registry.py` | Same |
| Deployment definition | `templates/compose.main.yaml` | `templates/compose.replica.yaml` |
| Environment example | `templates/main.env.example` | `templates/replica.env.example` |
| This guide | `docs/guided-setup.md` | Same |
| Transfer inventory | `manifest.json`, `INGRESS.txt` | Same |
| Worker isolation files | `deploy/discovery-seccomp.json`, `deploy/cats-worker-actions.apparmor`, `deploy/compose.worker-apparmor.yaml` | Not required |
| Default artifact mirror | `deploy/compose.discovery-mirror.yaml`, `deploy/discovery-mirror/manifest.json` | Not required |

Keep these paths intact. The Compose templates resolve relative paths from
`templates/`, including their sibling `deploy/` directory. No full source checkout,
frontend build, separate Nginx configuration, or separate identity-provider image
is required on the destination.

Before disconnected startup, these three images must already be loaded into the
destination's local Docker image store:

| Role | Main | Replica |
| --- | --- | --- |
| CATS | The full image selected during setup as `CATS_IMAGE` | The same full image selected as `CATS_IMAGE` |
| PostgreSQL | `postgres:16-alpine` | `postgres:16` |
| Nginx | The digest-pinned Compose default, or your approved local `CATS_NGINX_IMAGE` override | Same |

The PostgreSQL tag must match the selected template exactly. If a previously
loaded Nginx archive lacks the pinned digest reference, set `CATS_NGINX_IMAGE` to
a locally inspectable approved tag and verify its identity before startup.
Setup checks the chosen images locally and starts with pulls disabled. All three
images must target the same Linux CPU architecture and match the host.
The shared full CATS image requires Linux amd64 in both modes. Historical ARM64
checks of the legacy lightweight replica image do not qualify this full image
for ARM hosts.
Ensure enough space for Docker's loaded images and persistent application data.

`--files-only` remains a compatibility option for the default behavior. If image
delivery is explicitly needed later, opt in with `--include-images` and `--image`:

```sh
python3 scripts/package-cats-setup.py --mode main --output cats-with-images --include-images --image cats:1.3
```

That optional export requires Docker and all three images on the packaging
computer; it never builds or pulls images. It adds `images.tar` and verified image
identities to the manifest, and setup offers to import them. Packaging rejects an
existing output directory and never replaces it. After a failed export, use a new
destination; an incomplete directory is not ready for ingress.

## Prepare the destination and operator files

Install Docker Engine, the Docker Compose v2 plugin, Bash, OpenSSL, and Python 3.9 or newer
using approved Linux OS installation media or packages. The setup bundle does
not install the operating system, Docker, Python, kernel features, or host trust
stores. Setup requires local rootful Docker Engine; Docker Desktop, remote Docker
contexts, and rootless Docker need separate qualification. Confirm Docker is
running and the operator can access it. Provision
persistent storage for databases, evidence, cache, and backups; none of these
existing stores are copied into the bundle.

Create two distinct DNS names pointing at this host: one for the portal and one
for OCI access. Allow the intended clients to reach TCP 443 and ensure another
service is not already using it. Nginx routes both names on port 443 using the
configuration embedded in the Compose template. The private application and
database ports do not need host publishing.

Provide the following separately:

- A portal certificate directory (default `/opt/cats/certs/portal`) containing
  `tls.crt` (leaf certificate followed by intermediates) and its matching `tls.key`
  for the portal hostname.
- An OCI certificate directory (default `/opt/cats/certs/oci-proxy`) with the same
  filenames for the OCI hostname.
  A shared directory is possible when one certificate covers both names.
- The issuing CA chain for client trust and either the setup host trust store or
  the optional CA PEM path prompted by setup when using a private CA. Supply any
  private upstream registry CA through its approved
  trust configuration as well. Keep private keys and credentials in protected
  operator storage; the package does not collect them.
- For an upgrade, the existing protected environment file and its stable
  encryption key, database passwords, service credentials, and storage paths.
- For main CATS, a scan registry-auth directory. It may be empty for public
  sources. Private pulls require the approved, scoped Docker `config.json`
  credentials; helper-based workstation login configurations may also require
  helpers unavailable inside the container. Preserve the configured backup
  directory. Setup can create empty defaults for a fresh installation.
- For a replica, the original publisher root SHA-256 fingerprint obtained from
  the main administrator through an independently trusted channel.

The main template also mounts the host's `/var/run/docker.sock` into the patch
and provisioning workers. This is a host facility, not a transferable file.
The optional `CATS_MANAGED_VALIDATOR_RELEASE_SOURCE` is an empty named volume by
default; supply a verified staged directory only if explicitly using that option.
No `.env`, certificate, private key, registry credentials, host socket, backup,
database volume, runtime cache, or custom artifact mirror is copied from the
packaging workstation. The default bundle contains only the listed source files
and inventory. Use approved images on the target; `--include-images` also requires
release images checked for embedded secrets.

## Main worker isolation

The supplied profile is qualified for Ubuntu 24.04 with AppArmor 4 or newer.
On that host, install `apparmor_parser` from approved OS packages. Other
AppArmor-enabled hosts require separate qualification. Ubuntu 22.04 includes
AppArmor 3, but this profile uses AppArmor 4 ABI and `userns` policy syntax.
Use Ubuntu 24.04 for the current main installer; do not bypass its version check.
The main setup uses the bundled `cats-worker-actions` profile and Compose overlay
for Discovery, Scan, Patch, and Remediation. The seccomp file and overlay must
remain available on every recreate or upgrade. Do not substitute unconfined
workers or disable an active host policy to get past a failed check.

On Linux hosts without AppArmor, the base seccomp and worker namespace checks
still apply. The host must support the isolated worker actions; a healthy worker
probe checks the isolation path, not the availability of every chart, registry,
or scanner database. Replica mode has no action workers and needs none of these
main-only files or AppArmor installation steps.

## Additional offline feature inputs

Starting the stack does not supply every artifact a future assessment might
need. The unified release embeds its versioned intelligence distribution and
scanner tools. Runtime Grype and Trivy data live in their own persistent volumes;
retain those volumes on upgrades and verify their populated, approved databases
before accepting scans. The security-data worker manages refreshes independently
of the intelligence SQL schema initializer. A healthy SQL database or successful
setup is not proof of fresh scanner data. Transfer approved database updates
through the product's supported import process when the site is disconnected.

The bundled artifact mirror manifest is deliberately empty. Ingress approved
charts, dependent charts, images, and mirror content separately for the workloads
you plan to assess. Point `CATS_DISCOVERY_MIRROR_DIR` at the reviewed local mirror
when needed. Packaging rejects a populated default mirror so it cannot silently
carry site-specific artifacts or credentials.

Deployment Validation is optional and disabled by default. Before enabling it,
ingress the exact `CATS_KIND_NODE_IMAGE` from the environment example
and the workload images/charts it needs. Its reference also appears in
`INGRESS.txt`. Either preload the node image into the intended Docker daemon, or
provide a reviewed archive mounted into the service and set
`CATS_DEPLOYMENT_KIND_NODE_ARCHIVE` to its **container** path. Setting a path alone
does not mount a host file. Use a dedicated approved validation host; private
registry credentials are not automatically copied into the ephemeral cluster.
Select an approved node image at the main setup prompt, or set
`CATS_KIND_NODE_IMAGE` in the environment file. This selection does not enable
Deployment Validation or require the image to be present during setup.
Compose passes this to the application's `CATS_DEPLOYMENT_KIND_NODE_IMAGE`
setting. Existing environment files using that older name remain supported;
guided setup preserves their value under the public name unless a nonempty
`CATS_KIND_NODE_IMAGE` is already set.

New main installations default `CATS_SCAN_JOB_TIMEOUT` to `10800` seconds
(three hours). Guided setup retains an existing timeout override.

Managed validator provisioning has separate target/provider requirements. A
runtime-profile CATS image does not include the optional offline host installer.
Before disconnected provisioning, supply the verified payload and approved OS
packages/provider images for that target, or use an existing configured validator.
The setup bundle does not contain those optional inputs, even with `--include-images`.
An optional OIDC provider must also be reachable and configured separately.

## Connect registries after startup

After Compose and the portal are healthy, guided setup can authenticate and help
configure the OCI connection: main CATS uses an upstream and release publication
destination; a replica uses its local replicated registry. The installer connects
to an existing registry; Harbor and its replication rules are provisioned
separately and are not included in the setup bundle. Have the registry
URL, scoped credentials, and approved trust chain ready. Main setup can import
existing signing keys or generate new signing material. Replica setup asks for
the original publisher root fingerprint and release repository scope before
synchronization. This follows service startup so a configuration
failure has a concrete service response. Use `--skip-registry` to finish host
setup and configure this connection later through the portal. Check the
connection and authorization in the portal before admitting consumers.

## Upgrade an existing installation

Back up the existing deployment and database using the site's established
procedure. Build a fresh bundle from the matching release, extract it into a new
directory, and explicitly reuse the existing protected environment file. Retain
the original Compose project name, encryption key, passwords, tokens, named
volumes, absolute certificate/auth/backup paths, and all reviewed overrides.
Changing the project name can select new empty volumes; changing the encryption
key makes stored encrypted settings unreadable.

Review template changes and include every existing override with
`--extra-compose`. Keep any AppArmor overlay on the main deployment. Do not run
`docker compose down --volumes` or replace the environment file with an example.
The new bundle does not migrate old relative directories: preserve their existing
absolute paths when moving the installation files. Confirm both portal and OCI
HTTPS access, stored settings, worker health where applicable, and registry
connectivity before retiring the previous release directory.
