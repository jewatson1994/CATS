"""Save already-local exact images for disconnected managed validator deployment."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .deployment_bundle import build_helm_archive, file_digest
from .managed_validator_release import SCHEMA, load_release, configured_node_pin
from .managed_validator_bootstrap import BootstrapError


def run(command, *, failure_message=None, **kwargs):
    # Bound every external operation below the durable worker lease. Never
    # forward Docker logs to portal responses (registry URLs can be sensitive).
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('timeout', 1800)
    try:
        return subprocess.run(command, **kwargs)
    except (subprocess.SubprocessError, OSError) as exc:
        if failure_message is None:
            raise
        # Only report controlled metadata, never command arguments or output.
        if isinstance(exc, subprocess.TimeoutExpired):
            reason = "timed out"
        elif isinstance(exc, subprocess.CalledProcessError):
            reason = f"exit code {exc.returncode}"
        else:
            reason = f"OS error {exc.errno}" if exc.errno is not None else "OS error"
        raise BootstrapError(f"Validator payload preparation: {failure_message} ({reason}).") from None


def inspect(reference):
    result = run(["docker", "image", "inspect", reference], check=True, capture_output=True, text=True,
                 failure_message="cannot inspect the selected local image; check the provisioning worker's Docker access and image cache")
    try:
        rows = json.loads(result.stdout)
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or not re.fullmatch(r"sha256:[0-9a-f]{64}", rows[0].get("Id", "")):
            raise ValueError()
    except (ValueError, TypeError):
        raise BootstrapError("Validator payload preparation: Docker did not return one valid local image identity; check the selected image in the worker's Docker cache.") from None
    return rows[0]



def isolated_node_image(reference):
    """Derive a local node whose startup supports a gateway-free bridge.

    An isolated Docker bridge has no default gateway. Upstream Kind otherwise
    inserts an empty address into its DNS NAT rules, aborting before systemd.
    The link-only default route allows Kubernetes to select the node address;
    it creates neither a host gateway nor an external network connection.
    """
    base = inspect(reference)
    try:
        source = run(["docker", "run", "--rm", "--cpus", "0.5", "--memory", "256m", "--pids-limit", "64", "--network", "none", "--entrypoint", "cat", base["Id"], "/usr/local/bin/entrypoint"], check=True, capture_output=True, text=True).stdout
    except (subprocess.SubprocessError, OSError):
        raise BootstrapError("Cannot read the configured Kind node entrypoint. Select a linux/amd64 Kind node image with CATS_DEPLOYMENT_KIND_NODE_IMAGE and provision again.") from None
    patched = patch_isolated_entrypoint(source)
    base_tag = "cats-kind-base:" + base["Id"].split(":")[1]
    run(["docker", "tag", base["Id"], base_tag], check=True,
        failure_message="cannot tag the local Kind base; check the Docker daemon and image store")
    with tempfile.TemporaryDirectory(prefix="cats-isolated-node-") as directory, \
            tempfile.TemporaryDirectory(prefix="cats-buildx-") as buildx_directory:
        context = Path(directory)
        (context / "entrypoint").write_bytes(patched.encode("utf-8"))
        (context / "Dockerfile").write_text("FROM " + base_tag + "\nCOPY --chmod=0755 entrypoint /usr/local/bin/entrypoint\n", encoding="utf-8")
        run(["docker", "build", "--pull=false", "--network=none", "--iidfile", str(context / "image-id"), str(context)], check=True,
            # Registry credentials remain in the read-only DOCKER_CONFIG mount.
            # Buildx needs writable state, kept outside the uploaded build context.
            env={**os.environ, "BUILDX_CONFIG": buildx_directory},
            failure_message="cannot build the isolated Kind node; check the provisioning worker's Docker BuildKit/buildx support and daemon storage")
        image_id = (context / "image-id").read_text().strip()
    row = inspect(image_id)
    tag = "cats-kind-isolated:" + row["Id"].split(":")[1]
    run(["docker", "tag", row["Id"], tag], check=True,
        failure_message="cannot tag the isolated Kind node; check the Docker daemon and image store")
    return tag, row


def patch_isolated_entrypoint(source):
    anchor = "    docker_host_ip=$(ip -4 route show default | cut -d' ' -f3)"
    if source.count(anchor) != 1:
        raise BootstrapError("Configured Kind node entrypoint is incompatible with the isolated-network patch. Set CATS_DEPLOYMENT_KIND_NODE_IMAGE to a compatible Kind node image, or update the CATS runtime to support this node image before provisioning again.")
    fallback = """
    if [[ -z "${docker_host_ip}" ]]; then
      # Isolated bridges have no gateway; use this node for Docker DNS NAT.
      docker_host_ip=$(ip -4 -o addr show dev eth0 scope global | awk '{print $4}' | cut -d/ -f1)
      [[ -n "${docker_host_ip}" ]] || { log_error 'isolated node has no IPv4 address'; exit 1; }
      # Link-only: no gateway and no route outside the isolated Docker bridge.
      ip -4 route add default dev eth0
    fi"""
    return source.replace(anchor, anchor + fallback)


def validate_node_tools(cats_image, node_image, node_pin):
    """Check the exact binaries; the existing deployed self-test validates the pair."""
    versions = []
    for image, binary, args, pattern in (
        (cats_image, "kind", ["version"], r"kind (v\d+\.\d+\.\d+)(?:[-+][^\s]+)?(?:\s|$)"),
        (node_image, "kubeadm", ["version", "-o", "short"], r"(v\d+\.\d+\.\d+)(?:[-+][^\s]+)?(?:\s|$)"),
    ):
        try:
            result = run(["docker", "run", "--rm", "--cpus", "0.5", "--memory", "256m",
                          "--pids-limit", "64", "--network", "none", "--entrypoint", binary,
                          image, *args], check=True, text=True)
            match = re.match(pattern, result.stdout.strip())
            if not match:
                raise ValueError("Unrecognized tool version")
            versions.append(match.group(1))
        except (subprocess.SubprocessError, OSError, ValueError):
            raise BootstrapError("Cannot verify the bundled Kind/node tools. Ensure the selected CATS image contains a working Kind binary and CATS_DEPLOYMENT_KIND_NODE_IMAGE is a linux/amd64 Kind node image with kubeadm; then provision again.") from None
    tag = node_pin.split("@")[0].rsplit("/", 1)[-1].partition(":")[2]
    if re.fullmatch(r"v\d+\.\d+\.\d+", tag) and tag != versions[1]:
        raise BootstrapError("CATS_DEPLOYMENT_KIND_NODE_IMAGE version tag does not match the node's kubeadm version. Correct the image tag and digest before provisioning again.")
    # Kind has no universal Kubernetes version range: runtime compatibility is
    # established by creating a cluster, deploying the self-test and cleaning up.
    return tuple(versions)


def prepare(output, cats_image, node_image=None, *, node_pin=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "images").mkdir()
    cats = inspect(cats_image)
    node_pin = node_pin or configured_node_pin()
    node_ref = inspect(node_image or node_pin)["Id"]
    validate_node_tools(cats["Id"], node_ref, node_pin)
    node_ref, node = isolated_node_image(node_ref)  # Local pinned base only; no registry fallback.
    if any(row.get("Architecture") != "amd64" or row.get("Os") != "linux" for row in (cats, node)):
        raise BootstrapError("Validator payload preparation: both selected images must be linux/amd64; select compatible CATS and Kind node images.")
    if ((cats.get("Config") or {}).get("Labels") or {}).get("org.opencontainers.image.title") != "CATS":
        raise BootstrapError("Validator payload preparation: the selected runtime is not labeled as a CATS release image; use the unified CATS image for CATS_PROVISIONING_CATS_IMAGE.")
    # Exercise the exact image locally without host access or network acquisition.
    probe = "import pathlib,shutil,importlib.util; assert pathlib.Path('/app/validator_server.py').is_file(); assert importlib.util.find_spec('app.validator_api'); assert all(shutil.which(x) for x in ('docker','kind','kubectl','helm','bash','tar'))"
    run(["docker", "run", "--rm", "--cpus", "0.5", "--memory", "256m", "--pids-limit", "64", "--network", "none", "--entrypoint", "/opt/cats-venv/bin/python", cats["Id"], "-c", probe], check=True,
        failure_message="CATS runtime probe failed; verify the unified image contains validator_server.py, app.validator_api, Python, Docker, Kind, kubectl, Helm, bash and tar, and that the daemon can run the probe")
    reference = "cats-managed-validator:" + cats["Id"].split(":")[1]
    run(["docker", "tag", cats["Id"], reference], check=True,
        failure_message="cannot tag the CATS runtime; check the Docker daemon and image store")
    manifest = {"schema_version": SCHEMA}
    for key, ref, row, filename in (("cats_image", reference, cats, "images/cats.tar"), ("node_image", node_ref, node, "images/node.tar")):
        save_ref = ref.split("@")[0]
        run(["docker", "tag", row["Id"], save_ref], check=True,
            failure_message=f"cannot tag {key} for export; check the Docker daemon and image store")
        run(["docker", "save", "--output", str(output / filename), save_ref], check=True,
            failure_message=f"cannot export {key}; check provisioning cache permissions, free space and Docker daemon storage")
        manifest[key] = {"reference": ref, "image_id": row["Id"], "file": filename, "sha256": file_digest(output / filename)}
        if key == "node_image":
            manifest[key]["base_reference"] = node_pin
    pod = """apiVersion: v1
kind: Pod
metadata:
  name: cats-runtime-selftest
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: selftest
      image: IMAGE
      imagePullPolicy: Never
      command: [/opt/cats-venv/bin/python, -c, 'import time; time.sleep(900)']
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        requests: {cpu: 50m, memory: 32Mi}
        limits: {cpu: 100m, memory: 64Mi}
""".replace("IMAGE", reference)
    sources = {"Chart.yaml": "apiVersion: v2\nname: cats-runtime-selftest\nversion: 1.0.0\n", "templates/pod.yaml": pod}
    build_helm_archive(output / "selftest.zip", sources, service={"id": "managed-validator-selftest", "version": cats["Id"]})
    manifest["selftest"] = {"file": "selftest.zip", "sha256": file_digest(output / "selftest.zip"), "image_reference": reference}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    load_release(output)
    return manifest
