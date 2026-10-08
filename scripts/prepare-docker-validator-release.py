"""Save already-local exact images for disconnected managed validator deployment."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "portal"))
from app.deployment_validation import ValidationConfig
from app.deployment_bundle import build_helm_archive, file_digest
from app.managed_validator_release import SCHEMA, load_release


def inspect(reference):
    result = subprocess.run(["docker", "image", "inspect", reference], check=True, capture_output=True, text=True)
    rows = json.loads(result.stdout)
    if len(rows) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", rows[0].get("Id", "")):
        raise ValueError("Expected exactly one local image")
    return rows[0]



def isolated_node_image(reference):
    """Derive a local node whose startup supports a gateway-free bridge.

    An isolated Docker bridge has no default gateway. Upstream Kind otherwise
    inserts an empty address into its DNS NAT rules, aborting before systemd.
    The link-only default route allows Kubernetes to select the node address;
    it creates neither a host gateway nor an external network connection.
    """
    base = inspect(reference)
    source = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", base["Id"], "/usr/local/bin/entrypoint"], check=True, capture_output=True, text=True).stdout
    patched = patch_isolated_entrypoint(source)
    base_tag = "cats-kind-base:" + base["Id"].split(":")[1]
    subprocess.run(["docker", "tag", base["Id"], base_tag], check=True)
    with tempfile.TemporaryDirectory(prefix="cats-isolated-node-") as directory:
        context = Path(directory)
        (context / "entrypoint").write_bytes(patched.encode("utf-8"))
        (context / "Dockerfile").write_text("FROM " + base_tag + "\nCOPY --chmod=0755 entrypoint /usr/local/bin/entrypoint\n", encoding="utf-8")
        subprocess.run(["docker", "build", "--pull=false", "--network=none", "--iidfile", str(context / "image-id"), str(context)], check=True)
        image_id = (context / "image-id").read_text().strip()
    row = inspect(image_id)
    tag = "cats-kind-isolated:" + row["Id"].split(":")[1]
    subprocess.run(["docker", "tag", row["Id"], tag], check=True)
    return tag, row


def patch_isolated_entrypoint(source):
    anchor = "    docker_host_ip=$(ip -4 route show default | cut -d' ' -f3)"
    if source.count(anchor) != 1:
        raise ValueError("Pinned Kind entrypoint no longer matches the isolated-network compatibility patch")
    fallback = """
    if [[ -z "${docker_host_ip}" ]]; then
      # Isolated bridges have no gateway; use this node for Docker DNS NAT.
      docker_host_ip=$(ip -4 -o addr show dev eth0 scope global | awk '{print $4}' | cut -d/ -f1)
      [[ -n "${docker_host_ip}" ]] || { log_error 'isolated node has no IPv4 address'; exit 1; }
      # Link-only: no gateway and no route outside the isolated Docker bridge.
      ip -4 route add default dev eth0
    fi"""
    return source.replace(anchor, anchor + fallback)


def prepare(output, cats_image):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "images").mkdir()
    cats = inspect(cats_image)
    node_ref = ValidationConfig.kind_node_image
    node_ref, node = isolated_node_image(node_ref)  # Local pinned base only; no registry fallback.
    if any(row.get("Architecture") != "amd64" or row.get("Os") != "linux" for row in (cats, node)):
        raise ValueError("V1 validator images must be linux/amd64")
    if (cats.get("Config") or {}).get("Labels", {}).get("org.opencontainers.image.title") != "CATS":
        raise ValueError("Expected a CATS release image")
    # Exercise the exact image locally without host access or network acquisition.
    probe = "import pathlib,shutil,importlib.util; assert pathlib.Path('/app/validator_server.py').is_file(); assert importlib.util.find_spec('app.validator_api'); assert all(shutil.which(x) for x in ('docker','kind','kubectl','helm','bash','tar'))"
    subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "/opt/cats-venv/bin/python", cats["Id"], "-c", probe], check=True)
    reference = "cats-managed-validator:" + cats["Id"].split(":")[1]
    subprocess.run(["docker", "tag", cats["Id"], reference], check=True)
    manifest = {"schema_version": SCHEMA}
    for key, ref, row, filename in (("cats_image", reference, cats, "images/cats.tar"), ("node_image", node_ref, node, "images/node.tar")):
        save_ref = ref.split("@")[0]
        subprocess.run(["docker", "tag", row["Id"], save_ref], check=True)
        subprocess.run(["docker", "save", "--output", str(output / filename), save_ref], check=True)
        manifest[key] = {"reference": ref, "image_id": row["Id"], "file": filename, "sha256": file_digest(output / filename)}
        if key == "node_image":
            manifest[key]["base_reference"] = ValidationConfig.kind_node_image
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


def activate_release(output, env_file):
    """Persist the verified mount source for subsequent Compose recreations."""
    source = Path(output).resolve()
    load_release(source)
    path = Path(env_file)
    existing_bytes = path.read_bytes() if path.exists() else b""
    encoding = "utf-8-sig" if existing_bytes.startswith(b"\xef\xbb\xbf") else "utf-8"
    existing = existing_bytes.decode(encoding)
    newline = "\r\n" if "\r\n" in existing else "\n"
    key = "CATS_MANAGED_VALIDATOR_RELEASE_SOURCE"
    # Single quotes prevent Compose interpolation of dollar signs in paths.
    source_text = source.as_posix()
    if any(character in source_text for character in ("'", "\n", "\r")):
        raise ValueError("Release path cannot be represented safely in a Compose environment file")
    lines = [line for line in existing.splitlines() if not re.match(r"^\s*(?:export\s+)?" + key + r"\s*=", line)]
    lines.append(key + "='" + source_text + "'")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".validator-release-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write((newline.join(lines) + newline).encode(encoding))
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cats-image", required=True, help="Already-built local exact CATS image")
    parser.add_argument("--activate-env", help="Persist the verified release source in this Compose environment file")
    args = parser.parse_args()
    prepare(args.output, args.cats_image)
    if args.activate_env:
        activate_release(args.output, args.activate_env)
    print("Verified Docker-host release prepared: " + str(Path(args.output).resolve()))
