#!/usr/bin/env python3
"""Package a mode-specific CATS installer; include local images only on request."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
MAIN_FILES = (
    "deploy/discovery-seccomp.json",
    "deploy/cats-worker-actions.apparmor",
    "deploy/compose.worker-apparmor.yaml",
    "deploy/compose.discovery-mirror.yaml",
    "deploy/discovery-mirror/manifest.json",
)


def source_files(mode):
    """An allowlist, never a recursive copy of a checkout or deployment."""
    if mode not in ("main", "replica"):
        raise ValueError("Mode must be main or replica")
    files = [
        f"setup-{mode}.sh",
        "scripts/setup-cats.py",
        "scripts/cats_setup_registry.py",
        f"templates/{mode}.env.example",
        f"templates/compose.{mode}.yaml",
        "docs/guided-setup.md",
    ]
    return files + (list(MAIN_FILES) if mode == "main" else [])


def template_images(template, selected_image=None):
    """Read the actual template defaults without requiring PyYAML or Docker."""
    if selected_image is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", selected_image):
        raise ValueError("Use a Docker image tag or digest without whitespace")
    found = {}
    for value in re.findall(r"^[ \t]+image:[ \t]*([^\r\n]+)", template, re.MULTILINE):
        value = value.strip()
        if value.startswith(("${CATS_IMAGE:", "${CATS_REPLICA_IMAGE:")):
            role, reference = "cats", selected_image
        elif value.startswith("${CATS_NGINX_IMAGE:-") and value.endswith("}"):
            role, reference = "nginx", value[len("${CATS_NGINX_IMAGE:-"):-1]
            if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", reference):
                raise ValueError("The template Nginx default must be digest-pinned")
        elif value.startswith("postgres:"):
            role, reference = "postgres", value
        else:
            raise ValueError(f"Unrecognized template image: {value}; update the packager")
        if role in found and found[role] != reference:
            raise ValueError(f"Conflicting {role} images in template")
        found[role] = reference
    if set(found) != {"cats", "postgres", "nginx"}:
        raise ValueError("Expected CATS, PostgreSQL, and pinned Nginx images in template")
    return [{"role": role, "source_reference": found[role],
             "archive_reference": found[role], "image_id": None}
            for role in ("cats", "postgres", "nginx")]


def runtime_bind_inventory(template):
    """Report long-form binds and path/variable short mounts from the template.

    Named volumes are intentionally excluded: their contents belong to the
    installation, never to an ingress package. Variable mounts are included even
    when the default is a named volume (the optional staged validator release).
    """
    mounts = set()
    lines = template.splitlines()
    for index, line in enumerate(lines):
        if re.match(r"^\s+- type: bind\s*$", line):
            indent = len(line) - len(line.lstrip())
            fields = {}
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                field = re.match(r"^\s+(source|target):\s*(\S+)\s*$", following)
                if field:
                    fields[field[1]] = field[2]
            if set(fields) != {"source", "target"}:
                raise ValueError("Unrecognized bind declaration; update the packager")
            mounts.add((fields["source"], fields["target"]))
        else:
            match = re.match(r"^\s+-\s+([^\s]+?):(/[^\s:]+)(?::(?:ro|rw))?\s*$", line)
            if match and match[1].startswith(("/", "./", "../", "${")):
                mounts.add((match[1], match[2]))
    return [{"source": source, "target": target} for source, target in sorted(mounts)]


def ingress_requirements(mode, template):
    prerequisites = [
        "A Linux host with local rootful Docker Engine and Docker Compose v2, installed from approved OS media/packages",
        "Python 3.9 or newer, Bash, and OpenSSL on the target host; no pip packages are required by setup",
        "Linux amd64 for the full CATS release image shared by main and replica",
        "CPU architecture matching all images, adequate persistent storage, and two distinct DNS names pointing at the host",
        "TCP 443 available for the bundled Nginx service",
    ]
    operator_inputs = [
        "Portal TLS directory (default /opt/cats/certs/portal) containing tls.crt (leaf plus intermediates) and tls.key for the portal DNS name",
        "OCI TLS directory (default /opt/cats/certs/oci-proxy) containing tls.crt (leaf plus intermediates) and tls.key for the registry DNS name",
        "Issuing CA certificates for clients and the setup host trust store or prompted CA PEM file when using a private CA",
        "Existing protected environment file and unchanged encryption key/credentials when upgrading",
    ]
    optional = [
        "OCI upstream or replica local replicated registry URL, scoped credentials, and trust chain; configure after the stack is healthy",
        "A reachable approved OIDC provider and client settings, only if enabling single sign-on",
    ]
    if mode == "main":
        prerequisites += [
            "On AppArmor-enabled hosts: qualified Ubuntu 24.04 with AppArmor 4+ and apparmor_parser from approved OS packages",
            "Host Docker socket /var/run/docker.sock for the patch and provisioning workers",
        ]
        operator_inputs += [
            "Scan registry-auth directory (may be empty); private sources need scoped Docker config.json auths",
            "Persistent backup directory; preserve its existing absolute path during upgrades",
        ]
        node = re.search(r"CATS_DEPLOYMENT_KIND_NODE_IMAGE:\s*(?:\$\{CATS_KIND_NODE_IMAGE:-)?\$\{CATS_DEPLOYMENT_KIND_NODE_IMAGE:-([^}]+)\}", template)
        optional += [
            "Approved vulnerability database refresh/import inputs for runtime Grype/Trivy volumes; these volumes are not exported",
            "Approved charts, dependent charts, workload images and artifact mirror files required by submitted work",
            "Deployment Validation only: separately preload the image configured by CATS_KIND_NODE_IMAGE" + (" (template default: " + node[1] + ")" if node else "") + "; or mount its approved archive and configure CATS_DEPLOYMENT_KIND_NODE_ARCHIVE",
            "Managed validator provisioning only: verified validator payload/OS packages/provider images for the selected target; a runtime-profile image does not include the optional offline host installer",
            "Legacy staged validator release directory only when CATS_MANAGED_VALIDATOR_RELEASE_SOURCE is explicitly configured",
            "Existing release signing private/public keys and passphrase if importing; otherwise generate new signing material during setup",
        ]
    else:
        operator_inputs.append("Original publisher root SHA-256 fingerprint, obtained independently from the main administrator, for trusting replica releases")
    return {"host_prerequisites": prerequisites, "operator_provided": operator_inputs,
            "optional_feature_inputs": optional, "runtime_mounts": runtime_bind_inventory(template)}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_images(images):
    architecture = None
    for item in images:
        result = subprocess.run(["docker", "image", "inspect", item["source_reference"]],
                                check=True, capture_output=True, text=True)
        rows = json.loads(result.stdout)
        if len(rows) != 1 or rows[0].get("Os") != "linux":
            raise ValueError(f"A local Linux image is required: {item['source_reference']}")
        row = rows[0]
        identity = row.get("Id", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity) or not row.get("Architecture"):
            raise ValueError("Docker returned an invalid image identity")
        platform = (row["Architecture"], row.get("Variant", ""))
        if architecture is not None and architecture != platform:
            raise ValueError("All bundle images must use the same CPU architecture")
        architecture = platform
        item["image_id"] = identity
        # Docker archives do not reliably preserve repository digest lookup.
        # Content-specific tags survive save/load and retain the inspected ID.
        if item["role"] != "postgres":
            item["archive_reference"] = f"cats-setup/{item['role']}:{identity.split(':')[1]}"
    return "linux/" + "/".join(part for part in architecture if part)


def inspect_archive_images(path, images, platform):
    """Record identities shared by containerd and classic Docker after load.

    A containerd image ID can identify an index, while classic Docker uses the
    selected config digest. Only accept alternatives linked by hashed metadata
    to the inspected source ID and the archive's tagged Docker manifest entry.
    Layer contents are covered by the bundle's whole-archive checksum; here we
    check descriptor sizes, regular-file presence, order and config layer count.
    """
    digest_pattern = re.compile(r"sha256:[0-9a-f]{64}")
    index_types = {"application/vnd.oci.image.index.v1+json",
                   "application/vnd.docker.distribution.manifest.list.v2+json"}
    manifest_types = {"application/vnd.oci.image.manifest.v1+json",
                      "application/vnd.docker.distribution.manifest.v2+json"}
    config_types = {"application/vnd.oci.image.config.v1+json",
                    "application/vnd.docker.container.image.v1+json"}
    wanted = platform.split("/")
    if len(wanted) not in (2, 3) or wanted[0] != "linux":
        raise ValueError("Invalid archive image platform")

    def valid_digest(value):
        return isinstance(value, str) and digest_pattern.fullmatch(value)

    def normalized_reference(value):
        if not isinstance(value, str):
            return None
        value = value.removeprefix("docker.io/")
        return value.removeprefix("library/") if "/" in value else value

    try:
        archive = tarfile.open(path, "r:")
    except tarfile.TarError as exc:
        raise ValueError("Invalid Docker image archive") from exc
    with archive:
        members = {}
        for member in archive:
            if member.name in members:
                raise ValueError(f"Duplicate archive member: {member.name}")
            members[member.name] = member

        def regular(name):
            member = members.get(name) if isinstance(name, str) else None
            if member is None or not member.isfile():
                raise ValueError(f"Missing regular archive member: {name}")
            return member

        def read_json(name):
            member = regular(name)
            if member.size > 16 * 1024 * 1024:
                raise ValueError(f"Image metadata is too large: {name}")
            with archive.extractfile(member) as handle:
                data = handle.read()
            try:
                return json.loads(data), "sha256:" + hashlib.sha256(data).hexdigest()
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f"Invalid image metadata: {name}") from exc

        def descriptor_member(descriptor):
            if (not isinstance(descriptor, dict) or not valid_digest(descriptor.get("digest"))
                    or type(descriptor.get("size")) is not int or descriptor["size"] < 0):
                raise ValueError("Invalid image blob descriptor")
            name = "blobs/sha256/" + descriptor["digest"].split(":")[1]
            if regular(name).size != descriptor["size"]:
                raise ValueError(f"Image blob size mismatch: {name}")
            return name

        def descriptor_json(descriptor, allowed_types):
            name = descriptor_member(descriptor)
            if descriptor.get("mediaType") not in allowed_types:
                raise ValueError("Unsupported image metadata media type")
            document, digest = read_json(name)
            if digest != descriptor["digest"]:
                raise ValueError(f"Image blob digest mismatch: {name}")
            if not isinstance(document, dict):
                raise ValueError("Invalid image metadata object")
            return document

        def platform_matches(value):
            return (isinstance(value, dict) and value.get("os") == wanted[0]
                    and value.get("architecture") == wanted[1]
                    and value.get("variant", "") == (wanted[2] if len(wanted) == 3 else ""))

        def selected_manifest(descriptor, depth=0):
            if depth > 8:
                raise ValueError("Image index nesting is too deep")
            document = descriptor_json(descriptor, index_types | manifest_types)
            if document.get("schemaVersion") != 2:
                raise ValueError("Unsupported image metadata schema")
            if document.get("mediaType", descriptor["mediaType"]) != descriptor["mediaType"]:
                raise ValueError("Image metadata media type mismatch")
            if descriptor["mediaType"] in manifest_types:
                return descriptor["digest"], document
            children = document.get("manifests")
            if not isinstance(children, list) or not all(isinstance(child, dict) for child in children):
                raise ValueError("Invalid image index manifests")
            candidates = [child for child in children if platform_matches(child.get("platform"))
                          or ("platform" not in child and child.get("mediaType") in index_types)]
            if len(candidates) != 1:
                raise ValueError(f"Archive must contain one selected {platform} manifest")
            return selected_manifest(candidates[0], depth + 1)

        docker_manifest, _ = read_json("manifest.json")
        if not isinstance(docker_manifest, list) or not all(isinstance(row, dict) for row in docker_manifest):
            raise ValueError("Invalid Docker archive manifest")
        index = None
        if "index.json" in members:
            index, _ = read_json("index.json")
            if (not isinstance(index, dict) or index.get("schemaVersion") != 2
                    or not isinstance(index.get("manifests"), list)
                    or not all(isinstance(row, dict) for row in index["manifests"])):
                raise ValueError("Invalid OCI archive index")

        identities = []
        for item in images:
            rows = [row for row in docker_manifest if isinstance(row.get("RepoTags"), list)
                    and item["archive_reference"] in row["RepoTags"]]
            if len(rows) != 1:
                raise ValueError(f"Archive must contain one image for {item['archive_reference']}")
            row = rows[0]
            config, config_id = read_json(row.get("Config"))
            if (not isinstance(config, dict) or config.get("os") != wanted[0]
                    or config.get("architecture") != wanted[1]
                    or ("variant" in config and config["variant"] != (wanted[2] if len(wanted) == 3 else ""))):
                raise ValueError(f"Archive config platform does not match {platform}")
            layers = row.get("Layers")
            rootfs = config.get("rootfs", {})
            diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
            if (not isinstance(layers, list) or not isinstance(diff_ids, list)
                    or rootfs.get("type") != "layers" or len(layers) != len(diff_ids)
                    or not all(valid_digest(value) for value in diff_ids)):
                raise ValueError("Archive layers do not match image config")
            for name in layers:
                regular(name)
            source_id = item.get("image_id")
            if not valid_digest(source_id):
                raise ValueError("Invalid source image identity")
            manifest_id = None
            if index is not None:
                candidates = [entry for entry in index["manifests"] if entry.get("digest") == source_id]
                if not candidates and source_id == config_id:
                    candidates = [entry for entry in index["manifests"]
                                  if isinstance(entry.get("annotations"), dict)
                                  and normalized_reference(entry["annotations"].get("io.containerd.image.name"))
                                  == normalized_reference(item["archive_reference"])]
                if len(candidates) != 1:
                    raise ValueError("Source image identity is not linked to an archive index entry")
                manifest_id, selected = selected_manifest(candidates[0])
                linked_config = selected.get("config")
                descriptor_json(linked_config, config_types)
                if linked_config["digest"] != config_id or descriptor_member(linked_config) != row["Config"]:
                    raise ValueError("Source image identity does not match tagged archive config")
                linked_layers = selected.get("layers")
                if not isinstance(linked_layers, list):
                    raise ValueError("Invalid image manifest layers")
                if [descriptor_member(layer) for layer in linked_layers] != layers:
                    raise ValueError("Image manifest layers do not match tagged archive layers")
            elif source_id != config_id:
                raise ValueError("Source image identity does not match archive config")
            identities.append((config_id, manifest_id))
        # Do not leave a partially validated list if any selected image failed.
        for item, (config_id, manifest_id) in zip(images, identities):
            item["image_config_id"] = config_id
            item["image_manifest_id"] = manifest_id
    return images


def ingress_text(manifest):
    lines = [f"CATS {manifest['mode']} setup ingress", "", "Included files (verify manifest.json SHA-256 values):"]
    lines += ["  " + name for name in manifest["files"]]
    lines += ["  manifest.json (inventory; authenticate this separately via your approved transfer process)",
              "", "Required images:"]
    for item in manifest["images"]:
        if item['source_reference'] is None:
            lines.append("  cats: select CATS_IMAGE on the target host; setup prompts for its tag or digest.")
        elif manifest["files_only"]:
            suffix = " (suggested; existing target settings take precedence)" if item['role'] in ('cats', 'nginx') else ""
            lines.append(f"  {item['role']}: {item['source_reference']}" + suffix)
        else:
            lines.append(f"  {item['role']}: {item['source_reference']} -> {item['archive_reference']}")
    if manifest["files_only"]:
        lines += ["  FILES ONLY: images.tar is absent. Use images already available on the target host."]
    for key, heading in (("host_prerequisites", "Install on target separately"),
                         ("operator_provided", "Operator-provided inputs (not in this bundle)"),
                         ("optional_feature_inputs", "Additional inputs only for enabled features")):
        lines += ["", heading + ":"] + ["  " + item for item in manifest["ingress"][key]]
    lines += ["", "Runtime mounts from the selected template (contents are not recursively packaged):"]
    lines += ["  " + item["source"] + " -> " + item["target"]
              for item in manifest["ingress"]["runtime_mounts"]]
    lines += ["", f"Start: sudo bash setup-{manifest['mode']}.sh", "Read docs/guided-setup.md before an upgrade."]
    return "\n".join(lines) + "\n"


def export_bundle(output, mode, selected_image=None, files_only=False, root=None):
    root = Path(root or ROOT).resolve()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Output must be a new directory: {output}")
    if not files_only and selected_image is None:
        raise ValueError("Select a CATS image when including images in the bundle")
    names = source_files(mode)
    for name in names:
        source = root / name
        # Reject links, including a linked parent, so an allowed filename cannot
        # silently select credentials or unrelated material outside the tree.
        if any(path.is_symlink() for path in (source, *source.parents) if path != root):
            raise ValueError(f"Bundle source must not be a symbolic link: {name}")
        if not source.is_file():
            raise ValueError(f"Missing regular bundle source: {name}")
        source.resolve().relative_to(root)
    if mode == "main":
        mirror = json.loads((root / "deploy/discovery-mirror/manifest.json").read_text(encoding="utf-8-sig"))
        if mirror != {"version": 1, "artifacts": []}:
            raise ValueError("Bundle only the empty default discovery mirror; transfer custom mirror content separately")
    template = (root / f"templates/compose.{mode}.yaml").read_text(encoding="utf-8-sig")
    images = template_images(template, selected_image)
    ingress = ingress_requirements(mode, template)
    architecture = None if files_only else inspect_images(images)
    if architecture is not None and architecture != "linux/amd64":
        raise ValueError("The full CATS image shared by main and replica requires linux/amd64 images")
    output.mkdir(parents=True, exist_ok=False)
    for name in names:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, destination)
    if not files_only:
        for item in images:
            if item["archive_reference"] != item["source_reference"]:
                subprocess.run(["docker", "tag", item["image_id"], item["archive_reference"]], check=True)
        # Verify the literal PostgreSQL tag again; its name is fixed in Compose.
        postgres = next(item for item in images if item["role"] == "postgres")
        verified = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", postgres["source_reference"]],
                                  check=True, capture_output=True, text=True)
        if verified.stdout.strip() != postgres["image_id"]:
            raise ValueError("PostgreSQL tag changed while packaging; retry into a new directory")
        subprocess.run(["docker", "save", "--output", str(output / "images.tar")]
                       + [item["archive_reference"] for item in images], check=True)
        inspect_archive_images(output / "images.tar", images, architecture)
        names.append("images.tar")
    manifest = {"schema_version": 1, "mode": mode, "files_only": bool(files_only),
                "platform": architecture, "images": images, "ingress": ingress,
                "files": {name: sha256_file(output / name) for name in names}}
    # INGRESS.txt has no recursive self-checksum; its digest belongs to the
    # manifest, which is emitted last to mark successful completion.
    manifest["files"]["INGRESS.txt"] = ""
    (output / "INGRESS.txt").write_text(ingress_text(manifest), encoding="utf-8")
    manifest["files"]["INGRESS.txt"] = sha256_file(output / "INGRESS.txt")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("main", "replica"))
    parser.add_argument("--image", help="Full CATS image suggestion; required with --include-images")
    parser.add_argument("--output", required=True, type=Path, help="New output directory; never overwrite an installation")
    images = parser.add_mutually_exclusive_group()
    images.add_argument("--files-only", action="store_true", help="Copy installer files/inventory without Docker (the default); use images on the target host")
    images.add_argument("--include-images", action="store_true", help="Export the three local runtime images into images.tar")
    args = parser.parse_args(argv)
    if args.include_images and not args.image:
        parser.error("--image is required with --include-images")
    files_only = not args.include_images
    try:
        manifest = export_bundle(args.output, args.mode, args.image, files_only)
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        print(f"Setup bundle failed: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.strip(), file=sys.stderr)
        print("Use local, approved images; this command does not pull or build. A failed output directory is incomplete; retry with a new destination.", file=sys.stderr)
        return 1
    print(f"Created {args.mode} setup bundle: {args.output.resolve()}")
    print(f"{len(manifest['files'])} checksummed files; " + ("uses images already available on the target host" if files_only else "all three runtime images in images.tar"))
    print("Transfer the whole directory plus the operator-provided items in INGRESS.txt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
