"""Assemble final deployment bytes from a retained, version-scoped candidate."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import os
import re
import base64
import hashlib
from urllib.parse import urlsplit
from contextlib import contextmanager
from zipfile import ZipFile
import yaml

from .deployment_bundle import build_bundle, file_digest, dependency_inventory, workload_images, image_archive_identity, _untar
from .remediation_delivery import retained_candidate, checked_inventory, checked_values_files


@contextmanager
def configured_material(settings, helm_repository_urls=()):
    """Resolve existing saved CATS trust/auth into operation-scoped files only."""
    from .secrets import decrypt_secret
    from .trusted_ca import additional_pem
    def parsed(key, fallback):
        value = settings.get(key, fallback)
        return json.loads(value) if isinstance(value, str) else value
    certificates = parsed("trusted_ca_certificates", [])
    admin_pem = additional_pem(certificates)
    registries = parsed("oci_registries", [])
    with tempfile.TemporaryDirectory(prefix="cats-bundle-auth-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        ca = directory / "admin-ca.pem"
        if admin_pem:
            ca.write_text(admin_pem, encoding="utf-8")
        configuration = {"helm_ca_file": str(ca) if admin_pem else None,
                         "helm_repositories": [{"url": url, "ca_file": str(ca) if admin_pem else None}
                                               for url in sorted(set(helm_repository_urls))],
                         "image_registries": []}
        auths = {}
        for index, saved in enumerate(registries):
            endpoint = str(saved.get("endpoint") or "").rstrip("/")
            if "://" not in endpoint:
                endpoint = "https://" + endpoint
            parsed_endpoint = urlsplit(endpoint)
            if parsed_endpoint.scheme != "https" or not parsed_endpoint.netloc or parsed_endpoint.path or parsed_endpoint.username or parsed_endpoint.password:
                continue  # Insecure or non-registry connections cannot satisfy retrieval.
            pem = admin_pem + str(saved.get("ca_pem") or "")
            registry_ca = directory / f"registry-{index}.pem"
            if pem:
                registry_ca.write_text(pem, encoding="utf-8")
            username = str(saved.get("username") or "")
            password = decrypt_secret(str(saved.get("password") or "")) if saved.get("password") else ""
            row = {"endpoint": endpoint, "username": username, "password": password,
                   "ca_file": str(registry_ca) if pem else None}
            configuration["image_registries"].append(row)
            namespace = str(saved.get("namespace") or "").strip("/")
            repository = "oci://" + parsed_endpoint.netloc + ("/" + namespace if namespace else "")
            configuration["helm_repositories"].append({**row, "url": repository})
            if username or password:
                auths[parsed_endpoint.netloc] = {"auth": base64.b64encode(f"{username}:{password}".encode()).decode()}
        auth = directory / "registry-auth.json"
        auth.write_text(json.dumps({"auths": auths}), encoding="utf-8")
        os.chmod(auth, 0o600)
        configuration.update(helm_registry_config=str(auth), image_auth_file=str(auth))
        yield configuration


def _run(command, *, env=None, binary=False):
    try:
        result = subprocess.run(command, capture_output=True, text=not binary, timeout=300, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Configured artifact retrieval tool unavailable or timed out") from exc
    if result.returncode:
        # Tool output can include registry credentials; it is never returned to users.
        raise ValueError("Artifact operation failed; check configured endpoint, credentials and CA trust")
    return result


def _trusted_source(rows, endpoint, configuration):
    match = [row for row in rows if str(row.get("url", row.get("endpoint", ""))).rstrip("/") == endpoint.rstrip("/")]
    if len(match) != 1:
        raise ValueError("Artifact source is not uniquely configured in CATS")
    row = match[0]
    ca = row.get("ca_file") or configuration.get("helm_ca_file")
    if not ca or not Path(ca).is_file():
        raise ValueError("Configured artifact source requires explicit CA trust")
    return row, str(ca)


def _dependencies(chart, workspace, helm, configuration):
    """Expand safely, then acquire exact locked missing dependencies recursively."""
    evidence = []
    env = {**os.environ}
    if configuration.get("helm_registry_config"):
        env["HELM_REGISTRY_CONFIG"] = str(configuration["helm_registry_config"])
    for iteration in range(32):
        # Expanding local packages makes their nested missing dependencies addressable.
        packages = list(chart.rglob("charts/*.tgz"))
        for package in packages:
            with tempfile.TemporaryDirectory(dir=workspace, prefix="dependency-expand-") as temporary:
                expanded = Path(temporary)
                _untar(package, expanded)
                roots = list(expanded.glob("*/Chart.yaml"))
                if len(roots) != 1:
                    raise ValueError("Ambiguous packaged Helm dependency")
                source = roots[0].parent
                target = package.parent / source.name
                if target.exists():
                    raise ValueError("Duplicate packaged Helm dependency")
                shutil.move(str(source), str(target))
                package.unlink()  # Only the disposable materialized candidate is modified.
        inventory = dependency_inventory(chart, strict=False)
        missing = [item for item in inventory if not item["vendored"]]
        if not missing and not list(chart.rglob("charts/*.tgz")):
            return dependency_inventory(chart), evidence
        for item in missing:
            repository = item["repository"].rstrip("/")
            parsed = urlsplit(repository)
            if parsed.scheme not in {"https", "oci"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Missing dependency requires an explicit configured HTTPS or OCI repository")
            row, ca = _trusted_source(configuration.get("helm_repositories", []), repository, configuration)
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", item["name"]):
                raise ValueError("Invalid dependency chart name")
            destination = workspace / f"dependency-pull-{iteration}-{len(evidence)}"
            destination.mkdir()
            command = [helm, "pull"]
            if parsed.scheme == "oci":
                if row.get("username") and not configuration.get("helm_registry_config"):
                    raise ValueError("OCI chart credentials require a configured Helm registry auth file")
                command.append(repository + "/" + item["name"])
            else:
                command.extend([item["name"], "--repo", repository])
                for key in ("username", "password"):
                    if row.get(key):
                        command.extend(["--" + key, str(row[key])])
            command.extend(["--version", item["version"], "--ca-file", ca, "--destination", str(destination)])
            _run(command, env=env)
            archives = list(destination.glob("*.tgz"))
            if len(archives) != 1:
                raise ValueError("Dependency retrieval did not return one chart archive")
            expanded = destination / "expanded"
            expanded.mkdir()
            _untar(archives[0], expanded)
            roots = list(expanded.glob("*/Chart.yaml"))
            if len(roots) != 1:
                raise ValueError("Dependency retrieval returned an ambiguous chart")
            metadata = yaml.safe_load(roots[0].read_text(encoding="utf-8"))
            if metadata.get("name") != item["name"] or str(metadata.get("version")) != item["version"]:
                raise ValueError("Retrieved Helm dependency identity mismatch")
            parent = chart / item["parent"] if item["parent"] else chart
            target = parent / "charts" / roots[0].parent.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise ValueError("Dependency destination already exists")
            shutil.move(str(roots[0].parent), str(target))
            evidence.append({"kind": "helm-dependency", "name": item["name"], "version": item["version"],
                             "repository": repository, "archiveDigest": file_digest(archives[0]), "tlsVerified": True})
    raise ValueError("Helm dependency acquisition exceeds recursive depth limit")


def _acquire_image(reference, destination, workspace, configuration):
    """Skopeo writes layer bytes directly to disk, never through a JSON/base64 response."""
    host = reference.split("/", 1)[0]
    if "/" not in reference or ("." not in host and ":" not in host and host != "localhost"):
        host = "docker.io"
    endpoint = "https://" + host
    row, ca = _trusted_source(configuration.get("image_registries", []), endpoint, configuration)
    skopeo = shutil.which("skopeo")
    if not skopeo:
        raise ValueError("Skopeo is required to retrieve missing offline images")
    certs = workspace / ("image-trust-" + destination.stem)
    certs.mkdir()
    shutil.copyfile(ca, certs / "ca.crt")
    auth = configuration.get("image_auth_file")
    if not auth:
        auth = workspace / ("image-auth-" + destination.stem + ".json")
        credentials = {}
        if row.get("username") or row.get("password"):
            encoded = base64.b64encode(f"{row.get('username', '')}:{row.get('password', '')}".encode()).decode()
            credentials[host] = {"auth": encoded}
        auth.write_text(json.dumps({"auths": credentials}), encoding="utf-8")
        os.chmod(auth, 0o600)
    inspected = _run([skopeo, "inspect", "--raw", "--tls-verify=true", "--cert-dir", str(certs),
                      "--authfile", str(auth), "docker://" + reference], binary=True)
    raw = inspected.stdout
    if len(raw) > 4 * 1024 ** 2 or json.loads(raw).get("schemaVersion") != 2:
        raise ValueError("Unsupported or oversized registry image manifest")
    registry_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if "@" in reference and reference.rsplit("@", 1)[1] != registry_digest:
        raise ValueError("Registry image manifest digest mismatch")
    repository = reference.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    command = [skopeo, "copy", "--src-tls-verify=true", "--src-cert-dir", str(certs), "--authfile", str(auth),
               "docker://" + repository + "@" + registry_digest, "docker-archive:" + str(destination) + ":" + reference]
    _run(command)
    return {"kind": "image-acquisition", "reference": reference, "registry": endpoint,
            "archiveDigest": file_digest(destination), "identityType": "docker_config",
            "identity": image_archive_identity(destination, reference), "tlsVerified": True,
            "registryManifestDigest": registry_digest}


def assemble(record, root, attempt_id, bundle_type, service_version, configuration=None):
    configuration = configuration or {}
    candidate = retained_candidate(record, root)
    with tempfile.TemporaryDirectory(prefix="cats-final-bundle-") as temporary:
        workspace = Path(temporary)
        with ZipFile(candidate) as archive:
            names = checked_inventory(archive)
            if sum(archive.getinfo(name).file_size for name in names if name.startswith("candidate/")) > 200 * 1024 ** 2:
                raise ValueError("Candidate source tree exceeds assembly size limit")
            sources = {name[10:]: archive.read(name) for name in names
                       if name.startswith("candidate/") and not name.endswith("/")}
            manifest = json.loads(archive.read("manifest.json"))
            documentation_names = {name for name in names
                             if name in {"documentation/remediation/summary-of-changes.json",
                                         "documentation/remediation/summary-of-changes.md",
                                         "documentation/remediation/before-after.json",
                                         "documentation/remediation/changes.patch"}}
            if sum(archive.getinfo(name).file_size for name in documentation_names) > 16 * 1024 ** 2:
                raise ValueError("Remediation documentation exceeds assembly size limit")
            documentation = {name: archive.read(name) for name in documentation_names}
            images = []
            if bundle_type == "offline-bundle":
                for index, image in enumerate(manifest.get("images") or []):
                    name = image.get("archive_path")
                    if not name or name not in names:
                        continue
                    target = workspace / f"image-{index}.tar"
                    with archive.open(name) as incoming, target.open("wb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                    expected = image.get("artifact_sha256")
                    if expected and file_digest(target).removeprefix("sha256:") != expected.removeprefix("sha256:"):
                        raise ValueError("Retained image archive digest mismatch")
                    image_archive_identity(target, image["remediated"])
                    images.append({"reference": image["remediated"], "source_path": target,
                                   "archive_path": f"images/{index}.tar"})
        values = checked_values_files(manifest.get("values_files") or [], sources)
        charts = [name for name in sources if name.endswith("Chart.yaml") and "charts" not in Path(name).parts[:-1]]
        if len(charts) != 1:
            raise ValueError("A deployment bundle requires one explicitly selected root chart")
        chart_path = str(Path(charts[0]).parent).replace("\\", "/")
        for name, content in sources.items():
            target = workspace / "source" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        helm = shutil.which("helm")
        if not helm:
            raise ValueError("Helm is required to assemble the final deployment")
        dependencies, acquisition_evidence = _dependencies(workspace / "source" / chart_path, workspace, helm, configuration)
        command = [helm, "template", "cats-final", str(workspace / "source" / chart_path), "--include-crds"]
        for name in values:
            command.extend(["--values", str(workspace / "source" / name)])
        rendered = _run(command)
        if rendered.returncode or len(rendered.stdout.encode()) > 16 * 1024 ** 2:
            raise ValueError("Final deployment render failed")
        required = workload_images(rendered.stdout)
        images = [image for image in images if image["reference"] in required]
        if bundle_type == "offline-bundle":
            for reference in sorted(set(required) - {image["reference"] for image in images}):
                target = workspace / f"acquired-{len(images)}.tar"
                acquisition_evidence.append(_acquire_image(reference, target, workspace, configuration))
                images.append({"reference": reference, "source_path": target, "archive_path": f"images/{len(images)}.tar"})
        # Use the materialized tree after recursive acquisition; retain values order.
        source_root = workspace / "source"
        paths = list(source_root.rglob("*"))
        if any(path.is_symlink() for path in paths) or sum(path.stat().st_size for path in paths if path.is_file()) > 200 * 1024 ** 2:
            raise ValueError("Final chart source tree exceeds safe assembly limits")
        sources = {path.relative_to(source_root).as_posix(): path.read_bytes() for path in paths if path.is_file()}
        chart_prefix = chart_path.rstrip("/") + "/" if chart_path != "." else ""
        chart_files = {name: "sha256:" + hashlib.sha256(content).hexdigest() for name, content in sources.items()
                       if not chart_prefix or name.startswith(chart_prefix)}
        chart_identity = "sha256:" + hashlib.sha256(json.dumps(chart_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        output = Path(root) / record.job_key / f"delivery-{attempt_id}.zip"
        if set(sources).intersection(documentation):
            raise ValueError("Remediation documentation conflicts with chart sources")
        sources.update(documentation)
        build_bundle(output, bundle_type=bundle_type,
                     service={"id": record.service.service_key, "version": service_version},
                     source_files=sources, chart_path=chart_path, values_files=values,
                     rendered_manifests=rendered.stdout, image_archives=images,
                     evidence={"render": {"tool": "helm", "status": "PASSED", "valuesFiles": values,
                                           "requiredImages": sorted(required)},
                               "dependencies": dependencies, "acquisitions": acquisition_evidence},
                     provenance={"remediationJob": record.job_key, "sourceExecutionId": record.source_execution_id,
                                 "sourceVersionId": record.source_version_id, "candidateDigest": record.artifact_digest,
                                 "embeddedDeployment": {"type": "helm", "chartPath": chart_path,
                                                        "identityType": "source_tree_sha256", "digest": chart_identity}})
        return {"validation_type": bundle_type, "materialized_digest": file_digest(output),
                "service": {"id": record.service.service_key, "version": service_version},
                "artifact_identities": [{"kind": "bundle", "reference": output.name,
                                         "digest": file_digest(output), "identity_type": "bundle_sha256"},
                                        {"kind": "embedded-helm-deployment", "reference": chart_path,
                                         "digest": chart_identity, "identity_type": "source_tree_sha256"}]}, str(output)
