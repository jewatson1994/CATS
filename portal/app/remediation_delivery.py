"""Delivery of retained candidates. This module never invokes remediation tools."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import yaml
from zipfile import ZipFile, ZIP_DEFLATED
from datetime import datetime, timezone
from sqlalchemy import ForeignKey, String, JSON, DateTime, Text, select
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .secrets import decrypt_secret
from .service_oci import destination_trust, validate_destination
from .deployment_bundle import file_digest


class DeliveryAttempt(Base):
    __tablename__ = "remediation_delivery_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    remediation_id: Mapped[int] = mapped_column(ForeignKey("remediation_executions.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    destination: Mapped[dict] = mapped_column(JSON, default=dict)
    content_digest: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(30), default="queued")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


def attempt_dto(row):
    return {"id": row.id, "actor_id": row.actor_id, "destination": row.destination, "content_digest": row.content_digest,
            "status": row.status, "result": row.result, "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None}


def retained_candidate(record, root):
    path = Path(record.artifact_path or "")
    root_path = Path(root).resolve()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", record.job_key or ""):
        raise ValueError("Retained candidate is unavailable")
    expected = (root_path / record.job_key).resolve()
    if expected.parent != root_path:
        raise ValueError("Retained candidate is unavailable")
    if path.is_symlink() or not path.is_file() or path.resolve().parent != expected:
        raise ValueError("Retained candidate is unavailable")
    with path.open("rb") as stream:
        digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    if not record.artifact_digest or not hmac.compare_digest(digest, record.artifact_digest):
        raise ValueError("Retained candidate integrity mismatch")
    return path


def checked_inventory(bundle):
    entries = bundle.infolist()
    if len(entries) > 20000 or sum(i.file_size for i in entries) > 8 * 1024**3:
        raise ValueError("Candidate exceeds delivery limits")
    names = set()
    canonical_names = set()
    for info in entries:
        path = PurePosixPath(info.filename)
        if (path.is_absolute() or ".." in path.parts or "\\" in info.orig_filename or ":" in info.filename
                or info.filename in names or path.as_posix() in canonical_names
                or any(part.endswith((" ", ".")) for part in path.parts)
                or (info.external_attr >> 16) & 0o170000 == 0o120000):
            raise ValueError("Unsafe candidate archive entry")
        names.add(info.filename)
        canonical_names.add(path.as_posix())
    return names


def materialize(files, mappings):
    """Replace exact YAML scalar image references, not substrings or policy values."""
    import yaml
    def split_image(value):
        # Match a complete, proven image identity assembled from sibling values.
        # Never replace a registry or repository prefix throughout the chart.
        repository = value.get("repository")
        if not isinstance(repository, str) or not repository or not ({"tag", "digest"} & value.keys()):
            return None
        registry = value.get("registry", "")
        tag, digest = value.get("tag", ""), value.get("digest", "")
        if not isinstance(registry, str) or not isinstance(digest, str) or not isinstance(tag, (str, int, float)) or isinstance(tag, bool):
            return None
        reference = "/".join(part.strip("/") for part in (registry, repository) if part)
        if digest:
            reference += "@" + digest
        elif tag != "":
            reference += ":" + str(tag)
        replacement = mappings.get(reference)
        if not replacement:
            return None
        match = re.fullmatch(r"([^/@]+)/(.*?)@(sha256:[0-9a-f]{64})", replacement)
        if not match:
            raise ValueError("Delivery image mapping requires immutable identity")
        result = dict(value)
        if "registry" in value:
            result["registry"], result["repository"] = match[1], match[2]
        else:
            result["repository"] = match[1] + "/" + match[2]
        result["digest"] = match[3]
        if "tag" in value:
            result["tag"] = ""
        return result
    def visit(value, ancestors=()):
        if isinstance(value, (dict, list)) and id(value) in ancestors:
            raise ValueError("Recursive YAML candidate is unsupported")
        ancestors = (*ancestors, id(value))
        if isinstance(value, list):
            return [visit(v, ancestors) for v in value]
        if isinstance(value, dict):
            split = split_image(value)
            if split is not None:
                return {k: visit(v, ancestors) for k, v in split.items()}
            return {k: mappings.get(v, v) if k in {"image", "repository"} and isinstance(v, str)
                    else visit(v, ancestors) for k, v in value.items()}
        return value
    result = {}
    for path, content in files.items():
        if isinstance(content, bytes):
            # Vendored chart packages are opaque, integrity-preserved input.
            # The rendered-image gate below still rejects stale image identities.
            result[path] = content
            continue
        # Helm template syntax is not YAML. Replace quoted / standalone literals only.
        if "{{" in content:
            for old, new in mappings.items():
                content = re.sub(r"(?m)^(\s*(?:image|repository):\s*)(['\"]?)" + re.escape(old) +
                    r"\2(\s*(?:#.*)?)$", lambda match: match[1] + match[2] + new + match[2] + match[3], content)
            result[path] = content
        elif path.endswith((".yaml", ".yml")):
            result[path] = yaml.safe_dump_all([visit(v) for v in yaml.safe_load_all(content)], sort_keys=False)
        else:
            result[path] = content
    return result


def checked_values_files(values, files):
    """Keep ordered Helm overrides confined to retained candidate files."""
    if not isinstance(values, list) or len(values) > 50:
        raise ValueError("Invalid retained Helm values files")
    seen = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Invalid retained Helm values path")
        path = PurePosixPath(value)
        if (not value or path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value
                or path.as_posix() != value or any(part.endswith((" ", ".")) for part in path.parts)
                or value not in files or value in seen):
            raise ValueError("Helm values files must be confined to retained candidate files")
        seen.add(value)
    return list(values)


def embed_values(files, chart_root, values_files):
    """Helm's ordered values merge, retained inside the exact delivered chart."""
    def mapping(content):
        parsed = yaml.safe_load(content) if content else {}
        if parsed is None:
            return {}
        if not isinstance(parsed, dict):
            raise ValueError("Helm values must be mappings")
        return parsed
    def merge(base, override):
        result = dict(base)
        for key, value in override.items():
            result[key] = merge(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else value
        return result
    name = (PurePosixPath(str(chart_root).replace('\\', '/')) / 'values.yaml').as_posix()
    values = mapping(files.get(name, ''))
    for path in values_files:
        values = merge(values, mapping(files[path]))
    content = yaml.safe_dump(values, sort_keys=False)
    files[name] = content
    return name, content


def deliver(record, destination, attempt_id, root, *, signing_material=None):
    """Copy retained image archives, reconcile/package Helm; never patch or decide."""
    source = retained_candidate(record, root)
    validate_destination(destination)
    if not isinstance(attempt_id, int) or isinstance(attempt_id, bool) or attempt_id < 1:
        raise ValueError("Invalid delivery attempt")
    skopeo, helm = shutil.which("skopeo"), shutil.which("helm")
    host = destination["endpoint"].removeprefix("https://")
    namespace = destination.get("namespace", "")
    prefix = "/".join(p for p in (host, namespace) if p)
    results, mappings = [], {}
    with ZipFile(source) as bundle, tempfile.TemporaryDirectory(prefix="cats-delivery-") as temp:
        names = checked_inventory(bundle)
        manifest = json.loads(bundle.read("manifest.json"))
        values_files = checked_values_files(manifest.get("values_files", []),
            {name[10:] for name in names if name.startswith("candidate/") and not name.endswith("/")})
        work = Path(temp)
        work.chmod(0o700)
        password = decrypt_secret(destination.get("password", ""))
        username = destination.get("username", "")
        authfile = work / "auth.json"
        authfile.write_text(json.dumps({"auths": {host: {"auth": base64.b64encode(f"{username}:{password}".encode()).decode()}}} if username and password else {"auths": {}}))
        authfile.chmod(0o600)
        docker_config = work / "config.json"
        shutil.copyfile(authfile, docker_config)
        docker_config.chmod(0o600)
        def run(args, *, include_stderr=False, **kwargs):
            completed = subprocess.run(args, capture_output=True, text=True, timeout=600, check=False, **kwargs)
            if completed.returncode:
                raise ValueError("Registry operation failed; check destination TLS, authentication and repository permission")
            return completed.stdout + ("\n" + completed.stderr if include_stderr else "")
        with destination_trust(destination) as (ca, trust_env):
            env = {**os.environ, **trust_env, "HELM_REGISTRY_CONFIG": str(authfile), "DOCKER_CONFIG": str(work)}
            certdir = work / "certs"
            certdir.mkdir()
            if ca:
                shutil.copyfile(ca, certdir / "ca.crt")
            for image in manifest.get("images", []):
                archive_name = image.get("archive_path")
                if not archive_name:
                    continue
                if not skopeo or archive_name not in names or not re.fullmatch(r"images/[0-9a-f]{32}\.tar", archive_name):
                    raise ValueError("Retained image archive or delivery tool unavailable")
                archive = work / Path(archive_name).name
                with bundle.open(archive_name) as stream, archive.open("wb") as target:
                    shutil.copyfileobj(stream, target)
                with archive.open("rb") as stream:
                    actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
                expected = image.get("artifact_sha256")
                if not expected or not hmac.compare_digest(actual.removeprefix("sha256:"), expected.removeprefix("sha256:")):
                    raise ValueError("Retained image archive integrity mismatch")
                repository = "image-" + Path(archive_name).stem
                target = f"{prefix}/{repository}:{record.job_key.lower()}"
                digestfile = work / (repository + ".digest")
                run([skopeo, "copy", "--authfile", str(authfile), "--dest-cert-dir", str(certdir),
                     "--digestfile", str(digestfile),
                     "docker-archive:" + str(archive), "docker://" + target], env=env)
                digest = run([skopeo, "inspect", "--authfile", str(authfile), "--cert-dir", str(certdir),
                              "--format", "{{.Digest}}", "docker://" + target], env=env).strip()
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    raise ValueError("Registry did not return immutable image identity")
                copied_digest = digestfile.read_text().strip() if digestfile.is_file() else ""
                if not hmac.compare_digest(copied_digest, digest):
                    raise ValueError("Published image identity differs from retained delivery content")
                reference = target.split(":", 1)[0] if ":" not in host else target.rsplit(":", 1)[0]
                reference += "@" + digest
                mappings[image["remediated"]] = reference
                results.append({"kind": "image", "reference": reference, "digest": digest, "identity_type": "oci_manifest"})
            files = materialize({name[10:]: (bundle.read(name) if name.endswith(".tgz") else bundle.read(name).decode("utf-8")) for name in names if name.startswith("candidate/") and not name.endswith("/")}, mappings)
            candidate = work / "candidate"
            candidate.mkdir()
            for relative, content in files.items():
                target = candidate / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    target.write_bytes(content)
                else:
                    target.write_text(content, encoding="utf-8")
            charts = []
            chart_roots = [path.parent for path in candidate.rglob("Chart.yaml")
                           if "charts" not in path.relative_to(candidate).parts[:-1]]
            if chart_roots and not helm:
                raise ValueError("Helm delivery tool unavailable")
            if username and password and helm and chart_roots:
                args = [helm, "registry", "login", host, "--username", username, "--password-stdin"]
                if ca:
                    args += ["--ca-file", str(ca)]
                run(args, env=env, input=password + "\n")
            rendered_images = set()
            def collect_images(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key == "image" and isinstance(child, str):
                            rendered_images.add(child)
                        else:
                            collect_images(child)
                elif isinstance(value, list):
                    for child in value:
                        collect_images(child)
            for chart_root in chart_roots:
                name, content = embed_values(files, chart_root.relative_to(candidate), values_files)
                (candidate / name).write_text(content, encoding="utf-8")
                run([helm, "lint", str(chart_root)], env=env)
                rendered = run([helm, "template", "cats-delivery", str(chart_root)], env=env)
                for document in yaml.safe_load_all(rendered):
                    collect_images(document)
            if chart_roots and mappings and (set(mappings) & rendered_images or not set(mappings.values()).issubset(rendered_images)):
                raise ValueError("Rendered Helm images do not match immutable delivery identities")
            for chart_root in chart_roots:
                package_dir = work / "packages"
                package_dir.mkdir(exist_ok=True)
                before = set(package_dir.glob("*.tgz"))
                run([helm, "package", str(chart_root), "--destination", str(package_dir)], env=env)
                packages = set(package_dir.glob("*.tgz")) - before
                if len(packages) != 1:
                    raise ValueError("Helm package output ambiguous")
                archive = packages.pop()
                push_args = [helm, "push", str(archive), "oci://" + prefix]
                if ca:
                    push_args += ["--ca-file", str(ca)]
                output = run(push_args, env=env, include_stderr=True)
                match = re.search(r"(?im)^Digest:\s*(sha256:[0-9a-f]{64})\s*$", output)
                if not match:
                    raise ValueError("Helm registry did not return immutable identity")
                digest = file_digest(archive)
                charts.append(archive)
                results.extend([{"kind": "helm", "reference": archive.name, "digest": digest, "identity_type": "package_sha256"},
                                {"kind": "helm", "reference": prefix + "/" + str(yaml.safe_load((chart_root / "Chart.yaml").read_text())["name"]) + "@" + match.group(1), "digest": match.group(1), "identity_type": "oci_manifest"}])
            if not results:
                raise ValueError("No deliverable artifacts in retained candidate")
            for identity in results:
                identity["signature_status"] = "not_requested"
                if signing_material and identity["identity_type"] == "oci_manifest":
                    from .signing import sign_and_verify
                    try:
                        identity.update(sign_and_verify(identity["reference"], *signing_material, env))
                    except Exception:
                        # Publication and signing are independent, truthful outcomes.
                        identity["signature_status"] = "failed"
            output_path = source.parent / f"delivery-{attempt_id}.zip"
            with ZipFile(output_path, "w", ZIP_DEFLATED) as output:
                output.writestr("lineage.json", json.dumps({"remediation": record.job_key, "content_digest": record.artifact_digest, "artifacts": results, "values_files": values_files}))
                for relative, content in files.items():
                    output.writestr("candidate/" + relative, content)
                for archive in charts:
                    output.write(archive, "helm/" + archive.name)
            digest = file_digest(output_path)
            signatures = [item["signature_status"] for item in results if item["identity_type"] == "oci_manifest"]
            return {"artifact_identities": results, "materialized_digest": digest,
                    "values_files": values_files,
                    "values_embedded": True,
                    "signing_status": "failed" if "failed" in signatures else "verified" if signatures and all(value == "verified" for value in signatures) else "not_requested"}, str(output_path)
