"""Package a scoped project submission for the existing isolated scan worker."""
from contextlib import ExitStack
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
from zipfile import BadZipFile, ZipFile, is_zipfile

from fastapi import HTTPException
from sqlalchemy import select

from .compose_ingestion import PRIMARY_NAMES
from .helm_sources import normalize_chart_reference
from .models import Service, ServiceGroup
from .oci_transport import valid_image_reference
from .scan_coordination import enqueue_job
from .service_ownership import active_service_predicate
from .trusted_ca import configured_certificates


def _invalid(message):
    raise HTTPException(422, message)


def active_owner_id(db, service_id, *, lock=False):
    query = select(ServiceGroup.group_id).join(Service, Service.id == ServiceGroup.service_id).where(
        Service.id == service_id, active_service_predicate())
    # An ownership-only edit can update the association independently of other service columns.
    owners = list(db.scalars(query.with_for_update(of=ServiceGroup) if lock else query))
    return owners[0] if len(owners) == 1 else None


def _image(reference):
    if not valid_image_reference(reference):
        _invalid("Invalid OCI image reference")
    return reference


def _reference_kind(kind, reference):
    if kind == "auto":
        kind = "helm-chart" if reference.startswith("oci://") else "image"
    if kind == "image":
        return kind, _image(reference)
    if kind == "helm-chart" and reference.startswith("oci://") and len(reference) <= 512:
        try:
            return kind, normalize_chart_reference(reference)
        except ValueError:
            pass
    _invalid("Use a registry image reference or an oci:// Helm chart reference")


def _docker_manifest(value, names):
    if not isinstance(value, list) or not value:
        _invalid("Invalid docker-save image manifest")
    for entry in value:
        if (not isinstance(entry, dict) or not isinstance(entry.get("RepoTags"), list)
                or not entry["RepoTags"] or not isinstance(entry.get("Layers"), list)):
            _invalid("Each archived image must be tagged and include its config and layers")
        for tag in entry["RepoTags"]:
            _image(tag)
        for item in [entry.get("Config"), *entry["Layers"]]:
            if not isinstance(item, str) or str(PurePosixPath(item)) not in names:
                _invalid("Image archive is missing a declared config or layer")


def _oci_index(value, names):
    descriptors = value.get("manifests") if isinstance(value, dict) else None
    if not isinstance(descriptors, list) or not descriptors or "oci-layout" not in names:
        _invalid("Invalid OCI image layout")
    for item in descriptors:
        attrs = item.get("annotations") if isinstance(item, dict) else None
        tag = (attrs.get("io.containerd.image.name") or attrs.get("org.opencontainers.image.ref.name")) if isinstance(attrs, dict) else None
        digest = item.get("digest") if isinstance(item, dict) else None
        if not isinstance(tag, str) or not (":" in tag or "/" in tag):
            _invalid("Each OCI image archive descriptor must have a tagged image name")
        _image(tag)
        if not isinstance(digest, str) or not re.fullmatch("sha256:[a-f0-9]{64}", digest) or "blobs/" + digest.replace(":", "/") not in names:
            _invalid("OCI image archive is missing a declared manifest")


def _upload_kind(path, filename):
    suffix = filename.lower()
    if is_zipfile(path):
        with ZipFile(path) as bundle:
            members = bundle.infolist()
            if len(members) > int(os.getenv("CATS_PUBLIC_MAX_CHART_MEMBERS", "10000")):
                raise HTTPException(413, "Archive has too many entries")
            names = {str(PurePosixPath(member.filename)) for member in members if not member.is_dir()}
        kind = _package_kind(names)
        if kind == "docker-archive":
            _invalid("Package images as a tagged Docker-save or OCI image-layout tar archive")
        return kind, ".zip"
    with path.open("rb") as stream:
        gzip = stream.read(2) == b"\x1f\x8b"
    if not gzip and not suffix.endswith((".tar", ".tar.gz", ".tgz")) and not tarfile.is_tarfile(path):
        return "compose", ".yaml"
    names, manifests = set(), {}
    total = 0
    with tarfile.open(path, "r|*") as archive:
        for index, member in enumerate(archive):
            total += member.size
            if index >= 20000 or total > int(os.getenv("CATS_SCAN_DISK_BYTES", str(8 * 1024**3))):
                raise HTTPException(413, "Archive exceeds the scan workspace budget")
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or "\\" in member.name or ":" in member.name
                    or not (member.isfile() or member.isdir()) or str(name) in names):
                _invalid("Archive contains an unsafe or duplicate member")
            names.add(str(name))
            if member.isfile() and str(name) in {"manifest.json", "index.json"}:
                if member.size > 4 * 1024**2:
                    raise HTTPException(413, "Image archive manifest is too large")
                manifests[str(name)] = archive.extractfile(member).read()
    ext = ".tar.gz" if gzip else ".tar"
    kind = _package_kind(names)
    if kind == "docker-archive" and "manifest.json" in manifests:
        _docker_manifest(json.loads(manifests["manifest.json"]), names)
        return kind, ext
    if "oci-layout" in names and "index.json" in manifests:
        _oci_index(json.loads(manifests["index.json"]), names)
        return "docker-archive", ext
    if kind == "docker-archive":
        _invalid("Image archive has no valid manifest")
    return kind, ext


def _package_kind(names):
    basenames = {PurePosixPath(name).name for name in names}
    chart = "Chart.yaml" in basenames
    image = "manifest.json" in names or "oci-layout" in names
    compose = bool(basenames & PRIMARY_NAMES)
    if sum((chart, image, compose)) > 1:
        _invalid("Archive contains several artifact types. Submit the image, Helm chart or Compose stack separately")
    if image:
        return "docker-archive"
    return "helm-chart" if chart else "compose"


def prepare_scan(db, service, job_id, work_dir, *, kind="auto", reference=None, version=None, filename=None, values=None):
    """Return an uncommitted durable job. The caller owns admission, cleanup and the transaction."""
    from . import main
    if values is not None:
        _invalid("Supply Helm values as part of the uploaded chart")
    if not isinstance(kind, str) or kind not in {"auto", "image", "helm-chart", "docker-archive", "compose"}:
        _invalid("Unknown project scan input kind")
    work_dir = Path(work_dir)
    if not re.fullmatch("[0-9a-f]{32}", job_id) or work_dir.resolve() != (main.PUBLIC_JOB_ROOT.resolve() / job_id):
        raise ValueError("Invalid project job workspace")
    owner_id = active_owner_id(db, service.id, lock=True)
    if owner_id is None:
        raise HTTPException(409, "Project scans require an active service with one owning group")
    version = (version if version is not None else
               (service.current_version.version if service.current_version else service.manual_version) or "Unversioned")
    if not isinstance(version, str) or not version.strip() or len(version) > 120 or any(ord(ch) < 32 or ord(ch) == 127 for ch in version):
        _invalid("Invalid service version")
    version = version.strip()
    if version.lower() == "unknown":
        version = "Unversioned"
    uploaded = work_dir / "submission-input"
    if uploaded.is_symlink():
        _invalid("Invalid artifact upload")
    if bool(reference) == uploaded.is_file():
        _invalid("Supply one registry reference or one artifact upload")
    images, charts, compose, chart_urls = [], [], [], []
    archive, archive_names = None, []
    with ExitStack() as files:
        if reference:
            kind, ref = _reference_kind(kind, reference)
            (images if kind == "image" else chart_urls).append(ref)
        else:
            try:
                detected, extension = _upload_kind(uploaded, filename or "")
            except (BadZipFile, tarfile.TarError, OSError, EOFError, UnicodeError, ValueError, RecursionError):
                _invalid("Unrecognized or corrupt artifact archive")
            if kind != "auto" and detected != kind:
                _invalid("Uploaded artifact does not match its declared kind")
            kind = detected
            safe_filename = {"docker-archive": "images", "helm-chart": "chart", "compose": "compose"}[kind] + extension
            part = (files.enter_context(uploaded.open("rb")), safe_filename)
            archive_names = [safe_filename]
            if kind == "docker-archive":
                archive = part
            elif kind == "helm-chart":
                charts.append(part)
            else:
                compose.append(part)
        skipped, checksum = main._stage_scan_inputs(work_dir, job_id, images, charts, archive, compose, {},
            configured_certificates(db), [], project_submission=True)
    if uploaded.exists():
        if kind == "helm-chart" and extension == ".tar.gz":
            uploaded.rename(work_dir / "retained-chart.tgz")
        else:
            uploaded.unlink()
    return enqueue_job(db, job_id, {
        "job_id": job_id, "job_kind": "scan", "status": "queued", "phase": "queued", "input_digest": checksum,
        "ingest_service_id": service.service_key, "ingest_service_db_id": service.id, "ingest_service_version": version,
        "ingest_scope": "evidence", "pipeline_input_kind": kind, "pipeline_owning_group_id": owner_id,
        "credential_policy": "public", "owner_user_id": None,
        "image_list": "\n".join(images), "chart_url": "\n".join(chart_urls), "chart_names": [name for _, name in charts],
        "archive_names": archive_names, "compose_enabled": bool(compose), "skipped_charts": skipped,
        "summary": {}, "sbom_formats": ["syft-json"], "created_at": main.utcnow().isoformat(),
    })
