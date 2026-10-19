"""Immutable release documents shared by OCI and deployment bundle delivery.

Only the delivery executor calls generation; request handlers read bounded receipts.
The signed Export All ZIP is retained unchanged. A signed manifest also binds the
documentation digest and deployable identities. A bundle's outer digest is
recorded after assembly to avoid a self-referential hash.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from sqlalchemy import select

from .models import DeploymentValidationRun
from .deployment_bundle import file_digest
from .remediation_delivery import retained_candidate, candidate_provenance
from .release_exports import write_documentation, _candidate_results
from .release_signing import (sign_release_manifest, verify_release_manifest,
                              sign_release_archive, verify_release_archive)
from .purpose_exports import template_for_service
from .service_oci import destination_trust, validate_destination
from .secrets import decrypt_secret


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _root(record, root):
    candidate = retained_candidate(record, root)
    parent = candidate.parent / "release-documentation"
    if any(path.is_symlink() for path in (parent, *parent.parents)):
        raise ValueError("Unsafe release documentation path")
    parent.mkdir(exist_ok=True)
    return parent


class ReleaseDocumentationError(ValueError):
    def __init__(self, message, signing):
        super().__init__(message)
        self.receipt = {"status": "failed", "signing": signing, "error": message}


def _write(path, value):
    # Publish receipts only after all bytes are durable. An interrupted write
    # cannot turn a recoverable delivery into a permanently corrupt cache.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".release-record-", delete=False) as output:
            temporary = Path(output.name)
            output.write(canonical(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare(db, record, auth, root, artifacts, mode, signing_material):
    """Return (files, receipt), reusing bytes for an unchanged source snapshot."""
    if not auth.has("service.export", record.service_id):
        raise PermissionError("Service export permission required")
    parent = _root(record, root)
    templates = {kind: template_for_service(db, kind, record.service)
                 for kind in ("ppsm", "poam", "asset_list")}
    fields = ("id", "run_key", "execution_id", "artifact_revision_id", "status", "phase",
              "artifact_type", "reason_category", "cleanup_status")
    validations = [dict(zip(fields, row)) for row in db.execute(select(
        *(getattr(DeploymentValidationRun, field) for field in fields)).where(
            DeploymentValidationRun.service_id == record.service_id,
            DeploymentValidationRun.execution_id == record.source_execution_id
        ).order_by(DeploymentValidationRun.id).limit(101))]
    key = _identity({"export_format": "cats-export-all-v1",
                     "bundle_export": auth.has("bundle.export", record.service_id),
                     "source_execution_id": record.source_execution_id,
                     "source_version_id": record.source_version_id,
                     "candidate": record.artifact_digest, "templates": templates,
                     "validation": _candidate_results(record.validation_results or {}),
                     "deployment_validation": validations,
                     "changes": (record.validation_results or {}).get("summary_of_changes")})
    snapshot_path = parent / key
    if snapshot_path.is_symlink():
        raise ValueError("Unsafe release snapshot path")
    snapshot_path.mkdir(exist_ok=True)
    documentation = snapshot_path / "documentation.zip"
    receipt_path = snapshot_path / "snapshot.json"
    if receipt_path.exists():
        snapshot = json.loads(receipt_path.read_text(encoding="utf-8"))
        if documentation.is_symlink() or file_digest(documentation) != snapshot["digest"]:
            raise ValueError("Retained release documentation integrity mismatch")
    else:
        # Incomplete generation has no authoritative receipt; the generator uses
        # atomic replacement and cleans its own temporary file on exceptions.
        manifest = write_documentation(db, record, auth, documentation)
        snapshot = {"manifest": manifest, "digest": file_digest(documentation),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "bytes": documentation.stat().st_size}
        _write(receipt_path, snapshot)
    identities = []
    for item in artifacts:
        identity = {key: item[key] for key in ("kind", "reference", "digest", "identity_type") if key in item}
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(identity.get("digest", ""))):
            raise ValueError("Release artifact must have an immutable SHA-256 identity")
        identities.append(identity)
    if not identities:
        raise ValueError("Release documentation requires deployable artifact identities")
    manifest = {"schema": "cats.release/v1", "generated_at": snapshot["generated_at"],
                "snapshot": {**snapshot["manifest"], "remediation": candidate_provenance(record),
                             "deployment_validation": validations},
                "documentation": {"file": "documentation.zip", "digest": snapshot["digest"], "bytes": snapshot["bytes"]},
                "delivery_mode": mode, "artifacts": identities,
                "signer": {"fingerprint": signing_material[0].get("signing_fingerprint"),
                           "required": signing_material[0].get("signing_enabled") is True}}
    revision = _identity(manifest)
    directory = snapshot_path / revision
    if directory.is_symlink():
        raise ValueError("Unsafe release revision path")
    directory.mkdir(exist_ok=True)
    manifest_path = directory / "release-manifest.json"
    if manifest_path.exists():
        if manifest_path.is_symlink() or manifest_path.read_bytes() != canonical(manifest):
            raise ValueError("Immutable release manifest mismatch")
    else:
        _write(manifest_path, manifest)
    signature_path = directory / "signing.json"
    if signature_path.exists():
        signing = json.loads(signature_path.read_text(encoding="utf-8"))
        if signing.get("status") == "signed":
            verified = verify_release_manifest(manifest_path, directory / "release-manifest.sig",
                                               directory / "release-public-key.pem",
                                               expected_fingerprint=signing.get("key_fingerprint"))
            archive_verified = verify_release_archive(documentation, directory / "documentation.zip.sig",
                                                       directory / "release-public-key.pem",
                                                       expected_fingerprint=signing.get("key_fingerprint"))
            if verified.get("status") != "verified":
                raise ReleaseDocumentationError("Retained release signature verification failed", verified)
            if archive_verified.get("status") != "verified":
                raise ReleaseDocumentationError("Retained documentation ZIP signature verification failed", archive_verified)
    else:
        signing = sign_release_manifest(manifest_path, directory, signing_material)
        if signing["status"] == "verification_failed":
            raise ReleaseDocumentationError("Release signature verification failed", signing)
        if signing.get("status") == "signed":
            archive_signing = sign_release_archive(documentation, directory, signing_material)
            if archive_signing.get("status") != "signed":
                raise ReleaseDocumentationError("Documentation ZIP signature verification failed", archive_signing)
            signing = {**signing, "archive": archive_signing}
        _write(signature_path, signing)
    if manifest["signer"]["required"] and signing.get("status") != "signed":
        raise ValueError("Mandatory release signing did not complete")
    instructions = directory / "VERIFY.txt"
    if not instructions.exists():
        instructions.write_text(
            "CATS immutable release documentation\n"
            "Check release-manifest.json snapshot service/version and every deployable artifact digest.\n"
            "Compute SHA-256 of documentation.zip and compare to documentation.digest in release-manifest.json.\n"
            "Signed releases: obtain the approved public-key fingerprint independently of this download.\n"
            "cosign verify-blob --key release-public-key.pem --signature documentation.zip.sig "
            "--insecure-ignore-tlog=true --offline documentation.zip\n"
            "cosign verify-blob --key release-public-key.pem --signature release-manifest.sig "
            "--insecure-ignore-tlog=true --offline release-manifest.json\n"
            "Unsigned releases provide integrity identifiers only, not authenticity.\n"
            "Bundle: release manifest binds embedded deployment/source tree, rendered.yaml and image archives; "
            "the outer bundle digest and final validation receipt are recorded after assembly in CATS.\n"
            "documentation.zip is Export All captured from current service data at generation time. "
            "The source execution in the release manifest identifies the remediation baseline, not the "
            "scope of every exported entry. No new scan was performed to generate this documentation.\n",
            encoding="utf-8")
    files = {"documentation.zip": documentation, "release-manifest.json": manifest_path, "VERIFY.txt": instructions}
    if signing.get("status") == "signed":
        files.update({name: directory / name for name in ("documentation.zip.sig", "release-manifest.sig", "release-public-key.pem")})
    receipt = {"status": "ready", "sha256": snapshot["digest"], "revision": revision,
               "storage_key": f"{key}/{revision}", "manifest": manifest, "signing": signing,
               "files": {name: file_digest(path) for name, path in files.items()}, "publications": []}
    return files, receipt


def retained_files(record, root, receipt):
    key = receipt.get("storage_key", "")
    if not re.fullmatch(r"[0-9a-f]{64}/[0-9a-f]{64}", key):
        raise ValueError("Invalid retained release identity")
    parent = _root(record, root)
    directory = parent / key
    files = {}
    for name, digest in receipt.get("files", {}).items():
        if name not in {"documentation.zip", "release-manifest.json", "VERIFY.txt", "documentation.zip.sig", "release-manifest.sig", "release-public-key.pem"}:
            raise ValueError("Invalid retained release file")
        path = directory.parent / name if name == "documentation.zip" else directory / name
        if any(p.is_symlink() for p in (path, *path.parents)) or file_digest(path) != digest:
            raise ValueError("Retained release file integrity mismatch")
        files[name] = path
    if not {"documentation.zip", "release-manifest.json"}.issubset(files):
        raise ValueError("Retained release files unavailable")
    return files


@contextmanager
def registry_environment(destination, certificates=()):
    validate_destination(destination)
    with tempfile.TemporaryDirectory(prefix="cats-release-registry-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        password = decrypt_secret(destination.get("password", ""))
        username = destination.get("username", "")
        host = destination["endpoint"].removeprefix("https://")
        config = root / "config.json"
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump({"auths": {host: {"auth": auth}}} if username and password else {"auths": {}}, stream)
        with destination_trust(destination, certificates) as (_, trust):
            yield {**os.environ, **trust, "DOCKER_CONFIG": str(root)}


def publish(files, receipt, destination, checkpoint):
    from .release_oci import publish_documentation
    receipt = {**receipt, "publications": list(receipt.get("publications") or [])}
    identities = [item for item in receipt["manifest"]["artifacts"] if item.get("identity_type") == "oci_manifest"]
    if not identities:
        raise ValueError("No immutable OCI subject available for documentation")
    with registry_environment(destination) as env:
        for item in identities:
            from .remediation_jobs import check_worker
            check_worker()
            result = publish_documentation(files, subject=item["reference"], env=env)
            receipt["publications"] = [r for r in receipt["publications"] if r.get("subject") != item["reference"]] + [result]
            receipt["status"] = "failed" if result.get("status") != "published" else "publishing"
            checkpoint(receipt)
            if result.get("status") != "published":
                raise ValueError("Documentation publication or retrieval verification failed")
    receipt["status"] = "published"
    checkpoint(receipt)
    return receipt
