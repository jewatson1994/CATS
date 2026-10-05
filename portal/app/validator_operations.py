"""Operational extensions of the existing authenticated validator API."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import uuid
import asyncio
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from fastapi import HTTPException, Request

from .deployment_validation import ValidationArtifact, ValidationConfig, KindDeploymentValidator

TLS_RELOAD = None
IDENTITY_LOCK = threading.Lock()


def validator_identity():
    identity = os.getenv("CATS_VALIDATOR_ID", "")
    host = os.getenv("CATS_VALIDATOR_HOST", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", identity) or not host:
        raise ValueError("Managed validator identity is not configured")
    return identity, host


def identity_directory():
    from . import validator_api as api
    directory = api.STATE_DIR / "identity"
    if directory.is_symlink():
        raise ValueError("Unsafe identity directory")
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory


def private_write(path, payload):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def create_csr(client_identity):
    identity, host = validator_identity()
    directory = identity_directory()
    with IDENTITY_LOCK:
        pending = directory / "pending.json"
        if pending.exists():
            raise ValueError("Certificate rotation is already pending")
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        key_path = directory / (uuid.uuid4().hex + ".key")
        private_write(key_path, key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        try:
            hostname = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            hostname = x509.DNSName(host)
        csr = (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)]))
            .add_extension(x509.SubjectAlternativeName([hostname,
                x509.UniformResourceIdentifier("urn:cats:validator:" + identity)]), critical=False)
            .sign(key, hashes.SHA256()))
        try:
            private_write(pending, json.dumps({"key": str(key_path), "client": client_identity}).encode())
        except Exception:
            key_path.unlink(missing_ok=True)
            raise
        return {"validator_id": identity, "csr": csr.public_bytes(serialization.Encoding.PEM).decode()}


def install_certificate(body, client_identity):
    identity, host = validator_identity()
    directory = identity_directory()
    with IDENTITY_LOCK:
        if TLS_RELOAD is None:
            raise ValueError("Live TLS certificate reload is unavailable")
        pending_path = directory / "pending.json"
        pending = json.loads(pending_path.read_text())
        if pending.get("client") != client_identity:
            raise ValueError("Rotation belongs to another authenticated client")
        key_path = Path(pending["key"])
        if key_path.parent != directory or key_path.is_symlink():
            raise ValueError("Unsafe pending identity")
        certificate = x509.load_pem_x509_certificate(str(body.get("certificate", "")).encode())
        trust = x509.load_pem_x509_certificate(Path(os.environ["CATS_VALIDATOR_CLIENT_CA"]).read_bytes())
        supplied_ca = body.get("ca_certificate")
        if supplied_ca and x509.load_pem_x509_certificate(supplied_ca.encode()).fingerprint(hashes.SHA256()) != trust.fingerprint(hashes.SHA256()):
            raise ValueError("Rotation cannot change the enrolled CA")
        if certificate.issuer != trust.subject:
            raise ValueError("Certificate issuer does not match enrolled CA")
        public = trust.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), certificate.signature_hash_algorithm)
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(certificate.signature_hash_algorithm))
        else:
            raise ValueError("Unsupported CA key")
        now = datetime.now(timezone.utc)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("Certificate is outside its validity period")
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError("Certificate does not match locally generated key")
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        try:
            host_valid = ipaddress.ip_address(host) in names.get_values_for_type(x509.IPAddress)
        except ValueError:
            host_valid = host in names.get_values_for_type(x509.DNSName)
        if not host_valid or "urn:cats:validator:" + identity not in names.get_values_for_type(x509.UniformResourceIdentifier):
            raise ValueError("Certificate identity or host differs from enrolled validator")
        if certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != identity:
            raise ValueError("Certificate subject differs from enrolled validator")
        if ExtendedKeyUsageOID.SERVER_AUTH not in certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError("Certificate does not permit TLS server authentication")
        if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Server certificate cannot be a CA")
        cert_path = directory / (uuid.uuid4().hex + ".pem")
        private_write(cert_path, certificate.public_bytes(serialization.Encoding.PEM) + trust.public_bytes(serialization.Encoding.PEM))
        current = directory / "current.json"
        previous = current.read_bytes() if current.exists() else None
        staged = directory / (uuid.uuid4().hex + ".json")
        private_write(staged, json.dumps({"certificate": str(cert_path), "key": str(key_path)}).encode())
        try:
            TLS_RELOAD(str(cert_path), str(key_path))
            os.replace(staged, current)
        except Exception:
            # Restore the old in-memory certificate if durable activation failed.
            old = json.loads(previous) if previous else {"certificate": os.environ["CATS_VALIDATOR_SERVER_CERT"], "key": os.environ["CATS_VALIDATOR_SERVER_KEY"]}
            TLS_RELOAD(old["certificate"], old["key"])
            staged.unlink(missing_ok=True)
            cert_path.unlink(missing_ok=True)
            raise
        pending_path.unlink()
        return {"validator_id": identity, "status": "ROTATED", "certificate_fingerprint": certificate.fingerprint(hashes.SHA256()).hex()}


def self_test_artifact(job_id):
    configured = os.getenv("CATS_VALIDATOR_SELF_TEST_DIR", "")
    if not configured:
        raise ValueError("Trusted local self-test payload is not configured")
    configured_path = Path(configured).absolute()
    if any(path.is_symlink() for path in (configured_path, *configured_path.parents)):
        raise ValueError("Self-test payload root contains a symlink")
    root = configured_path.resolve(strict=True)
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("Invalid self-test manifest")
    from .validator_protocol import strict_json_loads
    manifest = strict_json_loads(manifest_path.read_bytes())
    if not isinstance(manifest, dict) or set(manifest) != {"chart", "archive", "image", "sha256"}:
        raise ValueError("Invalid self-test manifest fields")
    def local(name):
        if not isinstance(name, str) or not name or "\\" in name:
            raise ValueError("Invalid self-test payload path")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
            raise ValueError("Self-test payload path escapes its root")
        candidate = root / relative
        if any((root / Path(*relative.parts[:index])).is_symlink() for index in range(1, len(relative.parts) + 1)) or not candidate.resolve(strict=True).is_relative_to(root):
            raise ValueError("Self-test payload path escapes its root")
        return candidate
    chart = local(manifest["chart"])
    archive = local(manifest["archive"])
    image = manifest["image"]
    if not isinstance(image, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("Self-test image must use a digest-pinned local reference")
    if not chart.is_dir() or not archive.is_file() or not (chart / "Chart.yaml").is_file():
        raise ValueError("Incomplete local self-test payload")
    declared = manifest["sha256"]
    if not isinstance(declared, dict) or not declared or len(declared) > 1000:
        raise ValueError("Invalid self-test checksums")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError("Unsafe self-test payload entry")
        if path.is_file() and path != manifest_path:
            actual.add(path.relative_to(root).as_posix())
    required = {manifest["archive"]} | {path.relative_to(root).as_posix() for path in chart.rglob("*") if path.is_file()}
    if set(declared) != actual or actual != required:
        raise ValueError("Self-test manifest does not cover exact payload files")
    for name, expected in declared.items():
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid self-test checksum")
        digest = hashlib.sha256()
        with local(name).open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("Self-test payload integrity verification failed")
    files = {}
    for path in chart.rglob("*"):
        if path.is_symlink():
            raise ValueError("Self-test chart contains a symlink")
        if path.is_file():
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("Self-test chart file exceeds limit")
            files[path.relative_to(chart).as_posix()] = path.read_text()
    if sum(len(value.encode()) for value in files.values()) > 16 * 1024 * 1024:
        raise ValueError("Self-test chart exceeds limit")
    return ValidationArtifact(source_files=files, image_archives={image: str(archive)},
        expected_images=[image], offline=True, require_helm_lifecycle=True, job_id=job_id)


def execute_self_test(job_id):
    from . import validator_api as api
    phases = []
    current = ["PREFLIGHT"]
    with api.LOCK:
        api.RUNNING.add(job_id)
    def progress(phase):
        current[0] = phase
        if phase not in phases:
            phases.append(phase)
        api._update(job_id, status="RUNNING", phase=phase, stages=list(phases))
    try:
        progress("PREFLIGHT")
        artifact = self_test_artifact(job_id)
        config = ValidationConfig.from_env()
        config.strict_sandbox_policy = True
        config.permissive_workloads = False
        config.allow_network_egress = False
        config.require_local_images = True
        config.workspace_root = str(api.STATE_DIR / "workspaces")
        config.total_timeout_seconds = api.MAX_TIMEOUT
        if "@sha256:" not in config.kind_node_image:
            raise ValueError("Self-test requires a digest-pinned node image")
        result = KindDeploymentValidator(config, runner=api._runner(job_id, current)).validate_artifact(artifact, progress_callback=progress)
        safe = api._safe_result(result)
        helm = safe.get("helm_result") or {}
        passed = (safe.get("status") == "VERIFIED" and safe.get("cleanup_status") == "COMPLETE"
            and (safe.get("offline") or {}).get("network_isolated") is True
            and (safe.get("offline") or {}).get("external_image_pulls") == 0
            and (safe.get("offline") or {}).get("external_chart_fetches") == 0
            and helm.get("install") == "PASS" and helm.get("release_status") == "DEPLOYED"
            and helm.get("execution_mode") != "PREFLIGHTED_MANIFEST_APPLY")
        with api.LOCK:
            cancelled = api.JOBS[job_id].get("cancel_requested", False)
        if cancelled:
            safe["status"] = "CANCELLED"
        api._update(job_id, status="CANCELLED" if cancelled else "PASSED" if passed else "FAILED", phase="COMPLETE", completed_at=api._now(), result=safe, stages=phases)
    except Exception:
        api._update(job_id, status="FAILED", phase="COMPLETE", completed_at=api._now(), stages=phases,
            result={"status": "ERROR", "reason_category": "SELF_TEST_ERROR", "cleanup_status": "FAILED"})
    finally:
        with api.LOCK:
            api.RUNNING.discard(job_id)


def register_routes(app):
    @app.post("/api/v1/self-tests", status_code=202)
    def start_self_test(request: Request):
        from . import validator_api as api
        with api.LOCK:
            if sum(row["status"] in {"QUEUED", "RUNNING"} for row in api.JOBS.values()) >= api.MAX_JOBS or len(api.JOBS) >= api.MAX_RECORDS:
                raise HTTPException(429, "Validator capacity is full")
            job_id = uuid.uuid4().hex
            record = {"validation_id": job_id, "id": job_id, "kind": "SELF_TEST", "schema_version": "cats.validation/v1",
                "status": "QUEUED", "phase": "QUEUED", "created_at": api._now(), "cancel_requested": False,
                "client_identity": request.state.client_identity, "stages": []}
            api.JOBS[job_id] = record
            api._persist(record)
        api.EXECUTOR.submit(execute_self_test, job_id)
        return {"id": job_id, "status": "QUEUED"}

    @app.get("/api/v1/self-tests/{job_id}")
    def self_test_result(job_id: str, request: Request):
        from . import validator_api as api
        with api.LOCK:
            record = api.JOBS.get(job_id)
            if not re.fullmatch(r"[0-9a-f]{32}", job_id) or not record or record.get("kind") != "SELF_TEST" or record.get("client_identity") != request.state.client_identity:
                raise HTTPException(404)
            return {key: value for key, value in record.items() if key != "client_identity"}

    @app.post("/api/v1/identity/csr")
    def csr(request: Request):
        try:
            return create_csr(request.state.client_identity)
        except (ValueError, OSError):
            raise HTTPException(409, "Identity rotation is not available")

    @app.post("/api/v1/identity/certificate")
    async def certificate(request: Request):
        try:
            raw = bytearray()
            async with asyncio.timeout(30):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > 65536:
                        raise HTTPException(413, "Certificate payload too large")
                    raw.extend(chunk)
            from .validator_protocol import strict_json_loads
            body = strict_json_loads(raw)
            if not isinstance(body, dict):
                raise ValueError("Certificate payload must be an object")
            return install_certificate(body, request.state.client_identity)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(422, "Certificate rotation rejected")
