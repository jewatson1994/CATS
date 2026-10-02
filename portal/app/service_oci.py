"""Service-owned OCI delivery destinations; secrets never enter public responses."""
from __future__ import annotations

import base64
import hmac
import re
import ssl
import urllib.error
import urllib.request
from contextlib import contextmanager
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import Boolean, ForeignKey, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .auth import AuthContext, record_audit, require_permission
from .database import Base, get_db
from .models import Service
from .secrets import decrypt_secret, encrypt_secret, secret_configured
from .trusted_ca import ephemeral_trust


class ServiceOCIDestination(Base):
    __tablename__ = "service_oci_destinations"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    endpoint: Mapped[str] = mapped_column(String(500))
    namespace: Mapped[str] = mapped_column(String(300), default="")
    username: Mapped[str] = mapped_column(Text, default="")
    password: Mapped[str] = mapped_column(Text, default="")
    ca_pem: Mapped[str] = mapped_column(Text, default="")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)


def validate_destination(data):
    name = str(data.get("name", "")).strip()
    endpoint = str(data.get("endpoint", "")).strip().rstrip("/")
    parsed = urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(422, "Invalid OCI endpoint") from None
    if (not name or len(name) > 160 or len(endpoint) > 500 or parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", parsed.hostname)):
        raise HTTPException(422, "Use a named, credential-free HTTPS registry endpoint")
    namespace = str(data.get("namespace", "")).strip().strip("/")
    if len(namespace) > 300 or (namespace and not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", namespace)):
        raise HTTPException(422, "Invalid repository namespace")
    ca = str(data.get("ca_pem", ""))
    if len(ca) > 262144:
        raise HTTPException(422, "Destination CA is too large")
    if ca:
        try:
            ssl.create_default_context().load_verify_locations(cadata=ca)
        except (ValueError, ssl.SSLError):
            raise HTTPException(422, "Invalid destination CA certificate") from None
    return {"name": name, "endpoint": endpoint, "namespace": namespace, "ca_pem": ca}


def public_destination(row):
    return {"id": str(row.id), "scope": "service", "name": row.name,
            "endpoint": row.endpoint, "namespace": row.namespace, "is_default": row.is_default,
            "credentials_configured": secret_configured(row.password), "ca_configured": bool(row.ca_pem)}


def resolve_destination(db, service_id, destination_id, global_registries=()):
    """Resolve only a saved service destination or explicitly enabled global default."""
    value = str(destination_id)
    if value.startswith("global:"):
        row = next((r for r in global_registries if str(r.get("id")) == value[7:]
                    and r.get("use_for_remediation") is True), None)
        if not row:
            raise HTTPException(404, "Destination not found")
        validated = validate_destination({"name": row.get("display_name") or "CATS default",
                                          "endpoint": row.get("endpoint"), "namespace": row.get("namespace", ""),
                                          "ca_pem": row.get("ca_pem", "")})
        return {**row, **validated, "id": value, "scope": "global"}
    try:
        destination_id = int(value)
    except ValueError:
        raise HTTPException(404, "Destination not found") from None
    row = db.scalar(select(ServiceOCIDestination).where(ServiceOCIDestination.id == destination_id,
                                                       ServiceOCIDestination.service_id == service_id))
    if not row:
        raise HTTPException(404, "Destination not found")
    return {**public_destination(row), "username": decrypt_secret(row.username),
            "password": row.password, "ca_pem": row.ca_pem}


@contextmanager
def destination_trust(destination):
    """Private CA scope ends when this destination operation ends."""
    ca = destination.get("ca_pem")
    with ephemeral_trust([{"pem": ca}] if ca else []) as trust:
        yield trust


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def test_connection(destination):
    result = {"tls": "NOT TESTED", "authentication": "NOT TESTED", "registry_api": "NOT TESTED",
              "push": "NOT TESTED", "helm_oci": "NOT TESTED", "image_publish": "NOT TESTED",
              "detail": "Push, image publishing and Helm OCI support require an actual artifact operation."}
    try:
        context = ssl.create_default_context()
        if destination.get("ca_pem"):
            context.load_verify_locations(cadata=destination["ca_pem"])
        request = urllib.request.Request(destination["endpoint"] + "/v2/")
        username = destination.get("username", "")
        password = decrypt_secret(destination.get("password", ""))
        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            request.add_header("Authorization", "Basic " + token)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
        with opener.open(request, timeout=10) as response:
            result.update(tls="PASSED", authentication="PASSED" if password else "ANONYMOUS",
                          registry_api="PASSED" if response.status == 200 and response.headers.get("Docker-Distribution-Api-Version") == "registry/2.0" else "UNCONFIRMED")
    except urllib.error.HTTPError as exc:
        result.update(tls="PASSED", authentication="FAILED" if exc.code in (401, 403) else "UNCONFIRMED",
                      registry_api="REACHABLE", detail="Registry rejected the connection request.")
    except Exception:
        result.update(tls="FAILED OR UNAVAILABLE", detail="Connection failed; check endpoint, credentials and destination CA trust.")
    return result


router = APIRouter(prefix="/api/services/{service_key}/oci-destinations", tags=["service OCI"])


def _service(db, key):
    row = db.scalar(select(Service).where(Service.service_key == key))
    if not row:
        raise HTTPException(404, "Service not found")
    return row


def _csrf(request, auth):
    if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), auth.csrf_token):
        raise HTTPException(403, "Invalid CSRF token")


@router.get("")
def destinations(service_key: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    service = _service(db, service_key)
    return [public_destination(r) for r in db.scalars(select(ServiceOCIDestination).where(ServiceOCIDestination.service_id == service.id))]


async def _save(request, service_key, destination_id, db, auth):
    _csrf(request, auth)
    service = _service(db, service_key)
    row = None
    if destination_id is not None:
        row = db.scalar(select(ServiceOCIDestination).where(ServiceOCIDestination.id == destination_id, ServiceOCIDestination.service_id == service.id))
        if not row:
            raise HTTPException(404, "Destination not found")
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(422, "Destination object required")
    merged = {"name": row.name, "endpoint": row.endpoint, "namespace": row.namespace, "ca_pem": row.ca_pem} if row else {}
    values = validate_destination({**merged, **data})
    if row is None:
        row = ServiceOCIDestination(service_id=service.id)
        db.add(row)
    for key, value in values.items():
        setattr(row, key, value)
    for key in ("username", "password"):
        if key in data:
            if not isinstance(data[key], str) or len(data[key]) > 16384:
                raise HTTPException(422, "Invalid credential value")
            try:
                setattr(row, key, encrypt_secret(data[key]))
            except ValueError:
                raise HTTPException(503, "Encrypted secret storage is unavailable") from None
    if "is_default" in data:
        if not isinstance(data["is_default"], bool):
            raise HTTPException(422, "Default selection must be boolean")
        row.is_default = data["is_default"]
    if row.is_default:
        for other in db.scalars(select(ServiceOCIDestination).where(ServiceOCIDestination.service_id == service.id)):
            if other is not row:
                other.is_default = False
    db.flush()
    record_audit(db, auth, "service.oci.updated" if destination_id else "service.oci.created", "service", service.id, destination_id=row.id)
    db.commit()
    return public_destination(row)


@router.post("")
async def create(request: Request, service_key: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    return await _save(request, service_key, None, db, auth)


@router.patch("/{destination_id}")
async def update(request: Request, service_key: str, destination_id: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    return await _save(request, service_key, destination_id, db, auth)


@router.delete("/{destination_id}")
def delete(request: Request, service_key: str, destination_id: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    _csrf(request, auth)
    service = _service(db, service_key)
    row = db.scalar(select(ServiceOCIDestination).where(ServiceOCIDestination.id == destination_id, ServiceOCIDestination.service_id == service.id))
    if not row:
        raise HTTPException(404, "Destination not found")
    db.delete(row)
    record_audit(db, auth, "service.oci.deleted", "service", service.id, destination_id=destination_id)
    db.commit()
    return {"deleted": True}


@router.post("/{destination_id}/test")
def connection(request: Request, service_key: str, destination_id: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    _csrf(request, auth)
    service = _service(db, service_key)
    result = test_connection(resolve_destination(db, service.id, destination_id))
    record_audit(db, auth, "service.oci.tested", "service", service.id, destination_id=destination_id, result=result)
    db.commit()
    return result
