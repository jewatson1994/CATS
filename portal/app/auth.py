import hashlib
import hmac
import os
import secrets
import json
import base64
import urllib.parse
import urllib.request
import urllib.error
import ssl
try:
    import jwt
except ImportError:  # Optional until OIDC mode is enabled.
    jwt = None
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Form, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .database import SessionLocal, get_db
from .models import AuditEvent, Group, Role, Service, User, UserRoleAssignment, UserSession


def oidc_enabled(mode: str | None = None) -> bool:
    return (mode or os.getenv("CATS_IDENTITY_MODE", "local")).lower() in {"oidc", "both"}


def oidc_configuration(configuration: dict | None = None) -> dict[str, str]:
    configured = configuration or {}
    return {
        "issuer": str(configured.get("issuer") or os.getenv("CATS_OIDC_ISSUER_URL", "")).rstrip("/"),
        # The portal may reach the provider through a private/internal
        # network address while the user's browser needs a public URL.
        # Keep those authorities separate so server-side exchange stays safe.
        "browser_issuer": str(configured.get("browser_issuer") or os.getenv("CATS_OIDC_BROWSER_ISSUER_URL", "")).rstrip("/"),
        "client_id": str(configured.get("client_id") or os.getenv("CATS_OIDC_CLIENT_ID", "")),
        "client_secret": str(configured.get("client_secret") or os.getenv("CATS_OIDC_CLIENT_SECRET", "")),
        "redirect_uri": str(configured.get("redirect_uri") or os.getenv("CATS_OIDC_REDIRECT_URI", "")),
        "post_logout_redirect_uri": str(configured.get("post_logout_redirect_uri") or os.getenv("CATS_OIDC_POST_LOGOUT_REDIRECT_URI", "")),
        "scopes": str(configured.get("scopes") or os.getenv("CATS_OIDC_SCOPES", "openid profile email")),
        "groups_claim": str(configured.get("groups_claim") or os.getenv("CATS_OIDC_GROUPS_CLAIM", "")),
        "roles_claim": str(configured.get("roles_claim") or os.getenv("CATS_OIDC_ROLES_CLAIM", "")),
        "username_claim": str(configured.get("username_claim") or "preferred_username"),
        "email_claim": str(configured.get("email_claim") or "email"),
    }


def oidc_discovery(configuration: dict | None = None, ca_bundle: str | None = None) -> dict:
    config = oidc_configuration(configuration)
    if not config["issuer"]:
        raise RuntimeError("CATS_OIDC_ISSUER_URL is not configured")
    parsed = urllib.parse.urlparse(config["issuer"])
    if parsed.scheme == "http":
        opener = urllib.request.build_opener()
    else:
        context = ssl.create_default_context()
        if ca_bundle:
            if "BEGIN CERTIFICATE" in ca_bundle:
                context.load_verify_locations(cadata=ca_bundle)
            else:
                context.load_verify_locations(cafile=ca_bundle)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    with opener.open(f"{config['issuer']}/.well-known/openid-configuration", timeout=10) as response:
        return json.load(response)


def oidc_authorization_url(state: str, nonce: str, configuration: dict | None = None, ca_bundle: str | None = None) -> str:
    config = oidc_configuration(configuration)
    discovery = oidc_discovery(configuration, ca_bundle)
    query = urllib.parse.urlencode({
        "client_id": config["client_id"], "response_type": "code", "scope": config["scopes"],
        "redirect_uri": config["redirect_uri"], "state": state, "nonce": nonce,
    })
    endpoint = discovery["authorization_endpoint"]
    browser_issuer = config.get("browser_issuer")
    if browser_issuer:
        internal_issuer = config["issuer"]
        parsed_endpoint = urllib.parse.urlparse(endpoint)
        parsed_internal = urllib.parse.urlparse(internal_issuer)
        parsed_browser = urllib.parse.urlparse(browser_issuer)
        # Rewrite only the provider authority/base path.  Preserve the
        # discovered protocol path and reject unrelated endpoint shapes.
        if parsed_endpoint.scheme and parsed_endpoint.netloc and parsed_internal.path and parsed_endpoint.path.startswith(parsed_internal.path):
            suffix = parsed_endpoint.path[len(parsed_internal.path):]
            # The browser must never receive the Docker-only provider name.
            # Keep the discovered endpoint path, but use the browser-reachable
            # authority/base path and discard any provider-specific query.
            endpoint = urllib.parse.urlunparse(parsed_browser._replace(path=parsed_browser.path.rstrip("/") + suffix, query="", fragment=""))
    return f"{endpoint}?{query}"


def oidc_exchange_code(code: str, configuration: dict | None = None, ca_bundle: str | None = None) -> tuple[dict, dict]:
    config = oidc_configuration(configuration)
    discovery = oidc_discovery(configuration, ca_bundle)
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": config["redirect_uri"], "client_id": config["client_id"],
    }).encode()
    credentials = base64.b64encode(f"{config['client_id']}:{config['client_secret']}".encode()).decode()
    request = urllib.request.Request(discovery["token_endpoint"], data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {credentials}",
    })
    context = ssl.create_default_context()
    if ca_bundle:
        if "BEGIN CERTIFICATE" in ca_bundle:
            context.load_verify_locations(cadata=ca_bundle)
        else:
            context.load_verify_locations(cafile=ca_bundle)
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            tokens = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise ValueError("OIDC token endpoint rejected the client credentials") from exc
        raise ValueError(f"OIDC token endpoint returned HTTP {exc.code}") from exc
    return tokens, discovery


def verify_oidc_id_token(tokens: dict, discovery: dict, expected_nonce: str | None, configuration: dict | None = None) -> dict:
    if jwt is None:
        raise ValueError("OIDC support requires PyJWT; install the portal requirements")
    token = tokens.get("id_token")
    if not token:
        raise ValueError("OIDC token response did not include an ID token")
    signing_key = jwt.PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token)
    config = oidc_configuration(configuration)
    # Some providers publish a browser-facing authority while server-side
    # discovery uses a private address. Both values are administrator-
    # configured and validated.
    expected_issuer = config.get("browser_issuer") or config["issuer"]
    claims = jwt.decode(token, signing_key.key, algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"], audience=config["client_id"], issuer=expected_issuer)
    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise ValueError("OIDC nonce validation failed")
    return claims


def nested_claim(claims: dict, path: str, default=None):
    value = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return default
        value = value.get(part)
    return default if value is None else value


def oidc_claim_values(claims: dict, path: str) -> list[str]:
    value = nested_claim(claims, path, [])
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value] if isinstance(value, list) else []


def oidc_role_names(claims: dict, configuration: dict | None = None) -> list[str]:
    config = oidc_configuration(configuration)
    return sorted(set(oidc_claim_values(claims, config["roles_claim"]))) if config["roles_claim"] else []


def oidc_groups(claims: dict, configuration: dict | None = None) -> list[str]:
    claim = oidc_configuration(configuration)["groups_claim"]
    values = oidc_claim_values(claims, claim) if claim else []
    return sorted(set(item.strip("/") for item in values if item.strip("/")))


def provision_oidc_user(db: Session, claims: dict, configuration: dict | None = None) -> User:
    config = oidc_configuration(configuration)
    subject = str(claims.get("sub") or "").strip()
    username = str(claims.get(config["username_claim"]) or claims.get(config["email_claim"]) or subject).strip().lower()
    if not subject or not username:
        raise ValueError("OIDC token did not contain a subject or username")
    user = db.scalar(select(User).where(User.external_subject == subject))
    if not user:
        user = db.scalar(select(User).where(User.username == username))
    if not user:
        if os.getenv("CATS_OIDC_AUTO_PROVISION", "true").lower() != "true":
            raise ValueError("OIDC user is not provisioned in CATS")
        user = User(username=username[:120], display_name=str(claims.get("name") or username)[:240], auth_source="oidc", must_change_password=False)
        db.add(user); db.flush()
    user.auth_source = "oidc"
    user.external_subject = subject
    user.display_name = str(claims.get("name") or claims.get("email") or user.display_name)[:240]
    user.enabled = True
    role_by_name = {role.name.lower(): role for role in db.scalars(select(Role))}
    mapping = json.loads(os.getenv("CATS_OIDC_ROLE_MAP", "{}"))
    requested = [mapping.get(role, role) for role in oidc_role_names(claims, configuration)]
    default_role = os.getenv("CATS_OIDC_DEFAULT_ROLE", "").strip()
    if default_role:
        requested.append(default_role)
    roles = [role_by_name[name.lower()] for name in requested if name.lower() in role_by_name]
    if not roles:
        raise ValueError("OIDC user did not map to a CATS role")
    groups_by_name = {group.name.lower(): group for group in db.scalars(select(Group))}
    group_role_map = json.loads(os.getenv("CATS_OIDC_GROUP_ROLE_MAP", "{}"))
    for group_name in oidc_groups(claims, configuration):
        group = groups_by_name.get(group_name.lower())
        if not group:
            if os.getenv("CATS_OIDC_AUTO_PROVISION_GROUPS", "false").lower() != "true":
                continue
            group = Group(name=group_name, description="Provisioned from OIDC")
            db.add(group); db.flush()
        role_name = group_role_map.get(group_name) or group_role_map.get(group.name) or os.getenv("CATS_OIDC_GROUP_DEFAULT_ROLE", "Service Manager")
        role = role_by_name.get(str(role_name).lower())
        if role:
            roles.append(role)
            if not any(a.role_id == role.id and a.group_id == group.id for a in user.role_assignments):
                db.add(UserRoleAssignment(user=user, role=role, group=group))
    existing_global = [a for a in user.role_assignments if a.group_id is None and a.service_id is None]
    for role in set(roles):
        if not any(a.role_id == role.id and a.group_id is None and a.service_id is None for a in existing_global):
            db.add(UserRoleAssignment(user=user, role=role))
    db.flush()
    return user


PERMISSIONS = {
    "artifact.sign": "Sign portal-patched images with the configured signing key",
    "service.view": "View services, findings, evidence, and history",
    "service.export": "Export service and finding evidence",
    "service.edit": "Edit service metadata",
    "exception.request": "Request a finding exception",
    "exception.review": "Approve or reject exception requests",
    "exception.revoke": "Revoke active exceptions",
    "poam.request": "Add vulnerability and compliance items to a POA&M",
    "poam.review": "Approve or reject POA&M entries",
    "archive.request": "Request service archival",
    "archive.review": "Approve or reject archival requests",
    "service.restore": "Restore archived services",
    "audit.view": "View CATS audit history",
    "user.manage": "Create, disable, and reset user accounts",
    "role.manage": "Create roles and manage role assignments",
    "service.delete": "Permanently delete archived services",
    "config.manage": "Manage CATS operational configuration",
    "scan.ingest": "Ingest completed scans into scoped services",
    "evidence.remove": "Remove current missing-evidence observations",
    "remediation.execute": "Create and validate remediation candidates",
}

SYSTEM_ROLES = {
    "Administrator": [permission for permission in PERMISSIONS if permission != "scan.ingest"],
    "Assessor": ["service.view", "service.export", "audit.view"],
    "Service Manager": ["service.view", "service.export", "service.edit", "exception.request", "poam.request", "archive.request", "scan.ingest", "remediation.execute"],
    "Cybersecurity": [
        "artifact.sign",
        "service.view", "service.export", "service.edit", "exception.request",
        "exception.review", "exception.revoke", "archive.request", "archive.review",
        "poam.request", "poam.review",
        "evidence.remove",
        "service.restore", "audit.view", "config.manage", "scan.ingest", "remediation.execute",
    ],
}

PBKDF2_ITERATIONS = 600_000
SESSION_COOKIE = "cats_session"


def utcnow():
    return datetime.now(timezone.utc)


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def hash_password(password: str) -> str:
    if len(password) < 14:
        raise ValueError("Password must be at least 14 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, iterations, salt_hex, expected_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), expected_hex)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def seed_auth():
    with SessionLocal() as db:
        for name, permissions in SYSTEM_ROLES.items():
            role = db.scalar(select(Role).where(Role.name == name))
            if not role:
                db.add(Role(name=name, description=f"Built-in {name} role", permissions=permissions, system=True))
            else:
                role.permissions = permissions
                role.system = True
        db.flush()
        if not db.scalar(select(func.count(User.id))):
            username = os.getenv("CATS_BOOTSTRAP_USERNAME", "admin")
            password = os.getenv("CATS_BOOTSTRAP_PASSWORD", "change-this-password")
            user = User(
                username=username.lower(), display_name="CATS Administrator",
                password_hash=hash_password(password), must_change_password=True,
            )
            db.add(user)
            db.flush()
            admin = db.scalar(select(Role).where(Role.name == "Administrator"))
            db.add(UserRoleAssignment(user=user, role=admin, service_id=None))
        db.commit()


@dataclass
class AuthContext:
    user: User
    session: UserSession

    @property
    def csrf_token(self):
        return self.session.csrf_token

    def has(self, permission: str, service_id: int | None = None) -> bool:
        for assignment in self.user.role_assignments:
            if permission == "scan.ingest" and assignment.role.name == "Administrator":
                continue
            if permission not in (assignment.role.permissions or []):
                continue
            if assignment.service_id is None and assignment.group_id is None:
                return True
            if assignment.service_id is not None and assignment.service_id == service_id:
                return True
            if assignment.group_id is not None and service_id is not None and assignment.group:
                if any(service.id == service_id for service in assignment.group.services):
                    return True
        return False

    def accessible_service_ids(self, permission: str) -> set[int] | None:
        matching = [a for a in self.user.role_assignments if not (permission == "scan.ingest" and a.role.name == "Administrator") and permission in (a.role.permissions or [])]
        if any(a.service_id is None and a.group_id is None for a in matching):
            return None
        service_ids = {a.service_id for a in matching if a.service_id is not None}
        for assignment in matching:
            if assignment.group:
                service_ids.update(service.id for service in assignment.group.services)
        return service_ids

    def can_manage_group(self, group_id: int | None) -> bool:
        """Check configuration authority for a global or group scope."""
        for assignment in self.user.role_assignments:
            if "config.manage" not in (assignment.role.permissions or []):
                continue
            if assignment.service_id is None and assignment.group_id is None:
                return True
            if group_id is not None and assignment.group_id == group_id:
                return True
        return False


def optional_user(request: Request, db: Session = Depends(get_db)) -> AuthContext | None:
    """Return the current session when present, without redirecting guests."""
    supplied = request.cookies.get(SESSION_COOKIE, "")
    if not supplied:
        return None
    session = db.scalar(
        select(UserSession)
        .where(UserSession.token_hash == token_hash(supplied))
        .options(
            selectinload(UserSession.user)
            .selectinload(User.role_assignments)
            .selectinload(UserRoleAssignment.role),
            selectinload(UserSession.user)
            .selectinload(User.role_assignments)
            .selectinload(UserRoleAssignment.group)
            .selectinload(Group.services)
            .selectinload(Service.groups),
        )
    )
    if not session or aware(session.expires_at) <= utcnow() or not session.user.enabled:
        return None
    session.last_seen_at = utcnow()
    return AuthContext(session.user, session)


def require_user(request: Request, response: Response, db: Session = Depends(get_db)) -> AuthContext:
    supplied = request.cookies.get(SESSION_COOKIE, "")
    session = db.scalar(
        select(UserSession)
        .where(UserSession.token_hash == token_hash(supplied))
        .options(
            selectinload(UserSession.user)
            .selectinload(User.role_assignments)
            .selectinload(UserRoleAssignment.role),
            selectinload(UserSession.user)
            .selectinload(User.role_assignments)
            .selectinload(UserRoleAssignment.group)
            .selectinload(Group.services)
            .selectinload(Service.groups)
        )
    ) if supplied else None
    if not session or aware(session.expires_at) <= utcnow() or not session.user.enabled:
        # Development-only convenience for local UI testing.  The host check
        # prevents this from working when the app is reached by a VM/IP URL.
        dev_bypass = (
            os.getenv("CATS_ENV", "production").lower() == "development"
            and os.getenv("CATS_DEV_AUTH_BYPASS", "false").lower() == "true"
            and request.url.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if dev_bypass:
            username = (os.getenv("CATS_DEV_USER") or os.getenv("CATS_BOOTSTRAP_USERNAME", "admin")).lower()
            user = db.scalar(
                select(User).where(User.username == username)
                .options(
                    selectinload(User.role_assignments).selectinload(UserRoleAssignment.role),
                    selectinload(User.role_assignments).selectinload(UserRoleAssignment.group)
                    .selectinload(Group.services).selectinload(Service.groups),
                )
            )
            if user and user.enabled:
                # The dependency response is not always the same response object
                # ultimately returned by a route (notably TemplateResponse). If
                # the browser therefore does not persist the Set-Cookie header,
                # creating a fresh bypass session on every request makes the CSRF
                # token rendered by GET differ from the token checked by POST.
                # Reuse one short-lived development session so local forms remain
                # usable while keeping this convenience strictly development-only.
                dev_session = db.scalar(
                    select(UserSession)
                    .where(
                        UserSession.user_id == user.id,
                        UserSession.user_agent == "CATS development auth bypass",
                        UserSession.expires_at > utcnow(),
                    )
                    .order_by(UserSession.id.desc())
                )
                if not dev_session:
                    raw_token = secrets.token_urlsafe(48)
                    dev_session = UserSession(
                        token_hash=token_hash(raw_token), csrf_token=secrets.token_urlsafe(32),
                        user_id=user.id, expires_at=utcnow() + timedelta(hours=12),
                        user_agent="CATS development auth bypass", source_ip=request.client.host if request.client else None,
                    )
                    db.add(dev_session)
                    db.commit()
                else:
                    raw_token = supplied if supplied else None
                    if not raw_token:
                        # The cookie is only a convenience; the stable DB session
                        # above is what keeps the rendered CSRF token consistent.
                        raw_token = secrets.token_urlsafe(48)
                response.set_cookie(SESSION_COOKIE, raw_token, httponly=True, samesite="strict", max_age=12 * 60 * 60)
                return AuthContext(user, dev_session)
        raise HTTPException(status_code=303, headers={"Location": f"/login?next={request.url.path}"})
    session.last_seen_at = utcnow()
    return AuthContext(session.user, session)


def require_permission(permission: str, scoped: bool = False):
    def dependency(request: Request, auth: AuthContext = Depends(require_user), db: Session = Depends(get_db)):
        service_id = None
        if scoped:
            from .models import Finding, Service
            service_key = request.path_params.get("service_key")
            finding_id = request.path_params.get("finding_id")
            exception_id = request.path_params.get("exception_id")
            workflow_id = request.path_params.get("workflow_id")
            if service_key:
                service_id = db.scalar(select(Service.id).where(Service.service_key == service_key))
            elif finding_id:
                service_id = db.scalar(select(Finding.service_id).where(Finding.id == int(finding_id)))
            elif exception_id:
                from .models import ExceptionRecord
                service_id = db.scalar(select(Finding.service_id).join(ExceptionRecord).where(ExceptionRecord.id == int(exception_id)))
            elif workflow_id:
                from .models import WorkflowRequest
                service_id = db.scalar(select(WorkflowRequest.service_id).where(WorkflowRequest.id == int(workflow_id)))
        if not auth.has(permission, service_id):
            raise HTTPException(403, detail="Permission denied")
        return auth
    return dependency


def require_csrf(
    csrf_token: str = Form(),
    auth: AuthContext = Depends(require_user),
) -> AuthContext:
    if not hmac.compare_digest(csrf_token, auth.csrf_token):
        raise HTTPException(403, detail="Invalid CSRF token")
    return auth


def record_audit(db: Session, auth: AuthContext | None, action: str, target_type: str, target_id=None, **detail):
    if auth:
        detail.setdefault("actor_username", auth.user.username)
        detail.setdefault("actor_display_name", auth.user.display_name)
    db.add(AuditEvent(
        actor_user_id=auth.user.id if auth else None,
        action=action, target_type=target_type,
        target_id=str(target_id) if target_id is not None else None, detail=detail,
    ))
