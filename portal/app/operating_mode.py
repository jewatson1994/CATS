"""Fail-closed boundary between authoritative CATS and its local replicas.

The HTTP allowlist grants no authorization: each permitted route still applies
its normal authentication, RBAC and CSRF checks. Unknown writes stay denied.
"""
import os
import re

from starlette.responses import JSONResponse


def mode() -> str:
    value = os.getenv("CATS_MODE", "full").strip().lower()
    if value not in {"full", "replica"}:
        raise RuntimeError("CATS_MODE must be 'full' or 'replica'")
    return value


def is_replica() -> bool:
    return mode() == "replica"


REPLICA_PERMISSIONS = frozenset({
    "service.view", "metadata.view", "template.view",
    "audit.view", "user.manage", "role.manage", "config.manage",
    "release.destination.manage", "replica.admin", "replica.sync", "evidence.view",
    "local_override.create", "local_override.revoke", "local_override.view_audit",
})


def permission_available(permission: str) -> bool:
    return not is_replica() or permission in REPLICA_PERMISSIONS


# Use exact methods and full-path matches. Never allow an entire administrative
# prefix: many existing admin routes edit authoritative service evidence.
_LOCAL_WRITES = (
    ("POST", r"/(?:login|logout|account/password|account/appearance)"),
    ("POST", r"/admin/(?:users|roles|assignments|audit-policy)"),
    ("POST", r"/admin/users/\d+/(?:toggle|reset-password|delete)"),
    ("POST", r"/admin/assignments/\d+/delete"),
    ("POST", r"/admin/configuration/(?:oidc|oidc-test|oidc-mappings|oidc-mappings/discover|trusted-certificates)"),
    ("POST", r"/api/admin/accounts/(?:preview|apply)"),
    ("POST", r"/api/accounts/access-requests/\d+/claim"),
    ("POST", r"/api/oci/(?:upstreams|repositories|principals)"),
    ("PUT", r"/api/oci/(?:upstreams|repositories|principals)/\d+"),
    ("DELETE", r"/api/oci/(?:upstreams|repositories|principals)/\d+"),
    ("POST", r"/api/oci/(?:principals/\d+/rotate|repositories/\d+/test)"),
    ("POST", r"/api/replica/(?:sources|sync)"),
    ("PUT", r"/api/replica/sources/\d+"),
    ("DELETE", r"/api/replica/sources/\d+"),
    ("POST", r"/api/services/[^/]+/local-overrides(?:/\d+/revoke)?"),
)
_LOCAL_WRITE_PATTERNS = tuple((method, re.compile(path)) for method, path in _LOCAL_WRITES)
_FULL_ONLY_PAGES = frozenset({"/scan", "/patch", "/sbom", "/discovery", "/patch-campaigns", "/risk-intelligence", "/admin/validators", "/admin/staging"})


def request_available(method: str, path: str) -> bool:
    if not is_replica():
        return True
    if path in _FULL_ONLY_PAGES or re.fullmatch(r"(?:/api/public/(?:jobs|patch-jobs)/.*|/exports/.*|/poam/(?:services/[^/]+/)?export\.xlsx|/services/[^/]+/(?:exports/.*|export\.xlsx|bundle\.zip|helm-diagram\.svg))", path):
        return False
    if method in {"GET", "HEAD", "OPTIONS"}:
        return True
    return any(method == allowed and pattern.fullmatch(path) for allowed, pattern in _LOCAL_WRITE_PATTERNS)


class ReplicaModeMiddleware:
    def __init__(self, app):
        mode()  # Reject misspelled deployment modes during application startup.
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not request_available(scope["method"], scope["path"]):
            response = JSONResponse({"detail": "This operation is unavailable in replica mode. Imported service evidence is read-only.",
                                     "code": "replica_read_only"}, status_code=403,
                                    headers={"Cache-Control": "no-store"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
