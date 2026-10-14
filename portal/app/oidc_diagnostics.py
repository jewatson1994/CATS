"""Allowlisted OIDC diagnostics: never serialize exceptions or provider content."""
import json
import logging
from contextvars import ContextVar
from urllib.error import HTTPError, URLError

correlation_id = ContextVar("oidc_correlation_id", default="unavailable")
logger = logging.getLogger("cats.oidc")


class OidcDiagnosticError(ValueError):
    def __init__(self, reason, message=None):
        self.reason = reason
        super().__init__(message or reason)


def failure_reason(stage, exc):
    if isinstance(exc, OidcDiagnosticError):
        # All callers supply constants, never provider text.
        return exc.reason
    names = {
        "InvalidIssuerError": "issuer_mismatch", "InvalidAudienceError": "audience_mismatch",
        "InvalidSignatureError": "signature_invalid", "ExpiredSignatureError": "token_expired",
        "ImmatureSignatureError": "token_not_yet_valid", "InvalidIssuedAtError": "issued_at_invalid",
        "MissingRequiredClaimError": "required_claim_missing", "InvalidSubjectError": "subject_invalid",
        "InvalidAlgorithmError": "algorithm_rejected", "DecodeError": "token_malformed",
        "PyJWKClientError": "signing_key_unavailable", "PyJWKClientConnectionError": "signing_key_unavailable",
    }
    if type(exc).__name__ in names:
        return names[type(exc).__name__]
    if isinstance(exc, HTTPError):
        return "provider_access_denied" if exc.code in (401, 403) else "provider_http_error"
    if isinstance(exc, (URLError, TimeoutError, OSError)):
        return "provider_connection_failed"
    # Legacy provisioning raises fixed messages. Match only these known messages,
    # never return the exception (which can contain credentials).
    if isinstance(exc, ValueError):
        value = str(exc)
        for fragment, reason in (
            ("explicit OIDC account link", "account_link_required"),
            ("already linked", "identity_collision"),
            ("Legacy OIDC identity", "legacy_identity_requires_link"),
            ("Retired CATS account", "account_retired"),
            ("identity conflicts", "identity_collision"),
            ("nonce validation", "nonce_mismatch"),
            ("timestamp claim", "timestamp_invalid"),
            ("OIDC_CLOCK_SKEW_SECONDS", "clock_skew_configuration_invalid"),
            ("did not include an ID token", "id_token_missing"),
            ("rejected the client credentials", "client_authentication_rejected"),
        ):
            if fragment in value:
                return reason
    return stage + "_failed"


def diagnostic(stage, reason, *, outcome="failed"):
    event = {"correlation_id": correlation_id.get(), "stage": stage,
             "reason": reason, "outcome": outcome}
    logger.log(logging.INFO if outcome == "success" else logging.WARNING,
               "OIDC %s", json.dumps(event, sort_keys=True))
    return event


class RedactOidcAccessQuery(logging.Filter):
    """Uvicorn logs its own scope, outside ASGI middleware: filter at the logger."""
    def filter(self, record):
        if isinstance(record.args, tuple) and len(record.args) == 5:
            args = list(record.args)
            if isinstance(args[2], str) and args[2].split("?", 1)[0].rstrip("/").endswith("/auth/oidc/callback"):
                args[2] = args[2].split("?", 1)[0]
                record.args = tuple(args)
        return True


def install_access_log_filter():
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, RedactOidcAccessQuery) for item in access.filters):
        access.addFilter(RedactOidcAccessQuery())
