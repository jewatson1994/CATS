"""Real signed tokens and deterministic PyJWT clocks; JWKS network only is stubbed."""
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from app import auth

NOW = 1800000000
CONFIG = {"issuer": "https://issuer.example/realm", "client_id": "cats"}
DISCOVERY = {"jwks_uri": "https://issuer.example/jwks"}

@pytest.fixture
def tokens(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(auth, "jwt", jwt)
    monkeypatch.delenv("OIDC_CLOCK_SKEW_SECONDS", raising=False)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(NOW, tz=tz or timezone.utc)
    monkeypatch.setattr(jwt.api_jwt, "datetime", Clock)
    monkeypatch.setattr(auth, "datetime", Clock)
    class JWKClient:
        def __init__(self, *args, **kwargs): pass
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=key.public_key())
    monkeypatch.setattr(jwt, "PyJWKClient", JWKClient)
    def verify(overrides=None, missing=None, signing_key=None, nonce="nonce"):
        claims = {"iss": CONFIG["issuer"], "sub": "subject", "aud": "cats", "iat": NOW,
                  "exp": NOW+600, "nonce": "nonce", "email": "sensitive@example.org"}
        claims.update(overrides or {})
        if missing: claims.pop(missing)
        encoded = jwt.encode(claims, signing_key or key, algorithm="RS256")
        return auth.verify_oidc_id_token({"id_token": encoded}, DISCOVERY, nonce, CONFIG)
    return verify

@pytest.mark.parametrize("offset,accepted", [(0,True),(30,True),(59,True),(60,True),(61,False)])
def test_issued_at_default_leeway(tokens, offset, accepted):
    if accepted: assert tokens({"iat": NOW+offset})["iat"] == NOW+offset
    else:
        with pytest.raises(jwt.ImmatureSignatureError): tokens({"iat": NOW+offset})

@pytest.mark.parametrize("claim,offset,accepted", [("nbf",59,True),("nbf",61,False),
    ("exp",-59,True),("exp",-60,False),("exp",-61,False)])
def test_other_native_time_boundaries(tokens,claim,offset,accepted):
    if accepted: assert tokens({claim: NOW+offset})[claim] == NOW+offset
    else:
        with pytest.raises(jwt.InvalidTokenError): tokens({claim:NOW+offset})

@pytest.mark.parametrize("value", ["0","60","300"])
def test_configured_boundaries(tokens,monkeypatch,value):
    monkeypatch.setenv("OIDC_CLOCK_SKEW_SECONDS",value)
    assert tokens({"iat":NOW+int(value)})
    with pytest.raises(jwt.ImmatureSignatureError): tokens({"iat":NOW+int(value)+1})

@pytest.mark.parametrize("value", ["-1","301","999","1.5","invalid",""," 60","+60"])
def test_invalid_configuration_rejected(tokens,monkeypatch,value):
    monkeypatch.setenv("OIDC_CLOCK_SKEW_SECONDS",value)
    with pytest.raises(ValueError,match="OIDC_CLOCK_SKEW_SECONDS"): tokens()

@pytest.mark.parametrize("claim,value", [("iss","https://wrong.example"),("aud","wrong"),("sub",123)])
def test_identity_claims_still_verified(tokens,claim,value):
    with pytest.raises(jwt.InvalidTokenError): tokens({claim:value})

def test_invalid_signature(tokens):
    wrong = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    with pytest.raises(jwt.InvalidSignatureError): tokens(signing_key=wrong)

def test_nonce_still_verified(tokens):
    with pytest.raises(ValueError,match="nonce"): tokens(nonce="wrong")
    with pytest.raises(ValueError,match="nonce"): tokens(missing="nonce")

@pytest.mark.parametrize("claim", ["iat","nbf","exp"])
@pytest.mark.parametrize("value", [None,True,"1800000000","secret-malformed",[],{},float("nan"),float("inf"),10**400])
def test_malformed_timestamps_rejected_without_disclosure(tokens,caplog,claim,value):
    with caplog.at_level(logging.WARNING,logger="app.auth"):
        with pytest.raises((jwt.InvalidTokenError,ValueError,TypeError,OverflowError)):
            tokens({claim:value})
    assert "secret-malformed" not in caplog.text
    assert "sensitive@example.org" not in caplog.text

@pytest.mark.parametrize("claim", ["iss","sub","aud","iat","exp"])
def test_required_claims(tokens,claim):
    with pytest.raises(jwt.MissingRequiredClaimError): tokens(missing=claim)

@pytest.mark.parametrize("claim,offset", [("iat",61),("nbf",61),("exp",-61)])
def test_safe_timestamp_diagnostics(tokens,caplog,claim,offset):
    with caplog.at_level(logging.WARNING,logger="app.auth"):
        with pytest.raises(jwt.InvalidTokenError): tokens({claim:NOW+offset})
    assert "claim="+claim in caplog.text
    assert "skew_seconds=60" in caplog.text
    assert "delta_seconds="+str(float(offset)) in caplog.text
    assert "server_utc=" in caplog.text
    assert "token_timestamp="+str(NOW+offset) in caplog.text
    assert "sensitive@example.org" not in caplog.text
    assert "subject" not in caplog.text

def test_forged_token_has_no_timestamp_diagnostics(tokens,caplog):
    wrong = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    with caplog.at_level(logging.WARNING,logger="app.auth"):
        with pytest.raises(jwt.InvalidSignatureError): tokens({"iat":NOW+61},signing_key=wrong)
    assert "token_timestamp" not in caplog.text

@pytest.mark.parametrize("provider_error", [False, True])
def test_callback_errors_do_not_disclose_provider_details(monkeypatch, provider_error):
    from app import main
    from starlette.requests import Request
    from unittest.mock import Mock
    secret = "secret-provider-detail"
    query = "state=valid&" + ("error=" + secret if provider_error else "code=code")
    request = Request({"type": "http", "method": "GET", "path": "/auth/oidc/callback",
        "query_string": query.encode(), "headers": [(b"cookie", b"cats_oidc_state=valid")]})
    monkeypatch.setattr(main, "get_global_configuration", lambda db: {})
    def fail_exchange(*args):
        raise ValueError(secret)
    monkeypatch.setattr(main, "oidc_exchange_code", fail_exchange)
    db = Mock()
    response = main.oidc_callback(request, db)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=OIDC%20login%20failed"
    assert secret not in response.headers["location"]
    db.add.assert_not_called()

def test_callback_state_still_verified():
    from app import main
    from starlette.requests import Request
    from fastapi import HTTPException
    from unittest.mock import Mock
    request = Request({"type": "http", "method": "GET", "path": "/auth/oidc/callback",
        "query_string": b"state=wrong&code=code", "headers": [(b"cookie", b"cats_oidc_state=valid")]})
    with pytest.raises(HTTPException) as error:
        main.oidc_callback(request, Mock())
    assert error.value.status_code == 400
