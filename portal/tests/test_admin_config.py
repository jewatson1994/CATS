from pathlib import Path

import pytest

from app.admin_config import OS_DEFINITIONS, certificate_bundle_metadata, certificate_metadata, merge_certificate_metadata, normalize_policy, resolve_policy, validate_os_definition, validate_policy, write_repository_config
from app.secrets import decrypt_secret, encrypt_secret
from app.main import configured_ca_bundle, configured_oidc, configured_registries
from app import auth
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _certificate(common_name: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
        .not_valid_after(__import__("datetime").datetime.now(__import__("datetime").timezone.utc) + __import__("datetime").timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_builtin_operating_systems_have_supported_package_managers():
    assert {"ubuntu", "debian", "rhel", "rocky", "almalinux", "centos", "fedora", "alpine"} <= set(OS_DEFINITIONS)
    assert {item["package_manager"] for item in OS_DEFINITIONS.values()} <= {"apt", "dnf", "apk"}


def test_repository_policy_validation_and_resolution():
    assert validate_policy("Ubuntu", "default") == (True, "Valid")
    assert validate_policy("ubuntu", "custom", "https://mirror.example.invalid") == (True, "Valid")
    assert validate_policy("ubuntu", "custom", "file:///tmp/mirror")[0] is False
    assert resolve_policy("Ubuntu", {"ubuntu": {"mode": "custom", "url": "https://mirror.example.invalid"}})["mode"] == "custom"


def test_repository_verification_defaults_and_explicit_false_are_preserved():
    assert normalize_policy({"mode": "custom"})["verify_tls"] is True
    policy = resolve_policy("ubuntu", {"ubuntu": {"mode": "custom", "verify_tls": False, "verify_packages": False}})
    assert policy["verify_tls"] is False and policy["verify_packages"] is False


@pytest.mark.parametrize(("tls", "packages", "expected"), [
    (True, True, ("sslverify=1", "gpgcheck=1")),
    (True, False, ("sslverify=1", "gpgcheck=0")),
    (False, True, ("sslverify=0", "gpgcheck=1")),
    (False, False, ("sslverify=0", "gpgcheck=0")),
])
def test_rpm_repository_controls_cover_all_combinations(tmp_path: Path, tls: bool, packages: bool, expected):
    text = write_repository_config({"mode": "custom", "url": "https://mirror.example.invalid", "verify_tls": tls, "verify_packages": packages}, tmp_path, "rhel", "dnf").read_text()
    assert all(item in text for item in expected)


def test_apt_package_exception_is_repository_scoped(tmp_path: Path):
    text = write_repository_config({"mode": "custom", "url": "https://mirror.example.invalid", "verify_packages": False}, tmp_path, "ubuntu", "apt").read_text()
    assert text.startswith("deb [trusted=yes] ") and "AllowUnauthenticated" not in text


def test_admin_template_exposes_independent_verification_controls_and_warnings():
    template = Path(__file__).parents[1] / "app" / "templates" / "configuration.html"
    text = template.read_text(encoding="utf-8")
    assert 'name="verify_tls"' in text and 'name="verify_packages"' in text
    assert "TLS certificate verification is disabled" in text
    assert "package signature verification is disabled" in text


@pytest.mark.parametrize(("manager", "filename", "needle"), [("apt", "cats.list", "deb https://mirror.example.invalid stable main"), ("dnf", "cats.repo", "baseurl=https://mirror.example.invalid"), ("apk", "repositories", "https://mirror.example.invalid")])
def test_repository_override_is_ephemeral_and_manager_specific(tmp_path: Path, manager: str, filename: str, needle: str):
    path = write_repository_config({"mode": "custom", "url": "https://mirror.example.invalid/"}, tmp_path, "ubuntu", manager)
    assert path == tmp_path / filename
    assert needle in path.read_text(encoding="utf-8")


def test_rpm_repository_override_keeps_signature_and_tls_verification(tmp_path: Path):
    text = write_repository_config({"mode": "custom", "url": "https://mirror.example.invalid"}, tmp_path, "rhel", "dnf").read_text()
    assert "gpgcheck=1" in text and "sslverify=1" in text


def test_default_policy_does_not_create_override(tmp_path: Path):
    assert write_repository_config({"mode": "default", "url": ""}, tmp_path, "ubuntu", "apt") is None


def test_custom_os_definition_validation_is_safe_and_manager_specific():
    assert validate_os_definition("My-Linux", "My Linux", "dnf") == (True, "Valid")
    assert validate_os_definition("bad id", "Bad", "dnf")[0] is False
    assert validate_os_definition("custom", "Custom", "unknown")[0] is False


def test_invalid_trusted_certificate_is_rejected():
    with pytest.raises(ValueError, match="valid PEM"):
        certificate_metadata(b"-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n")


def test_single_pem_certificate_metadata_and_fingerprint():
    pem = _certificate("cats-root")
    metadata = certificate_metadata(pem)
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    assert metadata["subject"] and metadata["fingerprint"] == __import__("hashlib").sha256(der).hexdigest()


def test_multi_certificate_bundle_is_imported_as_individual_rows():
    rows = certificate_bundle_metadata(_certificate("root-one") + b"\n" + _certificate("root-two"))
    assert len(rows) == 2
    assert len({row["fingerprint"] for row in rows}) == 2


def test_duplicate_certificates_are_deduplicated_by_fingerprint():
    row = certificate_metadata(_certificate("duplicate-root"))
    merged = merge_certificate_metadata([], [row, row])
    assert len(merged) == 1


def test_malformed_bundle_and_private_key_are_rejected_without_partial_import():
    valid = _certificate("valid-root")
    with pytest.raises(ValueError, match="malformed|non-certificate"):
        certificate_bundle_metadata(valid + b"\n-----BEGIN CERTIFICATE-----\ninvalid")
    with pytest.raises(ValueError, match="Private keys"):
        certificate_bundle_metadata(valid + b"\n-----BEGIN PRIVATE KEY-----\nsecret")


def test_der_bytes_returned_by_parser_are_supported(monkeypatch):
    pem = _certificate("der-bytes")
    expected = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr("app.admin_config.ssl.PEM_cert_to_DER_cert", lambda _text: expected)
    metadata = certificate_metadata(pem)
    assert metadata["fingerprint"] == __import__("hashlib").sha256(expected).hexdigest()


def test_configured_secrets_are_encrypted_and_round_trip(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    value = encrypt_secret("registry-token-value")
    assert value.startswith("enc:v1:")
    assert "registry-token-value" not in value
    assert decrypt_secret(value) == "registry-token-value"


def test_runtime_configuration_views_never_expose_secret_values(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    oidc_secret = encrypt_secret("oidc-client-secret")
    registry_secret = encrypt_secret("registry-password")
    oidc = configured_oidc({"oidc_configuration": __import__("json").dumps({"issuer": "https://id.example", "client_secret": oidc_secret})})
    registries = configured_registries({"oci_registries": __import__("json").dumps([{"id": "r1", "endpoint": "https://registry.example", "password": registry_secret}])})
    assert "client_secret" not in oidc
    assert "oidc-client-secret" not in repr(oidc)
    assert registries[0]["secret_configured"] is True
    assert "registry-password" not in repr(registries)
    assert "password" not in registries[0]


def test_trusted_ca_bundle_is_combined_without_dropping_system_trust():
    first = "-----BEGIN CERTIFICATE-----\nfirst\n-----END CERTIFICATE-----"
    second = "-----BEGIN CERTIFICATE-----\nsecond\n-----END CERTIFICATE-----"
    bundle = configured_ca_bundle({"trusted_ca_certificates": __import__("json").dumps([
        {"pem": first}, {"pem": second}, {"pem": "not a certificate"}
    ])})
    assert bundle == f"{first}\n{second}\n"


def test_oidc_form_submits_test_action_without_separate_blank_form():
    template = Path(__file__).parents[1] / "app" / "templates" / "configuration.html"
    text = template.read_text(encoding="utf-8")
    assert 'action="/admin/configuration/oidc"' in text
    assert 'name="action" value="test"' in text
    assert 'action="/admin/configuration/oidc-test"' not in text


def test_oidc_authorization_uses_browser_issuer_for_docker_provider(monkeypatch):
    monkeypatch.setattr(auth, "oidc_discovery", lambda *args, **kwargs: {
        "authorization_endpoint": "http://keycloak:8080/realms/cats/protocol/openid-connect/auth",
    })
    url = auth.oidc_authorization_url("state", "nonce", {
        "issuer": "http://keycloak:8080/realms/cats",
        "browser_issuer": "http://localhost:8081/realms/cats",
        "client_id": "cats-portal",
        "redirect_uri": "http://localhost:8080/auth/oidc/callback",
        "scopes": "openid profile email groups",
    })
    assert url.startswith("http://localhost:8081/realms/cats/protocol/openid-connect/auth?")
    assert "keycloak:8080" not in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Foidc%2Fcallback" in url


def test_oidc_token_validation_uses_browser_issuer(monkeypatch):
    observed = {}

    class FakeJWKClient:
        def __init__(self, uri): observed["jwks_uri"] = uri
        def get_signing_key_from_jwt(self, token): return type("Key", (), {"key": "public-key"})()

    class FakeJWT:
        PyJWKClient = FakeJWKClient

        @staticmethod
        def decode(token, key, **kwargs):
            observed.update(kwargs)
            return {"nonce": "expected"}

    monkeypatch.setattr(auth, "jwt", FakeJWT)
    claims = auth.verify_oidc_id_token(
        {"id_token": "token"},
        {"jwks_uri": "http://keycloak:8080/realms/cats/protocol/openid-connect/certs"},
        "expected",
        {"issuer": "http://keycloak:8080/realms/cats", "browser_issuer": "http://localhost:8081/realms/cats", "client_id": "cats-portal"},
    )
    assert claims["nonce"] == "expected"
    assert observed["issuer"] == "http://localhost:8081/realms/cats"


def test_oidc_token_exchange_uses_client_secret_basic(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, *args): return b'{"access_token":"access","id_token":"id"}'

    monkeypatch.setattr(auth, "oidc_discovery", lambda *args: {"token_endpoint": "http://keycloak/token"})
    def open_request(request, **kwargs):
        captured["request"] = request
        return Response()
    monkeypatch.setattr(auth.urllib.request, "urlopen", open_request)
    auth.oidc_exchange_code("code", {"issuer": "http://keycloak", "client_id": "cats-portal", "client_secret": "secret", "redirect_uri": "http://localhost/callback"})
    request = captured["request"]
    assert request.get_header("Authorization").startswith("Basic ")
    assert b"client_secret" not in request.data


def test_oidc_defaults_are_provider_neutral():
    config = auth.oidc_configuration({"issuer": "https://identity.example"})
    assert config["scopes"] == "openid profile email"
    assert config["groups_claim"] == ""
    assert config["roles_claim"] == ""
    assert auth.oidc_role_names({"realm_access": {"roles": ["Administrator"]}}, config) == []


def test_login_and_configuration_use_generic_oidc_presentation():
    login = (Path(auth.__file__).parent / "templates" / "login.html").read_text(encoding="utf-8")
    configuration = (Path(auth.__file__).parent / "templates" / "configuration.html").read_text(encoding="utf-8")
    assert "Sign in with {{ oidc_provider_name or 'organizational account' }}" in login
    assert "realm_access.roles" not in configuration
    assert "Test Connection" in configuration


def test_registry_path_is_normalized_for_consumers():
    rows = configured_registries({"oci_registries": __import__("json").dumps([{
        "id": "registry", "display_name": "Registry", "endpoint": "https://registry.example.invalid/", "namespace": "/approved/"
    }])})
    assert rows[0]["endpoint"] == "https://registry.example.invalid"
    assert rows[0]["resolved_path"] == "registry.example.invalid/approved"
