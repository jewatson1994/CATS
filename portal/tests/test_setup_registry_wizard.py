"""Standalone stdlib tests: run this file directly, without the portal runtime."""
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.parse


SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "cats_setup_registry.py"
SPEC = importlib.util.spec_from_file_location("cats_setup_registry", SOURCE)
wizard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wizard)


class Response(io.BytesIO):
    def __init__(self, payload=b"", code=200, location=None):
        if not isinstance(payload, bytes):
            payload = json.dumps(payload).encode()
        super().__init__(payload)
        self.code = code
        self.headers = {} if location is None else {"Location": location}


class RegistryWizardTests(unittest.TestCase):
    def client(self, responses):
        client = wizard.PortalClient("https://cats.example.org")
        client.opener = Mock()
        client.opener.open.side_effect = responses
        return client

    def page_response(self, **fields):
        return Response({"data": {"csrf_token": "session-csrf", "cats_mode": "full", **fields}})

    def test_tls_requires_verified_https_and_adds_explicit_ca(self):
        with patch.object(wizard.ssl, "create_default_context", wraps=ssl.create_default_context) as create, \
                patch.object(wizard.urllib.request, "build_opener") as opener:
            client = wizard.PortalClient("https://cats.example.org")
            context = opener.call_args.args[0]._context
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIsInstance(opener.call_args.args[1], wizard.urllib.request.HTTPCookieProcessor)
            self.assertIsInstance(opener.call_args.args[2], wizard._NoRedirect)
            create.assert_called_once_with()
        with patch.object(wizard.ssl, "create_default_context") as create:
            wizard.PortalClient("https://cats.example.org", "trusted-chain.pem")
            create.return_value.load_verify_locations.assert_called_once_with(cafile="trusted-chain.pem")
        for origin in ("http://cats.example.org", "https://user:secret@cats.example.org", "https://cats.example.org/path"):
            with self.assertRaises(wizard.SetupError):
                wizard.PortalClient(origin)

    def test_forced_password_rotation_uses_normal_form_and_csrf(self):
        client = self.client([Response(code=303, location="/account/password"), self.page_response(), Response(code=303, location="/")])
        with patch.object(wizard.getpass, "getpass", side_effect=["", "new-password-long", "new-password-long"]), patch("sys.stdout", io.StringIO()):
            client.login("admin", "bootstrap-password")
        calls = client.opener.open.call_args_list
        first = urllib.parse.parse_qs(calls[0].args[0].data.decode())
        self.assertEqual(first["next"], ["/"])
        self.assertEqual(first["password"], ["bootstrap-password"])
        rotation = calls[2].args[0]
        body = urllib.parse.parse_qs(rotation.data.decode())
        self.assertEqual(body["csrf_token"], ["session-csrf"])
        self.assertEqual(body["current_password"], ["bootstrap-password"])
        self.assertEqual(body["new_password"], ["new-password-long"])
        self.assertEqual(rotation.get_header("X-csrf-token"), "session-csrf")

    def test_existing_account_does_not_rotate_password(self):
        client = self.client([Response(code=303, location="/"), self.page_response()])
        with patch.object(wizard.getpass, "getpass", return_value="current-password") as prompt:
            client.login("admin", "old-bootstrap")
        self.assertEqual(prompt.call_count, 1)
        self.assertEqual(client.opener.open.call_count, 2)

    def test_redirect_never_forwards_password(self):
        client = self.client([Response(code=303, location="https://other.example.org/login")])
        with self.assertRaisesRegex(wizard.SetupError, "unexpected redirect"):
            client.form("/login", {"password": "secret"}, login=True)
        self.assertEqual(client.opener.open.call_count, 1)

    def test_api_redirect_and_server_body_are_not_exposed(self):
        client = self.client([Response(code=303, location="/login")])
        with self.assertRaises(wizard.SetupError):
            client.json("/api/oci/upstreams")
        client = self.client([Response(b"secret echoed by server", code=422)])
        with self.assertRaises(wizard.SetupError) as failure:
            client.json("/api/oci/upstreams", {"password": "secret"})
        self.assertNotIn("secret", str(failure.exception))
        self.assertIn("422", str(failure.exception))

    def test_api_mutation_has_session_csrf_header(self):
        client = self.client([self.page_response(), Response({"id": 7})])
        client.page("/account/password")
        client.json("/api/oci/upstreams", {"name": "Registry"})
        request = client.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("X-csrf-token"), "session-csrf")
        self.assertEqual(json.loads(request.data), {"name": "Registry"})

    def test_opt_out_never_constructs_network_client(self):
        with patch("builtins.input", return_value="no"), patch.object(wizard, "PortalClient") as client, patch("sys.stdout", io.StringIO()):
            outcome = wizard.configure_registry("replica", "invalid-url", "admin", "password")
        client.assert_not_called()
        self.assertFalse(outcome["completed"])
        self.assertTrue(outcome["pending"])

    def test_individual_stage_skips_do_not_fetch_or_write_registry_settings(self):
        client = self.client([Response(code=303, location="/"), self.page_response(), Response(code=303, location="/login")])
        with patch("builtins.input", side_effect=["yes", "no", "no", "no"]), \
                patch.object(wizard, "PortalClient", return_value=client), patch.object(wizard.getpass, "getpass", return_value=""), patch("sys.stdout", io.StringIO()):
            outcome = wizard.configure_registry("main", "https://cats.example.org", "admin", "password")
        paths = [urllib.parse.urlsplit(call.args[0].full_url).path for call in client.opener.open.call_args_list]
        self.assertEqual(paths, ["/login", "/account/password", "/logout"])
        self.assertFalse(outcome["completed"])
        self.assertTrue(any("Signing" in item for item in outcome["pending"]))

    def test_wrong_operating_mode_logs_out_without_changing_registry_settings(self):
        client = self.client([Response(code=303, location="/"), self.page_response(cats_mode="replica"), Response(code=303, location="/login")])
        with patch("builtins.input", return_value="yes"), patch.object(wizard, "PortalClient", return_value=client), \
                patch.object(wizard.getpass, "getpass", return_value=""), self.assertRaisesRegex(wizard.SetupError, "operating mode"):
            wizard.configure_registry("main", "https://cats.example.org", "admin", "password")
        self.assertTrue(client.opener.open.call_args.args[0].full_url.endswith("/logout"))

    def test_replica_source_requires_independent_pin_and_queues_selected_source(self):
        client = self.client([Response({"sources": []}), Response({"id": 9}), Response({"jobs": [{"id": "job-1"}]})])
        client.csrf = "csrf"
        completed, pending = [], []
        answers = ["yes", "Local releases", "approved/*", "sha256:" + "a" * 64, "300", "yes"]
        with patch("builtins.input", side_effect=answers), patch("sys.stdout", io.StringIO()):
            wizard.replica_source(client, {"id": 2}, completed, pending)
        calls = client.opener.open.call_args_list
        payload = json.loads(calls[1].args[0].data)
        self.assertEqual(payload["upstream_id"], 2)
        self.assertEqual(payload["trusted_publishers"], ["sha256:" + "a" * 64])
        self.assertEqual(payload["poll_seconds"], 300)
        self.assertEqual(json.loads(calls[2].args[0].data), {"source_id": 9})
        self.assertTrue(any("confirm" in item for item in pending))

    def test_consumer_credential_is_not_created_when_output_is_redirected(self):
        client = self.client([Response([{"id": 3, "upstream_id": 2, "public_repository": "approved/*", "enabled": True}])])
        with patch("builtins.input", side_effect=["yes", "3", "yes"]), patch("sys.stdout", io.StringIO()):
            completed, pending = [], []
            wizard.distribution(client, {"id": 2}, completed, pending)
        self.assertEqual(client.opener.open.call_count, 1)
        self.assertTrue(any("terminal-only" in item for item in pending))

    def test_consumer_credential_is_scoped_to_one_mapping(self):
        client = self.client([Response([{"id": 3, "upstream_id": 2, "public_repository": "approved/*", "enabled": True}]), Response({"id": 4, "secret": "one-time-secret"})])
        output = io.StringIO()
        output.isatty = lambda: True
        with patch("builtins.input", side_effect=["yes", "3", "yes", "consumer-1", "30"]), \
                patch("sys.stdout", output), patch.object(wizard.sys.stdin, "isatty", return_value=True):
            wizard.distribution(client, {"id": 2}, [], [])
        payload = json.loads(client.opener.open.call_args.args[0].data)
        self.assertEqual(payload["repository_ids"], [3])
        self.assertEqual(payload["name"], "consumer-1")
        self.assertEqual(output.getvalue().count("one-time-secret"), 1)

    def test_key_generation_uses_offline_container_and_private_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def run(args, **kwargs):
                calls.append((args, dict(kwargs["env"])))
                root = Path(directory) / "signing"
                (root / "cats-signing.key").write_bytes(b"private-key")
                (root / "cats-signing.pub").write_bytes(b"public-key")
                return Mock(returncode=0)
            with patch.object(wizard.subprocess, "run", side_effect=run), patch.object(wizard.getpass, "getpass", return_value="private-passphrase"), \
                    patch.object(wizard.os, "getuid", return_value=1000, create=True), patch.object(wizard.os, "getgid", return_value=1000, create=True), patch("sys.stdout", io.StringIO()) as output, \
                    patch.dict(os.environ, {"DOCKER_CONTEXT": "remote", "DOCKER_HOST": "tcp://remote:2376", "DOCKER_TLS": "1", "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "remote-certs"}):
                private, public, password = wizard.generate_signing_key("cats-main:local", directory, "unix:///run/docker.sock")
            args, environment = calls[0]
            self.assertEqual(args[:3], ["docker", "--host", "unix:///run/docker.sock"])
            self.assertTrue({"DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}.isdisjoint(environment))
            self.assertEqual(args[args.index("--network") + 1], "none")
            self.assertEqual(args[args.index("--pull") + 1], "never")
            self.assertNotIn(password, args)
            self.assertEqual(environment["COSIGN_PASSWORD"], password)
            self.assertEqual((Path(directory) / "signing" / "passphrase.txt").read_text(), password)
            self.assertNotIn(password, output.getvalue())
            self.assertEqual((private, public), (b"private-key", b"public-key"))
            if os.name != "nt":
                self.assertEqual((Path(directory) / "signing").stat().st_mode & 0o777, 0o700)
                self.assertEqual((Path(directory) / "signing" / "passphrase.txt").stat().st_mode & 0o777, 0o600)
            with patch.object(wizard.subprocess, "run") as execute, self.assertRaises(wizard.SetupError):
                wizard.generate_signing_key("cats-main:local", directory, "unix:///run/docker.sock")
            execute.assert_not_called()

    def test_generation_requires_explicit_local_docker_endpoint(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(wizard.subprocess, "run") as execute:
            for endpoint in (None, "tcp://remote:2376", "ssh://remote"):
                with self.assertRaises(wizard.SetupError):
                    wizard.generate_signing_key("cats-main:local", directory, endpoint)
            self.assertFalse((Path(directory) / "signing").exists())
            execute.assert_not_called()

    def test_disabled_signing_keeps_and_enables_key_by_default(self):
        disabled = {"configured": True, "enabled": False, "fingerprint": "sha256:existing"}
        client = self.client([self.page_response(signing=disabled), Response(code=303, location="/admin/configuration"),
                              self.page_response(signing={**disabled, "enabled": True})])
        completed, pending = [], []
        with patch("builtins.input", return_value=""), patch.object(wizard, "generate_signing_key") as generate, patch("sys.stdout", io.StringIO()):
            wizard.signing(client, completed, pending, "cats-main:local", "unused", "unix:///run/docker.sock")
        generate.assert_not_called()
        request = client.opener.open.call_args_list[1].args[0]
        payload = urllib.parse.parse_qs(request.data.decode())
        self.assertEqual(payload, {"enabled": ["true"], "action": ["save"], "csrf_token": ["session-csrf"]})
        self.assertIn("Existing signing key enabled", completed)
        self.assertFalse(pending)

    def test_disabled_signing_can_be_retained_without_enabling(self):
        client = self.client([self.page_response(signing={"configured": True, "enabled": False, "fingerprint": "sha256:existing"})])
        completed, pending = [], []
        with patch("builtins.input", side_effect=["", "", "no"]), patch.object(wizard, "generate_signing_key") as generate, patch("sys.stdout", io.StringIO()):
            wizard.signing(client, completed, pending, "cats-main:local", "unused")
        generate.assert_not_called()
        self.assertEqual(client.opener.open.call_count, 1)
        self.assertIn("Existing signing key retained", completed)
        self.assertTrue(any("enable the retained" in item for item in pending))

    def test_project_scope_rejects_nested_wildcard(self):
        self.assertEqual(wizard.repo("approved/*", pattern=True), "approved/*")
        with self.assertRaises(ValueError):
            wizard.repo("approved/nested/*", pattern=True)

    def test_signing_upload_uses_existing_authenticated_endpoint(self):
        client = self.client([Response(code=303, location="/admin/configuration?saved=1#signing")])
        client.csrf = "session-csrf"
        client.upload("/admin/configuration/signing", {"key_password": "private-passphrase", "enabled": "true"}, [("private_key", "cosign.key", b"private-key")])
        request = client.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://cats.example.org/admin/configuration/signing")
        self.assertIn(b'name="csrf_token"\r\n\r\nsession-csrf', request.data)
        self.assertIn(b'name="private_key"; filename="cosign.key"', request.data)
        self.assertEqual(request.get_header("X-csrf-token"), "session-csrf")


class ApplicationTransport:
    """Adapt urllib requests to the real ASGI application, preserving HTTP cookies.

    No network, auth dependencies, route implementations or request schemas are
    mocked. The TestClient cookie jar supplies the server's normal session cookie.
    """
    def __init__(self, app):
        from fastapi.testclient import TestClient
        self.http = TestClient(app, base_url="https://cats.example.org")
        self.calls = []

    def open(self, request, timeout):
        response = self.http.request(request.method, request.full_url, content=request.data,
                                     headers=dict(request.header_items()), follow_redirects=False)
        self.calls.append((request, response))
        adapted = Response(response.content, response.status_code)
        adapted.headers = response.headers
        return adapted


def application_client(monkeypatch, mode):
    from cryptography.fernet import Fernet
    import test_portal as portal
    monkeypatch.setenv("CATS_MODE", mode)
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("CATS_IDENTITY_MODE", "local")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    portal.setup_function()
    transport = ApplicationTransport(portal.app)
    client = wizard.PortalClient("https://cats.example.org")
    client.opener = transport
    monkeypatch.setattr(wizard, "PortalClient", lambda *args, **kwargs: client)
    return client, transport, portal


def contract_terminal():
    output = io.StringIO()
    output.isatty = lambda: True
    return output


def assert_authenticated_contract(transport, portal):
    from sqlalchemy import func, select
    from app.auth import verify_password
    assert [response.status_code for _, response in transport.calls[:3]] == [303, 200, 303]
    assert transport.calls[0][1].headers["location"] == "/account/password"
    assert transport.calls[1][1].headers["content-type"].startswith(wizard.PAGE_TYPE)
    assert transport.calls[-1][0].full_url.endswith("/logout")
    for request, response in transport.calls:
        assert response.status_code in {200, 303}, (request.full_url, response.status_code)
        if "/api/" in request.full_url:
            assert "cats_session=" in response.request.headers["cookie"]
            if request.method == "POST":
                assert request.get_header("X-csrf-token")
    with portal.SessionLocal() as db:
        user = db.scalar(select(portal.User).where(portal.User.username == "admin"))
        assert not user.must_change_password
        assert verify_password("new-contract-password", user.password_hash)
        assert not verify_password("test-password-long", user.password_hash)
        assert db.scalar(select(func.count(portal.UserSession.id))) == 0


def test_main_wizard_matches_real_application_contract(monkeypatch, tmp_path):
    """Real login/forms/JSON/multipart; only the unavailable Cosign process is mocked."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from sqlalchemy import select
    from app import signing
    from app.oci_models import OCIPrincipal, OCIRepository, OCIUpstream
    from app.secrets import decrypt_secret
    client, transport, portal = application_client(monkeypatch, "full")
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    filename = tmp_path / "contract-signing.key"
    filename.write_bytes(private)
    monkeypatch.setattr(signing.shutil, "which", lambda _: "cosign")
    monkeypatch.setattr(signing, "_command", lambda args, env: Mock(stdout=public.decode()))
    answers = ["yes", "yes", "Main registry", "https://registry.example.org", "registry-reader", "", "", "",
               "yes", "https://publish.example.org", "approved", "Release destination", "registry-writer", "",
               "yes", str(filename), "", "yes", "approved/*", "", "yes", "main-reader", "30"]
    secrets_entered = ["", "new-contract-password", "new-contract-password", "upstream-secret", "destination-secret", "signing-secret"]
    output = contract_terminal()
    try:
        with patch("builtins.input", side_effect=answers), patch.object(wizard.getpass, "getpass", side_effect=secrets_entered), \
                patch("sys.stdout", output), patch.object(wizard.sys.stdin, "isatty", return_value=True):
            outcome = wizard.configure_registry("main", "https://cats.example.org", "admin", "test-password-long")
        assert_authenticated_contract(transport, portal)
        with portal.SessionLocal() as db:
            upstream = db.scalar(select(OCIUpstream))
            assert upstream.endpoint == "https://registry.example.org"
            assert decrypt_secret(upstream.password) == "upstream-secret"
            settings = {row.key: row.value for row in db.scalars(select(portal.PortalSetting))}
            destination = json.loads(settings["oci_registries"])[0]
            assert destination["endpoint"] == "https://publish.example.org"
            assert destination["namespace"] == "approved" and destination["use_for_remediation"] is True
            assert decrypt_secret(destination["password"]) == "destination-secret"
            metadata = signing.public_metadata(settings)
            assert metadata["configured"] and metadata["enabled"]
            assert metadata["fingerprint"] == signing.public_key(public)[1]
            mapping = db.scalar(select(OCIRepository))
            principal = db.scalar(select(OCIPrincipal))
            assert mapping.upstream_id == upstream.id and mapping.service_id is None
            assert mapping.public_repository == mapping.upstream_repository == "approved/*"
            assert principal.repository_ids == [mapping.id] and principal.name == "main-reader"
        assert "Signing key installed and enabled" in outcome["completed"]
        assert any("verify registry push access" in item for item in outcome["pending"])
        assert all(secret not in output.getvalue() for secret in secrets_entered if secret)

        # A rerun can enable a disabled key using the real save form, preserving
        # its encrypted material and publisher identity without a new upload.
        original_signing = json.loads(settings[signing.SETTING])
        with patch.object(wizard.getpass, "getpass", return_value=""):
            client.login("admin", "new-contract-password")
        client.form("/admin/configuration/signing", {"enabled": "false", "action": "save"})
        completed, pending = [], []
        with patch("builtins.input", return_value=""), patch("sys.stdout", output), patch.object(wizard, "generate_signing_key") as generate:
            wizard.signing(client, completed, pending, "cats-main:local", "unused", "unix:///run/docker.sock")
        generate.assert_not_called()
        assert "Existing signing key enabled" in completed and not pending
        with portal.SessionLocal() as db:
            retained = json.loads(db.scalar(select(portal.PortalSetting).where(portal.PortalSetting.key == signing.SETTING)).value)
            assert retained["enabled"] is True
            for field in ("private_key", "password", "public_key", "fingerprint", "publisher_root"):
                assert retained.get(field) == original_signing.get(field)
        client.form("/logout", {})
    finally:
        transport.http.close()


def test_replica_wizard_matches_real_application_contract(monkeypatch):
    """Real replica boundary, pinned source and durable sync admission; workers stay stopped."""
    from sqlalchemy import select
    from app.durable_jobs import DurableJob
    from app.oci_models import OCIPrincipal, OCIRepository, OCIUpstream
    from app.replica_models import ReplicaSource
    from app.secrets import decrypt_secret
    _, transport, portal = application_client(monkeypatch, "replica")
    pin = "sha256:" + "a" * 64
    answers = ["yes", "yes", "Local registry", "https://local-registry.example.org", "local-reader", "", "", "",
               "yes", "Signed releases", "approved/*", pin, "60", "yes", "yes", "approved/*", "local/*", "yes", "replica-reader", "30"]
    output = contract_terminal()
    try:
        with patch("builtins.input", side_effect=answers), patch.object(wizard.getpass, "getpass", side_effect=["", "new-contract-password", "new-contract-password", "local-secret"]), \
                patch("sys.stdout", output), patch.object(wizard.sys.stdin, "isatty", return_value=True):
            outcome = wizard.configure_registry("replica", "https://cats.example.org", "admin", "test-password-long")
        assert_authenticated_contract(transport, portal)
        with portal.SessionLocal() as db:
            upstream = db.scalar(select(OCIUpstream))
            source = db.scalar(select(ReplicaSource))
            mapping = db.scalar(select(OCIRepository))
            principal = db.scalar(select(OCIPrincipal))
            job = db.scalar(select(DurableJob).where(DurableJob.kind == "replica_sync"))
            assert decrypt_secret(upstream.password) == "local-secret"
            assert source.upstream_id == upstream.id and source.repository == "approved/*"
            assert source.trusted_publishers == [pin] and source.poll_seconds == 60 and source.enabled
            assert job.payload == {"source_id": source.id} and job.status == "queued"
            assert mapping.public_repository == "local/*" and mapping.upstream_repository == "approved/*"
            assert mapping.upstream_id == upstream.id and mapping.service_id is None
            assert principal.repository_ids == [mapping.id] and principal.name == "replica-reader"
            assert db.scalar(select(portal.PortalSetting).where(portal.PortalSetting.key == "image_signing")) is None
        assert "Initial replica sync queued" in outcome["completed"]
        assert any("confirm the sync succeeded" in item for item in outcome["pending"])
        assert "local-secret" not in output.getvalue()
    finally:
        transport.http.close()


if __name__ == "__main__":
    unittest.main()
