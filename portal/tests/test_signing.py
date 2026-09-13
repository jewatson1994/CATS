import base64
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from test_portal import setup_function, new_client, csrf, SessionLocal, PortalSetting, AuditEvent, app, add_user, ingest
from app.auth import AuthContext
from test_patching import run_worker, grype_report
from app import main, signing, patch_worker, patch_service
from app.patching import safe_job_config

DIGEST = "sha256:" + "a" * 64
REFERENCE = "registry.example/team/alpine@" + DIGEST
PRIVATE = b"-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\nTEST-PRIVATE-CONTENT\n-----END ENCRYPTED COSIGN PRIVATE KEY-----"


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr(signing.shutil, "which", lambda _: "cosign")
    monkeypatch.setattr(signing, "_command", lambda args, env: subprocess.CompletedProcess(args, 0, pem.decode(), ""))
    return pem


def configure(keys, enabled=True):
    saved = signing.store_keys(PRIVATE, keys, "key-password", enabled)
    with SessionLocal() as db:
        db.add(PortalSetting(key="image_signing", value=json.dumps(saved)))
        db.add(PortalSetting(key="oci_registries", value=json.dumps([{"id": "dest", "endpoint": "https://registry.example", "auth_mode": "none"}])))
        db.commit()
    return saved


def material(keys):
    return signing.job_material({"image_signing": json.dumps(signing.store_keys(PRIVATE, keys, "key-password", True))}, "push")


def test_key_configuration_encrypted_and_safe_metadata(keys):
    saved = signing.store_keys(PRIVATE, keys, "key-password", True)
    assert saved["private_key"].startswith("enc:v1:") and saved["password"].startswith("enc:v1:")
    assert "TEST-PRIVATE" not in json.dumps(saved) and "key-password" not in json.dumps(saved)
    config, credentials = signing.job_material({"image_signing": json.dumps(saved)}, "push")
    assert base64.b64decode(credentials["CATS_SIGNING_PRIVATE_KEY"]) == PRIVATE
    assert credentials["CATS_SIGNING_PASSWORD"] == "key-password"
    assert "private" not in json.dumps(config)
    assert safe_job_config({**config, "signing_private_key": "secret", "password": "secret"}) == config
    assert signing.public_metadata({"image_signing": json.dumps(saved)})["fingerprint"] == saved["fingerprint"]


def test_key_pair_mismatch_rejected(keys):
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError, match="does not match"):
        signing.store_keys(PRIVATE, other, "key-password", True)


def test_key_password_failure_sanitized_and_temporary_key_removed(keys, monkeypatch):
    paths = []
    def fail(args, env):
        paths.append(Path(args[-1]))
        assert paths[-1].read_bytes() == PRIVATE
        assert env["COSIGN_PASSWORD"] == "wrong-password"
        raise subprocess.CalledProcessError(1, args, stderr="TEST-PRIVATE-CONTENT wrong-password")
    monkeypatch.setattr(signing, "_command", fail)
    with pytest.raises(ValueError, match="Unable to unlock") as error:
        signing.store_keys(PRIVATE, keys, "wrong-password", True)
    assert "wrong-password" not in str(error.value)
    assert all(not p.exists() for p in paths)


@pytest.mark.parametrize("private", [b"kms://private/key", b"x" * (signing.MAX_KEY_BYTES + 1), b""], ids=["remote-key", "oversized", "empty"])
def test_invalid_key_input_rejected(keys, private):
    with pytest.raises(ValueError):
        signing.store_keys(private, keys, "", True)


def test_download_and_disabled_signing_do_not_load_secrets(keys, monkeypatch):
    saved = signing.store_keys(PRIVATE, keys, "", False)
    monkeypatch.delenv("CATS_CONFIG_ENCRYPTION_KEY")
    assert signing.job_material({"image_signing": json.dumps(saved)}, "push") == ({}, {})
    saved["enabled"] = True
    assert signing.job_material({"image_signing": json.dumps(saved)}, "download") == ({}, {})
    with pytest.raises(ValueError, match="could not be loaded"):
        signing.job_material({"image_signing": json.dumps(saved)}, "push")


@pytest.mark.parametrize("failure", [None, "sign", "verify"])
def test_sign_verify_order_cleanup_and_no_secret_logging(keys, monkeypatch, failure):
    config, credentials = material(keys)
    calls, paths = [], []
    def command(args, env):
        calls.append(args)
        assert env["DOCKER_CONFIG"] == "/isolated/docker"
        assert env["SSL_CERT_FILE"] == "/private/ca.pem"
        assert "COSIGN_REPOSITORY" not in env and "CATS_SIGNING_PRIVATE_KEY" not in env
        if "--key" in args:
            path = Path(args[args.index("--key") + 1]); paths.append(path)
            assert path.exists()
            if args[1] == "sign":
                assert path.read_bytes() == PRIVATE and env["COSIGN_PASSWORD"] == "key-password"
                assert "--yes" in args and "--tlog-upload=false" in args
            else:
                assert "COSIGN_PASSWORD" not in env and not paths[0].exists()
                assert "--offline" in args and "--insecure-ignore-tlog=true" in args
            assert args[-1] == REFERENCE
        if args[1] == failure:
            raise subprocess.CalledProcessError(1, args, stderr="TEST-PRIVATE-CONTENT key-password")
        return subprocess.CompletedProcess(args, 0, '{"gitVersion":"v2.6.1"}', "")
    monkeypatch.setattr(signing, "_command", command)
    env = {"DOCKER_CONFIG": "/isolated/docker", "SSL_CERT_FILE": "/private/ca.pem", "COSIGN_REPOSITORY": "evil.example", **credentials}
    if failure:
        with pytest.raises(RuntimeError) as error:
            signing.sign_and_verify(REFERENCE, config, credentials, env)
        assert "key-password" not in str(error.value) and "TEST-PRIVATE" not in str(error.value)
    else:
        result = signing.sign_and_verify(REFERENCE, config, credentials, env)
        assert result["signature_status"] == "verified" and result["signature"]["image"] == REFERENCE
        assert result["signature"]["generator_version"] == "v2.6.1"
        assert [c[1] for c in calls] == ["sign", "verify", "version"]
    assert all(not p.exists() for p in paths)


@pytest.mark.parametrize("reference", ["registry.example/image:tag", "", "-bad@" + DIGEST, "registry.example@sha256:wrong"])
def test_signing_requires_immutable_reference(keys, reference):
    config, credentials = material(keys)
    with pytest.raises(RuntimeError, match="immutable digest"):
        signing.sign_and_verify(reference, config, credentials, {})


def test_admin_upload_keep_disable_remove_public_download_and_audit(keys):
    client = new_client()
    response = client.post("/admin/configuration/signing", data={"csrf_token": csrf(client), "enabled": "true", "key_password": "key-password"},
                           files={"private_key": ("cosign.key", PRIVATE), "public_key": ("cosign.pub", keys)}, follow_redirects=False)
    assert response.status_code == 303
    page = client.get("/admin/configuration")
    assert page.status_code == 200 and "Image signing" in page.text
    assert "TEST-PRIVATE" not in page.text and "key-password" not in page.text
    assert client.get("/admin/configuration/signing/public-key").content == keys
    with SessionLocal() as db:
        original = json.loads(db.scalar(select(PortalSetting.value).where(PortalSetting.key == "image_signing")))
    assert client.post("/admin/configuration/signing", data={"csrf_token": csrf(client)}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        saved = json.loads(db.scalar(select(PortalSetting.value).where(PortalSetting.key == "image_signing")))
        assert saved["private_key"] == original["private_key"] and not saved["enabled"]
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "configuration.signing_updated"))
    assert client.post("/admin/configuration/signing", data={"csrf_token": csrf(client), "action": "remove"}, follow_redirects=False).status_code == 303
    assert client.get("/admin/configuration/signing/public-key").status_code == 404


def test_upload_requires_csrf_and_admin(keys):
    client = new_client()
    assert client.post("/admin/configuration/signing", data={"csrf_token": "bad"}).status_code == 403
    guest = TestClient(app)
    assert guest.post("/admin/configuration/signing", data={"csrf_token": "bad"}, follow_redirects=False).status_code in {303, 401, 403}


def test_signed_push_authorization_csrf_secret_transport_and_audits(keys, monkeypatch, tmp_path):
    configure(keys)
    jobs = []
    monkeypatch.setattr(main, "PATCH_JOB_ROOT", tmp_path)
    monkeypatch.setattr(main.PUBLIC_WORKERS, "submit", lambda fn, job, creds: jobs.append((job, creds)))
    data = {"source_image": "alpine:3.20", "output_mode": "push", "destination_registry_id": "dest", "destination_image": "team/alpine:patched"}
    assert TestClient(app).post("/patch", data=data).status_code == 403
    client = new_client()
    assert client.post("/patch", data=data).status_code == 403
    response = client.post("/patch", data={**data, "csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303 and len(jobs) == 1
    job, credentials = jobs[0]
    assert credentials["CATS_SIGNING_PASSWORD"] == "key-password"
    durable = (tmp_path / job / "job-config.json").read_text()
    assert json.loads(durable)["signing_enabled"] is True
    assert "TEST-PRIVATE" not in durable and "key-password" not in durable
    main._patch_job_update(job, status="complete", phase="completed")
    with SessionLocal() as db:
        assert not db.scalar(select(AuditEvent.id).where(AuditEvent.action == "signing.failed", AuditEvent.target_id == job))
    main._patch_job_update(job, status="complete", phase="completed", result={"signature_status": "verified", "immutable_destination": REFERENCE,
                                                                          "signature": {"image": REFERENCE, "key_fingerprint": json.loads(durable)["signing_fingerprint"]}})
    main._patch_job_update(job, status="complete")
    with SessionLocal() as db:
        actions = list(db.scalars(select(AuditEvent.action).where(AuditEvent.target_id == job)))
        assert actions.count("signing.requested") == 1 and actions.count("signing.verified") == 1


@pytest.mark.parametrize("mode,enabled,failure", [("push", True, False), ("push", True, True), ("push", False, False), ("download", True, False)])
def test_worker_signing_is_portal_push_only_and_failure_is_terminal(keys, monkeypatch, tmp_path, mode, enabled, failure):
    config, credentials = material(keys)
    config.update(job_id="sign-test", source_mode="oci", source_image="docker.io/library/alpine:3.20", output_mode=mode, destination_image="registry.example/team/alpine:patched", signing_enabled=enabled)
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("COSIGN_PRIVATE_KEY", "legacy-must-not-trigger-signing")
    invoked = []
    def sign(reference, cfg, creds, env):
        invoked.append(reference)
        assert reference == REFERENCE and creds == credentials
        assert "CATS_SIGNING_PRIVATE_KEY" not in env and "COSIGN_PRIVATE_KEY" not in env
        if failure:
            raise RuntimeError("Signature verification failed")
        return {"signature_status": "verified", "signature": {"image": reference, "key_fingerprint": cfg["signing_fingerprint"]}}
    monkeypatch.setattr(patch_worker, "sign_and_verify", sign)
    code, output, state, calls = run_worker(monkeypatch, tmp_path, config, grype_report([]), grype_report([]), push_digest=DIGEST)
    result = json.loads((output / "patch-result.json").read_text())
    assert len(invoked) == int(mode == "push" and enabled)
    if failure:
        assert code == 1 and state["failed_stage"] == "signing_image"
        assert result["signature_status"] == "failed" and result["immutable_destination"] == REFERENCE
        assert result["artifact_available"] and result["delivery_status"] == "failed"
        assert state["stages"]["pushing_image"]["status"] == "success"
    else:
        assert code == 0
        assert result["signature_status"] == ("verified" if invoked else "not_configured")
    assert "TEST-PRIVATE" not in (output / "patch-events.jsonl").read_text()


def test_worker_does_not_sign_when_push_returns_no_digest(keys, monkeypatch, tmp_path):
    config, credentials = material(keys)
    config.update(job_id="no-digest", source_mode="oci", source_image="docker.io/library/alpine:3.20", output_mode="push", destination_image="registry.example/team/alpine:patched")
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)
    code, output, state, _ = run_worker(monkeypatch, tmp_path, config, grype_report([]), grype_report([]))
    assert code == 1 and state["failed_stage"] == "signing_image"
    assert json.loads((output / "patch-result.json").read_text())["signature_status"] == "failed"


def test_portal_rejects_unsigned_completion_from_old_worker_and_on_reload(keys, monkeypatch, tmp_path):
    config, _ = material(keys)
    job = "oldworker"
    monkeypatch.setattr(main, "PATCH_JOB_ROOT", tmp_path)
    main.PATCH_JOBS[job] = {"job_id": job, "status": "running", "phase": "pushing_image", **config}
    unsigned = {"status": "complete", "delivery_status": "delivered", "signature_status": "not_configured"}
    main._patch_job_update(job, status="complete", phase="completed", result=unsigned)
    assert main.PATCH_JOBS[job]["status"] == "failed"
    output = tmp_path / job / "output"; output.mkdir()
    (output / "patch-state.json").write_text(json.dumps({"status": "complete", "phase": "completed"}))
    (output / "patch-result.json").write_text(json.dumps(unsigned))
    assert main._load_patch_job(job)["status"] == "failed"


@pytest.mark.parametrize("result", [None, "malformed", {"signature_status": "verified", "signature": ["malformed"]}])
def test_partial_signing_result_fails_without_unhandled_error(result):
    current = {"signing_enabled": True, "signing_fingerprint": "sha256:key"}
    values = {"status": "complete", "result": result}
    main._enforce_required_signature(current, values)
    assert values["status"] == "failed" and values["failed_stage"] == "signing_image"


@pytest.mark.parametrize("status", ["failed", "cancelled"])
def test_unsuccessful_signing_job_has_one_terminal_audit(keys, monkeypatch, tmp_path, status):
    config, _ = material(keys)
    job = "terminalaudit"
    monkeypatch.setattr(main, "PATCH_JOB_ROOT", tmp_path)
    main.PATCH_JOBS[job] = {"job_id": job, "status": "running", **config}
    with SessionLocal() as db:
        main._audit_signing_request(db, job, None, config)
    main._patch_job_update(job, status=status, phase="signing_image")
    main._patch_job_update(job, status=status)
    with SessionLocal() as db:
        audits = list(db.scalars(select(AuditEvent).where(AuditEvent.target_id == job)))
        assert [event.action for event in audits].count("signing.failed") == 1
        assert "TEST-PRIVATE" not in json.dumps([event.detail for event in audits])


def test_service_manager_cannot_use_global_signing_key_or_configure_it(keys):
    configure(keys)
    add_user("manager", "Service Manager")
    client = new_client("manager")
    assert client.post("/admin/configuration/signing", data={"csrf_token": csrf(client)}).status_code == 403
    response = client.post("/patch", data={"csrf_token": csrf(client), "source_image": "alpine:3.20", "output_mode": "push",
                                           "destination_registry_id": "dest", "destination_image": "team/alpine:patched"})
    assert response.status_code == 403


def test_scoped_signing_permission_cannot_sign_for_other_services(keys):
    configure(keys)
    assignment = SimpleNamespace(service_id=5, group_id=None, group=None, role=SimpleNamespace(name="Signer", permissions=["artifact.sign"]))
    auth = AuthContext(SimpleNamespace(enabled=True, role_assignments=[assignment]), None)
    with SessionLocal() as db:
        config, _ = main._portal_signing_material(db, auth, "push", SimpleNamespace(id=5))
        assert config["signing_enabled"]
        for service in (None, SimpleNamespace(id=6)):
            with pytest.raises(main.HTTPException) as error:
                main._portal_signing_material(db, auth, "push", service)
            assert error.value.status_code == 403


def test_pipeline_ingestion_does_not_sign(keys, monkeypatch):
    configure(keys)
    monkeypatch.setattr(main, "_portal_signing_material", lambda *a, **kw: pytest.fail("Pipeline must not request signing"))
    response = ingest(TestClient(app))
    assert response.status_code == 201


def test_remote_worker_passes_signing_secrets_only_through_environment(keys, monkeypatch, tmp_path):
    config, credentials = material(keys)
    config.update(job_id="remotesigning", output_mode="push")
    monkeypatch.setattr(patch_service, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(patch_service, "TOKEN", "worker-token")
    captured = {}
    def popen(args, **kw):
        captured.update(kw)
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(patch_service.subprocess, "Popen", popen)
    monkeypatch.setattr(patch_service.threading, "Thread", lambda **kw: SimpleNamespace(start=lambda: None))
    payload = {"config": {**config, "private_key": "must-be-removed"}, "credentials": {**credentials, "COSIGN_REPOSITORY": "untrusted"}}
    client = TestClient(patch_service.app)
    assert client.post("/internal/patch-jobs/remotesigning", json=payload).status_code == 403
    response = client.post("/internal/patch-jobs/remotesigning", json=payload, headers={"X-CATS-Worker-Token": "worker-token"})
    assert response.status_code == 200
    assert captured["env"]["CATS_SIGNING_PASSWORD"] == "key-password"
    assert "COSIGN_REPOSITORY" not in captured["env"]
    contents = (tmp_path / "remotesigning" / "job-config.json").read_text()
    assert "private_key" not in contents and "key-password" not in contents
    patch_service.PROCESSES.pop("remotesigning", None)


@pytest.mark.skipif(not os.getenv("CATS_TEST_COSIGN"), reason="Set CATS_TEST_COSIGN to run real Cosign key validation")
def test_real_cosign_key_upload_and_wrong_password(monkeypatch, tmp_path):
    binary = os.environ["CATS_TEST_COSIGN"]
    monkeypatch.setattr(signing.shutil, "which", lambda _: binary)
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    env = signing.clean_environment(dict(os.environ))
    env["COSIGN_PASSWORD"] = "temporary-test-password"
    prefix = tmp_path / "real-key"
    subprocess.run([binary, "generate-key-pair", "--output-key-prefix", str(prefix)], env=env, check=True,
                   capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    private, public = prefix.with_suffix(".key").read_bytes(), prefix.with_suffix(".pub").read_bytes()
    saved = signing.store_keys(private, public, "temporary-test-password", True)
    assert saved["fingerprint"] == signing.public_key(public)[1]
    assert saved["public_key"].encode() == public
    with pytest.raises(ValueError, match="Unable to unlock"):
        signing.store_keys(private, public, "incorrect", True)
