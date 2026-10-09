from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import scan_access


def auth(owner, services=()):
    return SimpleNamespace(user=SimpleNamespace(id=owner), has=lambda permission, service: service in services)


def request(token="", cookies=None):
    return SimpleNamespace(headers={"X-Scan-Access-Token": token}, cookies=cookies or {}, scope={})


def test_default_admission_requires_auth_and_service_scopes(monkeypatch):
    monkeypatch.delenv("CATS_SCAN_ALLOW_ANONYMOUS", raising=False)
    with pytest.raises(HTTPException) as error:
        scan_access.admission_policy(None)
    assert error.value.status_code == 401
    assert scan_access.admission_policy(auth(1))["credential_policy"] == "public"
    assert scan_access.admission_policy(auth(1, [3]), 3)["credential_policy"] == "service"
    with pytest.raises(HTTPException):
        scan_access.admission_policy(auth(1), 3)


def test_owner_and_scoped_service_access(monkeypatch):
    job = {"job_id": "a" * 32, "owner_user_id": 4, "ingest_service_db_id": 8}
    scan_access.authorize_job(job, auth(4))
    scan_access.authorize_job(job, auth(9, [8]))
    with pytest.raises(HTTPException):
        scan_access.authorize_job(job, auth(9, [7]))
    with pytest.raises(HTTPException):
        scan_access.authorize_job(job, None)


def test_opt_in_capability_access_is_job_specific_and_hash_only(monkeypatch):
    monkeypatch.setenv("CATS_SCAN_ALLOW_ANONYMOUS", "true")
    first = {"job_id": "a" * 32}
    token = scan_access.issue_access(first)
    assert token not in first.values()
    assert len(first["access_token_hash"]) == 64
    scan_access.authorize_job(first, None, request(token))
    scan_access.authorize_job(first, None, request(cookies={scan_access.cookie_name(first["job_id"]): token}))
    second = {"job_id": "b" * 32}
    scan_access.issue_access(second)
    with pytest.raises(HTTPException):
        scan_access.authorize_job(second, None, request(token))
    with pytest.raises(HTTPException):
        scan_access.authorize_job(first, None, request("bad-token"))
    with pytest.raises(HTTPException):
        scan_access.admission_policy(None, 3)


def test_job_capability_cannot_authorize_owned_or_service_job(monkeypatch):
    monkeypatch.setenv("CATS_SCAN_ALLOW_ANONYMOUS", "true")
    job = {"job_id": "a" * 32}
    token = scan_access.issue_access(job)
    job["owner_user_id"] = 3
    with pytest.raises(HTTPException):
        scan_access.authorize_job(job, None, request(token))
    job["owner_user_id"] = None
    job["ingest_service_id"] = "sensitive-service"
    with pytest.raises(HTTPException):
        scan_access.authorize_job(job, None, request(token))


def test_public_projection_never_exposes_job_secrets():
    job = {"job_id": "a" * 32, "status": "running", "owner_user_id": 7,
           "access_token_hash": "secret", "log_tail": "sensitive registry output",
           "definition_context": {"token": "secret"}, "image_list": "private-registry/app",
           "summary": {"images": 2, "vulnerabilities": {"Critical": 1}, "token": "secret"}}
    result = scan_access.public_projection(job)
    assert result == {"job_id": "a" * 32, "status": "running", "summary": {"images": 2, "vulnerabilities": {"Critical": 1}, "formats": []}, "error": ""}


def test_intelligence_projection_reports_versions_and_superseded_sources(monkeypatch, tmp_path):
    from app.scan_intelligence import publish_generation, pin_databases
    stage = tmp_path / 'stage'; stage.mkdir()
    (stage / 'database').write_bytes(b'old')
    source = tmp_path / 'grype'
    publish_generation(stage, source, 'grype', {'schemaVersion': 6, 'built': '2026-10-01'})
    pinned = pin_databases({'CATS_SCAN_GRYPE_SOURCE': str(source), 'CATS_SCAN_TRIVY_SOURCE': str(tmp_path / 'missing')}, tmp_path / 'attempt')
    monkeypatch.setenv('GRYPE_DB_CACHE_DIR', str(source))
    monkeypatch.setenv('TRIVY_CACHE_DIR', str(tmp_path / 'missing'))
    old = scan_access.public_projection({}, {'databases': pinned})['intelligence']
    assert old['databases']['grype'] == {'status': 'current', 'version': '6', 'built': '2026-10-01'}
    assert old['status'] == 'missing'
    (stage / 'database').write_bytes(b'new')
    publish_generation(stage, source, 'grype', {'schemaVersion': 7, 'built': '2026-10-08'})
    updated = scan_access.public_projection({}, {'databases': pinned})['intelligence']
    assert updated['databases']['grype']['status'] == 'superseded'
    assert str(tmp_path) not in str(updated)
