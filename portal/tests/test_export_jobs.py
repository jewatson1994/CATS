"""Real retained export bytes, async admission, snapshot and authorization tests."""
from datetime import timedelta
from io import BytesIO
from pathlib import Path
from time import perf_counter
from zipfile import ZipFile

import pytest
from sqlalchemy import delete, event, select

from app import export_jobs, export_worker
from app.durable_jobs import DurableJob, claim, execute
from app.models import Execution, Service, UserRoleAssignment, utcnow
from test_portal import SessionLocal, add_user, new_client, setup_function
from test_purpose_exports import _service


@pytest.fixture(autouse=True)
def storage(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_EXPORT_JOB_ROOT", str(tmp_path / "exports"))


def run_one():
    job = claim(("export",), "test-export", SessionLocal)
    assert job
    execute(job, export_worker.generate, SessionLocal)
    with SessionLocal() as db:
        return db.get(DurableJob, job.id)


def test_all_returns_job_before_builder_and_downloads_real_archive(monkeypatch):
    _service()
    client = new_client()
    original = export_jobs.BUILDERS["all"]
    monkeypatch.setitem(export_jobs.BUILDERS, "all", lambda **kwargs: pytest.fail("HTTP generated export"))
    response = client.get("/services/export-test/exports/all.zip")
    assert response.status_code == 202
    identifier = response.json()["job_id"]
    assert client.get(f"/api/v1/exports/{identifier}/download").status_code == 409
    monkeypatch.setitem(export_jobs.BUILDERS, "all", original)
    job = run_one()
    assert job.status == "completed", job.error
    downloaded = client.get(job.result["download_url"])
    assert downloaded.status_code == 200
    with ZipFile(BytesIO(downloaded.content)) as archive:
        assert archive.testzip() is None
        assert {"ppsm.xlsx", "poam.xlsx", "findings.xlsx", "cats-service.zip"} <= set(archive.namelist())
    assert not list(export_jobs.output_root().rglob("*.part"))


def test_new_assessment_while_queued_is_not_silently_exported():
    _service()
    client = new_client()
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "export-test"))
        db.add(Execution(service_id=service.id, execution_key="newer", scanned_at=utcnow(), complete=True, raw_payload={}))
        db.commit()
    job = run_one()
    assert job.status == "failed"
    assert "changed while queued" in job.error
    assert not list(export_jobs.output_root().rglob("output"))


def test_download_rechecks_revoked_scope_and_requesting_identity():
    _service()
    add_user("export-assessor", "Assessor")
    client = new_client("export-assessor")
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    job = run_one()
    assert job.status == "completed", job.error
    assert client.get(job.result["download_url"]).status_code == 200
    assert new_client().get(job.result["download_url"]).status_code == 404
    with SessionLocal() as db:
        db.execute(delete(UserRoleAssignment).where(UserRoleAssignment.user_id == job.requested_by_id))
        db.commit()
    assert client.get(job.result["download_url"]).status_code == 403


def test_access_revoked_before_execution_prevents_output():
    _service()
    add_user("revoked-export", "Assessor")
    client = new_client("revoked-export")
    identifier = client.get("/services/export-test/exports/all.zip").json()["job_id"]
    with SessionLocal() as db:
        job = db.get(DurableJob, identifier)
        db.execute(delete(UserRoleAssignment).where(UserRoleAssignment.user_id == job.requested_by_id))
        db.commit()
    job = run_one()
    assert job.status == "failed" and "revoked" in job.error
    assert not list(export_jobs.output_root().rglob("output"))


@pytest.mark.parametrize("complete_first", [False, True])
def test_deleted_service_revokes_global_portfolio_export(complete_first):
    # A global administrator retains role grants after deletion; those grants
    # must not permit download of a deleted service's retained portfolio data.
    with SessionLocal() as db:
        db.add(Service(service_key="deleted-source", name="Deleted Source"))
        db.commit()
    client = new_client()
    identifier = client.get("/exports/services.xlsx").json()["job_id"]
    if complete_first:
        assert run_one().status == "completed"
    with SessionLocal() as db:
        db.execute(delete(Service).where(Service.service_key == "deleted-source"))
        db.commit()
    assert client.get(f"/api/v1/exports/{identifier}/download").status_code == 403
    if not complete_first:
        job = run_one()
        assert job.status == "failed" and "revoked" in job.error
        assert not list(export_jobs.output_root().rglob("output"))


def test_disk_budget_and_expiry_cleanup(monkeypatch):
    _service()
    client = new_client()
    monkeypatch.setenv("CATS_EXPORT_DISK_BYTES", "1")
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    job = run_one()
    assert job.status == "failed" and "storage budget" in job.error
    monkeypatch.setenv("CATS_EXPORT_DISK_BYTES", str(4 * 1024**3))
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    job = run_one()
    assert job.status == "completed", job.error
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        row.completed_at = utcnow() - timedelta(hours=25)
        db.commit()
    assert client.get(job.result["download_url"]).status_code == 410
    export_worker.cleanup(SessionLocal)
    assert not (export_jobs.output_root() / job.id).exists()


def test_browser_is_sent_to_persisted_jobs_page():
    _service()
    response = new_client().get("/services/export-test/exports/all.zip", headers={"Accept": "text/html"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/jobs?job=")


def test_completed_archive_stays_bound_after_new_assessment():
    import json
    _service()
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "export-test"))
        db.add(Execution(service_id=service.id, execution_key="original-evidence", scanned_at=utcnow(),
            complete=True, raw_payload={"sbom_components": [{"name": "original-component", "version": "1"}]}))
        db.commit()
    client = new_client()
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    job = run_one()
    assert job.status == "completed", job.error
    original = client.get(job.result["download_url"]).content
    with SessionLocal() as db:
        db.add(Execution(service_id=service.id, execution_key="replacement-evidence", scanned_at=utcnow(),
            complete=True, raw_payload={"sbom_components": [{"name": "replacement-component"}]}))
        db.commit()
    assert client.get(job.result["download_url"]).content == original
    with ZipFile(BytesIO(original)) as archive:
        sbom = json.loads(archive.read("sbom-components.json"))
        assert sbom["execution_id"] == "original-evidence"
        assert sbom["components"][0]["name"] == "original-component"


def test_changed_version_before_generation_fails():
    _service()
    client = new_client()
    assert client.get("/services/export-test/export.xlsx").status_code == 202
    with SessionLocal() as db:
        db.scalar(select(Service).where(Service.service_key == "export-test")).manual_version = "changed"
        db.commit()
    job = run_one()
    assert job.status == "failed" and "changed while queued" in job.error


def test_response_byte_limit_never_publishes_partial_output(monkeypatch):
    _service()
    monkeypatch.setenv("CATS_EXPORT_MAX_BYTES", "10")
    client = new_client()
    identifier = client.get("/services/export-test/export.xlsx").json()["job_id"]
    job = run_one()
    assert job.status == "failed" and "CATS_EXPORT_MAX_BYTES" in job.error
    assert client.get(f"/api/v1/exports/{identifier}/download").status_code == 409
    assert not list(export_jobs.output_root().rglob("output*"))


def test_storage_lock_prevents_parallel_generation_and_cleanup():
    from app.delivery_execution import delivery_lock
    _service()
    client = new_client()
    identifier = client.get("/services/export-test/export.xlsx").json()["job_id"]
    root = export_worker._safe_root()
    with delivery_lock(root, 1) as acquired:
        assert acquired
        export_worker.cleanup(SessionLocal)
        job = run_one()
        assert job.status == "queued"  # Safe retry, no second builder.
        assert not (root / identifier).exists()


def test_role_upgrade_cannot_expand_queued_all_export():
    from app.models import Role, User
    _service()
    add_user("limited-export", "Assessor")
    client = new_client("limited-export")
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "limited-export"))
        admin = db.scalar(select(Role).where(Role.name == "Administrator"))
        db.add(UserRoleAssignment(user_id=user.id, role_id=admin.id))
        db.commit()
    job = run_one()
    assert job.status == "completed", job.error
    with ZipFile(BytesIO(client.get(job.result["download_url"]).content)) as archive:
        assert "cats-service.zip" not in archive.namelist()


def test_optional_bundle_permission_revocation_blocks_completed_all_download():
    from app.models import Role
    _service()
    client = new_client()
    assert client.get("/services/export-test/exports/all.zip").status_code == 202
    job = run_one()
    assert job.status == "completed", job.error
    with SessionLocal() as db:
        role = db.scalar(select(Role).where(Role.name == "Administrator"))
        role.permissions = [permission for permission in role.permissions if permission != "bundle.export"]
        db.commit()
    assert client.get(job.result["download_url"]).status_code == 403


def test_cancellation_before_publication_discards_completed_generation(monkeypatch):
    _service()
    client = new_client()
    identifier = client.get("/services/export-test/exports/ppsm.xlsx").json()["job_id"]
    original = export_jobs.BUILDERS["purpose"]
    def cancel_after_build(**kwargs):
        response = original(**kwargs)
        with SessionLocal() as db:
            db.get(DurableJob, identifier).cancel_requested = True
            db.commit()
        return response
    monkeypatch.setitem(export_jobs.BUILDERS, "purpose", cancel_after_build)
    job = run_one()
    assert job.status == "cancelled"
    assert not list(export_jobs.output_root().rglob("output*"))
    assert not list(export_jobs.output_root().rglob("scratch"))
    assert client.get(f"/api/v1/exports/{identifier}/download").status_code == 409


def test_synthetic_95_charts_1700_findings_admission_never_loads_evidence(monkeypatch):
    from app.database import engine
    from app.models import Finding, ServiceArtifact
    _service()
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "export-test"))
        db.add_all(ServiceArtifact(service_id=service.id, artifact_type="helm_chart", artifact_name=f"chart-{i}") for i in range(95))
        stamp = utcnow()
        db.add_all(Finding(service_id=service.id, cve=f"CVE-{i}", severity="High", active=True,
                          first_seen=stamp, last_seen=stamp, episode_started=stamp) for i in range(1700))
        db.commit()
    client = new_client()
    statements = []
    def track(conn, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", track)
    try:
        start = perf_counter()
        response = client.get("/services/export-test/exports/all.zip")
        elapsed = perf_counter() - start
    finally:
        event.remove(engine, "before_cursor_execute", track)
    assert response.status_code == 202
    assert not any("executions.raw_payload" in sql or "FROM findings" in sql or "FROM service_artifacts" in sql for sql in statements)
    assert elapsed < 2
    print(f"Synthetic 95 charts/1700 findings export admission: {elapsed:.3f}s, {len(statements)} SQL statements; generation excluded")
