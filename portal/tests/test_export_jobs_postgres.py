"""Opt-in real PostgreSQL export snapshot regression in a disposable schema."""
import json
import os
import uuid
from zipfile import ZipFile

import pytest
from openpyxl import load_workbook
from io import BytesIO
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from test_portal import Base
from app import export_jobs, export_worker
from app.durable_jobs import DurableJob, claim, execute, submit
from app.models import Execution, Role, Service, ServiceImage, User, UserRoleAssignment, utcnow


@pytest.mark.skipif(not os.getenv("CATS_TEST_POSTGRES_URL"), reason="Requires a disposable PostgreSQL connection")
def test_real_postgres_all_archive_uses_one_snapshot_during_concurrent_scan(tmp_path, monkeypatch):
    engine = create_engine(os.environ["CATS_TEST_POSTGRES_URL"])
    schema = "cats_export_test_" + uuid.uuid4().hex
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    # Raw trigger/function DDL is not rewritten by schema_translate_map.
    # Scope every connection so both SQLAlchemy and that DDL use this schema.
    isolated = create_engine(os.environ['CATS_TEST_POSTGRES_URL'],
                             connect_args={'options': f'-c search_path={schema}'})
    sessions = sessionmaker(bind=isolated, expire_on_commit=False)
    monkeypatch.setenv("CATS_EXPORT_JOB_ROOT", str(tmp_path / "exports"))
    try:
        Base.metadata.create_all(isolated)
        with sessions() as db:
            service = Service(service_key="snapshot-export", name="Original Service", manual_version="1.0")
            user = User(username="snapshot-admin", display_name="Snapshot Admin", enabled=True)
            role = Role(name="Export administrator", permissions=["service.export", "bundle.export"])
            db.add_all([service, user, role])
            db.flush()
            db.add(UserRoleAssignment(user_id=user.id, role_id=role.id))
            db.add(ServiceImage(service_id=service.id, image_reference="example.test/image:1"))
            db.add(Execution(service_id=service.id, execution_key="original-scan", scanned_at=utcnow(),
                complete=True, raw_payload={"sbom_components": [{"name": "original-component", "version": "1"}]}))
            db.commit()
            original_snapshot = export_jobs.snapshots(db, [service.id])
            job = submit(db, kind="export", service_id=service.id, requested_by_id=user.id,
                source_execution_id=original_snapshot[0]["execution_id"], version="1.0",
                payload={"builder": "all", "arguments": {"service_key": service.service_key},
                    "scopes": {str(service.id): ["service.export", "bundle.export"]}, "snapshot": original_snapshot})

        original_builder = export_jobs.BUILDERS["all"]

        def build_after_concurrent_commit(**kwargs):
            # Worker has checked the snapshot. Commit changed service metadata
            # and an assessment through a distinct PostgreSQL connection before
            # any of the real archive's lazy queries run.
            with sessions() as concurrent:
                row = concurrent.get(Service, service.id)
                row.name, row.manual_version = "Replacement Service", "2.0"
                concurrent.add(Execution(service_id=service.id, execution_key="replacement-scan", scanned_at=utcnow(),
                    complete=True, raw_payload={"sbom_components": [{"name": "replacement-component", "version": "2"}]}))
                concurrent.commit()
            return original_builder(**kwargs)

        monkeypatch.setitem(export_jobs.BUILDERS, "all", build_after_concurrent_commit)
        claimed = claim(("export",), "snapshot-worker", sessions)
        assert claimed and claimed.id == job.id
        execute(claimed, export_worker.generate, sessions)
        with sessions() as db:
            completed = db.get(DurableJob, job.id)
            assert completed.status == "completed", completed.error
            assert export_jobs.snapshots(db, [service.id]) != original_snapshot
            assert completed.result["snapshot"] == original_snapshot
        with ZipFile(export_jobs.output_root() / job.id / "output") as archive:
            assert archive.testzip() is None
            sbom = json.loads(archive.read("sbom-components.json"))
            assert sbom["execution_id"] == "original-scan"
            assert sbom["components"][0]["name"] == "original-component"
            assert "cats-service.zip" in archive.namelist()
            workbook = load_workbook(BytesIO(archive.read("asset_list.xlsx")), data_only=True)
            values = [cell.value for row in workbook.active for cell in row]
            assert "Original Service" in values and "Replacement Service" not in values
    finally:
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
