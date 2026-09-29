"""Confirmation-level portability, conflict, rollback and legacy regressions."""
from datetime import timedelta
import re

from sqlalchemy import select, func

from app.models import Service, Execution, Finding, ServiceMetadata, BundlePreview
from app.service_bundle import export_bundle
from test_portal import setup_function, new_client, csrf, SessionLocal
from test_exchange import seed


def preview(client, data, target, mode="create"):
    return client.post("/exchange/bundles/preview", data={"csrf_token": csrf(client), "target_key": target, "mode": mode}, files={"upload": ("service.zip", data)})


def confirm(client, response):
    assert response.status_code == 200, response.text
    token = re.search(r'/bundles/confirm/([a-f0-9]+)', response.text).group(1)
    return client.post("/exchange/bundles/confirm/" + token, data={"csrf_token": csrf(client), "confirm": "true"}, follow_redirects=False)


def test_metadata_selected_replace_and_stale_preview():
    client = new_client()
    seed(client)
    with SessionLocal() as db:
        source = db.scalar(select(Service))
        db.add(ServiceMetadata(service_id=source.id, values={"system.poc.name": "Original"}))
        target = Service(service_key="existing-target", name="Keep target identity")
        db.add(target)
        db.flush()
        db.add(ServiceMetadata(service_id=target.id, values={"classification": "Old"}))
        db.commit()
    data = client.get("/services/payments-service/bundle.zip").content
    first = preview(client, data, "existing-target", "replace_metadata")
    second = preview(client, data, "existing-target", "replace_metadata")
    assert confirm(client, first).status_code == 303
    assert confirm(client, second).status_code == 409
    with SessionLocal() as db:
        target = db.scalar(select(Service).where(Service.service_key == "existing-target"))
        assert target.name == "Keep target identity"
        assert db.get(ServiceMetadata, target.id).values == {"system.poc.name": "Original"}
        assert db.scalar(select(func.count()).select_from(Execution).where(Execution.service_id == target.id)) == 0


def test_portable_bundle_never_restores_scan_history_as_current_findings():
    client = new_client()
    seed(client)
    old = client.get("/services/payments-service/bundle.zip").content
    assert confirm(client, preview(client, old, "history-target")).status_code == 303
    seed(client, "1.5", "CVE-NEW", 1)
    all_versions = client.get("/services/payments-service/bundle.zip").content
    # V3 carries authoritative inputs only. Adding history cannot revive source findings.
    assert preview(client, all_versions, "history-target", "add_history").status_code == 200
    with SessionLocal() as db:
        target = db.scalar(select(Service).where(Service.service_key == "history-target"))
        assert target.assessment_status == "assessment_pending"
        assert db.scalar(select(Execution).where(Execution.service_id == target.id)) is None
        assert list(db.scalars(select(Finding).where(Finding.service_id == target.id))) == []
    result = preview(client, all_versions, "history-target", "add_history")
    assert confirm(client, result).status_code == 303
    assert confirm(client, preview(client, all_versions, "history-target", "add_history")).status_code == 303
    with SessionLocal() as db:
        target = db.scalar(select(Service).where(Service.service_key == "history-target"))
        assert list(db.scalars(select(Finding).where(Finding.service_id == target.id))) == []
        assert db.scalar(select(func.count()).select_from(Execution).where(Execution.service_id == target.id)) == 0


def test_legacy_v1_remains_importable_as_new_service_only():
    client = new_client()
    seed(client)
    with SessionLocal() as db:
        legacy = export_bundle(db.scalars(select(Execution)).all())
    assert confirm(client, preview(client, legacy, "legacy-target")).status_code == 303
    assert preview(client, legacy, "legacy-target", "add_history").status_code == 422
    with SessionLocal() as db:
        target = db.scalar(select(Service).where(Service.service_key == "legacy-target"))
        assert target.assessment_status == "assessment_pending"
        assert db.scalar(select(func.count()).select_from(Execution).where(Execution.service_id == target.id)) == 0
        assert db.scalar(select(func.count()).select_from(Finding).where(Finding.service_id == target.id)) == 0
    history = client.get("/services/legacy-target/history?version=1.4")
    assert history.status_code == 200
    assert "Imported historical evidence" in history.text and "CVE-OLD" in history.text


def test_bundle_confirmation_replay_and_create_race():
    client = new_client()
    seed(client)
    data = client.get("/services/payments-service/bundle.zip").content
    first = preview(client, data, "race-target")
    second = preview(client, data, "race-target")
    assert confirm(client, first).status_code == 303
    assert confirm(client, first).status_code == 409
    assert confirm(client, second).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Service).where(Service.service_key == "race-target")) == 1
