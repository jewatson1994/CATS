from io import BytesIO
import json
from zipfile import ZipFile, ZIP_DEFLATED

import pytest
from sqlalchemy import select

from app.service_transfer import parse_service
from app.models import Service, Execution
from test_portal import setup_function, new_client, csrf, SessionLocal, page_data
from test_exchange import seed


def test_multi_version_round_trip_and_collision():
    client = new_client()
    seed(client)
    seed(client, "1.5", "CVE-NEW", 1)
    response = client.get("/services/payments-service/bundle.zip")
    assert response.status_code == 200
    manifest, state = parse_service(response.content)
    assert manifest["schema_version"] == 3
    assert manifest["semantics"] == "authoritative_inputs"
    assert state["records"]["executions"] == []
    assert state["records"]["findings"] == []
    data = {"csrf_token": csrf(client), "target_key": "copied-service"}
    preview = client.post("/exchange/bundles/preview", data=data, files={"upload": ("service.zip", response.content)})
    assert preview.status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(Service).where(Service.service_key == "copied-service")) is None
    token = page_data(preview)["token"]
    result = client.post(f"/exchange/bundles/confirm/{token}", data={"csrf_token": csrf(client), "confirm": "true"}, follow_redirects=False)
    assert result.status_code == 303
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "copied-service"))
        assert service.assessment_status == "assessment_pending"
        assert list(db.scalars(select(Execution).where(Execution.service_id == service.id))) == []
    old = client.get("/services/copied-service/history?version=1.4")
    assert "CVE-OLD" not in old.text and "CVE-NEW" not in old.text
    assert client.post("/exchange/bundles/preview", data=data, files={"upload": ("service.zip", response.content)}).status_code == 409


@pytest.mark.parametrize("mode", ["hash", "path", "duplicate", "schema"])
def test_bundle_rejects_tampering(mode):
    client = new_client()
    seed(client)
    data = client.get("/services/payments-service/bundle.zip").content
    with ZipFile(BytesIO(data)) as original:
        manifest, evidence = original.read("manifest.json"), original.read("service.json")
    if mode == "hash":
        evidence += b" "
    if mode == "schema":
        parsed = json.loads(manifest)
        parsed["schema_version"] = 999
        manifest = json.dumps(parsed).encode()
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest)
        archive.writestr("../service.json" if mode == "path" else "service.json", evidence)
        if mode == "duplicate":
            archive.writestr("extra.json", b"{}")
    with pytest.raises(ValueError):
        parse_service(output.getvalue())


def test_bundle_transaction_rolls_back(monkeypatch):
    from app import service_transfer
    client = new_client()
    seed(client)
    seed(client, "1.5", "CVE-NEW", 1)
    data = client.get("/services/payments-service/bundle.zip").content
    preview = client.post("/exchange/bundles/preview", data={"csrf_token": csrf(client), "target_key": "rollback-service"}, files={"upload": ("bundle.zip", data)})
    token = page_data(preview)["token"]
    calls = []
    def failing(name):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("test rollback")
    monkeypatch.setattr(service_transfer, "import_phase", failing)
    with pytest.raises(RuntimeError, match="test rollback"):
        client.post(f"/exchange/bundles/confirm/{token}", data={"csrf_token": csrf(client), "confirm": "true"})
    with SessionLocal() as db:
        assert db.scalar(select(Service).where(Service.service_key == "rollback-service")) is None
