from io import BytesIO
from datetime import datetime, timedelta, timezone
import re

import pytest
from openpyxl import load_workbook
from sqlalchemy import select

from app.exchange import builtins, workbook, parse_workbook, context_and_rows
from app.models import InventoryRecord, PoamEntry, Service
from test_portal import setup_function, new_client, csrf, payload, pipeline_headers, SessionLocal, add_user


def seed(client, version="1.4", cve="CVE-OLD", offset=0):
    body = payload("version-" + version, datetime.now(timezone.utc) + timedelta(days=offset), [cve])
    body["service"]["version"] = version
    body["service_overview"] = {"ports": [{"port": 5432 if version == "1.4" else 8443, "protocol": "TCP", "service": version}], "images": [{"image": "registry.test/app:" + version}]}
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201


def xlsx(dataset, rows):
    output = BytesIO()
    workbook(builtins()[dataset], {"system.name": "Test"}, rows).save(output)
    return output.getvalue()


@pytest.mark.parametrize("dataset,rows", [
    ("ppsm", [{"network.port": 443, "network.protocol": "TCP", "network.data_service": "https"}]),
    ("assets", [{"asset.name": "=unsafe()", "asset.type": "VM"}]),
    ("poam", [{"finding.identifier": "P-1", "finding.description": "Description"}]),
])
def test_workbook_round_trip(dataset, rows):
    data = xlsx(dataset, rows)
    parsed = parse_workbook(data, builtins()[dataset])
    assert parsed["recognized"] == 1 and not parsed["errors"]
    for key, value in rows[0].items():
        assert parsed["rows"][0]["values"][key] == value
    book = load_workbook(BytesIO(data))
    assert book.active.freeze_panes and book.active.auto_filter.ref
    assert all(c.data_type != "f" for row in book.active for c in row)


def test_version_isolation_and_ui():
    client = new_client()
    seed(client)
    seed(client, "1.5", "CVE-NEW", 1)
    for page in ("/services/payments-service?overview=true", "/services/payments-service?findings_view=raw", "/services/payments-service?findings_view=simplified"):
        header = client.get(page)
        assert header.status_code == 200
        assert "Version:" in header.text
        assert 'class="actions-menu version-menu"' in header.text
        assert "/services/payments-service/history?version=1.4" in header.text
        assert "/services/payments-service/history?version=1.5" in header.text
        assert "Historical versions</a>" not in header.text
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        _, rows = context_and_rows(db, service, "1.4", "poam", "admin")
        assert [r["finding.identifier"] for r in rows] == ["CVE-OLD"]
        _, rows = context_and_rows(db, service, "1.4", "ppsm", "admin")
        assert rows[0]["network.port"] == "5432"
        _, rows = context_and_rows(db, service, "1.4", "assets", "admin")
        assert rows and rows[0]["asset.os_version"] == "1.4"
    response = client.get("/services/payments-service/exchange?version=1.4")
    assert response.status_code == 200 and "Selected version: 1.4" in response.text
    assert client.get("/exchange/templates").status_code == 200
    assert client.get("/services/payments-service/exchange?version=missing").status_code == 404


@pytest.mark.parametrize("dataset,rows,model", [
    ("ppsm", [{"network.port": 443, "network.protocol": "TCP"}], InventoryRecord),
    ("assets", [{"asset.name": "Server", "asset.type": "VM"}], InventoryRecord),
    ("poam", [{"finding.identifier": "P-1", "finding.description": "Description", "finding.status": "approved"}], PoamEntry),
])
def test_preview_confirmation_and_replay(dataset, rows, model):
    client = new_client()
    seed(client)
    response = client.post(f"/services/payments-service/exchange/{dataset}/preview", data={"csrf_token": csrf(client), "version": "1.4"}, files={"upload": ("input.xlsx", xlsx(dataset, rows))})
    assert response.status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(model)) is None
    token = re.search(r'/exchange/confirm/([a-f0-9]+)', response.text).group(1)
    response = client.post(f"/services/payments-service/exchange/confirm/{token}", data={"csrf_token": csrf(client), "conflict_action": "update"}, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        item = db.scalar(select(model))
        assert item is not None
        if model is PoamEntry:
            assert item.status == "pending_approval"
    assert client.post(f"/services/payments-service/exchange/confirm/{token}", data={"csrf_token": csrf(client), "conflict_action": "update"}).status_code == 409


@pytest.mark.parametrize("rows", [
    [{"network.port": 0, "network.protocol": "TCP"}],
    [{"network.port": 1.5, "network.protocol": "TCP"}],
    [{"network.port": 443, "network.protocol": "BAD"}],
    [{"network.port": 443, "network.protocol": "TCP"}] * 2,
])
def test_invalid_rows(rows):
    assert parse_workbook(xlsx("ppsm", rows), builtins()["ppsm"])["errors"]


def test_scoped_permissions_and_csrf():
    admin = new_client()
    seed(admin)
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id))
    add_user("observer", "Assessor", service_id)
    observer = new_client("observer")
    assert observer.get("/services/payments-service/exchange/ppsm/export.xlsx").status_code == 403
    assert observer.get("/exchange/templates").status_code == 403
    assert admin.post("/services/payments-service/exchange/metadata", data={"csrf_token": "bad", "values": "{}"}).status_code == 403


def test_reject_arbitrary_mapping():
    from app.exchange import validate_template
    template = builtins()["ppsm"]
    template["columns"][0]["field"] = "__import__('os')"
    with pytest.raises(ValueError, match="Unknown field"):
        validate_template(template)


def test_record_identity_treats_missing_and_blank_equally():
    from app.exchange import record_key
    assert record_key("ppsm", {"network.port": 443, "network.protocol": "TCP"}) == record_key("ppsm", {"network.port": 443, "network.protocol": "TCP", "network.data_service": None})


def test_exchange_migration_preserves_legacy_rows_and_is_idempotent():
    from sqlalchemy import create_engine, inspect, text
    from app.exchange_migrations import upgrade
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE poam_entries (id INTEGER PRIMARY KEY, title VARCHAR(240))"))
        connection.execute(text("INSERT INTO poam_entries (id, title) VALUES (1, 'Legacy entry')"))
    upgrade(engine)
    upgrade(engine)
    with engine.connect() as connection:
        assert {"service_version", "exchange_key", "supplemental_fields"} <= {column["name"] for column in inspect(connection).get_columns("poam_entries")}
        assert connection.execute(text("SELECT title, service_version FROM poam_entries")).one() == ("Legacy entry", None)
