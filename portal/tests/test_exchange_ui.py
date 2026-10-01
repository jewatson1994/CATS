import json

import pytest
from sqlalchemy import select

from test_portal import setup_function, new_client, csrf, SessionLocal, page_data, page_envelope
from test_exchange import seed
from app.exchange import builtins, validate_template
from app.exchange_ui import export_preview, metadata_groups
from app.models import ExportTemplate, ServiceMetadata


def test_designer_and_metadata_forms_round_trip():
    client = new_client()
    seed(client)
    page = client.get("/exchange/templates")
    assert page.status_code == 200
    assert page_envelope(page)["page"] == "exchange"
    assert page_data(page)["may_manage_templates"] is True
    assert page_data(page)["field_catalog"]["datasets"]
    assert page_data(page)["template_catalog"]["ppsm"]["columns"]
    definition = builtins()["ppsm"]
    definition.update(name="Custom registration", description="Team export", block_missing=True)
    definition["columns"][0]["label"] = "Sequence"
    response = client.post("/exchange/templates", data={"csrf_token": csrf(client), "definition": json.dumps(definition), "enabled": "true"})
    assert response.status_code == 200
    with SessionLocal() as db:
        saved = db.scalar(select(ExportTemplate))
        assert saved.definition["description"] == "Team export"
        assert saved.definition["columns"][0]["label"] == "Sequence"
    response = client.post("/services/payments-service/exchange/metadata", data={"csrf_token": csrf(client), "values": json.dumps({"system.owner": "Operations", "classification": "Internal"})})
    assert response.status_code == 200
    data = page_data(response)
    assert data["metadata"]["system.owner"] == "Operations"
    assert all(field["key"] != "system.name" for group in data["metadata_groups"].values() for field in group)
    assert any(row["counts"].get("Configured") == 1 for row in data["export_preview"])
    assert any(row["counts"].get("Missing optional", 0) > 0 for row in data["export_preview"])


@pytest.mark.parametrize("key", ["system.name", "service.name", "service.version", "export.generated_by", "export.generated_at"])
def test_metadata_rejects_authoritative_keys(key):
    client = new_client()
    seed(client)
    response = client.post("/services/payments-service/exchange/metadata", data={"csrf_token": csrf(client), "values": json.dumps({key: "forged"})})
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(ServiceMetadata)) is None


def test_population_summary_distinguishes_sources_and_optional_gaps():
    definition = {"metadata": [{"field": "system.owner", "label": "Owner"}, {"field": "system.type", "label": "Type", "default": "Application"}], "columns": [{"field": "network.port", "label": "Port", "required": True}, {"field": "network.purpose", "label": "Purpose"}]}
    rows = export_preview(definition, {"system.owner": "Team"}, [{"network.port": 443}, {}], {"system.owner": "Team"})
    assert rows[0]["counts"] == {"Configured": 1}
    assert rows[1]["counts"] == {"Default": 1}
    assert rows[2]["counts"] == {"Automatic": 1, "Missing required": 1}
    assert rows[3]["counts"] == {"Missing optional": 2}
    assert not any(field["key"].startswith(("service.", "export.")) or field["key"] == "system.name" for fields in metadata_groups().values() for field in fields)


def test_description_is_bounded():
    definition = builtins()["ppsm"]
    definition["description"] = "x" * 2001
    with pytest.raises(ValueError, match="Description"):
        validate_template(definition)
