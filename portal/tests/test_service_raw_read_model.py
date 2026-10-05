from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import main
from app.database import Base
from app.models import Service, ServiceVersion, Execution, Finding, PolicyFinding, ExceptionRecord, utcnow


@pytest.mark.parametrize("state", ["active", "resolved"])
def test_explicit_raw_route_pages_before_hydration(monkeypatch, state):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    monkeypatch.setattr(main, "configuration_for_service", lambda *args: dict(main.CONFIG_DEFAULTS, incomplete_noncompliant="true"))
    monkeypatch.setattr(main, "page_context", lambda auth, **kw: kw)
    monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
    monkeypatch.setattr(main, "remediation_enabled", lambda db: False)
    monkeypatch.setattr("app.findings_query.prepare_findings_view", lambda *args: pytest.fail("whole service finding preparation"))
    with Session(engine) as db:
        service = Service(service_key="raw", name="Raw")
        db.add(service); db.flush()
        versions = [ServiceVersion(service_id=service.id, version=str(index)) for index in range(2)]
        db.add_all(versions); db.flush()
        service.current_version_id = versions[0].id
        db.add_all([Execution(service_id=service.id, service_version_id=version.id,
            execution_key=f"execution-{index}", scanned_at=now-timedelta(days=1-index),
            complete=index == 0, raw_payload={}) for index, version in enumerate(versions)])
        for index in range(121):
            db.add(Finding(service_id=service.id, cve=f"CVE-{index:04}", severity="High",
                active=state == "active", episode_started=now-timedelta(days=100), first_seen=now, last_seen=now))
        db.add(PolicyFinding(service_id=service.id, identity_key="policy", finding="Policy", severity="High",
            active=state == "active", episode_started=now-timedelta(days=100), first_seen=now, last_seen=now))
        db.commit(); db.expunge_all()
        request = Request({"type":"http", "method":"GET", "path":"/", "query_string":b"", "headers":[]})
        auth = SimpleNamespace(accessible_service_ids=lambda permission: None)
        result = main.service_detail("raw", request, findings_view="raw", finding_state=state,
                                     page=3, severity=[], db=db, auth=auth)
        assert result["total_items"] == 122
        assert result["total_pages"] == 3
        assert result["page"] == 3
        assert len(result["findings"]) == 21
        assert len(result["policy_findings"]) == 1
        assert sum(isinstance(row, (Finding, PolicyFinding)) for row in db.identity_map.values()) == 22
        assert result["view"]["oldest_age"] == 100 if state == "active" else result["view"]["oldest_age"] is None
        assert result["view"]["compliant"] is (state == "resolved")
        assert result["view"]["version"] == "0"
        assert result["view"]["last_execution"] == now-timedelta(days=1)
        assert result["view"]["incomplete"] is False
        assert "findings_view=raw" in result["pagination_base"]



def test_raw_severity_options_exclude_only_hidden_excepted_risk(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    cfg = dict(main.CONFIG_DEFAULTS, compliance_mode="risk_based", minimum_severity="Critical",
               kev_enabled="false", epss_enabled="false")
    monkeypatch.setattr(main, "configuration_for_service", lambda *args: cfg)
    monkeypatch.setattr(main, "page_context", lambda auth, **kw: kw)
    monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
    monkeypatch.setattr(main, "remediation_enabled", lambda db: False)
    with Session(engine) as db:
        service = Service(service_key="risk", name="Risk"); db.add(service); db.flush()
        finding = Finding(service_id=service.id, cve="CVE-HIDDEN", severity="Low", active=True,
            first_seen=now, last_seen=now, episode_started=now)
        db.add(finding); db.flush()
        db.add(ExceptionRecord(finding_id=finding.id, justification="approved", approved_by="test",
            starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=1)))
        db.commit(); db.expunge_all()
        request = Request({"type":"http", "method":"GET", "path":"/", "query_string":b"", "headers":[]})
        result = main.service_detail("risk", request, findings_view="raw", severity=[], db=db,
            auth=SimpleNamespace(accessible_service_ids=lambda permission: None))
        assert result["total_items"] == 0
        assert result["severity_options"] == []
