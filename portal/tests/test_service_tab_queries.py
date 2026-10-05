from datetime import timedelta
import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.main import CONFIG_DEFAULTS, service_view
from app.models import (ExceptionRecord, Execution, Finding, FindingObservation,
                        Group, Service, ServiceVersion, utcnow)
from app.service_tab_queries import prepare_service_tab_view, prepare_dependency_evidence


@pytest.mark.parametrize("settings", [
    {"compliance_mode": "raw"},
    {"minimum_severity": "High"},
    {"kev_enabled": "true", "kev_noncompliant": "true"},
    {"epss_enabled": "true", "epss_threshold": "0.9"},
])
def test_architecture_validation_header_matches_projection_with_bounded_rows(settings):
    from sqlalchemy import event
    from app.frontend import _service_data
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    configuration = {**CONFIG_DEFAULTS, **settings}
    with Session(engine) as db:
        service = Service(service_key="header", name="Header", groups=[Group(name="Group")])
        db.add(service)
        db.flush()
        version = ServiceVersion(service_id=service.id, version="current")
        db.add(version)
        db.flush()
        service.current_version_id = version.id
        db.add_all([
            Execution(service_id=service.id, service_version_id=version.id, execution_key="current",
                      scanned_at=now-timedelta(days=1), complete=True, raw_payload={}),
            Execution(service_id=service.id, execution_key="global", scanned_at=now,
                      complete=False, raw_payload={"skipped_images": ["global-only"]}),
        ])
        for index in range(200):
            finding = Finding(service_id=service.id, cve=f"CVE-TEST-{index}", severity="High",
                first_seen=now-timedelta(days=100), last_seen=now,
                episode_started=now-timedelta(days=100), active=True)
            db.add(finding)
            db.flush()
            db.add(FindingObservation(finding_id=finding.id, execution_id=1,
                                     image="image", evidence={"epss": .99, "kev": True}))
        db.commit()
        service_id = service.id
        canonical = service_view(service, now, configuration)
        expected = {"can": {}}
        _service_data(expected, {"view": canonical}, None, {})
        db.expunge_all()
        service = db.get(Service, service_id)
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, parameters, context, many:
                     statements.append(statement))
        view, proxy, current = prepare_service_tab_view(db, service, now, configuration, service_view,
                                                      header_only=True)
        actual = {"can": {}}
        _service_data(actual, {"view": view}, None, {})
        assert actual == expected
        assert current.execution_key == "current"
        assert len(proxy.executions) == 2
        assert proxy.findings == proxy.policy_findings == []
        assert not any(isinstance(item, (Finding, FindingObservation)) for item in db.identity_map.values())
        finding_queries = [sql for sql in statements if "FROM findings" in sql]
        assert len(finding_queries) == 1
        assert finding_queries[0].startswith("SELECT EXISTS")
        assert "findings.first_seen" not in finding_queries[0]


def test_activity_header_matches_canonical_view_without_history_hydration():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key="activity", name="Activity", groups=[Group(name="Group")])
        db.add(service)
        db.flush()
        versions = [ServiceVersion(service_id=service.id, version=str(index)) for index in range(2)]
        db.add_all(versions)
        db.flush()
        service.current_version_id = versions[0].id
        scans = [Execution(service_id=service.id, execution_key=f"history-{index}",
                           service_version_id=versions[index % 2].id,
                           scanned_at=now - timedelta(minutes=100-index), complete=True,
                           raw_payload={"service": {"version": str(index % 2)}, "unused": "retained history"})
                 for index in range(100)]
        db.add_all(scans)
        db.flush()
        findings = [Finding(service_id=service.id, cve=f"CVE-TEST-{index}", severity="High",
                            first_seen=now-timedelta(days=100), last_seen=now,
                            episode_started=now-timedelta(days=100), active=index != 2)
                    for index in range(3)]
        db.add_all(findings)
        db.flush()
        for finding in findings:
            for scan in scans:
                db.add(FindingObservation(finding_id=finding.id, execution_id=scan.id,
                                          image="image", evidence={"epss": .99}))
        db.add(ExceptionRecord(finding_id=findings[0].id, justification="approved", approved_by="tester",
                               starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=1)))
        db.commit()
        service_id = service.id
        canonical = service_view(service, now, CONFIG_DEFAULTS)
        summary = {key: canonical[key] for key in ("compliant", "version", "last_execution", "archive",
                   "skipped_images", "skipped_charts", "oldest_age", "risk_metadata", "warning_items", "noncompliance_items")}
        finding_ids = {key: [finding.id for finding in canonical[key]]
                       for key in ("active", "excepted", "resolved", "noncompliant")}
        db.expunge_all()
        service = db.get(Service, service_id)
        view, proxy, latest = prepare_service_tab_view(db, service, now, CONFIG_DEFAULTS, service_view)
        assert {key: view[key] for key in summary} == summary
        assert {key: [finding.id for finding in view[key]] for key in finding_ids} == finding_ids
        assert [group.name for group in proxy.groups] == ["Group"]
        assert latest.id == scans[-2].id
        assert len(proxy.executions) == 2
        assert all(len(finding.observations) == 1 for finding in proxy.findings)
        assert not any(isinstance(item, (Finding, FindingObservation)) for item in db.identity_map.values())
        assert "findings" not in service.__dict__
        assert "executions" not in service.__dict__
        selected, choices = prepare_dependency_evidence(db, proxy, scans[0].id, latest)
        assert selected.id == scans[0].id
        assert len(choices) == 100
        assert all("raw_payload" not in row.__dict__ for row in choices)
        assert all(len(finding.observations) == 1 for finding in proxy.findings)
        # Selecting dependency evidence no longer replaces the header's finding
        # graph. The dependency read model resolves its own selected execution.
        assert all(finding.observations[0].execution_id != selected.id for finding in proxy.findings)
        assert prepare_dependency_evidence(db, proxy, -1, latest)[0] is None
        oldest_id = selected.id
        db.expunge_all()
        service = db.get(Service, service_id)
        dependency_view, dependency_proxy, latest = prepare_service_tab_view(
            db, service, now, CONFIG_DEFAULTS, service_view, include_global_latest=False)
        selected, choices = prepare_dependency_evidence(db, dependency_proxy, oldest_id, latest)
        assert "raw_payload" not in selected.__dict__
        assert {key: dependency_view[key] for key in summary} == summary
        assert len(choices) == 100
        assert sum(isinstance(row, Execution) for row in db.identity_map.values()) == 2




def test_header_evidence_preview_is_bounded_and_never_loads_payload():
    from sqlalchemy import event
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key="large-header", name="Large")
        db.add(service)
        db.flush()
        scan = Execution(service_id=service.id, execution_key="large", scanned_at=now, complete=False,
            raw_payload={"skipped_images": [f"image-{i}" for i in range(100)],
                         "skipped_charts": [f"chart-{i}" for i in range(75)],
                         "sbom_components": [{"name": "huge"}] * 1000})
        db.add(scan)
        db.flush()
        from app.execution_summaries import refresh_execution_summary
        refresh_execution_summary(db, scan)
        db.commit()
        service_id = service.id
        db.expunge_all()
        service = db.get(Service, service_id)
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, *args:
                     statements.append(statement))
        view, proxy, current = prepare_service_tab_view(db, service, now,
            {**CONFIG_DEFAULTS, "incomplete_noncompliant": "true"}, service_view,
            header_only=True)
        assert len(view["skipped_images"]) == len(view["skipped_charts"]) == 10
        assert view["skipped_image_count"] == 100
        assert view["skipped_chart_count"] == 75
        assert "100 skipped images, 75 skipped charts" in view["evidence_state"]
        assert view["evidence_noncompliant"] and view["evidence_preview_truncated"]
        assert len([row for row in view["noncompliance_items"] if row["type"] == "Evidence"]) <= 10
        assert "raw_payload" not in current.__dict__
        assert not any("executions.raw_payload" in sql for sql in statements)
        # A detail reader still receives the authoritative deferred payload.
        assert len(current.raw_payload["sbom_components"]) == 1000
