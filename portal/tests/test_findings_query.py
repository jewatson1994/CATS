from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.findings_query import (load_filter_support, load_page_support,
                               load_simplified_support, prepare_findings_view)
from app.models import (ExceptionRecord, Execution, Finding, FindingObservation,
                        Service, ServiceVersion)


def test_version_menu_uses_scalar_values_without_execution_hydration():
    from app.exchange import versions
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        service = Service(service_key="versions", name="Versions", manual_version="fallback")
        db.add(service)
        db.flush()
        assert versions(db, service) == ["fallback"]
        for index, value in enumerate(["1", "2", "1", None, 3]):
            db.add(Execution(service_id=service.id, execution_key=f"version-{index}",
                             scanned_at=now + timedelta(seconds=index), complete=True,
                             raw_payload={"service": {"version": value}, "unused": "large evidence"}))
        db.commit()
        service_id = service.id
        db.expunge_all()
        service = db.get(Service, service_id)
        assert versions(db, service) == ["3", "Unknown", "1", "2"]
        assert not any(isinstance(item, Execution) for item in db.identity_map.values())


def test_projection_and_page_support_do_not_hydrate_history():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        service = Service(service_key="bounded", name="Bounded")
        db.add(service)
        db.flush()
        executions = [Execution(service_id=service.id, execution_key=f"scan-{i}",
                                scanned_at=now + timedelta(seconds=i), complete=True,
                                raw_payload={}) for i in range(25)]
        db.add_all(executions)
        db.flush()
        findings = [Finding(service_id=service.id, cve=f"CVE-{i}", severity="High",
                            first_seen=now, episode_started=now, last_seen=now,
                            active=i == 0) for i in range(2)]
        db.add_all(findings)
        db.flush()
        for finding in findings:
            for execution in executions:
                db.add(FindingObservation(finding_id=finding.id, execution_id=execution.id,
                                          image=f"image-{execution.id}", evidence={"epss": .9}))
        db.commit()
        service_id = service.id
        db.expunge_all()
        service = db.get(Service, service_id)
        view, proxy, latest = prepare_findings_view(db, service, now, {},
                                                   lambda projected, *_: {"service": projected})
        assert view["service"] is proxy
        assert all(isinstance(f, SimpleNamespace) for f in proxy.findings)
        assert all(len(f.observations) == 1 for f in proxy.findings)
        assert len(proxy.executions) == 1
        assert not any(isinstance(obj, (Finding, FindingObservation)) for obj in db.identity_map.values())
        load_filter_support(db, service_id, proxy.findings)
        assert all(len(f.observations) == 20 for f in proxy.findings)
        load_simplified_support(db, service_id, proxy.findings, SimpleNamespace(id=999999))
        assert len(proxy.findings[0].observations) == 1
        assert proxy.findings[0].observations[0].execution_id == latest.id
        load_simplified_support(db, service_id, proxy.findings, latest)
        assert len(proxy.findings[0].observations) == 1
        orm_finding = db.get(Finding, proxy.findings[0].id)
        assert "observations" not in orm_finding.__dict__
        orm_images = load_page_support(db, service_id, [orm_finding], latest)
        assert orm_images[orm_finding.id] == [f"image-{latest.id}"]
        assert "observations" not in orm_finding.__dict__
        assert not db.dirty
        db.expunge(orm_finding)
        # The active row follows the supplied current execution, while the
        # resolved row uses its own latest observation's execution.
        current = SimpleNamespace(id=latest.id - 1)
        images = load_page_support(db, service_id, proxy.findings, current)
        assert images[proxy.findings[0].id] == [f"image-{current.id}"]
        assert images[proxy.findings[1].id] == [f"image-{latest.id}"]
        assert all(len(f.observations) == 1 for f in proxy.findings)
        assert not any(isinstance(obj, (Finding, FindingObservation)) for obj in db.identity_map.values())


def test_empty_page_support_does_not_query():
    assert load_page_support(None, 1, [], None) == {}


def test_simplified_groups_preserve_duplicate_cves_fallback_and_order():
    from app.findings_query import group_simplified_findings
    now = datetime.now(timezone.utc)
    def finding(identifier, cve, severity, observations):
        return SimpleNamespace(id=identifier, cve=cve, severity=severity,
                               observations=observations)
    def observation(identifier, execution, package, fixed, image, evidence=None):
        return SimpleNamespace(id=identifier, execution_id=execution, package=package,
                               fixed_version=fixed, image=image, evidence=evidence or {})
    rows = [
        finding(1, " cve-b ", "High", [observation(1, 1, "zlib", "2", "b")]),
        finding(2, "CVE-B", "Critical", [observation(2, 1, "zlib", "3", "a")]),
        finding(3, "CVE-A", "Low", [observation(3, 1, "zlib", "2", "b")]),
        finding(4, "", "Medium", [observation(4, 1, "zlib", "2", "")]),
        finding(5, "CVE-C", "Unknown", [observation(5, 2, "Alpha", None, "old",
                                                        {"recommendation": "Rebuild"})]),
    ]
    groups = group_simplified_findings(rows, SimpleNamespace(id=1),
                                     {1: now, 2: now - timedelta(days=1), 3: None, 4: None, 5: None})
    assert [group["package"] for group in groups] == ["Alpha", "zlib"]
    assert groups[0]["images"] == []
    assert groups[0]["remediation"] == "Rebuild"
    assert groups[0]["fixed_version"] == "Latest fixed version"
    assert groups[1] == {
        "package": "zlib", "fixed_versions": ["2", "3"],
        "fixed_version": "2, 3", "remediation": "Update the affected package to the fixed version.",
        "cves": ["CVE-A", "CVE-B"], "finding_ids": [3, 1], "images": ["a", "b"],
        "severities": ["High", "Critical", "Low", "Medium"], "severity": "Critical",
        "due": now - timedelta(days=1),
    }
    assert group_simplified_findings([], None, {}) == []


def test_support_batches_preserve_evidence_below_sqlite_parameter_limit():
    import sqlite3
    from sqlalchemy import event, insert

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(insert(Service), {"id": 1, "service_key": "large", "name": "Large"})
        connection.execute(insert(Execution), {"id": 1, "service_id": 1,
                           "execution_key": "large-scan", "scanned_at": now, "complete": True,
                           "raw_payload": {}})
        connection.execute(insert(Finding), [dict(id=i, service_id=1, cve=f"CVE-{i}",
                           severity="High", first_seen=now, last_seen=now,
                           episode_started=now, active=True) for i in range(1, 1201)])
        connection.execute(insert(FindingObservation), [dict(id=i, finding_id=i,
                           execution_id=1, image=f"image-{i}", package=f"package-{i}",
                           evidence={"epss": .9}) for i in range(1, 1201)])
        connection.connection.driver_connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    parameters = []
    def record(_connection, _cursor, _statement, bound, _context, _many):
        parameters.append(len(bound))
    event.listen(engine, "before_cursor_execute", record)
    with Session(engine) as db:
        findings = [SimpleNamespace(id=i, active=True, observations=[]) for i in range(1, 1201)]
        load_filter_support(db, 1, findings)
        assert all(finding.observations[0].finding_id == finding.id for finding in findings)
        load_simplified_support(db, 1, findings, SimpleNamespace(id=1))
        images = load_page_support(db, 1, findings, SimpleNamespace(id=1))
        assert images == {i: [f"image-{i}"] for i in range(1, 1201)}
        assert all(finding.observations[0].package == f"package-{finding.id}" for finding in findings)
        assert not any(isinstance(item, FindingObservation) for item in db.identity_map.values())
    assert max(parameters) <= 999
    assert len(parameters) == 15
    engine.dispose()


def test_current_version_header_global_images_risk_and_exceptions():
    from app.main import CONFIG_DEFAULTS, service_view

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        service = Service(service_key="versions", name="Versions")
        db.add(service)
        db.flush()
        versions = [ServiceVersion(service_id=service.id, version=str(i)) for i in range(2)]
        db.add_all(versions)
        db.flush()
        service.current_version_id = versions[0].id
        scans = [Execution(service_id=service.id, execution_key=f"version-{i}",
                           service_version_id=version.id, scanned_at=now + timedelta(seconds=i),
                           complete=True, raw_payload={}) for i, version in enumerate(versions)]
        db.add_all(scans)
        db.flush()
        findings = [Finding(service_id=service.id, cve=f"CVE-2099-{i}", severity="High",
                            first_seen=now - timedelta(days=100), episode_started=now - timedelta(days=100),
                            last_seen=now, active=True) for i in range(3)]
        db.add_all(findings)
        db.flush()
        for finding in findings:
            db.add(FindingObservation(finding_id=finding.id, execution_id=scans[0].id,
                                      image="current", evidence={"epss": .1}))
        for finding in findings[:2]:
            db.add(FindingObservation(finding_id=finding.id, execution_id=scans[1].id,
                                      image="global", evidence={"epss": .99}))
        db.add_all([
            ExceptionRecord(finding_id=findings[0].id, justification="active", approved_by="tester",
                            starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=1)),
            ExceptionRecord(finding_id=findings[1].id, justification="expired", approved_by="tester",
                            starts_at=now - timedelta(days=2), expires_at=now - timedelta(days=1)),
        ])
        db.commit()
        service_id, current_id, global_id = service.id, scans[0].id, scans[1].id
        db.expunge_all()
        configuration = dict(CONFIG_DEFAULTS, epss_enabled="true", epss_threshold="0.9",
                             kev_enabled="false", minimum_severity="None", overdue_days="90",
                             compliance_mode="risk_based", epss_rules="[]")
        view, proxy, current = prepare_findings_view(db, db.get(Service, service_id), now,
                                                   configuration, service_view)
        assert current.id == current_id
        assert view["version"] == "0"
        assert len(proxy.executions) == 2
        assert len(proxy.findings[0].exceptions) == 1
        assert proxy.findings[1].exceptions == []
        assert view["due_dates"][proxy.findings[1].id] == now - timedelta(days=10)
        assert proxy.findings[1].id in view["risk_findings"]
        assert proxy.findings[0].id not in view["risk_findings"]
        assert view["risk_metadata"][proxy.findings[1].id]["epss"] == .99
        global_scan = max(proxy.executions, key=lambda row: (row.scanned_at, row.id))
        assert global_scan.id == global_id
        # Simplified grouping needs fallback before page-support replaces it.
        load_simplified_support(db, service_id, proxy.findings, global_scan)
        assert proxy.findings[2].observations[0].execution_id == current_id
        images = load_page_support(db, service_id, proxy.findings, global_scan)
        assert images[proxy.findings[0].id] == ["global"]
        assert images[proxy.findings[2].id] == []
        assert not any(isinstance(obj, (Finding, FindingObservation)) for obj in db.identity_map.values())
