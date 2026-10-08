from types import SimpleNamespace
from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.database import Base
from app.dashboard_metric_details import TITLES, metric_details
from app.models import DependencyWatchlistEntry, DependencyWatchlistMatch, Execution, Finding, FindingObservation, PoamEntry, Service, utcnow


@pytest.fixture
def metric_db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db


def auth(ids=None):
    return SimpleNamespace(accessible_service_ids=lambda permission: ids)


def add_finding(db, service, index, severity="Critical", kev=True):
    now = utcnow()
    scan = Execution(execution_key=f"{service.service_key}-{index}", service_id=service.id,
                     scanned_at=now, complete=True, raw_payload={"sbom_images": ["image"]})
    db.add(scan)
    db.flush()
    finding = Finding(service_id=service.id, cve=f"CVE-{index:03}", severity=severity,
                      first_seen=now, last_seen=now, episode_started=now, active=True)
    db.add(finding)
    db.flush()
    db.add_all([
        FindingObservation(finding_id=finding.id, execution_id=scan.id, image="image", package="old", fixed_version="", evidence={"kev": False}),
        FindingObservation(finding_id=finding.id, execution_id=scan.id, image="image", package=f"package-{index:03}", fixed_version="2", evidence={"kev": kev}),
    ])


def test_metric_scope_latest_observation_and_attention_weights(metric_db):
    db = metric_db
    allowed = Service(service_key="allowed", name="Allowed")
    hidden = Service(service_key="hidden", name="Hidden")
    archived = Service(service_key="archived", name="Archived", lifecycle_status="archived")
    db.add_all([allowed, hidden, archived])
    db.flush()
    for service in (allowed, hidden, archived):
        add_finding(db, service, service.id)
    db.commit()
    scoped = auth({allowed.id})
    details = metric_details(db, scoped, "patchable")
    assert details["services"] == [{"service_key": "allowed", "name": "Allowed", "count": 1}]
    assert details["packages"] == [{"package": f"package-{allowed.id:03}", "count": 1}]
    assert details["cves"] == [{"cve": f"CVE-{allowed.id:03}", "count": 1}]
    attention = metric_details(db, scoped, "attention")
    assert attention["services"][0]["count"] == 2
    assert attention["cves"][0]["count"] == 2
    assert {row["service_key"] for row in metric_details(db, auth(), "services")["services"]} == {"allowed", "hidden"}
    with pytest.raises(HTTPException) as denied:
        metric_details(db, auth(set()), "critical")
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as invalid:
        metric_details(db, scoped, "invalid")
    assert invalid.value.status_code == 422


def test_top_ten_and_no_payload_reads_for_warm_projection(metric_db):
    db = metric_db
    service = Service(service_key="one", name="One")
    db.add(service)
    db.flush()
    for index in range(13):
        add_finding(db, service, index)
    db.commit()
    metric_details(db, auth(), "vulnerabilities")  # Prepare the normal posture read model.
    statements = []
    def collect(conn, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(db.bind, "before_cursor_execute", collect)
    try:
        details = metric_details(db, auth(), "vulnerabilities")
        assert len(details["cves"]) == len(details["packages"]) == 10
        assert details["services"][0]["count"] == 13
        assert details["cves"][0] == {"cve": "CVE-000", "count": 1}
        assert not any("raw_payload" in statement for statement in statements)
        for metric in TITLES:
            value = metric_details(db, auth(), metric)
            assert set(value) == {"title", "description", "services", "cves", "packages"}
            assert all(len(value[key]) <= 10 for key in ("services", "cves", "packages"))
    finally:
        event.remove(db.bind, "before_cursor_execute", collect)


def test_watchlist_uses_latest_scan_and_poam_counts_entries(metric_db):
    db = metric_db
    service = Service(service_key="one", name="One")
    entry = DependencyWatchlistEntry(name="watched")
    db.add_all([service, entry])
    db.flush()
    add_finding(db, service, 1)
    db.flush()
    finding = db.query(Finding).one()
    old_scan = db.query(Execution).one()
    latest = Execution(execution_key="latest", service_id=service.id, scanned_at=utcnow() + timedelta(seconds=1), complete=True, raw_payload={})
    db.add(latest)
    db.flush()
    db.add_all([
        DependencyWatchlistMatch(entry_id=entry.id, execution_id=old_scan.id, service_id=service.id, component_name="old-watch", image="image"),
        DependencyWatchlistMatch(entry_id=entry.id, execution_id=latest.id, service_id=service.id, component_name="new-watch", image="image"),
        PoamEntry(service_id=service.id, finding_id=finding.id, item_type="vulnerability", title="one", description="one", remediation="update", status="active", created_by_id=1, due_date=utcnow() - timedelta(days=1)),
        PoamEntry(service_id=service.id, finding_id=finding.id, item_type="vulnerability", title="two", description="two", remediation="update", status="active", created_by_id=1, due_date=utcnow() + timedelta(days=1)),
    ])
    db.commit()
    watched = metric_details(db, auth(), "watchlist")
    assert watched["packages"] == [{"package": "new-watch", "count": 1}]
    assert watched["cves"] == []
    assert metric_details(db, auth(), "poam")["cves"] == [{"cve": "CVE-001", "count": 2}]
    assert metric_details(db, auth(), "poam_overdue")["cves"] == [{"cve": "CVE-001", "count": 1}]
    attention = metric_details(db, auth(), "attention")
    assert attention["cves"] == [{"cve": "CVE-001", "count": 4}]
    assert {row["package"]: row["count"] for row in attention["packages"]} == {"package-001": 4, "new-watch": 1}
