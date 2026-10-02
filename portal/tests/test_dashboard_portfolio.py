from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.database import Base
from app.dashboard_portfolio import portfolio
from app.models import Execution, Finding, FindingObservation, Service, utcnow


@pytest.fixture
def portfolio_db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db


def auth(ids=None):
    return SimpleNamespace(accessible_service_ids=lambda permission: ids)


def add_service(db, key, history=0):
    now = utcnow()
    service = Service(service_key=key, name=key, lifecycle_status="active")
    db.add(service)
    db.flush()
    for i in range(history):
        db.add(Execution(execution_key=f"{key}-{i}", service_id=service.id,
            scanned_at=now-timedelta(hours=history-i), complete=True,
            raw_payload={"secret": "never returned", "sbom_images": ["image"]}))
    db.flush()
    return service


def test_metrics_precede_filters_and_rows_are_bounded_and_scoped(portfolio_db):
    db = portfolio_db
    first = add_service(db, "first", 3)
    second = add_service(db, "second", 2)
    db.commit()
    data = portfolio(db, auth(), q="first", page_size=1)
    assert data["metrics"]["services"] == 2
    assert data["metrics"]["scanned"] == 2
    assert data["metrics"]["sbom_coverage"] == 2
    assert data["pagination"]["total"] == 1
    assert [row["service"]["service_key"] for row in data["rows"]] == ["first"]
    assert "history" not in data
    assert "secret" not in str(data)
    scoped = portfolio(db, auth({second.id}))
    assert scoped["metrics"]["services"] == 1
    assert scoped["services"] == [{"service_key": "second", "name": "second"}]
    with pytest.raises(HTTPException) as denied:
        portfolio(db, auth(set()))
    assert denied.value.status_code == 403


def test_counts_use_latest_observation_and_query_count_does_not_grow(portfolio_db):
    db = portfolio_db
    service = add_service(db, "one", 100)
    scan = db.query(Execution).filter_by(service_id=service.id).order_by(Execution.id.desc()).first()
    now = utcnow()
    finding = Finding(service_id=service.id, cve="CVE-TEST", severity="Critical", first_seen=now,
        last_seen=now, episode_started=now, active=True)
    db.add(finding)
    db.flush()
    db.add_all([FindingObservation(finding_id=finding.id, execution_id=scan.id, image="image", package="old-component", fixed_version="1", evidence={"kev": True}),
        FindingObservation(finding_id=finding.id, execution_id=scan.id, image="image", package="new-component", fixed_version="", evidence={"kev": False})])
    db.commit()
    statements = []
    def collect(conn, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(db.bind, "before_cursor_execute", collect)
    try:
        data = portfolio(db, auth())
        count = len(statements)
        assert data["metrics"]["critical"] == 1
        assert data["metrics"]["patchable"] == 0
        assert data["metrics"]["kev"] == 0
        # Components preserve the old search across all active observations.
        assert portfolio(db, auth(), component="old-component")["pagination"]["total"] == 1
        assert all("JSON_EXTRACT" in statement for statement in statements if "executions.raw_payload" in statement)
        for i in range(10):
            add_service(db, f"extra-{i}", 5)
        db.commit()
        statements.clear()
        larger = portfolio(db, auth(), page_size=1)
        assert len(statements) == count
        assert len(larger["rows"]) == 1
        assert larger["pagination"]["total"] == 11
    finally:
        event.remove(db.bind, "before_cursor_execute", collect)
