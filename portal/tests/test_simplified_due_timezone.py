"""Simplified due dates do not depend on the database session's time zone.

Root cause: on PostgreSQL the group due date was ``to_char(episode_started +
N * interval '1 day')``. ``to_char`` of a ``timestamptz`` prints local time,
which the page then read as UTC, and ``timestamptz + interval '1 day'`` steps
local calendar days (23 or 25 hours across a daylight-saving change). Due
dates are the episode start plus whole 24-hour days in UTC, as ``service_view``
computes them in the shipped (UTC) configuration and as the overdue
predicates compare them. Both the live query and the stored-
classification query are checked, in UTC and non-UTC sessions.

The PostgreSQL cases run with ``CATS_TEST_DATABASE_URL``.
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app import finding_classification as fc, main
from app.database import SessionLocal, engine
from app.models import Execution, Finding, Service
from app.simplified_queries import group_page
from test_portal import new_client, pipeline_headers, setup_function as portal_setup

# A Medium finding (raw-mode due rule: 90 days) started before the US
# daylight-saving change of 2026-11-01, due after it; a Critical one (30 days)
# due in the same offset; a High one (60 days) also due after the change.
EPISODES = {"High": datetime(2026, 9, 2, 5, 45, 0, 654321, tzinfo=timezone.utc),
            "Medium": datetime(2026, 9, 15, 12, 34, 56, 123456, tzinfo=timezone.utc),
            "Critical": datetime(2026, 9, 20, 23, 30, 0, tzinfo=timezone.utc)}  # scan order
ZONES = ["UTC", "America/New_York", "Asia/Kolkata", "Australia/Lord_Howe"]


def setup_function():
    if engine.dialect.name == "postgresql":
        from app.database import Base
        from app.main import seed_auth
        engine.dispose()
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        Base.metadata.create_all(engine)
        seed_auth()
    else:
        portal_setup()


@pytest.fixture(autouse=True)
def no_background_refresh(monkeypatch):
    monkeypatch.setattr(fc, "schedule", lambda *args, **kwargs: None)


def seed():
    client = new_client()
    for index, (severity, started) in enumerate(EPISODES.items()):
        body = {"schema_version": "1.0", "execution_id": f"due-{index}", "scanned_at": started.isoformat(), "complete": True,
                "skipped_images": [], "fixable_only": True,
                "service": {"id": "due", "name": "Due", "version": "1", "poc": "poc@example.invalid"},
                # One package per severity: one Simplified group each.
                "findings": [{"cve": f"CVE-2026-{1000 + other}", "severity": name, "image": "registry/app:1",
                              "package": f"package-{name.lower()}", "fixed_version": "2.0", "evidence": {}}
                             for other, name in enumerate(EPISODES) if other <= index]}
        assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        return db.scalar(select(Service.id).where(Service.service_key == "due"))


def expected_dues(db, service, configuration, now):
    """The due dates every other view uses (``service_view``)."""
    from app.findings_query import prepare_findings_view
    view, _, _ = prepare_findings_view(db, service, now, configuration, main.service_view)
    packages = {finding.id: finding.severity for finding in db.scalars(select(Finding).where(Finding.service_id == service.id))}
    return {f"package-{packages[finding_id].lower()}": due for finding_id, due in view["due_dates"].items()}


def simplified_dues(db, service, configuration, now):
    latest = db.scalar(select(Execution).where(Execution.service_id == service.id)
                       .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    items, _, _ = group_page(db, service, latest, now, configuration, state="active")
    return {item["package"]: item["due"] for item in items}


@pytest.mark.parametrize("classified", [False, True])
@pytest.mark.parametrize("zone", ZONES if engine.dialect.name == "postgresql" else ["(dialect default)"])
def test_due_dates_are_utc_episode_plus_days_in_any_session_time_zone(zone, classified, monkeypatch):
    service_id = seed()
    monkeypatch.setattr(fc, "enabled", lambda: classified)
    now = datetime(2026, 9, 25, tzinfo=timezone.utc)  # every finding active, none overdue
    with SessionLocal() as db:
        if engine.dialect.name == "postgresql":
            db.execute(text("SELECT set_config('TimeZone', :zone, false)"), {"zone": zone})
        service = db.get(Service, service_id)
        configuration = main.configuration_for_service(db, service)
        if classified:
            assert fc.ensure_current(db, service_id, configuration, now)
        actual = simplified_dues(db, service, configuration, now)
    with SessionLocal() as db:
        # The reference evaluator in the shipped (UTC) session configuration.
        if engine.dialect.name == "postgresql":
            db.execute(text("SELECT set_config('TimeZone', 'UTC', false)"))
        service = db.get(Service, service_id)
        expected = expected_dues(db, service, main.configuration_for_service(db, service), now)
    days = {"Medium": 90, "Critical": 30, "High": 60}
    utc_rule = {f"package-{name.lower()}": started + timedelta(days=days[name]) for name, started in EPISODES.items()}
    assert actual == expected == utc_rule
    # The same instants, labelled UTC, as the page reads them.
    assert all(value.utcoffset() == timedelta(0) for value in actual.values())
