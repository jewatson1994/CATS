"""Precomputed finding classification: parity, invalidation and recovery.

Parity is asserted against both reference implementations: the live SQL
expressions the readers used before (``_risk_finding_expressions``, the
current-exception predicate, the Simplified current-observation rule and the
search surface) and the Python ``service_view`` evaluator. Invalidation,
time windows, concurrent writes, interrupted refreshes, configuration
changes, deletions and bulk statements are each exercised.
"""
from datetime import datetime, timedelta, timezone
import json

import pytest
from sqlalchemy import delete, func, select, true as sqlalchemy_true, update

from app import finding_classification as fc, main
from app.database import SessionLocal, engine
from app.models import (ExceptionRecord, Finding, FindingClassification, FindingClassificationChange,
                        FindingClassificationState, FindingObservation, PortalSetting, Service, utcnow)
from test_portal import new_client, pipeline_headers, setup_function as portal_setup


def setup_function():
    if engine.dialect.name == "postgresql":
        # CATS_TEST_DATABASE_URL: a disposable PostgreSQL database.
        from sqlalchemy import text
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

PAGE = {"Accept": "application/vnd.cats.page+json"}


@pytest.fixture(autouse=True)
def no_background_refresh(monkeypatch):
    """Refreshes run where each test triggers them (PostgreSQL would also
    schedule background ones, racing the assertions about pending work)."""
    monkeypatch.setattr(fc, "schedule", lambda *args, **kwargs: None)
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
# Evidence values covering JSON truthiness and EPSS parsing edge cases.
EVIDENCE = [{}, {"kev": True}, {"kev": False}, {"known_exploited": "yes"}, {"kev": ""}, {"kev": []}, {"kev": [1]},
            {"kev": {}}, {"kev": 0}, {"kev": 2}, {"kev": None}, {"epss": 0.97}, {"epss": "0.91"}, {"epss": "1e-3"},
            {"epss_score": 0.85}, {"epss": "junk"}, {"epss": None}, {"epss": True}, {"epss": "0.9_5"},
            {"epss": 0.5, "kev": True}, {"remediation": "Upgrade the base image"}, {"recommendation": "Rebuild"},
            {"remediation": ""}, {"remediation": "Upgrade the base image", "epss": "0.99"}]


def scan(key, execution, when, cves, *, packages=3, images=2):
    findings = []
    for index, cve in enumerate(cves):
        evidence = dict(EVIDENCE[index % len(EVIDENCE)])
        for image in range(1 + index % images):
            findings.append({"cve": cve, "severity": SEVERITIES[index % len(SEVERITIES)],
                             "image": f"registry/{key}-image-{image}:{execution}",
                             "package": f"package-{index % packages}", "installed_version": "1.0",
                             "fixed_version": f"1.{index % 2 + 1}", "evidence": evidence})
    return {"schema_version": "1.0", "execution_id": execution, "scanned_at": when.isoformat(), "complete": True,
            "skipped_images": [], "fixable_only": True,
            "service": {"id": key, "name": key.title(), "version": "1.0", "poc": "poc@example.invalid"},
            "findings": findings}


def seed(client, key="alpha", count=48):
    old = datetime.now(timezone.utc) - timedelta(days=150)
    recent = datetime.now(timezone.utc) - timedelta(days=40)
    first = [f"CVE-2024-{index:04d}" for index in range(count)]
    # The second scan resolves a few findings and adds new ones.
    second = first[4:] + [f"CVE-2025-{index:04d}" for index in range(6)]
    for execution, when, cves in ((f"{key}-1", old, first), (f"{key}-2", recent, second)):
        response = client.post("/api/v1/pipeline-results", json=scan(key, execution, when, cves), headers=pipeline_headers)
        assert response.status_code == 201, response.text[:300]
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == key))
        ids = db.scalars(select(Finding.id).where(Finding.service_id == service_id, Finding.active.is_(True))
                         .order_by(Finding.id)).all()
        now = utcnow()
        for position, finding_id in enumerate(ids[:12]):
            starts, expires = [(-5, 30), (-60, -1), (3, 40), (-2, 1)][position % 4]
            db.add(ExceptionRecord(finding_id=finding_id, justification="test", approved_by="admin",
                                   starts_at=now + timedelta(days=starts), expires_at=now + timedelta(days=expires),
                                   revoked_at=now if position == 5 else None))
        db.commit()
    return service_id


CONFIGURATIONS = [
    {},
    {"raw_due_rules": json.dumps([{"severity": "Critical", "days": 10}, {"severity": "Medium", "days": 200}])},
    {"compliance_mode": "risk_based", "minimum_severity": "High", "kev_enabled": "false", "epss_enabled": "false"},
    {"compliance_mode": "risk_based", "minimum_severity": "None", "kev_enabled": "true", "kev_noncompliant": "true",
     "epss_enabled": "false"},
    {"compliance_mode": "risk_based", "minimum_severity": "Medium", "kev_enabled": "true", "kev_noncompliant": "false",
     "epss_enabled": "true"},
    {"compliance_mode": "risk_based", "minimum_severity": "None", "kev_enabled": "false", "epss_enabled": "true",
     "epss_rules": "[]", "epss_threshold": "0.5"},
]


def configure(settings):
    with SessionLocal() as db:
        db.execute(delete(PortalSetting).where(PortalSetting.key.in_(list({key for c in CONFIGURATIONS for key in c}))))
        for key, value in settings.items():
            db.add(PortalSetting(key=key, value=value))
        db.commit()


def service_of(db, service_id):
    return db.get(Service, service_id)


def live_sets(db, service_id, configuration, now):
    exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None),
                                                 ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
    eligible, noncompliant, _ = main._risk_finding_expressions({service_id: configuration}, now, exception)
    latest = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("latest_id")).group_by(
        FindingObservation.finding_id).subquery()
    base = select(Finding.id).outerjoin(latest, latest.c.finding_id == Finding.id).outerjoin(
        FindingObservation, FindingObservation.id == latest.c.latest_id).where(Finding.service_id == service_id, Finding.active.is_(True))
    return {"eligible": set(db.scalars(base.where(eligible))),
            "excepted": set(db.scalars(base.where(eligible, exception))),
            "noncompliant": set(db.scalars(base.where(noncompliant, ~exception))),
            "active": set(db.scalars(base.where(eligible, ~noncompliant, ~exception)))}


def stored_sets(db, service_id, configuration, now):
    eligible, excepted, noncompliant = fc.predicates({service_id: configuration}, now)
    base = select(FindingClassification.finding_id).where(FindingClassification.service_id == service_id,
                                                          FindingClassification.active.is_(True))
    return {"eligible": set(db.scalars(base.where(eligible))),
            "excepted": set(db.scalars(base.where(eligible, excepted))),
            "noncompliant": set(db.scalars(base.where(noncompliant, ~excepted))),
            "active": set(db.scalars(base.where(eligible, ~noncompliant, ~excepted)))}


def python_sets(db, service_id, configuration, now):
    from app.findings_query import prepare_findings_view
    view, _, _ = prepare_findings_view(db, service_of(db, service_id), now, configuration, main.service_view)
    return {"excepted": {item.id for item in view["excepted"]}, "noncompliant": {item.id for item in view["noncompliant"]},
            "active": {item.id for item in view["active"]}}


@pytest.mark.parametrize("settings", CONFIGURATIONS)
def test_stored_classification_matches_live_sql_and_python_evaluator(settings):
    client = new_client()
    service_id = seed(client)
    configure(settings)
    now = utcnow()
    with SessionLocal() as db:
        configuration = main.configuration_for_service(db, service_of(db, service_id))
        assert fc.ensure_current(db, service_id, configuration, now)
        stored, live = stored_sets(db, service_id, configuration, now), live_sets(db, service_id, configuration, now)
        assert stored == live
        python = python_sets(db, service_id, configuration, now)
        assert {key: stored[key] for key in python} == python
        # Each class is populated, so the comparison is not vacuous.
        assert stored["eligible"]
        if settings.get("compliance_mode") != "risk_based":
            assert stored["excepted"] and stored["active"] and stored["noncompliant"]
        # Overdue is evaluated at read time: months later more is overdue,
        # and the stored rows still agree, without a rebuild, for every
        # finding whose exception state cannot have changed meanwhile.
        later = now + timedelta(days=100)
        untouched = set(db.scalars(select(Finding.id).where(Finding.service_id == service_id, ~Finding.id.in_(
            select(ExceptionRecord.finding_id)))))
        later_stored = select(FindingClassification.finding_id).where(
            FindingClassification.service_id == service_id, FindingClassification.active.is_(True),
            fc.predicates({service_id: configuration}, later)[2])
        assert set(db.scalars(later_stored)) & untouched == live_sets(db, service_id, configuration, later)["noncompliant"] & untouched
        assert len(set(db.scalars(later_stored))) >= len(stored["noncompliant"])


def test_three_valued_results_are_stored_as_the_live_expressions_evaluate(monkeypatch):
    """Stored values are the canonical expressions' own results (nullable,
    never coalesced), here for a finding without any observation or evidence
    under an EPSS-only policy; pages are identical to the live queries."""
    client = new_client()
    service_id = seed(client)
    configure({"compliance_mode": "risk_based", "minimum_severity": "None", "kev_enabled": "false",
               "epss_enabled": "true", "epss_rules": json.dumps([{"severity": "Any", "threshold": 0.5, "noncompliant": True}])})
    old = utcnow() - timedelta(days=300)
    with SessionLocal() as db:
        orphan = Finding(service_id=service_id, cve="CVE-2023-9999", severity="Critical", first_seen=old,
                         episode_started=old, last_seen=old, active=True)
        db.add(orphan)
        db.commit()
        orphan_id = orphan.id
    now = utcnow()
    with SessionLocal() as db:
        configuration = main.configuration_for_service(db, service_of(db, service_id))
        assert fc.ensure_current(db, service_id, configuration, now)
        # The live expression's own value, whatever it is on this dialect.
        exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id).exists()
        _, live_rule, _ = main._risk_finding_expressions({service_id: configuration}, now, exception, overdue=sqlalchemy_true())
        expected = db.scalar(select(live_rule).select_from(Finding).outerjoin(
            FindingObservation, FindingObservation.finding_id == Finding.id).where(Finding.id == orphan_id))
        assert db.scalar(select(FindingClassification.noncompliant_rule).where(FindingClassification.finding_id == orphan_id)) == expected
        assert stored_sets(db, service_id, configuration, now) == live_sets(db, service_id, configuration, now)
        assert orphan_id not in stored_sets(db, service_id, configuration, now)["active"]
    frozen = utcnow()
    monkeypatch.setattr(main, "utcnow", lambda: frozen)
    stored = _pages(client, "alpha")
    monkeypatch.setattr(fc, "enabled", lambda: False)
    assert _pages(client, "alpha") == stored


def _pages(client, key):
    simplified = f"/services/{key}?findings=true&findings_view=simplified"
    raw = f"/services/{key}?findings_view=raw"
    urls = [simplified, simplified + "&finding_state=noncompliant", simplified + "&finding_state=exceptions",
            simplified + "&finding_state=resolved", simplified + "&severity=High", simplified + "&q=package-1",
            simplified + "&q=image-1", simplified + "&page_size=50&page=2",
            raw, raw + "&finding_state=resolved", raw + "&finding_state=exceptions", raw + "&q=package-2",
            raw + "&severity=Critical", raw + "&resource=image-1", raw + "&finding_state=noncompliant",
            f"/services/{key}?overview=true", f"/services/{key}?architecture=true"]
    pages = {}
    for url in urls:
        response = client.get(url, headers=PAGE)
        assert response.status_code == 200, (url, response.text[:300])
        data = response.json()["data"]
        data.pop("csrf_token", None)
        pages[url] = data
    data = pages[simplified]
    groups = data.get("simplified_groups") or data.get("groups") or []
    for group in groups[:3]:
        url = f"/api/v1/services/{key}/findings/simplified/{group['group_id']}/members"
        response = client.get(url)
        assert response.status_code == 200
        pages[url] = response.json()
    pages["services"] = client.get("/api/dashboard/services?page_size=200").json()["views"]
    return pages


@pytest.mark.parametrize("settings", [CONFIGURATIONS[0], CONFIGURATIONS[4]])
def test_pages_are_identical_with_and_without_stored_classification(settings, monkeypatch):
    client = new_client()
    seed(client)
    configure(settings)
    frozen = utcnow()
    monkeypatch.setattr(main, "utcnow", lambda: frozen)
    monkeypatch.setattr(fc, "enabled", lambda: False)
    live = _pages(client, "alpha")
    monkeypatch.setattr(fc, "enabled", lambda: True)
    _pages(client, "alpha")  # builds the rows inline
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(FindingClassification)) > 0
        state = db.scalar(select(FindingClassificationState))
        assert state is not None and state.findings > 0
    stored = _pages(client, "alpha")
    assert stored == live


def _state(service_id):
    with SessionLocal() as db:
        configuration = main.configuration_for_service(db, service_of(db, service_id))
        return fc.status(db, service_id, configuration, utcnow())


def _build(service_id, now=None):
    with SessionLocal() as db:
        configuration = main.configuration_for_service(db, service_of(db, service_id))
        assert fc.ensure_current(db, service_id, configuration, now or utcnow())


def _pending(service_id):
    with SessionLocal() as db:
        return db.scalars(select(FindingClassificationChange.finding_id).where(
            FindingClassificationChange.service_id == service_id)).all()


def test_writes_record_targeted_or_whole_service_changes_in_their_transaction():
    client = new_client()
    service_id = seed(client)
    _build(service_id)
    assert _state(service_id) == ("current", 0)
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).where(Finding.service_id == service_id, Finding.active.is_(True)).order_by(Finding.id.desc()))
        finding_id = finding.id
        exception = ExceptionRecord(finding_id=finding.id, justification="x", approved_by="admin",
                                    starts_at=utcnow() - timedelta(days=1), expires_at=utcnow() + timedelta(days=9))
        db.add(exception)
        db.flush()
        db.rollback()  # a rolled-back write leaves nothing behind
    assert _pending(service_id) == [] and _state(service_id) == ("current", 0)
    with SessionLocal() as db:
        db.add(ExceptionRecord(finding_id=finding_id, justification="x", approved_by="admin",
                               starts_at=utcnow() - timedelta(days=1), expires_at=utcnow() + timedelta(days=9)))
        db.commit()
    assert _pending(service_id) == [finding_id]
    assert _state(service_id) == ("targeted", 1)
    with SessionLocal() as db:
        assert db.scalar(select(FindingClassification.excepted).where(FindingClassification.finding_id == finding_id)) is False
    _build(service_id)
    assert _pending(service_id) == [] and _state(service_id) == ("current", 0)
    with SessionLocal() as db:
        assert db.scalar(select(FindingClassification.excepted).where(FindingClassification.finding_id == finding_id)) is True
    # A new scan changes every finding's current observation: whole service.
    body = scan("alpha", "alpha-3", datetime.now(timezone.utc), ["CVE-2024-0010"])
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    assert None in _pending(service_id)
    assert _state(service_id)[0] == "full"
    _build(service_id)
    with SessionLocal() as db:
        active = db.scalars(select(FindingClassification.cve).where(FindingClassification.service_id == service_id,
                                                                    FindingClassification.active.is_(True))).all()
    assert active == ["CVE-2024-0010"]


def test_targeted_refresh_rewrites_only_the_changed_findings(monkeypatch):
    client = new_client()
    service_id = seed(client)
    _build(service_id)
    with SessionLocal() as db:
        target = db.scalar(select(Finding).where(Finding.service_id == service_id, Finding.active.is_(True),
                                                 Finding.severity != "Low").order_by(Finding.id))
        target.severity = "Low"
        db.commit()
    seen = []
    original = fc._classification_select

    def spy(db, service_id, configuration, now, latest_id, finding_ids=None):
        seen.append(None if finding_ids is None else sorted(finding_ids))
        return original(db, service_id, configuration, now, latest_id, finding_ids)
    monkeypatch.setattr(fc, "_classification_select", spy)
    _build(service_id)
    assert seen == [[target.id]]
    with SessionLocal() as db:
        assert db.scalar(select(FindingClassification.severity).where(FindingClassification.finding_id == target.id)) == "Low"


def test_exception_boundaries_expire_the_state_and_reclassify_by_time_alone(monkeypatch):
    client = new_client()
    service_id = seed(client)
    now = utcnow()
    _build(service_id, now)
    with SessionLocal() as db:
        state = db.get(FindingClassificationState, service_id)
        boundaries = [fc._aware(value) for row in db.execute(select(ExceptionRecord.starts_at, ExceptionRecord.expires_at)
                                                             .where(ExceptionRecord.revoked_at.is_(None))) for value in row]
        assert fc._aware(state.valid_until) == min(value for value in boundaries if value > now)
        assert fc._aware(state.valid_from) == max(value for value in boundaries if value <= now)
        configuration = main.configuration_for_service(db, service_of(db, service_id))
    later = now + timedelta(days=5)  # one exception has started, another expired
    with SessionLocal() as db:
        verdict = fc.status(db, service_id, configuration, later)
        assert verdict[0] == "targeted"
        assert fc.ensure_current(db, service_id, configuration, later)
        assert stored_sets(db, service_id, configuration, later) == live_sets(db, service_id, configuration, later)
        # A reader whose clock is behind the build is outside the window too.
        assert fc.status(db, service_id, configuration, now)[0] == "targeted"


def test_a_write_committed_during_a_refresh_keeps_the_service_stale(monkeypatch):
    client = new_client()
    service_id = seed(client)
    _build(service_id)
    with SessionLocal() as db:
        first, second = db.scalars(select(Finding.id).where(Finding.service_id == service_id, Finding.active.is_(True))
                                   .order_by(Finding.id).limit(2)).all()
        db.execute(update(Finding).where(Finding.id == first).values(severity="Low"))
        db.add(FindingClassificationChange(service_id=service_id, finding_id=first))
        db.commit()
    original = fc._classification_select
    raced = []

    def racing(db, *args, **kwargs):
        if not raced:
            raced.append(True)
            # Another transaction commits a change after the refresh read the log.
            with SessionLocal() as writer:
                writer.scalar(select(Finding).where(Finding.id == second)).severity = "Negligible"
                writer.commit()
        return original(db, *args, **kwargs)
    monkeypatch.setattr(fc, "_classification_select", racing)
    with SessionLocal() as db:
        configuration = main.configuration_for_service(db, service_of(db, service_id))
        fc.refresh(db.get_bind(), service_id, utcnow())
    assert _pending(service_id) == [second]
    assert _state(service_id) == ("targeted", 1)
    monkeypatch.setattr(fc, "_classification_select", original)
    _build(service_id)
    with SessionLocal() as db:
        assert db.scalar(select(FindingClassification.severity).where(FindingClassification.finding_id == second)) == "Negligible"


def test_an_interrupted_refresh_changes_nothing(monkeypatch):
    client = new_client()
    service_id = seed(client)
    _build(service_id)
    with SessionLocal() as db:
        before = db.execute(select(FindingClassification).order_by(FindingClassification.finding_id)).scalars().all()
        before = [(row.finding_id, row.excepted, row.eligible, row.group_id) for row in before]
        state_before = db.get(FindingClassificationState, service_id).built_at
    body = scan("alpha", "alpha-3", datetime.now(timezone.utc), ["CVE-2024-0010"])
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201

    def failing(*args, **kwargs):
        raise RuntimeError("interrupted")
    monkeypatch.setattr(fc, "_classification_select", failing)
    with SessionLocal() as db:
        with pytest.raises(RuntimeError):
            fc.refresh(db.get_bind(), service_id, utcnow())
        configuration = main.configuration_for_service(db, service_of(db, service_id))
        # Readers fall back to the live queries instead of failing.
        assert fc.ensure_current(db, service_id, configuration, utcnow()) is False
    with SessionLocal() as db:
        after = db.execute(select(FindingClassification).order_by(FindingClassification.finding_id)).scalars().all()
        assert [(row.finding_id, row.excepted, row.eligible, row.group_id) for row in after] == before
        assert db.get(FindingClassificationState, service_id).built_at == state_before
    assert None in _pending(service_id) and _state(service_id)[0] == "full"
    response = client.get("/services/alpha?findings=true&findings_view=simplified", headers=PAGE)
    assert response.status_code == 200


def test_configuration_and_intelligence_changes_make_rows_stale(monkeypatch):
    client = new_client()
    service_id = seed(client)
    configure(CONFIGURATIONS[4])  # risk based with KEV and EPSS: catalog-dependent
    _build(service_id)
    assert _state(service_id) == ("current", 0)
    from app import policy_data
    monkeypatch.setattr(policy_data, "risk_catalog_token", lambda: "another-catalog")
    assert _state(service_id)[0] == "full"
    monkeypatch.undo()
    configure(CONFIGURATIONS[0])  # raw mode: the catalogs do not matter
    assert _state(service_id)[0] == "full"
    _build(service_id)
    monkeypatch.setattr(policy_data, "risk_catalog_token", lambda: "another-catalog")
    assert _state(service_id) == ("current", 0)
    # Due-date settings only change the overdue term, evaluated at read time.
    with SessionLocal() as db:
        db.add(PortalSetting(key="overdue_days", value="15"))
        db.commit()
    assert _state(service_id) == ("current", 0)


def test_bulk_writes_are_detected_and_orphaned_rows_are_removed():
    client = new_client()
    alpha, beta = seed(client, "alpha"), seed(client, "beta")
    _build(alpha)
    _build(beta)
    # A bulk statement that names its service marks that service whole.
    with SessionLocal() as db:
        db.execute(update(Finding).where(Finding.service_id == beta).values(severity="Low"))
        db.commit()
    assert _state(beta)[0] == "full" and _state(alpha) == ("current", 0)
    _build(beta)
    with SessionLocal() as db:
        assert set(db.scalars(select(FindingClassification.severity).where(FindingClassification.service_id == beta))) == {"Low"}
    # One that names no service replaces the posture epoch: everything is stale.
    with SessionLocal() as db:
        epoch = fc._epoch(db)
        db.execute(update(Finding).values(recurrence_count=Finding.recurrence_count))
        db.commit()
        assert fc._epoch(db) != epoch
    assert _state(alpha)[0] == "full" and _state(beta)[0] == "full"
    # Rows left behind by a service that no longer exists are removed by the
    # startup preparation, which then rebuilds every stale service.
    with SessionLocal() as db:
        db.add(FindingClassificationState(service_id=999999, algorithm=fc.ALGORITHM_VERSION, findings=0))
        db.add(FindingClassificationChange(service_id=999999, finding_id=None))
        db.commit()
    assert fc.warm(engine) == 2
    with SessionLocal() as db:
        assert db.get(FindingClassificationState, 999999) is None
        assert not db.scalars(select(FindingClassificationChange).where(FindingClassificationChange.service_id == 999999)).all()
    assert _state(alpha) == ("current", 0) and _state(beta) == ("current", 0)


def test_findings_of_a_deleted_service_leave_no_rows():
    client = new_client()
    alpha = seed(client, "alpha")
    _build(alpha)
    with SessionLocal() as db:
        fc._forget(db.connection(), [alpha])
        db.commit()
        assert db.scalar(select(func.count()).select_from(FindingClassification).where(FindingClassification.service_id == alpha)) == 0
        assert db.get(FindingClassificationState, alpha) is None
    # Rebuilt on the next read, from authoritative findings.
    assert client.get("/services/alpha?findings=true&findings_view=simplified", headers=PAGE).status_code == 200
    assert _state(alpha) == ("current", 0)


def test_switching_classification_off_and_on_rebuilds_what_changed_meanwhile(monkeypatch):
    client = new_client()
    alpha, beta = seed(client, "alpha"), seed(client, "beta")
    _build(alpha)
    _build(beta)
    monkeypatch.setenv("CATS_FINDING_CLASSIFICATION", "false")
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).where(Finding.service_id == alpha, Finding.severity != "Low").order_by(Finding.id))
        finding.severity = "Low"
        db.commit()
    # Nothing is logged while off (nothing would consume it) ...
    assert _pending(alpha) == []
    monkeypatch.delenv("CATS_FINDING_CLASSIFICATION")
    # ... but the written service is no longer current, the other still is.
    assert _state(alpha)[0] == "full" and _state(beta) == ("current", 0)
    _build(alpha)
    with SessionLocal() as db:
        assert db.scalar(select(FindingClassification.severity).where(FindingClassification.finding_id == finding.id)) == "Low"


def test_a_reused_finding_id_never_removes_another_services_row():
    """SQLite reuses the id of a deleted row: a stale row of the finding's
    former service must not shadow, or be removed by, the new owner."""
    client = new_client()
    alpha, beta = seed(client, "alpha"), seed(client, "beta")
    _build(alpha)
    _build(beta)
    with SessionLocal() as db:
        victim = db.scalar(select(Finding.id).where(Finding.service_id == beta).order_by(Finding.id.desc()))
        # Simulate an id now owned by alpha while beta's row is not yet refreshed.
        db.execute(update(FindingClassification).where(FindingClassification.finding_id == victim).values(service_id=beta))
        moved = db.get(Finding, victim)
        moved.service_id, moved.cve = alpha, "CVE-2026-7777"
        # beta's own deletion of that id is still pending in its change log.
        db.add(FindingClassificationChange(service_id=beta, finding_id=victim))
        db.commit()
    _build(alpha)
    _build(beta)
    with SessionLocal() as db:
        assert db.scalar(select(FindingClassification.service_id).where(FindingClassification.finding_id == victim)) == alpha
        configuration = main.configuration_for_service(db, service_of(db, alpha))
        assert stored_sets(db, alpha, configuration, utcnow()) == live_sets(db, alpha, configuration, utcnow())
    assert _state(alpha) == ("current", 0) and _state(beta) == ("current", 0)


def test_a_missing_service_falls_back_instead_of_failing():
    client = new_client()
    seed(client)
    with SessionLocal() as db:
        assert fc.ensure_current(db, 424242, main.get_configuration(db), utcnow()) is False
        assert fc.is_current(db, 424242, main.get_configuration(db), utcnow()) is False


def test_disabled_classification_serves_the_live_queries(monkeypatch):
    client = new_client()
    seed(client)
    monkeypatch.setenv("CATS_FINDING_CLASSIFICATION", "false")
    response = client.get("/services/alpha?findings=true&findings_view=simplified", headers=PAGE)
    assert response.status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(FindingClassification)) == 0
