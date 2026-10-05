import ast
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from app import models
from app.database import Base
from app.overview import normalize_overview
from app.risk_sql import evidence_score, evidence_truth


NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)
CATALOG_KEV = {"CVE-CATALOG"}
CATALOG_EPSS = {"CVE-CATALOG": .99}


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def active_exception(finding, now):
    return next((item for item in finding.exceptions if not item.revoked_at
                 and aware(item.starts_at) <= now < aware(item.expires_at)), None)


def original_functions():
    source = ast.parse((Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8"))
    names = {"service_view", "_raw_overdue_expression", "_risk_finding_expressions"}
    functions = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {**vars(models), "__package__": "app", "json": json,
        "timedelta": timedelta, "aware": aware, "active_exception": active_exception,
        "archive_state": lambda service: False, "normalize_overview": normalize_overview,
        "kev_cves": lambda: CATALOG_KEV, "epss_scores": lambda: CATALOG_EPSS,
        "risk_metadata": lambda cve: (str(cve).strip().upper() in CATALOG_KEV,
                                      CATALOG_EPSS.get(str(cve).strip().upper())),
        **{key: getattr(sa, key) for key in ("and_", "or_", "true", "false", "func", "case")}}
    tree = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
                           *functions], type_ignores=[])
    exec(compile(ast.fix_missing_locations(tree), "isolated_risk", "exec"), namespace)
    return namespace


@pytest.mark.parametrize("overrides", [
    {"compliance_mode": "raw"},
    {"minimum_severity": "Unknown"},
    {"minimum_severity": "High"},
    {"kev_enabled": "true", "kev_noncompliant": "true"},
    {"kev_enabled": "true", "kev_noncompliant": "false"},
    {"epss_enabled": "true"},
    {"epss_enabled": "true", "epss_rules": '[{"severity":"Any","threshold":0,"noncompliant":true}]'},
    {"epss_enabled": "true", "epss_rules": '[{"severity":"High","threshold":0.1,"noncompliant":false},{"severity":"Any","threshold":0.1,"noncompliant":true}]'},
    {"epss_enabled": "true", "epss_rules": '[{"severity":"","threshold":0.1,"noncompliant":true}]'},
    {"epss_enabled": "true", "kev_enabled": "true", "minimum_severity": "Medium"},
])
def test_database_expressions_match_original_service_view(overrides):
    namespace = original_functions()
    cfg = {"compliance_mode": "risk_based", "overdue_days": "90", "minimum_severity": "None",
           "raw_due_rules": '[{"severity":"High","days":1},{"severity":"HIGH","days":120}]',
           "epss_rules": '[{"severity":"Any","threshold":0.90,"noncompliant":true}]', **overrides}
    engine = sa.create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = models.Service(service_key="risk", name="Risk")
        db.add(service)
        db.flush()
        execution = models.Execution(execution_key="risk", service_id=service.id,
            scanned_at=NOW, complete=True, raw_payload={"service": {"version": "1"}})
        db.add(execution)
        db.flush()
        evidence_cases = [{}, {"epss": 0, "epss_score": .99}, {"epss": None, "epss_score": .99},
            {"epss": "invalid", "epss_score": .99}, {"epss_score": .99}, {"epss": "0.95"},
            {"kev": False, "known_exploited": True}, {"kev": None, "known_exploited": True},
            {"known_exploited": True}, {"kev": "false"}, {"kev": []}, {"kev": {"key": 0}},
            {"epss": "1.2junk"}, {"epss": ".95"}, {"epss": "9.5e-1"}, {"epss": True},
            {"epss": "NaN"}, {"epss": "inf"}, {"epss": "1_0"}, {"epss": "1__0"}]
        for index, evidence in enumerate(evidence_cases * 3):
            finding = models.Finding(service_id=service.id,
                cve=" cve-catalog " if index % 4 == 0 else f"CVE-{index}",
                severity=("High", "HIGH", "unknown", "other", "Critical", "low")[index % 6],
                first_seen=NOW, last_seen=NOW, episode_started=NOW-timedelta(days=(89, 90, 121)[index % 3]))
            # CVEs are unique per service; only one finding uses the catalog key.
            if index % 4 == 0 and index:
                finding.cve = f"CVE-{index}"
            db.add(finding)
            db.flush()
            db.add(models.FindingObservation(finding_id=finding.id, execution_id=execution.id,
                image="image", evidence={"epss": 1, "kev": True}))
            db.add(models.FindingObservation(finding_id=finding.id, execution_id=execution.id,
                image="image", evidence=evidence))
            if index % 7 == 0:
                db.add(models.ExceptionRecord(finding_id=finding.id, justification="test", approved_by="test",
                    starts_at=NOW-timedelta(days=1), expires_at=NOW+timedelta(days=1)))
        db.commit()
        expected = namespace["service_view"](service, NOW, cfg)
        exception = sa.select(models.ExceptionRecord.id).where(
            models.ExceptionRecord.finding_id == models.Finding.id,
            models.ExceptionRecord.revoked_at.is_(None), models.ExceptionRecord.starts_at <= NOW,
            models.ExceptionRecord.expires_at > NOW).exists()
        eligible, noncompliant, observations = namespace["_risk_finding_expressions"]({service.id: cfg}, NOW, exception)
        latest = sa.select(models.FindingObservation.finding_id,
            sa.func.max(models.FindingObservation.id).label("latest_id")).group_by(models.FindingObservation.finding_id).subquery()
        query = sa.select(models.Finding.id, eligible.label("eligible"),
                          sa.and_(noncompliant, ~exception).label("noncompliant"))
        if observations:
            query = query.outerjoin(latest, latest.c.finding_id == models.Finding.id).outerjoin(
                models.FindingObservation, models.FindingObservation.id == latest.c.latest_id)
        actual = db.execute(query).all()
        assert {row.id for row in actual if row.eligible} == expected["risk_eligible"]
        assert {row.id for row in actual if row.noncompliant} == expected["risk_findings"]
    engine.dispose()


@pytest.mark.parametrize("value", [0, None, False, True, "bad", "1.2junk", "0.95", "+.95", "95e-2",
    "9.5_0e-1", "1__0", "", [], {}, "nan", "inf", "-Infinity", " 1. "])
def test_sqlite_score_python_coercion(value):
    expected = 0
    try:
        expected = float(value or 0)
    except (TypeError, ValueError):
        pass
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        actual = connection.scalar(sa.select(evidence_score(sa.literal({"epss": value}, type_=sa.JSON))))
    if expected != expected:
        assert actual is None  # NaN never reaches any threshold.
    else:
        assert actual == expected


def test_postgresql_compilation_guards_casts_and_preserves_json_key_presence():
    score_sql = str(sa.select(evidence_score(models.FindingObservation.evidence)).compile(dialect=postgresql.dialect()))
    truth_sql = str(sa.select(evidence_truth(models.FindingObservation.evidence)).compile(dialect=postgresql.dialect()))
    assert "? 'epss'" in score_sql and "WHEN s ~" in score_sql
    assert "AS numeric" in score_sql and "abs(n)" in score_sql
    assert "? 'kev'" in truth_sql and "jsonb_array_length" in truth_sql
