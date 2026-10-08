"""Cybersecurity's KEV/EPSS evidence casts never fail the page.

Root cause: the Cybersecurity read model cast evidence text straight to a
boolean / double precision (``CAST(evidence ->> 'kev' AS boolean)``). On
PostgreSQL any text that is not a literal of that type (``""``, ``[1]``,
``2``, ``"junk"``, booleans for EPSS, out-of-range numbers) raised and the
endpoint returned 500. Values that cast keep exactly that result; only the
values that raised use Services' normalization (Python truthiness for KEV,
Python ``float()`` for EPSS). Cybersecurity's own coalescing and compliance
formulas are unchanged. SQLite compiles exactly as before.

The PostgreSQL tests run with ``CATS_TEST_DATABASE_URL``.
"""
from datetime import datetime, timedelta, timezone
import json
import math

import pytest
from sqlalchemy import JSON, literal_column, select, text
from sqlalchemy.dialects import sqlite

from app import risk_sql
from app.database import SessionLocal, engine
from app.models import FindingObservation, PortalSetting
from test_portal import new_client, pipeline_headers, setup_function as portal_setup

postgresql = pytest.mark.skipif(engine.dialect.name != "postgresql", reason="needs CATS_TEST_DATABASE_URL (PostgreSQL)")

# JSON values a scanner might emit for a KEV or EPSS field.
VALUES = [True, False, None, "", " ", "true", "false", "TRUE", " yes ", "no", "y", "n", "on", "off", "t", "f", "1", "0",
          "2", "maybe", "kev", "[]", 0, 1, 2, -1, 0.0, 1.5, 1e300, [], [1], {}, {"a": 1}, "0.97", " 0.5 ", "1e-3",
          ".5", "5.", "+0.25", "-1", "1e400", "1e-400", "0.9_5", "nan", "Infinity", "-inf", "junk", "0x10"]


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


def test_sqlite_compiles_exactly_as_before():
    evidence = FindingObservation.evidence
    pairs = [(risk_sql.evidence_key_boolean(evidence, key), evidence[key].as_boolean()) for key in ("kev", "known_exploited")]
    pairs += [(risk_sql.evidence_key_float(evidence, key), evidence[key].as_float()) for key in ("epss", "epss_score")]
    for new, old in pairs:
        new_sql, old_sql = select(new).compile(dialect=sqlite.dialect()), select(old).compile(dialect=sqlite.dialect())
        assert str(new_sql) == str(old_sql)
        assert list(new_sql.params.values()) == list(old_sql.params.values())


def python_truth(value):
    return bool(value)


def python_float(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def same(left, right):
    if isinstance(left, float) and isinstance(right, float) and math.isnan(left) and math.isnan(right):
        return True
    return left == right


@postgresql
@pytest.mark.parametrize("pre16", [False, True])
def test_every_value_keeps_its_cast_or_uses_services_normalization(pre16, monkeypatch):
    if pre16:
        # The explicit literal test used on servers without pg_input_is_valid.
        monkeypatch.setattr(engine.dialect, "server_version_info", (14, 0))
    document = literal_column("docs.evidence", JSON)
    with SessionLocal() as db:
        # Values come from table rows, as in the real query (a constant would be
        # folded by the planner, which is not how evidence is ever read).
        db.execute(text("CREATE TEMPORARY TABLE docs (id integer, evidence json)"))
        for key, build, sql_type, normalize in (
                ("kev", risk_sql.evidence_key_boolean, "boolean", python_truth),
                ("epss", risk_sql.evidence_key_float, "double precision", python_float)):
            db.execute(text("DELETE FROM docs"))
            for index, value in enumerate(VALUES + ["<missing>"]):
                doc = json.dumps({key: value} if value != "<missing>" else {})
                db.execute(text("INSERT INTO docs VALUES (:id, CAST(:doc AS json))"), {"id": index, "doc": doc})
            actual = dict(db.execute(select(literal_column("docs.id"), build(document, key)).select_from(text("docs"))).all())
            for index, value in enumerate(VALUES):
                try:
                    with db.begin_nested():
                        expected = db.execute(text(f"SELECT CAST((evidence ->> '{key}') AS {sql_type}) FROM docs WHERE id = :id"),
                                              {"id": index}).scalar()
                except Exception:
                    expected = normalize(value)  # the old cast raised: Services' value
                if pre16 and value == "0x10":
                    # Without pg_input_is_valid, hexadecimal float text (accepted by
                    # the C parser) is not recognized and gets Services' value.
                    expected = normalize(value)
                assert same(actual[index], expected), (key, value, actual[index], expected)
            # A missing key is NULL, as before (the coalesce moves on).
            assert actual[len(VALUES)] is None


def ingest(client, key, evidence):
    body = {"schema_version": "1.0", "execution_id": f"{key}-1", "scanned_at": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
            "complete": True, "skipped_images": [], "fixable_only": True,
            "service": {"id": key, "name": key.title(), "version": "1", "poc": "poc@example.invalid"},
            "findings": [{"cve": f"CVE-2024-{index:04d}", "severity": "High", "image": "registry/app:1", "package": "openssl",
                          "fixed_version": "9.9", "evidence": item} for index, item in enumerate(evidence)]}
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201


@pytest.mark.parametrize("settings", [{}, {"compliance_mode": "risk_based", "minimum_severity": "None",
                                          "kev_enabled": "true", "kev_noncompliant": "true", "epss_enabled": "true"}])
def test_cybersecurity_loads_with_any_evidence(settings):
    client = new_client()
    with SessionLocal() as db:
        for key, value in settings.items():
            db.add(PortalSetting(key=key, value=value))
        db.commit()
    unusual = [{"kev": ""}, {"kev": [1]}, {"kev": 2}, {"kev": {}}, {"kev": "maybe"}, {"kev": None, "known_exploited": "yes"},
               {"epss": "junk"}, {"epss": ""}, {"epss": True}, {"epss": [0.5]}, {"epss_score": "0.95"}]
    ingest(client, "unusual", unusual)
    ingest(client, "ordinary", [{"kev": True}, {"kev": False}, {"epss": 0.97}, {}])
    response = client.get("/api/dashboard/cybersecurity?page_size=200")
    assert response.status_code == 200, response.text[:300]
    rows = {row["service"]["service_key"]: row for row in response.json()["rows"]}
    assert rows["ordinary"]["kev"] == 1
    if engine.dialect.name == "postgresql":
        # [1], 2 and "maybe" are truthy, "" and {} are not; null kev falls back
        # to known_exploited "yes", a valid literal, as before.
        assert rows["unusual"]["kev"] == 4
