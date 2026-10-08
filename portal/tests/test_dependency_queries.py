from types import SimpleNamespace

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, defer

from app.database import Base
from app.dependency_queries import dependency_page, ensure_projection, persist_projection, dependency_version
from app.dependency_view import dependency_rows
from app.models import Execution


def fixture(db):
    execution = Execution(id=1, execution_key="test", service_id=1, complete=True,
        raw_payload={"sbom_components": [
            {"name": f"Straße%_{i:03}", "version": "1", "image": "app", "ecosystem": "npm",
             "license_expression": "MIT" if i % 2 else ""} for i in range(125)]})
    from datetime import datetime, timezone
    execution.scanned_at = datetime.now(timezone.utc)
    db.add(execution)
    db.flush()
    observation = SimpleNamespace(execution_id=1, package="Straße%_000", installed_version="1",
        image="app", fixed_version="2", evidence={"scanner": "A"})
    finding = SimpleNamespace(cve="CVE-1", severity="Critical", observations=[observation])
    return execution, [finding]


def test_projection_sql_paging_filters_and_invalidation():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        execution, findings = fixture(db)
        risk = lambda cve: (True, .8)
        assert ensure_projection(db, execution, [], findings, risk)
        assert not ensure_projection(db, execution, [], findings, risk)
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, parameters, context, many:
                     statements.append(statement))
        result = dependency_page(db, 1, q="STRASSE%_", page=2, page_size=10)
        canonical = dependency_rows(execution, [], findings, risk)
        # Listings omit per-vulnerability detail; each row's detail is the exact canonical row.
        from app.dependency_queries import LISTING_OMITS, component_detail
        listed = result["dependency_rows"]
        assert len(statements) == 3  # page with window total, one aggregate of all counts, distinct type/image pairs
        assert [{k: v for k, v in row.items() if k not in ("vulnerability_count", "position", "detail_on_demand")} for row in listed] == \
            [{k: v for k, v in row.items() if k not in LISTING_OMITS} for row in canonical[10:20]]
        assert [row["vulnerability_count"] for row in listed] == [len(row["vulnerabilities"]) for row in canonical[10:20]]
        assert [component_detail(db, 1, row["position"]) for row in listed] == canonical[10:20]
        assert result["dependency_total"] == 125
        assert result["critical_components"] == result["kev_components"] == result["fixed_components"] == 1
        assert result["dependency_types"] == ["npm"]
        assert result["dependency_images"] == ["app"]
        assert any("dependency_projection_rows.data" in sql and "LIMIT" in sql for sql in statements)
        statements.clear()
        past = dependency_page(db, 1, q="STRASSE%_", page=99, page_size=10)
        assert (past["dependency_page"], past["dependency_pages"], len(past["dependency_rows"])) == (13, 13, 5)
        assert dependency_page(db, 1, filter="kev", epss=.7)["dependency_total"] == 1
        assert dependency_page(db, 1, license="mit")["dependency_total"] == 62
        assert dependency_page(db, 1, filter="license_unknown")["dependency_total"] == 63
        findings[0].severity = "Low"
        assert ensure_projection(db, execution, [], findings, risk)
        assert dependency_page(db, 1, filter="critical")["dependency_total"] == 0
        assert ensure_projection(db, execution, [], findings, lambda cve: (False, .1))
        assert dependency_page(db, 1, filter="kev")["dependency_total"] == 0
        assert dependency_page(db, 1, epss=.7)["dependency_total"] == 0
        execution.raw_payload = {"sbom_components": [{"name": "new"}]}
        assert ensure_projection(db, execution, [], findings, risk)
        assert dependency_page(db, 1)["dependency_all_total"] == 1


def test_owned_projection_transaction_does_not_commit_request_changes(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'cache.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        execution, findings = fixture(db)
        db.commit()
        execution.pipeline_url = "uncommitted"
        assert persist_projection(db, execution, [], findings, lambda cve: (False, None))
        assert execution in db.dirty
        db.rollback()
    with Session(engine) as db:
        assert db.get(Execution, 1).pipeline_url is None
        assert dependency_page(db, 1)["dependency_all_total"] == 125


def test_ten_thousand_components_warm_page_does_not_load_payload_or_all_rows():
    from app.execution_summaries import refresh_execution_summary
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        execution, findings = fixture(db)
        execution.raw_payload = {"service": {"version": "  exact-version  "},
            "sbom_components": [{"name": f"package-{index:05}", "ecosystem": "npm" if index % 2 else "pypi",
                                  "image": "app" if index % 3 else "other", "version": "1"}
                                 for index in range(10000)]}
        refresh_execution_summary(db, execution)
        ensure_projection(db, execution, [], findings, lambda cve: (False, None))
        db.commit()
        db.expunge_all()
        execution = db.scalar(select(Execution).options(defer(Execution.raw_payload)).where(Execution.id == 1))
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, parameters, context, many:
                     statements.append(sql))
        assert not ensure_projection(db, execution, [], findings, lambda cve: (False, None))
        result = dependency_page(db, 1, page=73, page_size=50)
        assert result["dependency_all_total"] == result["dependency_total"] == 10000
        assert len(result["dependency_rows"]) == 50
        assert result["dependency_rows"][0]["name"] == "package-03600"
        assert result["dependency_types"] == ["npm", "pypi"]
        assert result["dependency_images"] == ["app", "other"]
        assert dependency_page(db, 1, component_type="npm")["dependency_total"] == 5000
        assert dependency_page(db, 1, component_type="NPM")["dependency_total"] == 0
        assert dependency_page(db, 1, image="other")["dependency_total"] == 3334
        assert dependency_version(db, execution) == "  exact-version  "
        assert "raw_payload" not in execution.__dict__
        assert not any("executions.raw_payload" in sql for sql in statements)
        hydrated = [sql for sql in statements if "dependency_projection_rows.data" in sql]
        assert hydrated and all("LIMIT" in sql for sql in hydrated)


def test_flushed_request_changes_are_never_committed_by_shared_sqlite_cache(tmp_path):
    from sqlalchemy.pool import StaticPool
    engines = [create_engine("sqlite://", poolclass=StaticPool),
               create_engine("sqlite://"),
               create_engine(f"sqlite:///{tmp_path / 'writer.db'}")]
    for engine in engines:
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            execution, findings = fixture(db)
            db.commit()
            execution.pipeline_url = "already-flushed"
            db.flush()
            assert persist_projection(db, execution, [], findings, lambda cve: (False, None))
            assert dependency_page(db, 1)["dependency_all_total"] == 125
            db.rollback()
        with Session(engine) as db:
            assert db.get(Execution, 1).pipeline_url is None
            assert dependency_page(db, 1)["dependency_all_total"] == 0
        engine.dispose()


def test_current_projection_warm_uses_scalar_metadata_and_invalidates_evidence():
    from datetime import datetime, timezone
    from sqlalchemy import update
    from app.models import Finding, FindingObservation
    from app.execution_summaries import refresh_execution_summary
    from app.dependency_queries import persist_current_projection
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        execution, _ = fixture(db)
        refresh_execution_summary(db, execution)
        finding = Finding(service_id=1, cve="CVE-real", severity="High",
            first_seen=datetime.now(timezone.utc), episode_started=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc))
        db.add(finding)
        db.flush()
        observation = FindingObservation(finding_id=finding.id, execution_id=execution.id,
            image="app", package="Straße%_000", installed_version="1", fixed_version="2",
            evidence={"scanner": "A"})
        db.add(observation)
        db.commit()
        assert persist_current_projection(db, execution, lambda cve: (False, .2))
        db.commit()
        db.expunge_all()
        execution = db.scalar(select(Execution).options(defer(Execution.raw_payload)).where(Execution.id == 1))
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, params, context, many:
            statements.append(sql))
        assert not persist_current_projection(db, execution, lambda cve: (False, .2))
        assert "raw_payload" not in execution.__dict__
        assert not any("finding_observations.evidence" in sql or "executions.raw_payload" in sql for sql in statements)
        assert dependency_page(db, 1, filter="fixed")["dependency_total"] == 1
        observation = db.scalar(select(FindingObservation))
        observation.fixed_version = None
        db.commit()
        assert persist_current_projection(db, execution, lambda cve: (False, .2))
        assert dependency_page(db, 1, filter="fixed")["dependency_total"] == 0
        db.commit()
        db.execute(update(FindingObservation).values(fixed_version="3"))
        db.commit()
        assert persist_current_projection(db, execution, lambda cve: (False, .2))
        assert dependency_page(db, 1, filter="fixed")["dependency_total"] == 1
        assert persist_current_projection(db, execution, lambda cve: (True, .9))
        assert dependency_page(db, 1, filter="kev")["dependency_total"] == 1


def test_revision_catalog_warm_reads_avoid_all_finding_rows_and_nested_evidence_invalidates():
    from datetime import datetime, timezone
    from app.models import Finding, FindingObservation
    from app.execution_summaries import refresh_execution_summary
    from app.dependency_queries import persist_current_projection
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    def risk(cve):
        return False, .2
    risk.cache_token = lambda: "catalog-revision-1"
    with Session(engine) as db:
        execution, _ = fixture(db)
        refresh_execution_summary(db, execution)
        now = datetime.now(timezone.utc)
        finding = Finding(service_id=1, cve="CVE-real", severity="High",
            first_seen=now, episode_started=now, last_seen=now)
        db.add(finding)
        db.flush()
        observation = FindingObservation(finding_id=finding.id, execution_id=execution.id,
            image="app", package="Straße%_000", installed_version="1", fixed_version="2",
            evidence={"scanner": "A", "kev": False, "nested": [{"value": 1}]})
        db.add(observation)
        db.commit()
        assert persist_current_projection(db, execution, risk)
        db.commit()
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, params, context, many:
            statements.append(sql))
        assert not persist_current_projection(db, execution, risk)
        assert not any("FROM findings" in sql or "FROM finding_observations" in sql or
            "FROM dependency_watchlist_matches" in sql for sql in statements)
        observation.evidence["kev"] = True
        observation.evidence["nested"][0]["value"] = 2
        db.flush()
        assert persist_current_projection(db, execution, risk)
        assert dependency_page(db, 1, filter="kev")["dependency_total"] == 1
        db.rollback()
        assert dependency_page(db, 1, filter="kev")["dependency_total"] == 0
        finding.severity = "Critical"
        db.flush()
        assert persist_current_projection(db, execution, risk)
        assert dependency_page(db, 1, filter="critical")["dependency_total"] == 1


def test_selected_execution_watchlist_and_observation_deletion_are_isolated():
    from datetime import datetime, timezone
    from app.models import Finding, FindingObservation, DependencyWatchlistMatch
    from app.execution_summaries import refresh_execution_summary
    from app.dependency_queries import persist_current_projection
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    def risk(cve):
        return False, None
    risk.cache_token = lambda: "revision"
    with Session(engine) as db:
        first, _ = fixture(db)
        second = Execution(id=2, execution_key="second", service_id=1, complete=True,
            scanned_at=datetime.now(timezone.utc), raw_payload={"sbom_components": [
                {"name": "selected", "version": "2", "image": "history", "purl": "pkg:npm/selected@2"}]})
        db.add(second)
        refresh_execution_summary(db, first)
        refresh_execution_summary(db, second)
        now = datetime.now(timezone.utc)
        finding = Finding(service_id=1, cve="CVE-selected", severity="Critical",
            first_seen=now, episode_started=now, last_seen=now)
        db.add(finding)
        db.flush()
        observation = FindingObservation(finding_id=finding.id, execution_id=2,
            image="history", package="selected", installed_version="2", fixed_version="3", evidence={})
        match = DependencyWatchlistMatch(entry_id=1, execution_id=2, service_id=1,
            component_name="selected", component_version="2", component_purl="pkg:npm/selected@2", image="history")
        db.add_all([observation, match])
        db.commit()
        assert persist_current_projection(db, first, risk)
        assert persist_current_projection(db, second, risk)
        db.commit()
        assert dependency_page(db, 1)["dependency_total"] == 125
        assert dependency_page(db, 2, filter="vulnerable")["dependency_total"] == 1
        assert dependency_page(db, 2, filter="watchlisted")["dependency_total"] == 1
        db.delete(observation)
        db.delete(match)
        db.flush()
        assert not persist_current_projection(db, first, risk)
        assert persist_current_projection(db, second, risk)
        assert dependency_page(db, 2, filter="vulnerable")["dependency_total"] == 0
        assert dependency_page(db, 2, filter="watchlisted")["dependency_total"] == 0


def test_production_catalog_token_changes_on_refresh_and_snapshots_are_immutable(tmp_path, monkeypatch):
    from app import policy_data
    monkeypatch.setattr(policy_data, "DATA_DIR", tmp_path)
    (tmp_path / "kev.json").write_text('{"vulnerabilities": []}')
    (tmp_path / "epss.csv").write_text("cve,epss\nCVE-test,0.1\n")
    policy_data.kev_cves.cache_clear()
    policy_data.epss_scores.cache_clear()
    try:
        token = policy_data.risk_metadata.cache_token()
        assert policy_data.risk_metadata("CVE-test") == (False, .1)
        assert token == policy_data.risk_metadata.cache_token()
        (tmp_path / "kev.json").write_text('{"vulnerabilities": [{"cveID": "CVE-test"}]}')
        (tmp_path / "epss.csv").write_text("cve,epss\nCVE-test,0.9\n")
        policy_data.kev_cves.cache_clear()
        policy_data.epss_scores.cache_clear()
        assert policy_data.risk_metadata.cache_token() != token
        assert policy_data.risk_metadata("CVE-test") == (True, .9)
        import pytest
        with pytest.raises(TypeError):
            policy_data.epss_scores()["CVE-TEST"] = .2
        assert isinstance(policy_data.kev_cves(), frozenset)
    finally:
        policy_data.kev_cves.cache_clear()
        policy_data.epss_scores.cache_clear()
