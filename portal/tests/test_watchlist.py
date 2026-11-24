from app.watchlist import component_matches, parse_entries, version_matches


def test_import_formats_and_comments():
    assert parse_entries("# ignored\n\nopenssl\npkg:pypi/requests\n", "txt") == [
        {"purl": "", "ecosystem": "", "name": "openssl", "version_constraint": ""},
        {"purl": "pkg:pypi/requests", "ecosystem": "", "name": "", "version_constraint": ""}]
    csv_rows = parse_entries("purl,ecosystem,name,version_constraint\n,python,requests,>=2.30\n", "csv")
    yaml_rows = parse_entries("entries:\n  - ecosystem: python\n    name: requests\n    version_constraint: '>=2.30'\n", "yaml")
    assert csv_rows == yaml_rows


def test_precise_purl_name_ecosystem_and_version():
    component = {"purl": "pkg:pypi/requests@2.31.0", "ecosystem": "python", "name": "requests", "version": "2.31.0"}
    assert component_matches({"purl": "pkg:pypi/requests"}, component)
    assert component_matches({"name": "requests", "ecosystem": "python", "version_constraint": ">=2.30"}, component)
    assert not component_matches({"name": "request"}, component)
    assert not component_matches({"name": "requests", "ecosystem": "npm"}, component)
    assert not component_matches({"purl": "pkg:pypi/requests@2.30.0"}, component)
    assert not version_matches("2.29", ">=2.30")


def test_invalid_import_does_not_guess():
    import pytest
    with pytest.raises(ValueError):
        parse_entries("entries:\n  - name: requests\n    version_constraint: probably-new\n", "yaml")


def test_indexed_matches_preserve_rule_semantics_and_skip_unrelated_rules(monkeypatch):
    from types import SimpleNamespace
    from app import watchlist

    def rule(i, purl="", ecosystem="", name="", version_constraint=""):
        return SimpleNamespace(id=i, purl=purl, ecosystem=ecosystem, name=name, version_constraint=version_constraint)

    rules = [rule(i, name=f"unrelated-{i}") for i in range(1000)]
    rules.extend([
        rule(1000, name="My_lib", ecosystem="PYTHON", version_constraint=">=2"),
        rule(1001, purl="pkg:pypi/my-lib?arch=amd64"),
        rule(1002, purl="pkg:pypi/my-lib@2.1", name="ignored", ecosystem="ignored"),
        rule(1003, purl="pkg:pypi/my-lib@1.1"),
        rule(1004, name="my-lib", ecosystem="npm"),
    ])
    component = {"name": "my.lib", "purl": "pkg:pypi/my-lib@2.1?arch=arm64", "ecosystem": "python", "version": "2.1"}
    expected = {r.id for r in rules if component_matches(vars(r), component)}
    calls = []
    def compare(entry, candidate):
        calls.append(entry["id"])
        return component_matches(entry, candidate)
    monkeypatch.setattr(watchlist, "component_matches", compare)
    rows = watchlist.match_rows([component, dict(component, image=""), None], watchlist.index_entries(rules), 9, 4)
    assert {r["entry_id"] for r in rows.values()} == expected == {1000, 1001, 1002}
    assert len(rows) == 3
    assert set(calls) == {1000, 1001, 1002, 1004}


def test_unchanged_matches_preserve_cached_projections():
    from sqlalchemy import create_engine, event, select
    from sqlalchemy.orm import Session
    from app import main  # Register projection and posture invalidation hooks.
    from app.database import Base
    from app.models import DependencyProjection, DependencyWatchlistEntry, DependencyWatchlistMatch, Execution, Service, utcnow
    from app.watchlist import reconcile_matches

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="watchlist-cache", name="Watchlist")
        service2 = Service(service_key="watchlist-other", name="Other")
        db.add_all([service, service2])
        db.flush()
        def scan(key, sid):
            return Execution(execution_key=key, service_id=sid, scanned_at=utcnow(), complete=True,
                             raw_payload={"sbom_components": [{"name": "openssl"}]})
        first, other = scan("first", service.id), scan("other", service2.id)
        rule = DependencyWatchlistEntry(name="openssl", enabled=True)
        db.add_all([first, other, rule])
        db.flush()
        assert reconcile_matches(db, first) == 1
        db.flush()
        match_id = db.scalar(select(DependencyWatchlistMatch.id))
        for execution in (first, other):
            db.add(DependencyProjection(execution_id=execution.id, fingerprint="same", status="ready"))
        db.commit()
        assert reconcile_matches(db, first) == 1
        db.commit()
        assert db.scalar(select(DependencyWatchlistMatch.id)) == match_id
        assert set(db.scalars(select(DependencyProjection.execution_id))) == {first.id, other.id}
        rule.enabled = False
        db.flush()
        assert reconcile_matches(db, first) == 0
        db.rollback()
        assert db.scalar(select(DependencyWatchlistMatch.id)) == match_id
        assert db.get(DependencyProjection, first.id) is not None
        rule.enabled = False
        db.flush()
        assert reconcile_matches(db, first) == 0
        db.commit()
        assert list(db.scalars(select(DependencyProjection.execution_id))) == [other.id]

        rule.enabled = True
        first.raw_payload = {"sbom_components": [{"name": "openssl", "version": str(i)} for i in range(1200)]}
        db.flush()
        writes = []
        def track_write(conn, cursor, statement, params, context, many):
            if statement.startswith(("INSERT ", "UPDATE ", "DELETE ")):
                writes.append(statement)
        event.listen(engine, "before_cursor_execute", track_write)
        assert reconcile_matches(db, first) == 1200
        db.commit()
        assert sum(s.startswith("INSERT INTO dependency_watchlist_matches") for s in writes) == 3
        assert sum(s.startswith("DELETE FROM dependency_projections") for s in writes) == 1
        assert sum(s.startswith("UPDATE service_posture") for s in writes) == 1
