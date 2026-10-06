from datetime import timedelta
from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import DeploymentValidationRun, Execution, Service, ServiceImage, utcnow
from app.overview_queries import architecture_execution_query, overview_architecture_execution


@pytest.mark.parametrize("value", [None, False, True, 0, 1, -1, "", "false", [], [1], {}, {"x": 1}])
@pytest.mark.parametrize("path", ["rendered_resources", "helm_source_files", "nested"])
def test_architecture_predicate_matches_python_truth_and_transfers_one_payload(value, path):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="overview", name="Overview")
        db.add(service)
        db.flush()
        payload = {"service_overview": {"rendered_resources": value}} if path == "nested" else {path: value}
        now = utcnow()
        scans = [Execution(service_id=service.id, execution_key=f"scan-{index}", scanned_at=now,
                           raw_payload=payload, complete=True) for index in range(2)]
        db.add_all(scans)
        db.commit()
        service_id, first_id = service.id, scans[0].id
        db.expunge_all()
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda session, obj: loaded.append(obj))
        selected = overview_architecture_execution(db, service_id)
        assert (selected.id if selected else None) == (first_id if value else None)
        assert len(loaded) == int(bool(value))
    engine.dispose()


@pytest.mark.parametrize("tab", ["architecture", "validation"])
def test_evidence_tabs_select_old_eligible_scan_without_loading_history(monkeypatch, tab):
    from app import main
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key="bounded", name="Bounded")
        db.add(service); db.flush()
        scans = [Execution(service_id=service.id, execution_key=f"scan-{i}",
            scanned_at=now - timedelta(minutes=100-i), complete=True, scan_scope="service",
            raw_payload={"artifact_type": "helm", "helm_source_files": {"Chart.yaml": "name: test"},
                         "rendered_resources": []} if i == 40 else {"service": {"version": str(i)}})
            for i in range(100)]
        db.add_all(scans); db.flush()
        db.add_all(DeploymentValidationRun(service_id=service.id, execution_id=scan.id,
            run_key=f"run-{i}", created_at=scan.scanned_at, status="VERIFIED", phase="COMPLETE",
            cleanup_status="COMPLETE") for i, scan in enumerate(scans))
        db.commit(); db.expunge_all()
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda session, obj: loaded.append(obj))
        monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
        monkeypatch.setattr(main, "page_context", lambda auth, **context: context)
        monkeypatch.setattr(main, "configuration_for_service", lambda *args: main.CONFIG_DEFAULTS)
        request = SimpleNamespace(query_params={}, headers={}, url=SimpleNamespace(path="/services/bounded", query=""))
        auth = SimpleNamespace(has=lambda *args: False)
        monkeypatch.setattr(main, "deployment_validation_enabled", lambda: True)
        context = main.service_detail("bounded", request, overview=False, db=db, auth=auth,
                                      severity=[], **{tab: True})
        if tab == "architecture":
            assert context["latest_execution"].execution_key == "scan-40"
            assert context["architecture_verification"]["run_key"] == "run-40"
        else:
            assert context["validation_unavailable_reason"] is None
            # History is paged (50 per page) instead of hydrating 100 full runs.
            assert len(context["validation_runs"]) == 50
            assert context["validation_history"] == {"page": 1, "pages": 2, "total": 100, "page_size": 50}
            assert context["validation_runs"][0]["run_key"] == "run-99"
        assert len([item for item in loaded if isinstance(item, Execution) and "raw_payload" in item.__dict__]) <= 3
    engine.dispose()


def test_architecture_postgresql_compilation_uses_guarded_json_truth_and_limit():
    from sqlalchemy.dialects import postgresql
    sql = str(architecture_execution_query(1).compile(dialect=postgresql.dialect()))
    assert "jsonb_typeof" in sql and "jsonb_array_length" in sql and "LIMIT" in sql
    assert "executions.id ASC" in sql and "service_overview,rendered_resources" in sql


def test_overview_route_matches_original_context_without_history_graph(monkeypatch):
    from pathlib import Path
    from app import main
    from app.frontend import page_data
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    payload = {"service": {"version": "1"}, "helm_source_files": {"Chart.yaml": "name: test"},
               "service_overview": {"rendered_resources": [], "images": []},
               "skipped_images": [{"image": "missing", "reason": "unavailable"}]}
    with Session(engine) as db:
        service = Service(service_key="overview", name="Overview")
        db.add(service)
        db.flush()
        db.add_all(Execution(service_id=service.id, execution_key=f"history-{index}",
                   scanned_at=now - timedelta(minutes=100-index), complete=False,
                   raw_payload=payload if index == 40 else {"service": {"version": str(index)}})
                   for index in range(100))
        db.add(ServiceImage(service_id=service.id, image_reference="example:image"))
        db.flush()
        scans = db.query(Execution).order_by(Execution.id).all()
        db.add_all(DeploymentValidationRun(service_id=service.id, execution_id=scan.id,
            run_key=f"validation-{index}", created_at=now - timedelta(minutes=100-index),
            status="VERIFIED", phase="COMPLETE", cleanup_status="COMPLETE")
            for index, scan in enumerate(scans))
        db.commit()
        auth = SimpleNamespace(has=lambda *args: False)
        request = SimpleNamespace(query_params={}, headers={}, url=SimpleNamespace(path="/services/overview", query=""))
        monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
        monkeypatch.setattr(main, "page_context", lambda auth, **context: context)
        monkeypatch.setattr(main, "configuration_for_service", lambda *args: main.CONFIG_DEFAULTS)
        monkeypatch.setattr(main, "utcnow", lambda: now)
        canonical_service = db.get(Service, service.id)
        canonical_view = main.service_view(canonical_service, now, main.CONFIG_DEFAULTS)
        runs = db.query(DeploymentValidationRun).order_by(DeploymentValidationRun.created_at.desc()).all()
        # Execute the retained original mixed-tab overview branch as a truth oracle.
        source = (Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8-sig")
        start = source.index("    if overview:", source.index("def service_detail("))
        end = source.index("    if simplified:", start)
        function = "def original_overview():\n" + source[start:end]
        namespace = dict(vars(main), db=db, service=canonical_service, overview=True,
            latest_execution=max(canonical_service.executions, key=lambda scan: (main.aware(scan.scanned_at), scan.id)),
            view=canonical_view, validation_records=runs, latest_validation=main.deployment_validation_view(runs[0]),
            request=request, auth=auth, now=now, finding_type="all", archive_pending=False)
        exec(function, namespace)
        expected = namespace["original_overview"]()
        expected_data = page_data(request, "service_overview.html", expected)
        db.expunge_all()
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda session, obj: loaded.append(obj))
        actual = main.service_detail("overview", request, overview=True, db=db, auth=auth, severity=[])
        assert page_data(request, "service_overview.html", actual) == expected_data
        assert len([item for item in loaded if isinstance(item, Execution) and "raw_payload" in item.__dict__]) <= 3
        assert actual["architecture_verification"]["run_key"] == "validation-40"
        assert len(actual["service_images"]) == 1
    engine.dispose()
