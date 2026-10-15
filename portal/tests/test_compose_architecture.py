"""Compose discovery feeds the same graph, selection, and page contract as Helm."""
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.architecture import build_architecture_graph
from app.architecture_evidence import architecture_verification
from app.architecture_layout import project_graph
from app.compose_ingestion import discover
from app.database import Base
from app.execution_summaries import build_summary
from app.models import Execution, ExecutionSummary, Service, utcnow


@pytest.fixture
def compose_payload(tmp_path):
    (tmp_path / "compose.yaml").write_text("""services:
  api:
    image: harbor.example/team/app:2
    depends_on: {db: {condition: service_healthy}}
    ports: ["127.0.0.1:8080:80"]
    expose: ["9000/udp"]
    volumes: ["data:/data", "/host/config:/config:ro"]
    networks: [backend]
    secrets: [password]
    configs: [{source: settings, target: /etc/settings}]
    environment: {PASSWORD: secret-value-must-not-appear}
    command: ["serve", "secret-command-must-not-appear"]
  worker:
    image: harbor.example/team/app:2
    networks: [backend]
  db:
    image: postgres:16
    networks: [backend]
volumes: {data: {}}
networks: {backend: {external: true}}
secrets: {password: {external: true}}
configs: {settings: {external: true}}
""", encoding="utf-8")
    model = discover(tmp_path, ["compose.yaml"], [])
    return {"complete": True, "artifact_type": "compose", "service_overview": {"compose": model}}


def test_compose_graph_preserves_declared_relationships_and_redaction(compose_payload):
    graph = build_architecture_graph(compose_payload)
    nodes = graph["nodes"]
    assert len([n for n in nodes if n["kind"] == "ComposeService"]) == 3
    assert len([n for n in nodes if n["kind"] == "ContainerImage"]) == 2
    image = next(n for n in nodes if n["name"] == "harbor.example/team/app:2")
    assert len([e for e in graph["relationships"] if e["target"] == image["id"]]) == 2
    dependency = next(e for e in graph["relationships"] if e["label"] == "depends on")
    assert dependency["source"].endswith(":api") and dependency["target"].endswith(":db")
    assert len([e for e in graph["relationships"] if e["label"] == "joins network"]) == 3
    assert not any(e["source"].endswith(":worker") and e["target"].endswith(":db") for e in graph["relationships"])
    assert {n["kind"] for n in nodes} >= {"BindMount", "ComposeVolume", "ComposeConfig", "ComposeSecret"}
    published = [e for e in graph["relationships"] if (e.get("network") or {}).get("evidence_type") == "Compose published host port"]
    assert len(published) == 1 and published[0]["label"] == "8080 → 80/TCP"
    assert any(p["port"] == "9000" and p["name"] == "Internal only (expose)" for p in graph["ports"])
    assert all(n["provenance"] == "DECLARED" for n in nodes)
    assert graph["summary"]["runtime_verified"] == 0
    assert all(e["classification"] == "DECLARED" for e in graph["relationships"])
    assert "No rendered Kubernetes" not in json.dumps(graph)
    assert "secret-value-must-not-appear" not in json.dumps(graph)
    assert "secret-command-must-not-appear" not in json.dumps(graph)
    for view, kind in (("containers", "ContainerImage"), ("network", "ComposeNetwork"),
                       ("storage", "BindMount"), ("configuration", "ComposeSecret")):
        visible, edges = project_graph(graph, view)
        assert any(n["kind"] == kind for n in visible)
        assert edges and graph["layouts"][view]["node_ids"]


def test_default_network_host_mode_partial_evidence_and_unknown_image():
    services = [{"name": name, "image": image, "configuration": config} for name, image, config in (
        ("web", "app:1", {}), ("host", "app:1", {"network_mode": "host"}),
        ("isolated", None, {"network_mode": "none"}),
        ("unknown", "[unresolved]", {"network_mode": "service:web"}),
    )]
    graph = build_architecture_graph({"complete": False, "service_overview": {"compose": {"services": services}}})
    assert graph["incomplete"] and len([n for n in graph["nodes"] if n["kind"] == "ComposeService"]) == 4
    assert len([n for n in graph["nodes"] if n["kind"] == "ContainerImage"]) == 1
    membership = [e for e in graph["relationships"] if e["label"] == "joins network"]
    assert len(membership) == 1 and membership[0]["source"].endswith(":web")
    assert any(e["label"] == "shares network namespace" for e in graph["relationships"])


def test_mixed_graph_keeps_helm_and_shared_image(compose_payload):
    compose_payload["artifact_type"] = "helm"
    compose_payload["rendered_resources"] = [{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "helm"},
        "spec": {"containers": [{"name": "app", "image": "harbor.example/team/app:2"}]}}]
    graph = build_architecture_graph(compose_payload)
    assert any(n["kind"] == "Pod" for n in graph["nodes"])
    assert len([n for n in graph["nodes"] if n["name"] == "harbor.example/team/app:2"]) == 1
    assert build_summary(compose_payload, True)["architecture"]["applicable"] is True
    run = {"id": 1, "execution_id": 1, "phase": "COMPLETE", "status": "VERIFIED", "comparison": {"matched": ["Pod/default/helm"]}}
    state = architecture_verification(applicable=True, declared_count=1, compose_declared_count=3, runs=[run], execution_id=1)
    assert state["state"] == "PARTIALLY_VERIFIED" and state["expected"] == 4


@pytest.mark.parametrize("complete", [True, False])
def test_saved_compose_scan_with_stale_summary_renders_architecture(monkeypatch, compose_payload, complete):
    from app import main
    from app.evidence_reads import architecture_execution, execution_metadata
    from app.overview_queries import overview_architecture_execution
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="compose-graph", name="Compose graph")
        db.add(service); db.flush()
        execution = Execution(service_id=service.id, execution_key="compose-graph", scanned_at=utcnow(),
                              scan_scope="service", raw_payload=compose_payload, complete=complete)
        db.add(execution); db.flush()
        summary = db.get(ExecutionSummary, execution.id)
        if summary is None:
            summary = ExecutionSummary(execution_id=execution.id)
            db.add(summary)
        summary.summary_version = 4
        summary.data = {"architecture": {"has_architecture": False}}
        summary.source_complete = complete
        summary.payload_digest = execution.payload_digest or "legacy"
        db.commit()
        service_id, execution_id = service.id, execution.id
        db.expunge_all()
        assert architecture_execution(execution_metadata(db, service_id)).id == execution_id
        assert overview_architecture_execution(db, service_id).id == execution_id
        monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
        monkeypatch.setattr(main, "page_context", lambda auth, **context: context)
        monkeypatch.setattr(main, "configuration_for_service", lambda *args: main.CONFIG_DEFAULTS)
        request = SimpleNamespace(query_params={}, headers={}, url=SimpleNamespace(path="/services/compose-graph", query=""))
        context = main.service_detail("compose-graph", request, overview=False, architecture=True, db=db,
                                      auth=SimpleNamespace(has=lambda *args: False), severity=[])
        assert context["architecture_state"] == "READY"
        assert context["architecture_verification"]["state"] == "DECLARED"
        assert context["architecture_verification"]["runtime_supported"] is False
        assert context["architecture_graph"]["nodes"]
    engine.dispose()
