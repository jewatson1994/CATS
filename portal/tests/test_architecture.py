import importlib.util
import json
from pathlib import Path

from app.architecture import build_architecture_graph
from app.architecture_layout import NODE_H, NODE_W, _allocate_anchors, _route_edges, _segment_hits_rect, build_layout, project_graph


def payload():
    return {"complete": True, "service_overview": {"ports": [{"port": "8080", "protocol": "TCP", "service": "web", "declared_by": "Service/web"}]}, "rendered_resources": [
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": "public", "namespace": "default", "labels": {"app": "edge"}, "source_file": "templates/ingress.yaml"}, "spec": {"rules": [{"host": "app.example", "http": {"paths": [{"path": "/", "backend": {"service": {"name": "web", "port": {"number": 8080}}}}]}}]}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "web", "namespace": "default", "source_file": "templates/service.yaml"}, "spec": {"selector": {"app": "web"}, "ports": [{"port": 8080, "protocol": "TCP"}]}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "default", "source_file": "templates/deployment.yaml"}, "spec": {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "registry.example/web:2"}, {"name": "sidecar", "image": "busybox:1"}]}}}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "web-config", "namespace": "default", "source_file": "values.yaml"}},
        {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "web-data", "namespace": "default", "source_file": "templates/pvc.yaml"}},
    ]}


def test_graph_contains_resource_image_and_relationship_evidence():
    graph = build_architecture_graph(payload())
    assert {node["kind"] for node in graph["nodes"]} >= {"Ingress", "Service", "Deployment", "ContainerImage"}
    classifications = {edge["classification"] for edge in graph["relationships"]}
    assert {"DECLARED", "DERIVED"} <= classifications
    assert any(edge["label"] == "8080/TCP" and edge["network"]["evidence_type"] == "Ingress backend" and edge["evidence"][0]["source"] == "templates/ingress.yaml" for edge in graph["relationships"])
    assert graph["summary"]["ports"] == 1
    assert next(node for node in graph["nodes"] if node["kind"] == "Service")["ports"][0]["protocol"] == "TCP"
    external = next(node for node in graph["nodes"] if node["kind"] == "ExternalEndpoint")
    assert external["external"] is True
    assert any(edge["source"] == external["id"] for edge in graph["relationships"])


def test_graph_reports_partial_missing_and_unresolved_evidence():
    graph = build_architecture_graph({"complete": False, "service_overview": {"missing_evidence": [{"type": "Chart", "item": "worker", "reason": "not rendered"}]}})
    assert graph["incomplete"] is True
    assert graph["warnings"]
    assert graph["summary"]["unresolved"] == 0


def test_inferred_edges_are_conservative_and_marked():
    data = payload()
    deployment = data["rendered_resources"][2]
    deployment["spec"]["template"]["spec"]["containers"][0]["env"] = [{"name": "WEB_HOST", "value": "web.default.svc.cluster.local"}]
    graph = build_architecture_graph(data)
    assert any(edge["classification"] == "INFERRED" and edge["confidence"] == "medium" for edge in graph["relationships"])


def test_service_relationship_resolves_numeric_named_and_multiple_ports():
    data = payload()
    service = data["rendered_resources"][1]
    service["spec"]["ports"] = [
        {"name": "https", "port": 443, "targetPort": "https", "protocol": "TCP"},
        {"name": "dns", "port": 5353, "targetPort": 5353, "protocol": "UDP"},
    ]
    deployment = data["rendered_resources"][2]
    deployment["spec"]["template"]["spec"]["containers"][0]["ports"] = [
        {"name": "https", "containerPort": 8443, "protocol": "TCP"},
        {"name": "dns", "containerPort": 5353, "protocol": "UDP"},
    ]
    graph = build_architecture_graph(data)
    relationship = next(edge for edge in graph["relationships"] if edge["source"].startswith("service:") and edge["target"].startswith("deployment:"))
    assert relationship["label"] == "443 → 8443/TCP, 5353/UDP"
    assert relationship["network"]["ports"][0]["containerPort"] == 8443
    assert relationship["network"]["ports"][1]["protocol"] == "UDP"


def test_non_network_relationships_do_not_receive_port_metadata():
    graph = build_architecture_graph(payload())
    runs = next(edge for edge in graph["relationships"] if edge["label"] == "runs")
    assert "network" not in runs
    assert runs["primary"] is False


def test_primary_communication_ranks_are_monotonic_and_images_are_secondary():
    data = payload()
    data["rendered_resources"].append({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "database", "namespace": "default"},
        "spec": {"selector": {"app": "db"}, "ports": [{"port": 5432, "targetPort": 5432}]},
    })
    data["rendered_resources"].append({
        "apiVersion": "apps/v1", "kind": "StatefulSet",
        "metadata": {"name": "database", "namespace": "default"},
        "spec": {"template": {"metadata": {"labels": {"app": "db"}}, "spec": {
            "containers": [{"name": "db", "image": "postgres:16", "ports": [{"containerPort": 5432}]}]
        }}}
    })
    deployment = data["rendered_resources"][2]
    deployment["spec"]["template"]["spec"]["containers"][0]["env"] = [
        {"name": "DATABASE_HOST", "value": "database.default.svc.cluster.local"}
    ]
    graph = build_architecture_graph(data)
    ranks = {node["id"]: node["flow_rank"] for node in graph["nodes"]}
    for relationship in graph["relationships"]:
        if relationship["primary"]:
            assert ranks[relationship["target"]] > ranks[relationship["source"]]
    assert ranks["service:default:database"] > ranks["deployment:default:web"]
    assert all(not relationship["primary"] for relationship in graph["relationships"] if relationship["label"] == "runs")


def test_architecture_view_defaults_to_all_resources_and_lists_views_alphabetically():
    template = (Path(__file__).parents[1] / "app" / "templates" / "service_architecture.html").read_text(encoding="utf-8")
    script = (Path(__file__).parents[1] / "app" / "static" / "architecture_graph.js").read_text(encoding="utf-8")
    assert '<option value="all" selected>All Resources</option>' in template
    assert template.index('value="all"') < template.index('value="configuration"') < template.index('value="containers"') < template.index('value="flow"') < template.index('value="network"') < template.index('value="storage"')
    for label in ("All Resources", "Network", "Containers", "Configuration", "Storage"):
        assert label in template
    assert "data-architecture-close" in template
    assert "is-dim" in script
    assert "node.kind || node.type" in script
    assert "No resources applicable" in script
    assert 'viewBox="0 0 1200 620"' in template
    assert "data-zoom-in" in template
    assert "data-zoom-out" in template
    assert "data-zoom-fit" in template
    assert "architecture-arrow" in template
    assert 'fill="context-stroke"' in template
    assert 'refX="5"' in template
    css = (Path(__file__).parents[1] / "app" / "static" / "app.css").read_text(encoding="utf-8")
    assert "stroke:var(--green)!important" in css
    assert "stroke-dasharray:8 5!important" in css
    assert 'src="/static/architecture_graph.js"' in template
    assert "Legacy SVG" not in template
    assert 'edge.setAttribute("marker-end", "url(#architecture-arrow)")' in script
    assert "currentLayout().bounds" in script
    assert "setPointerCapture" in script


def geometry_graph():
    nodes = [
        {"id": "external", "kind": "ExternalEndpoint", "name": "traffic", "namespace": "outside"},
        {"id": "ingress", "kind": "Ingress", "name": "public", "namespace": "default"},
        {"id": "service", "kind": "Service", "name": "api", "namespace": "default"},
        {"id": "api", "kind": "Deployment", "name": "api", "namespace": "default"},
        {"id": "db-service", "kind": "Service", "name": "db", "namespace": "default"},
        {"id": "db", "kind": "StatefulSet", "name": "db", "namespace": "default"},
        {"id": "image", "kind": "ContainerImage", "name": "api:1", "namespace": "default"},
        {"id": "secret", "kind": "Secret", "name": "db", "namespace": "default"},
        {"id": "pvc", "kind": "PersistentVolumeClaim", "name": "db", "namespace": "default"},
        {"id": "orphan", "kind": "Deployment", "name": "orphan", "namespace": "default"},
    ]
    def edge(edge_id, source, target, label, classification="DERIVED", network=True):
        item = {"id": edge_id, "source": source, "target": target, "label": label, "classification": classification, "evidence": [{"source": edge_id, "detail": label}]}
        if network:
            item["network"] = {"ports": [{"protocol": "TCP", "targetPort": int(label.split("/")[0]) if label.split("/")[0].isdigit() else None}]}
        return item
    relationships = [
        edge("e1", "external", "ingress", "443/TCP"),
        edge("e2", "ingress", "service", "443/TCP", "DECLARED"),
        edge("e3", "service", "api", "443 → 8080/TCP"),
        edge("e4", "api", "db-service", "5432/TCP", "INFERRED"),
        edge("e5", "db-service", "db", "5432/TCP"),
        edge("runs", "api", "image", "runs", "DECLARED", False),
        edge("reads", "api", "secret", "reads", "DECLARED", False),
        edge("uses", "db", "pvc", "uses", "DECLARED", False),
    ]
    return {"nodes": nodes, "relationships": relationships}


def test_layout_follows_topology_and_keeps_leaf_entrypoint_local():
    layout = build_layout(geometry_graph(), "flow")
    positions = layout["positions"]
    chain = ["external", "ingress", "service", "api", "db-service", "db"]
    assert [positions[node]["rank"] for node in chain] == list(range(len(chain)))
    assert positions["external"]["y"] == positions["ingress"]["y"]
    connected_gap = abs(positions["external"]["x"] - positions["ingress"]["x"])
    orphan_gap = abs(positions["external"]["y"] - positions["orphan"]["y"])
    assert connected_gap < orphan_gap * 4


def test_components_are_packed_independently_and_isolated_nodes_remain_visible():
    layout = build_layout(geometry_graph(), "flow")
    assert len(layout["components"]) == 2
    assert ["orphan"] in layout["components"]
    assert "orphan" in layout["node_ids"]
    main_y = {layout["positions"][node]["y"] for node in ("external", "ingress", "service", "api", "db-service", "db")}
    assert layout["positions"]["orphan"]["y"] > max(main_y)


def test_same_graph_produces_identical_geometry():
    first = build_layout(geometry_graph(), "all")
    second = build_layout(geometry_graph(), "all")
    assert first == second


def test_routes_clip_to_boundaries_and_avoid_unrelated_nodes():
    layout = build_layout(geometry_graph(), "flow")
    for edge in layout["edges"]:
        source = layout["positions"][edge["source"]]
        target = layout["positions"][edge["target"]]
        start, end = edge["points"][0], edge["points"][-1]
        assert abs(start["x"] - source["x"]) >= NODE_W / 2 - 0.01 or abs(start["y"] - source["y"]) >= NODE_H / 2 - 0.01
        assert abs(end["x"] - target["x"]) >= NODE_W / 2 - 0.01 or abs(end["y"] - target["y"]) >= NODE_H / 2 - 0.01
        for node_id, point in layout["positions"].items():
            if node_id in {edge["source"], edge["target"]}:
                continue
            rect = (point["x"] - NODE_W / 2, point["y"] - NODE_H / 2, point["x"] + NODE_W / 2, point["y"] + NODE_H / 2)
            assert not any(_segment_hits_rect(a, b, rect) for a, b in zip(edge["points"], edge["points"][1:]))


def test_parallel_declared_and_inferred_edges_get_distinct_geometry():
    graph = geometry_graph()
    duplicate = dict(next(edge for edge in graph["relationships"] if edge["id"] == "e4"))
    duplicate.update({"id": "e4-declared", "classification": "DECLARED", "label": "policy allows 5432/TCP"})
    graph["relationships"].append(duplicate)
    layout = build_layout(graph, "network")
    routes = [edge for edge in layout["edges"] if edge["source"] == "api" and edge["target"] == "db-service"]
    assert len(routes) == 2
    assert routes[0]["points"] != routes[1]["points"]
    assert {route["classification"] for route in routes} == {"DECLARED", "INFERRED"}


def test_data_flow_aggregation_preserves_evidence_and_strongest_classification():
    graph = geometry_graph()
    duplicate = dict(next(edge for edge in graph["relationships"] if edge["id"] == "e4"))
    duplicate.update({"id": "e4-declared", "classification": "DECLARED", "evidence": [{"source": "policy", "detail": "allows 5432"}]})
    graph["relationships"].append(duplicate)
    _, edges = project_graph(graph, "flow")
    logical = next(edge for edge in edges if edge["source"] == "api" and edge["target"] == "db-service")
    assert logical["aggregated"] is True
    assert logical["classification"] == "DECLARED"
    assert set(logical["supporting_relationships"]) == {"e4", "e4-declared"}
    assert len(logical["evidence"]) == 2


def test_labels_avoid_nodes_and_port_labels_are_retained():
    layout = build_layout(geometry_graph(), "flow")
    assert all(edge["label_position"] for edge in layout["edges"])
    assert {edge["label"] for edge in layout["edges"]} >= {"443/TCP", "443 → 8080/TCP", "5432/TCP"}
    for edge in layout["edges"]:
        label = edge["label_position"]
        for point in layout["positions"].values():
            assert not (point["x"] - NODE_W / 2 < label["x"] < point["x"] + NODE_W / 2 and point["y"] - NODE_H / 2 < label["y"] < point["y"] + NODE_H / 2)


def test_specialized_views_keep_only_relationship_neighborhoods():
    graph = geometry_graph()
    assert set(build_layout(graph, "containers")["node_ids"]) == {"api", "image"}
    assert set(build_layout(graph, "configuration")["node_ids"]) == {"api", "secret"}
    assert set(build_layout(graph, "storage")["node_ids"]) == {"db", "pvc"}


def test_fit_bounds_include_routes_labels_and_isolated_nodes_without_extreme_margin():
    layout = build_layout(geometry_graph(), "all")
    bounds = layout["bounds"]
    for point in layout["positions"].values():
        assert bounds["x"] <= point["x"] - NODE_W / 2
        assert bounds["x"] + bounds["width"] >= point["x"] + NODE_W / 2
        assert bounds["y"] <= point["y"] - NODE_H / 2
        assert bounds["y"] + bounds["height"] >= point["y"] + NODE_H / 2
    node_width = max(point["x"] for point in layout["positions"].values()) - min(point["x"] for point in layout["positions"].values()) + NODE_W
    assert bounds["width"] < node_width + 300


def test_fan_in_and_fan_out_receive_distinct_ordered_boundary_anchors():
    positions = {
        "source": {"x": 100.0, "y": 200.0},
        "upper": {"x": 400.0, "y": 100.0},
        "middle": {"x": 400.0, "y": 200.0},
        "lower": {"x": 400.0, "y": 300.0},
        "destination": {"x": 700.0, "y": 200.0},
    }
    edges = [
        {"id": "out-upper", "source": "source", "target": "upper", "classification": "DECLARED"},
        {"id": "out-middle", "source": "source", "target": "middle", "classification": "DERIVED"},
        {"id": "out-lower", "source": "source", "target": "lower", "classification": "INFERRED"},
        {"id": "in-upper", "source": "upper", "target": "destination", "classification": "DECLARED"},
        {"id": "in-middle", "source": "middle", "target": "destination", "classification": "DERIVED"},
        {"id": "in-lower", "source": "lower", "target": "destination", "classification": "INFERRED"},
    ]
    anchors = _allocate_anchors(edges, positions)
    outgoing = [anchors[(edge_id, "source")]["y"] for edge_id in ("out-upper", "out-middle", "out-lower")]
    incoming = [anchors[(edge_id, "target")]["y"] for edge_id in ("in-upper", "in-middle", "in-lower")]
    assert outgoing == sorted(outgoing) and len(set(outgoing)) == 3
    assert incoming == sorted(incoming) and len(set(incoming)) == 3
    assert min(incoming) > positions["destination"]["y"] - NODE_H / 2
    assert max(incoming) < positions["destination"]["y"] + NODE_H / 2


def test_parallel_routes_and_final_approaches_remain_separated():
    positions = {"a": {"x": 100.0, "y": 100.0}, "b": {"x": 500.0, "y": 100.0}}
    edges = [
        {"id": "declared", "source": "a", "target": "b", "classification": "DECLARED", "label": "5432/TCP", "network": {"ports": []}},
        {"id": "inferred", "source": "a", "target": "b", "classification": "INFERRED", "label": "5432/TCP inferred", "network": {"ports": []}},
    ]
    routes = _route_edges(edges, positions)
    assert routes[0]["points"] != routes[1]["points"]
    assert routes[0]["source_anchor"] != routes[1]["source_anchor"]
    assert routes[0]["destination_anchor"] != routes[1]["destination_anchor"]
    assert abs(routes[0]["destination_anchor"]["y"] - routes[1]["destination_anchor"]["y"]) >= 10
    assert routes[0]["points"][-2:] != routes[1]["points"][-2:]


def test_port_labels_stay_upstream_of_dense_destination_convergence():
    graph = geometry_graph()
    graph["relationships"].extend([
        {"id": "fan-a", "source": "service", "target": "db-service", "label": "5432/TCP", "classification": "DECLARED", "network": {"ports": [{"protocol": "TCP", "targetPort": 5432}]}, "evidence": []},
        {"id": "fan-b", "source": "ingress", "target": "db-service", "label": "15432/TCP", "classification": "INFERRED", "network": {"ports": [{"protocol": "TCP", "targetPort": 15432}]}, "evidence": []},
    ])
    layout = build_layout(graph, "network")
    target = layout["positions"]["db-service"]
    incoming = [edge for edge in layout["edges"] if edge["target"] == "db-service"]
    assert len({edge["destination_anchor"]["y"] for edge in incoming}) == len(incoming)
    for edge in incoming:
        assert edge["label_position"] is not None
        assert abs(edge["label_position"]["x"] - target["x"]) >= NODE_W / 2 + 30


def test_rendered_resource_normalizer_handoff_reaches_architecture(tmp_path):
    script = Path(__file__).parents[2] / "scanning-main" / "scripts" / "normalize-service-overview.py"
    spec = importlib.util.spec_from_file_location("normalize_service_overview", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    resources = payload()["rendered_resources"]
    source = tmp_path / "resources.json"
    output = tmp_path / "service-overview.json"
    source.write_text(json.dumps(resources), encoding="utf-8")
    module.main(str(source), str(output))
    persisted_overview = json.loads(output.read_text(encoding="utf-8"))
    graph = build_architecture_graph({"complete": True, "service_overview": persisted_overview})
    assert len(persisted_overview["rendered_resources"]) == len(resources)
    assert graph["summary"]["nodes"] >= 7
    assert graph["summary"]["relationships"] >= 4
    assert any(node["name"] == "web" and node["source"] == "templates/service.yaml" for node in graph["nodes"])
