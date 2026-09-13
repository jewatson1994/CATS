"""Generic topology and responsive geometry acceptance tests."""
import random
from pathlib import Path
import yaml

import pytest

from app.architecture import build_architecture_graph
from app.architecture_layout import (
    NODE_W, NODE_H, _box_overlap, _component_geometry, build_layout,
)
from app.architecture_export import build_architecture_svg


def flows(count=1, kind="Deployment", services=1, ports=1):
    resources = []
    for index in range(count):
        name = f"application-{index}"
        resources.append({"kind": kind, "metadata": {"name": name}, "spec": {
            "template": {"metadata": {"labels": {"app": name}}, "spec": {
                "containers": [{"name": "app", "ports": [{"containerPort": 8000}]}]}}}})
        for service in range(services):
            resources.append({"kind": "Service", "metadata": {"name": f"{name}-{service}"}, "spec": {
                "selector": {"app": name}, "ports": [
                    {"port": 8000 + port, "targetPort": 8000 + port, "protocol": "UDP" if port % 2 else "TCP"}
                    for port in range(ports)]}})
    return {"rendered_resources": resources}


def rect(box):
    return box["x"], box["y"], box["x"] + box["width"], box["y"] + box["height"]


def assert_clear(layout):
    boxes = layout["component_bounds"]
    for i, box in enumerate(boxes):
        assert all(not _box_overlap(rect(box), rect(other)) for other in boxes[i + 1:])
    labels = []
    for edge in layout["edges"]:
        p, size = edge["label_position"], edge["label_size"]
        box = (p["x"] - size["width"] / 2, p["y"] - size["height"] / 2,
               p["x"] + size["width"] / 2, p["y"] + size["height"] / 2)
        assert all(not _box_overlap(box, other) for other in labels)
        labels.append(box)
        for point in layout["positions"].values():
            assert not _box_overlap(box, (point["x"] - NODE_W / 2, point["y"] - NODE_H / 2,
                                         point["x"] + NODE_W / 2, point["y"] + NODE_H / 2))


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet", "DaemonSet"])
@pytest.mark.parametrize("services", [1, 3])
def test_generic_pair_and_fan_in(kind, services):
    layout = build_architecture_graph(flows(kind=kind, services=services))["layouts"]["flow"]
    assert len(layout["components"]) == 1
    assert len(layout["components"][0]) == services + 1
    for edge in layout["edges"]:
        assert layout["positions"][edge["source"]]["x"] < layout["positions"][edge["target"]]["x"]
    assert_clear(layout)


def test_eight_flows_reflow_without_changing_internal_geometry():
    graph = build_architecture_graph(flows(8))
    layouts = [build_layout(graph, "flow", width) for width in (1000, 1400, 1920)]
    columns = [len({box["x"] for box in layout["component_bounds"]}) for layout in layouts]
    assert columns == [1, 2, 3]
    assert layouts[0]["bounds"]["height"] > layouts[-1]["bounds"]["height"]
    for layout in layouts:
        assert len(layout["components"]) == 8
        assert_clear(layout)
        for base, edge in zip(layouts[0]["edges"], layout["edges"]):
            def relative(route):
                origin = route["points"][0]
                return [(round(p["x"] - origin["x"], 6), round(p["y"] - origin["y"], 6)) for p in route["points"]]
            assert relative(base) == relative(edge)
    before = _component_geometry.cache_info()
    build_layout(graph, "flow", 1600)
    after = _component_geometry.cache_info()
    assert after.misses == before.misses
    assert after.hits >= before.hits + 8


def test_mixed_sizes_keep_large_component_intact():
    data = flows(5)
    for i in range(4):
        data["rendered_resources"].append({"kind": "Service", "metadata": {"name": f"extra-{i}"},
            "spec": {"selector": {"app": "application-0"}, "ports": [{"port": 9000 + i}]}})
    layout = build_architecture_graph(data, 1920)["layouts"]["flow"]
    assert sorted(map(len, layout["components"])) == [2, 2, 2, 2, 6]
    assert len({box["x"] for box in layout["component_bounds"]}) > 1
    large = next(box for box in layout["component_bounds"] if len(box["node_ids"]) == 6)
    assert all(box["y"] < large["height"] for box in layout["component_bounds"])
    assert_clear(layout)


def test_long_ports_wrap_preserve_information_and_export():
    graph = build_architecture_graph(flows(3, ports=20), 1920)
    layout = graph["layouts"]["flow"]
    assert_clear(layout)
    for edge in layout["edges"]:
        assert len(edge["label_lines"]) > 1
        assert " ".join(edge["label_lines"]) == edge["label"]
        assert edge["label_size"]["width"] < 200
    svg = build_architecture_svg(graph, "flow")
    assert "<tspan" in svg and "8019/UDP" in svg and 'refX="5"' in svg


def test_resource_and_relationship_order_do_not_change_geometry():
    data = flows(8, services=2)
    original = build_architecture_graph(data)
    random.Random(7).shuffle(data["rendered_resources"])
    shuffled = build_architecture_graph(data)
    assert original["layouts"] == shuffled["layouts"]
    random.Random(9).shuffle(shuffled["nodes"])
    random.Random(10).shuffle(shuffled["relationships"])
    assert build_layout(original, "flow") == build_layout(shuffled, "flow")


def test_repository_helm_demo_rendered_fixture():
    # Regenerate with Helm 3.17.3: helm template demo scanning-main/examples/helm-diagram-demo
    resources = list(yaml.safe_load_all(Path(__file__).with_name("fixtures-helm-demo-rendered.yaml").read_text(encoding="utf-8")))
    graph = build_architecture_graph({"rendered_resources": resources}, 1920)
    assert {node["kind"] for node in graph["nodes"]} >= {"Service", "Ingress", "Deployment", "StatefulSet", "ConfigMap", "Secret"}
    layout = graph["layouts"]["flow"]
    assert len(layout["components"]) > 1
    assert_clear(layout)
    assert any(edge["source"].startswith("external:") for edge in layout["edges"])
    resources.reverse()
    assert build_architecture_graph({"rendered_resources": resources}, 1920)["layouts"] == graph["layouts"]


def test_cycles_keep_relationships_and_have_bounded_deterministic_ranks():
    data = flows()
    data["rendered_resources"][0]["spec"]["template"]["spec"]["containers"][0]["env"] = [
        {"name": "HOST", "value": "application-0-0"}]
    graph = build_architecture_graph(data)
    layout = graph["layouts"]["flow"]
    assert len(layout["edges"]) == 2
    assert {edge["classification"] for edge in layout["edges"]} == {"DERIVED", "INFERRED"}
    assert max(point["rank"] for point in layout["positions"].values()) < len(layout["node_ids"])


def test_dense_many_to_many_long_labels_are_never_hidden_or_overlapped():
    data = flows(3, services=3, ports=12)
    for resource in data["rendered_resources"]:
        if resource["kind"] == "Deployment":
            resource["spec"]["template"]["metadata"]["labels"]["app"] = "shared"
        else:
            resource["spec"]["selector"]["app"] = "shared"
    graph = build_architecture_graph(data)
    layout = graph["layouts"]["flow"]
    assert len(layout["components"]) == 1
    assert len(layout["edges"]) == 27
    assert_clear(layout)


def test_selector_relationship_without_ports_still_groups_the_flow():
    graph = build_architecture_graph(flows(ports=0))
    layout = graph["layouts"]["flow"]
    assert len(layout["components"]) == 1
    assert layout["edges"][0]["label"] == "selects"
