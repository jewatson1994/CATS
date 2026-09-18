"""Deterministic presentation geometry for CATS architecture graphs.

This module consumes the canonical evidence graph.  It never infers, removes,
or reverses canonical relationships; it only projects and lays them out.
"""
from __future__ import annotations

from collections import defaultdict, deque
from math import hypot
from functools import lru_cache
import json
import textwrap
from copy import deepcopy
from typing import Any

NODE_W = 184.0
NODE_H = 56.0
NODE_PAD = 14.0
RANK_GAP = 92.0
ROW_GAP = 54.0
COMPONENT_GAP = 90.0
MARGIN = 48.0


def label_lines(label: str) -> list[str]:
    """Bound label width without discarding port mappings or protocol data."""
    return textwrap.wrap(label, width=28, break_long_words=True, break_on_hyphens=False) or [""]


def _label_size(label: str) -> tuple[float, float]:
    lines = label_lines(label)
    return max(26.0, max(map(len, lines)) * 6.2 + 10), len(lines) * 16.0 + 4

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}
FLOW_KINDS = WORKLOADS | {"ExternalEndpoint", "Ingress", "Gateway", "Service"}
NETWORK_KINDS = FLOW_KINDS | {"NetworkPolicy"}
VIEW_KINDS = {
    "flow": FLOW_KINDS,
    "network": NETWORK_KINDS,
    "containers": WORKLOADS | {"ContainerImage"},
    "configuration": WORKLOADS | {"ConfigMap", "Secret"},
    "storage": WORKLOADS | {"PersistentVolumeClaim"},
}
VIEW_LABELS = {
    "containers": {"runs"},
    "configuration": {"reads", "mounts"},
    "storage": {"uses", "mounts"},
}
STRENGTH = {"INFERRED": 1, "DERIVED": 2, "DECLARED": 3}


def _stable_node(node: dict[str, Any]) -> tuple[str, str, str, str]:
    return (str(node.get("namespace", "")), str(node.get("kind", node.get("type", ""))), str(node.get("name", "")), str(node.get("id", "")))


def _display_label(edge: dict[str, Any]) -> str:
    label = str(edge.get("label", ""))
    for suffix in (" · inferred", " · policy"):
        if label.lower().endswith(suffix):
            return label[: -len(suffix)]
    return label


def _communication_key(edge: dict[str, Any]) -> tuple[Any, ...]:
    ports = (edge.get("network") or {}).get("ports") or []
    normalized = tuple(sorted((str(item.get("protocol") or "TCP"), str(item.get("targetPort") or item.get("containerPort") or item.get("servicePort") or "")) for item in ports))
    return (edge.get("source"), edge.get("target"), normalized or (_display_label(edge),))


def _aggregate_flow(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        grouped[_communication_key(edge)].append(edge)
    projected = []
    for key in sorted(grouped, key=str):
        items = sorted(grouped[key], key=lambda edge: str(edge.get("id")))
        best = max(items, key=lambda item: (STRENGTH.get(str(item.get("classification")), 0), str(item.get("id", ""))))
        item = dict(best)
        item["id"] = "logical:" + "|".join(map(str, key))
        item["classification"] = best.get("classification", "INFERRED")
        item["classifications"] = sorted({str(edge.get("classification", "")) for edge in items})
        item["supporting_relationships"] = [edge.get("id") for edge in items]
        item["evidence"] = [evidence for edge in items for evidence in edge.get("evidence", [])]
        item["aggregated"] = len(items) > 1
        projected.append(item)
    return projected


def project_graph(graph: dict[str, Any], view: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    all_nodes = sorted(graph.get("nodes", []), key=_stable_node)
    if view == "declared":
        nodes = [node for node in all_nodes if node.get("provenance", "DECLARED") in {"DECLARED", "DECLARED_AND_OBSERVED", "INFERRED"}]
    elif view == "runtime":
        nodes = [node for node in all_nodes if node.get("provenance") in {"OBSERVED", "DECLARED_AND_OBSERVED"}]
    elif view == "differences":
        nodes = [node for node in all_nodes if node.get("provenance") == "OBSERVED" or (
            node.get("provenance") == "DECLARED" and node.get("kind") not in {"ContainerImage", "ExternalEndpoint"}
        )]
    else:
        nodes = None
    kinds = VIEW_KINDS.get(view)
    if nodes is None:
        nodes = all_nodes if view == "all" else [node for node in all_nodes if node.get("kind", node.get("type")) in (kinds or set())]
    visible = {node["id"] for node in nodes}
    edges = [dict(edge) for edge in graph.get("relationships", []) if edge.get("source") in visible and edge.get("target") in visible]
    if view == "network":
        edges = [edge for edge in edges if edge.get("network") or edge.get("label") == "applies to" or edge.get("source", "").startswith("networkpolicy:")]
    if view in VIEW_LABELS:
        edges = [edge for edge in edges if edge.get("label") in VIEW_LABELS[view]]
        connected = {value for edge in edges for value in (edge["source"], edge["target"])}
        nodes = [node for node in nodes if node["id"] in connected]
    if view == "flow":
        edges = _aggregate_flow(edges)
    return nodes, sorted(edges, key=lambda edge: (str(edge.get("source")), str(edge.get("target")), str(edge.get("id"))))


def _components(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[list[str]]:
    adjacency = {node["id"]: set() for node in nodes}
    for edge in edges:
        if edge["source"] in adjacency and edge["target"] in adjacency:
            adjacency[edge["source"]].add(edge["target"])
            adjacency[edge["target"]].add(edge["source"])
    unseen = set(adjacency)
    result = []
    while unseen:
        start = min(unseen)
        queue = deque([start])
        unseen.remove(start)
        component = []
        while queue:
            node_id = queue.popleft()
            component.append(node_id)
            for neighbor in sorted(adjacency[node_id] & unseen):
                unseen.remove(neighbor)
                queue.append(neighbor)
        result.append(component)
    return sorted(result, key=lambda item: (-len(item), item))


def _ranks(component: list[str], edges: list[dict[str, Any]]) -> dict[str, int]:
    if not component:
        return {}
    members = set(component)
    outgoing = {node_id: [] for node_id in component}
    indegree = {node_id: 0 for node_id in component}
    for edge in edges:
        source, target = edge["source"], edge["target"]
        if source in members and target in members and source != target:
            outgoing[source].append(target)
            indegree[target] += 1
    roots = sorted(node_id for node_id in component if indegree[node_id] == 0)
    rank = {node_id: 0 for node_id in component}
    queue = deque(roots)
    remaining = dict(indegree)
    visited = set()
    semantic_order = {"external": 0, "externalendpoint": 0, "ingress": 1, "gateway": 1, "route": 1, "service": 2}
    while len(visited) < len(component):
        if not queue:
            # A cycle cannot have every edge point right. Keep all relationships,
            # choose a stable entry, and render feedback edges back toward it.
            queue.append(min((node_id for node_id in component if node_id not in visited),
                             key=lambda node_id: (semantic_order.get(node_id.split(":")[0].lower(), 3), node_id)))
        source = queue.popleft()
        if source in visited:
            continue
        visited.add(source)
        for target in sorted(outgoing[source]):
            if target in visited:
                continue
            rank[target] = max(rank[target], rank[source] + 1)
            remaining[target] -= 1
            if remaining[target] == 0:
                queue.append(target)
    return rank


def _ordered_layers(component: list[str], edges: list[dict[str, Any]], rank: dict[str, int], node_by_id: dict[str, dict[str, Any]]) -> dict[int, list[str]]:
    layers: dict[int, list[str]] = defaultdict(list)
    for node_id in component:
        layers[rank[node_id]].append(node_id)
    for depth in layers:
        layers[depth].sort(key=lambda node_id: _stable_node(node_by_id[node_id]))
    neighbors = defaultdict(set)
    for edge in edges:
        if edge["source"] in rank and edge["target"] in rank:
            neighbors[edge["source"]].add(edge["target"])
            neighbors[edge["target"]].add(edge["source"])
    depths = sorted(layers)
    for _ in range(6):
        for sweep in (depths[1:], list(reversed(depths[:-1]))):
            positions = {node_id: index for depth in depths for index, node_id in enumerate(layers[depth])}
            for depth in sweep:
                layers[depth].sort(key=lambda node_id: (
                    sum(positions.get(neighbor, 0) for neighbor in neighbors[node_id]) / max(1, len(neighbors[node_id])),
                    -len(neighbors[node_id]),
                    _stable_node(node_by_id[node_id]),
                ))
    return layers


def _component_positions(component: list[str], edges: list[dict[str, Any]], node_by_id: dict[str, dict[str, Any]]) -> tuple[dict[str, dict[str, float]], float, float]:
    rank = _ranks(component, edges)
    layers = _ordered_layers(component, edges, rank, node_by_id)
    gaps = {}
    for depth in range(max(layers, default=0)):
        labels = [_display_label(edge) for edge in edges if rank.get(edge["source"]) == depth and rank.get(edge["target"]) == depth + 1]
        gaps[depth] = NODE_W + RANK_GAP + max([_label_size(label)[0] for label in labels] or [0])
    xs = {0: NODE_W / 2}
    for depth in range(1, max(layers, default=0) + 1):
        xs[depth] = xs[depth - 1] + gaps.get(depth - 1, NODE_W + RANK_GAP)
    max_rows = max((len(items) for items in layers.values()), default=1)
    row_gap = max(ROW_GAP, max((_label_size(_display_label(edge))[1] + 24 for edge in edges), default=0))
    height = max_rows * NODE_H + max(0, max_rows - 1) * row_gap
    positions = {}
    for depth, items in layers.items():
        for index, node_id in enumerate(items):
            positions[node_id] = {"x": xs[depth], "y": NODE_H / 2 + (height - (len(items) * NODE_H + max(0, len(items) - 1) * row_gap)) / 2 + index * (NODE_H + row_gap), "rank": depth}
    width = max(xs.values(), default=NODE_W / 2) + NODE_W / 2
    return positions, width, height


def _rect(point: dict[str, float], padding: float = 0.0) -> tuple[float, float, float, float]:
    return (point["x"] - NODE_W / 2 - padding, point["y"] - NODE_H / 2 - padding, point["x"] + NODE_W / 2 + padding, point["y"] + NODE_H / 2 + padding)


def _boundary(point: dict[str, float], toward: dict[str, float]) -> dict[str, float]:
    dx, dy = toward["x"] - point["x"], toward["y"] - point["y"]
    if not dx and not dy:
        return {"x": point["x"] + NODE_W / 2, "y": point["y"]}
    scale = 1.0 / max(abs(dx) / (NODE_W / 2), abs(dy) / (NODE_H / 2))
    return {"x": point["x"] + dx * scale, "y": point["y"] + dy * scale}


def _segment_hits_rect(a: dict[str, float], b: dict[str, float], rect: tuple[float, float, float, float]) -> bool:
    left, top, right, bottom = rect
    dx, dy = b["x"] - a["x"], b["y"] - a["y"]
    p = (-dx, dx, -dy, dy)
    q = (a["x"] - left, right - a["x"], a["y"] - top, bottom - a["y"])
    low, high = 0.0, 1.0
    for pi, qi in zip(p, q):
        if pi == 0:
            if qi < 0:
                return False
            continue
        value = qi / pi
        if pi < 0:
            low = max(low, value)
        else:
            high = min(high, value)
        if low > high:
            return False
    return high > 0.001 and low < 0.999


def _segments(points: list[dict[str, float]]) -> list[tuple[dict[str, float], dict[str, float]]]:
    return list(zip(points, points[1:]))


def _overlap(first: tuple[dict[str, float], dict[str, float]], second: tuple[dict[str, float], dict[str, float]]) -> float:
    a, b = first
    c, d = second
    if abs(a["y"] - b["y"]) < 0.5 and abs(c["y"] - d["y"]) < 0.5 and abs(a["y"] - c["y"]) < 2:
        return max(0.0, min(max(a["x"], b["x"]), max(c["x"], d["x"])) - max(min(a["x"], b["x"]), min(c["x"], d["x"])))
    if abs(a["x"] - b["x"]) < 0.5 and abs(c["x"] - d["x"]) < 0.5 and abs(a["x"] - c["x"]) < 2:
        return max(0.0, min(max(a["y"], b["y"]), max(c["y"], d["y"])) - max(min(a["y"], b["y"]), min(c["y"], d["y"])))
    return 0.0


def _preferred_sides(source: dict[str, float], target: dict[str, float]) -> tuple[str, str]:
    dx, dy = target["x"] - source["x"], target["y"] - source["y"]
    if dx:
        return ("right", "left") if dx >= 0 else ("left", "right")
    return ("bottom", "top") if dy >= 0 else ("top", "bottom")


def _allocate_anchors(edges: list[dict[str, Any]], positions: dict[str, dict[str, float]]) -> dict[tuple[str, str], dict[str, float]]:
    """Allocate deterministic, ordered boundary slots for every edge endpoint."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    edge_sides = {}
    for edge in edges:
        source, target = positions[edge["source"]], positions[edge["target"]]
        source_side, target_side = _preferred_sides(source, target)
        edge_sides[edge["id"]] = (source_side, target_side)
        groups[(edge["source"], source_side)].append({"edge": edge, "role": "source", "neighbor": target})
        groups[(edge["target"], target_side)].append({"edge": edge, "role": "target", "neighbor": source})
    anchors = {}
    corner_padding = 11.0
    for (node_id, side), endpoints in sorted(groups.items()):
        vertical = side in {"left", "right"}
        endpoints.sort(key=lambda item: (
            item["neighbor"]["y"] if vertical else item["neighbor"]["x"],
            str(item["edge"].get("source")), str(item["edge"].get("target")),
            str(item["edge"].get("classification")), str(item["edge"].get("id")), item["role"],
        ))
        point = positions[node_id]
        usable = (NODE_H if vertical else NODE_W) - 2 * corner_padding
        spacing = usable / (len(endpoints) + 1)
        for index, endpoint in enumerate(endpoints, 1):
            if vertical:
                anchor = {"x": point["x"] + (NODE_W / 2 if side == "right" else -NODE_W / 2), "y": point["y"] - NODE_H / 2 + corner_padding + spacing * index}
            else:
                anchor = {"x": point["x"] - NODE_W / 2 + corner_padding + spacing * index, "y": point["y"] + (NODE_H / 2 if side == "bottom" else -NODE_H / 2)}
            anchors[(endpoint["edge"]["id"], endpoint["role"])] = anchor
    return anchors


def _route_edges(edges: list[dict[str, Any]], positions: dict[str, dict[str, float]]) -> list[dict[str, Any]]:
    pair_total = defaultdict(int)
    for edge in edges:
        pair_total[(edge["source"], edge["target"])] += 1
    pair_seen = defaultdict(int)
    occupied = []
    routed = []
    anchors = _allocate_anchors(edges, positions)
    for edge in sorted(edges, key=lambda item: (not bool(item.get("network")), str(item.get("source")), str(item.get("target")), str(item.get("id")))):
        source, target = positions[edge["source"]], positions[edge["target"]]
        pair = (edge["source"], edge["target"])
        lane = pair_seen[pair] - (pair_total[pair] - 1) / 2
        pair_seen[pair] += 1
        start = dict(anchors[(edge["id"], "source")])
        end = dict(anchors[(edge["id"], "target")])
        dx, dy = end["x"] - start["x"], end["y"] - start["y"]
        length = hypot(dx, dy) or 1.0
        obstacles = [_rect(point, NODE_PAD) for node_id, point in positions.items() if node_id not in pair]
        mid_x, mid_y = (start["x"] + end["x"]) / 2, (start["y"] + end["y"]) / 2
        lane_offset = lane * 14.0
        candidates = [
            [start, end],
            [start, {"x": end["x"], "y": start["y"]}, end],
            [start, {"x": start["x"], "y": end["y"]}, end],
            [start, {"x": mid_x + lane_offset, "y": start["y"]}, {"x": mid_x + lane_offset, "y": end["y"]}, end],
            [start, {"x": start["x"], "y": mid_y + lane_offset}, {"x": end["x"], "y": mid_y + lane_offset}, end],
        ]
        blockers = [rect for rect in obstacles if _segment_hits_rect(start, end, rect)]
        for rect in blockers:
            candidates.extend([
                [start, {"x": start["x"], "y": rect[1] - 22}, {"x": end["x"], "y": rect[1] - 22}, end],
                [start, {"x": start["x"], "y": rect[3] + 22}, {"x": end["x"], "y": rect[3] + 22}, end],
            ])
        def cost(points: list[dict[str, float]]) -> float:
            segments = _segments(points)
            node_hits = sum(_segment_hits_rect(a, b, rect) for a, b in segments for rect in obstacles)
            overlap = sum(_overlap(segment, prior) for segment in segments for prior in occupied)
            distance = sum(hypot(b["x"] - a["x"], b["y"] - a["y"]) for a, b in segments)
            return node_hits * 1_000_000 + overlap * 2_000 + distance + max(0, len(points) - 2) * 35
        points = min(candidates, key=lambda candidate: (cost(candidate), [(point["x"], point["y"]) for point in candidate]))
        occupied.extend(_segments(points))
        routed.append({**edge, "points": points, "lane": lane, "source_anchor": start, "destination_anchor": end, "label": _display_label(edge)})
    return routed


def _box_overlap(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> bool:
    return a[0] < b[2] and a[2] > b[0] and a[1] < b[3] and a[3] > b[1]


def _place_labels(routes: list[dict[str, Any]], positions: dict[str, dict[str, float]]) -> None:
    node_boxes = [_rect(point, 5) for point in positions.values()]
    arrow_boxes = [(route["points"][-1]["x"] - 18, route["points"][-1]["y"] - 18, route["points"][-1]["x"] + 18, route["points"][-1]["y"] + 18) for route in routes]
    used = []
    ordered = sorted(routes, key=lambda route: (not bool(route.get("network")), str(route.get("id"))))
    for route in ordered:
        label = route.get("label", "")
        if not label:
            route["label_position"] = None
            continue
        segments = sorted(_segments(route["points"]), key=lambda item: -hypot(item[1]["x"] - item[0]["x"], item[1]["y"] - item[0]["y"]))
        width, height = _label_size(label)
        route["label_lines"] = label_lines(label)
        route["label_size"] = {"width": width, "height": height}
        candidates = []
        for a, b in segments:
            dx, dy = b["x"] - a["x"], b["y"] - a["y"]
            length = hypot(dx, dy) or 1.0
            nx, ny = -dy / length, dx / length
            for fraction in (0.5, 0.35, 0.65, 0.2, 0.8):
                for offset in (height / 2 + 4, -height / 2 - 4, height / 2 + 16, -height / 2 - 16):
                    x = a["x"] + dx * fraction + nx * offset
                    y = a["y"] + dy * fraction + ny * offset
                    box = (x - width / 2, y - height / 2, x + width / 2, y + height / 2)
                    destination = positions[route["target"]]
                    convergence = abs(x - destination["x"]) < NODE_W / 2 + 55 and abs(y - destination["y"]) < NODE_H / 2 + 38
                    collisions = sum(_box_overlap(box, other) for other in node_boxes) * 1000 + sum(_box_overlap(box, other) for other in used) * 500 + sum(_box_overlap(box, other) for other in arrow_boxes) * 750
                    candidates.append((collisions + (180 if convergence else 0) + abs(fraction - 0.42) * 10 + abs(offset) / 10, x, y, box))
        best = min(candidates, default=None)
        if best and best[0] < 500:
            route["label_position"] = {"x": best[1], "y": best[2]}
            used.append(best[3])
        else:
            # Dense convergence sometimes leaves no collision-free label site.
            # Reserve an exterior track for this relationship rather than hide
            # its label or place it over another label. This track is part of
            # the component bounds, so packing cannot put another group on it.
            start, end = route["source_anchor"], route["destination_anchor"]
            direction = 1 if end["x"] >= start["x"] else -1
            left_x, right_x = start["x"] + direction * 24, end["x"] - direction * 24
            top = min(box[1] for box in node_boxes + used + arrow_boxes)
            y = top - height / 2 - 24
            x = (left_x + right_x) / 2
            route["points"] = [start, {"x": left_x, "y": start["y"]}, {"x": left_x, "y": y},
                               {"x": right_x, "y": y}, {"x": right_x, "y": end["y"]}, end]
            route["label_position"] = {"x": x, "y": y - height / 2 - 4}
            used.append((x - width / 2, y - height - 4, x + width / 2, y - 4))


def _bounds(positions, routes):
    xs = [value for point in positions.values() for value in (point["x"] - NODE_W / 2, point["x"] + NODE_W / 2)]
    ys = [value for point in positions.values() for value in (point["y"] - NODE_H / 2, point["y"] + NODE_H / 2)]
    for route in routes:
        xs.extend(point["x"] for point in route["points"])
        ys.extend(point["y"] for point in route["points"])
        if route.get("label_position"):
            width, height = _label_size(route["label"])
            xs.extend((route["label_position"]["x"] - width / 2, route["label_position"]["x"] + width / 2))
            ys.extend((route["label_position"]["y"] - height / 2, route["label_position"]["y"] + height / 2))
    bounds = {"x": min(xs, default=0) - MARGIN, "y": min(ys, default=0) - MARGIN, "width": max(xs, default=1200) - min(xs, default=0) + MARGIN * 2, "height": max(ys, default=620) - min(ys, default=0) + MARGIN * 2}
    return bounds


@lru_cache(maxsize=256)
def _component_geometry(serialized: str):
    """Cache local geometry, independent of viewport. Never mutate cached objects."""
    nodes, edges = json.loads(serialized)
    positions, _, _ = _component_positions([node["id"] for node in nodes], edges, {node["id"]: node for node in nodes})
    routes = _route_edges(edges, positions)
    _place_labels(routes, positions)
    return positions, routes, _bounds(positions, routes)


def _pack_boxes(sizes, viewport_width):
    """Bottom-left skyline packing also fills space beside tall components."""
    skyline = [(0.0, 0.0, max(240.0, viewport_width))]
    offsets = []
    for width, height in sizes:
        choices = []
        for index, (x, _, _) in enumerate(skyline):
            if x + width > viewport_width:
                continue
            y = max(segment_y for sx, segment_y, sw in skyline[index:] if sx < x + width)
            choices.append((y, x))
        y, x = min(choices) if choices else (max(item[1] for item in skyline), 0.0)
        offsets.append((x, y))
        right = min(viewport_width, x + width)
        updated = []
        for sx, sy, sw in skyline:
            if sx < x:
                updated.append((sx, sy, min(sw, x - sx)))
            if sx + sw > right:
                updated.append((max(sx, right), sy, sx + sw - max(sx, right)))
        updated.append((x, y + height, right - x))
        skyline = sorted(updated)
        merged = []
        for segment in skyline:
            if merged and merged[-1][1] == segment[1]:
                previous = merged.pop()
                merged.append((previous[0], previous[1], previous[2] + segment[2]))
            else:
                merged.append(segment)
        skyline = merged
    return offsets


def build_layout(graph: dict[str, Any], view: str, viewport_width: float = 1200) -> dict[str, Any]:
    """Lay out whole weak components before width-aware skyline packing.

    Relationships determine ranks inside each group, never global kind columns.
    Routed edges and wrapped labels participate in group bounds. Resizing only
    translates cached groups, so routing and topology remain stable. Tall groups
    go first; stable IDs break ties. The skyline accepts mixed sizes without splitting
    a connected topology, and oversized components retain readable dimensions.
    """
    nodes, edges = project_graph(graph, view)
    components = _components(nodes, edges)
    by_id = {node["id"]: node for node in nodes}
    membership = {node_id: index for index, group in enumerate(components) for node_id in group}
    grouped_edges = defaultdict(list)
    for edge in edges:
        grouped_edges[membership[edge["source"]]].append(edge)
    groups = []
    for index, component in enumerate(components):
        geometry = deepcopy(_component_geometry(json.dumps([
            [by_id[node_id] for node_id in sorted(component)], grouped_edges[index]
        ], sort_keys=True)))
        groups.append((component, *geometry))
    groups.sort(key=lambda group: (-group[3]["height"], -group[3]["width"], sorted(group[0])))
    positions, routes, boxes = {}, [], []
    offsets = _pack_boxes([(group[3]["width"], group[3]["height"]) for group in groups], viewport_width)
    for (component, local, local_routes, bounds), (x, y) in zip(groups, offsets):
        width, height = bounds["width"], bounds["height"]
        dx, dy = x - bounds["x"], y - bounds["y"]
        for node_id, point in local.items():
            positions[node_id] = {**point, "x": point["x"] + dx, "y": point["y"] + dy}
        for route in local_routes:
            # Anchors may share dict identity with points; replace rather than mutate.
            route["points"] = [{"x": p["x"] + dx, "y": p["y"] + dy} for p in route["points"]]
            for field in ("source_anchor", "destination_anchor", "label_position"):
                if route.get(field):
                    p = route[field]
                    route[field] = {"x": p["x"] + dx, "y": p["y"] + dy}
            routes.append(route)
        boxes.append({"node_ids": component, "x": x, "y": y, "width": width, "height": height})
    return {"view": view, "node_ids": [node["id"] for node in nodes], "positions": positions, "edges": routes,
            "components": components, "component_bounds": boxes, "bounds": _bounds(positions, routes)}


def build_layouts(graph: dict[str, Any], viewport_width: float = 1200) -> dict[str, dict[str, Any]]:
    return {view: build_layout(graph, view, viewport_width) for view in ("flow", "all", "declared", "runtime", "differences", "network", "containers", "configuration", "storage")}
