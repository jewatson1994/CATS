"""Static SVG exports for the evidence-backed Architecture projections."""
from __future__ import annotations

from html import escape
from typing import Any


def build_architecture_svg(graph: dict[str, Any], view: str) -> str:
    layout = (graph.get("layouts") or {}).get(view) or {}
    positions = layout.get("positions") or {}
    bounds = layout.get("bounds") or {"x": 0, "y": 0, "width": 1200, "height": 620}
    nodes = {node["id"]: node for node in graph.get("nodes", []) if node.get("id") in positions}
    width, height = max(1200, int(bounds.get("width", 1200))), max(620, int(bounds.get("height", 620)))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="{bounds.get("x", 0)} {bounds.get("y", 0)} {bounds.get("width", width)} {bounds.get("height", height)}" role="img" aria-labelledby="title desc">',
        '<defs><marker id="arrow" markerWidth="5" markerHeight="5" refX="5" refY="2.5" orient="auto" markerUnits="strokeWidth" overflow="visible"><path d="M0,0 L5,2.5 L0,5 z" fill="context-stroke"/></marker></defs>',
        f'<title id="title">CATS Architecture — {escape(view.replace("-", " ").title())}</title>',
        '<desc id="desc">Architecture projection derived from rendered Helm and Kubernetes evidence.</desc>',
        '<style>text{font-family:Arial,sans-serif;fill:#eef6f3;font-size:12px}.node{fill:#14211f;stroke:#263735;stroke-width:1.5}.edge{fill:none;stroke:#72e0b4;stroke-width:2.5;marker-end:url(#arrow)}.edge.inferred{stroke:#b79cff;stroke-dasharray:8 5}.label{fill:#9fb1ac;font-size:11px;paint-order:stroke;stroke:#08100f;stroke-width:4px}</style>',
    ]
    for edge in layout.get("edges", []):
        points = edge.get("points") or []
        if len(points) < 2:
            continue
        path = " ".join(f'{"M" if index == 0 else "L"}{point["x"]},{point["y"]}' for index, point in enumerate(points))
        classification = str(edge.get("classification", "DERIVED")).lower()
        parts.append(f'<path class="edge {classification}" d="{path}" data-relationship="{escape(str(edge.get("id", "")))}"/>')
        label = edge.get("label_position")
        if label and edge.get("label"):
            lines = edge.get("label_lines") or [edge["label"]]
            parts.append('<text class="label" text-anchor="middle">')
            for index, line in enumerate(lines):
                y = label["y"] + (index - (len(lines) - 1) / 2) * 16 + 4
                parts.append(f'<tspan x="{label["x"]}" y="{y}">{escape(line)}</tspan>')
            parts.append('</text>')
    for node_id, point in positions.items():
        node = nodes.get(node_id)
        if not node:
            continue
        x, y = point["x"], point["y"]
        parts.append(f'<rect class="node" x="{x - 92}" y="{y - 28}" width="184" height="56" rx="8"/>')
        parts.append(f'<text x="{x}" y="{y - 3}" text-anchor="middle">{escape(str(node.get("kind", node.get("type", "Unknown"))))}</text>')
        name = str(node.get("name", "unnamed"))
        display_name = name if len(name) <= 25 else name[:24] + "…"
        parts.append(f'<text class="label" x="{x}" y="{y + 16}" text-anchor="middle"><title>{escape(name)}</title>{escape(display_name)}</text>')
    parts.append("</svg>")
    return "".join(parts)
