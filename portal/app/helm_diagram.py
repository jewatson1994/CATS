"""Small, dependency-free SVG diagram for Helm-rendered service evidence."""
from __future__ import annotations

from html import escape
from typing import Any


def _text(value: Any, fallback: str = "") -> str:
    value = "" if value is None else str(value).strip()
    return value or fallback


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def _label(value: str, limit: int = 44) -> str:
    value = _text(value, "Unknown")
    return value if len(value) <= limit else value[: limit - 1] + "…"


def build_helm_diagram(service: Any, latest_execution: Any = None) -> str:
    """Compatibility URL: architecture evidence uses the canonical renderer.

    Older assessments only contain chart/image provenance, not resource topology;
    retain their evidence summary instead of inventing Kubernetes relationships.
    """
    from .architecture import build_architecture_graph
    from .architecture_export import build_architecture_svg

    payload = latest_execution.raw_payload if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
    graph = build_architecture_graph(payload)
    if graph["nodes"]:
        return build_architecture_svg(graph, "all")
    return _build_provenance_diagram(service, latest_execution)


def _build_provenance_diagram(service: Any, latest_execution: Any = None) -> str:
    payload = latest_execution.raw_payload if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
    overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    charts: list[dict[str, str]] = []
    seen_charts: set[tuple[str, str, str]] = set()
    for raw in [*_items(overview.get("helm_components")), *_items(overview.get("charts")), *_items(overview.get("helm_charts"))]:
        raw = raw if isinstance(raw, dict) else {"chart": raw}
        name = _text(raw.get("chart") or raw.get("name") or raw.get("artifact"), "Unknown chart")
        path = _text(raw.get("path") or raw.get("chart_path"), "—")
        parent = _text(raw.get("parent_chart") or raw.get("parent"))
        key = (name, path, parent)
        if key not in seen_charts:
            seen_charts.add(key)
            charts.append({"name": name, "path": path, "parent": parent})

    images: list[dict[str, str]] = []
    seen_images: set[str] = set()
    for raw in [*_items(overview.get("images") or overview.get("container_images"))]:
        raw = raw if isinstance(raw, dict) else {"image": raw}
        image = _text(raw.get("image") or raw.get("reference") or raw.get("name"))
        if image and image not in seen_images:
            seen_images.add(image)
            images.append({
                "image": image,
                "source": _text(raw.get("source_chart") or raw.get("discovered_from") or raw.get("found_in") or raw.get("source"), "Rendered manifest"),
            })

    ports: list[dict[str, str]] = []
    seen_ports: set[tuple[str, str, str, str]] = set()
    for raw in _items(overview.get("ports")):
        raw = raw if isinstance(raw, dict) else {"port": raw}
        port = _text(raw.get("port") or raw.get("container_port"), "Not provided")
        protocol = _text(raw.get("protocol"), "TCP").upper()
        service_name = _text(raw.get("service") or raw.get("name"), "Port")
        source = _text(raw.get("source_file") or raw.get("declared_by") or raw.get("source"), "Rendered manifest")
        key = (port, protocol, service_name, source)
        if key not in seen_ports:
            seen_ports.add(key)
            ports.append({"port": port, "protocol": protocol, "service": service_name, "source": source})

    title = _label(_text(getattr(service, "name", None), "Service") + " · Helm rendering", 90)
    width = 1120
    chart_x, image_x = 70, 650
    top = 115
    row_height = 76
    relationship_bottom = top + max(len(charts), len(images), 1) * row_height
    ports_top = relationship_bottom + 38
    height = max(300, ports_top + (max((len(ports) + 2) // 3, 1) * 66) + 60)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="diagram-title diagram-desc">',
        '<style>text{font-family:Arial,sans-serif;fill:#17312b}.title{font-size:24px;font-weight:700}.subtitle{font-size:13px;fill:#55706a}.heading{font-size:14px;font-weight:700}.node{fill:#f5faf8;stroke:#76a99b;stroke-width:2}.image{fill:#fff8ec;stroke:#c7924b;stroke-width:2}.edge{stroke:#9aaea8;stroke-width:2;fill:none;marker-end:url(#arrow)}</style>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#9aaea8"/></marker></defs>',
        f'<title id="diagram-title">{escape(title)}</title><desc id="diagram-desc">A basic evidence diagram derived from Helm-rendered chart and image provenance.</desc>',
        f'<text x="40" y="42" class="title">{escape(title)}</text>',
        '<text x="40" y="68" class="subtitle">Evidence relationships only; runtime traffic is not inferred.</text>',
        f'<text x="{chart_x}" y="94" class="heading">Helm charts / components ({len(charts)})</text>',
        f'<text x="{image_x}" y="94" class="heading">Rendered container images ({len(images)})</text>',
        f'<text x="40" y="{ports_top}" class="heading">Ports / protocols ({len(ports)})</text>',
    ]

    for index, chart in enumerate(charts):
        y = top + index * row_height
        parts.append(f'<rect x="{chart_x}" y="{y}" width="360" height="48" rx="8" class="node"/><text x="{chart_x + 14}" y="{y + 21}" font-weight="700">{escape(_label(chart["name"]))}</text><text x="{chart_x + 14}" y="{y + 39}" class="subtitle">{escape(_label(chart["path"], 52))}</text>')
    for index, image in enumerate(images):
        y = top + index * row_height
        parts.append(f'<rect x="{image_x}" y="{y}" width="400" height="48" rx="8" class="image"/><text x="{image_x + 14}" y="{y + 21}" font-weight="700">{escape(_label(image["image"]))}</text><text x="{image_x + 14}" y="{y + 39}" class="subtitle">{escape(_label(image["source"], 49))}</text>')

    for image_index, image in enumerate(images):
        source = image["source"].casefold()
        matching = next((index for index, chart in enumerate(charts) if chart["name"].casefold() in source or chart["path"].casefold() in source), None)
        if matching is not None:
            y1 = top + matching * row_height + 24
            y2 = top + image_index * row_height + 24
            parts.append(f'<path d="M{chart_x + 360},{y1} C530,{y1} 570,{y2} {image_x},{y2}" class="edge"/>')

    if not charts and not images:
        parts.append('<text x="40" y="160" class="subtitle">No Helm chart or rendered image evidence was supplied by the latest assessment.</text>')
    elif charts and not images:
        parts.append(f'<text x="{image_x}" y="{top + 22}" class="subtitle">No rendered image evidence supplied.</text>')
    elif images and not charts:
        parts.append(f'<text x="{chart_x}" y="{top + 22}" class="subtitle">No Helm chart component evidence supplied.</text>')

    if ports:
        for index, port in enumerate(ports):
            column = index % 3
            row = index // 3
            x = 40 + column * 360
            y = ports_top + 14 + row * 66
            parts.append(f'<rect x="{x}" y="{y}" width="330" height="48" rx="8" class="node"/><text x="{x + 14}" y="{y + 21}" font-weight="700">{escape(port["service"])} · {escape(port["port"])}/{escape(port["protocol"])}</text><text x="{x + 14}" y="{y + 39}" class="subtitle">{escape(_label(port["source"], 40))}</text>')
    else:
        parts.append(f'<text x="40" y="{ports_top + 24}" class="subtitle">No port or protocol evidence was supplied by the rendered chart.</text>')
    parts.append("</svg>")
    return "".join(parts)
