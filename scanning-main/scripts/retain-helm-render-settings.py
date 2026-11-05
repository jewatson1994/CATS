#!/usr/bin/env python3
"""Retain exact Helm inputs per rendered instance for candidate verification."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def retain(root: Path, overview: Path) -> None:
    root = root.resolve()
    retained = root / "charts"

    def relative(value):
        path = Path(str(value))
        if not path.is_absolute():
            path = root / path
        path = path.resolve()
        # An unavailable acquisition directory must not accidentally match a
        # different retained chart. Verification rejects this explicit path.
        if not path.is_relative_to(retained):
            return "__unretained__/" + path.name
        return path.relative_to(retained).as_posix()

    settings, seen = [], set()
    for directory in (root / "helm-image-rendered", root / "helm-rendered"):
        for metadata in sorted(directory.glob("*.chart.json")):
            item = json.loads(metadata.read_text(encoding="utf-8"))
            if not item.get("render_chart_root"):
                continue
            overrides = item.get("set") or []
            if isinstance(overrides, dict):
                def text(value):
                    return json.dumps(value, separators=(",", ":")) if not isinstance(value, str) else value
                overrides = [f"{key}={text(value)}" for key, value in overrides.items()]
            entry = {"chart_root": relative(item["render_chart_root"]),
                     "release": item["release"], "namespace": item["namespace"],
                     "values": [relative(value) for value in item.get("values") or []],
                     "set": overrides, "include_crds": item.get("include_crds", True)}
            identity = json.dumps(entry, sort_keys=True)
            if identity not in seen:
                seen.add(identity)
                settings.append(entry)
    value = json.loads(overview.read_text(encoding="utf-8"))
    if settings:
        value["helm_render_settings"] = settings
    overview.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    retain(Path(sys.argv[1]), Path(sys.argv[2]))
