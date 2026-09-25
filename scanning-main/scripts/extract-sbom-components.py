#!/usr/bin/env python3
"""Create a bounded, nonsensitive package inventory for portal watchlist matching."""

import json
from pathlib import Path
import sys


def main(root: Path, output: Path) -> None:
    components = []
    images = []
    for path in sorted(root.glob("*.json")):
        image_path = path.with_suffix(".image")
        if not image_path.is_file():
            continue
        image = image_path.read_text(encoding="utf-8").strip()[:1000]
        try:
            sbom = json.loads(path.read_text(encoding="utf-8"))
            artifacts = sbom.get("artifacts", [])
            if not isinstance(artifacts, list):
                continue
            images.append(image)
            for artifact in artifacts:
                if len(components) >= 50000:
                    break
                if not isinstance(artifact, dict):
                    continue
                purl = artifact.get("purl") or ""
                components.append({"name": str(artifact.get("name") or "")[:300],
                                   "version": str(artifact.get("version") or "")[:200],
                                   "ecosystem": str(artifact.get("type") or "")[:80],
                                   "purl": str(purl)[:700], "image": image})
        except (OSError, ValueError, UnicodeError):
            continue
    output.write_text(json.dumps({"components": components, "images": sorted(set(images))}), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
