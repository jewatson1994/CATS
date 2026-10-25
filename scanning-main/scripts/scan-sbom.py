#!/usr/bin/env python3
"""Run Grype on a frozen native inventory and retain the input/output byte binding."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from sbom_identity import _digest, document_binding


def scan(sbom_path, result_path):
    sbom_path, result_path = Path(sbom_path), Path(result_path)
    binding_path = result_path.with_suffix(".binding")
    binding_path.unlink(missing_ok=True)
    raw_bytes = sbom_path.read_bytes()
    document = json.loads(raw_bytes)
    image_path, provenance_path = sbom_path.with_suffix(".image"), sbom_path.with_suffix(".provenance")
    image = image_path.read_text(encoding="utf-8").strip() if image_path.is_file() else ""
    provenance = json.loads(provenance_path.read_bytes()) if provenance_path.is_file() else None
    binding = document_binding(raw_bytes, document, image, provenance)
    # A separate immutable input snapshot prevents a later SBOM replacement from
    # retroactively changing the inventory that this Grype result claims to use.
    with tempfile.TemporaryDirectory(prefix="cats-grype-input-") as folder:
        snapshot = Path(folder) / "inventory.json"
        snapshot.write_bytes(raw_bytes)
        with result_path.open("wb") as stream:
            completed = subprocess.run(["grype", "sbom:" + str(snapshot), "--only-fixed", "-o", "json"], stdout=stream)
    if completed.returncode:
        result_path.unlink(missing_ok=True)
        return completed.returncode
    binding.update(image=image, scanner_report_digest=_digest(result_path.read_bytes()))
    binding_path.write_text(json.dumps(binding, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(scan(*sys.argv[1:]))
