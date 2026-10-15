"""Build a remediation comparison only from complete, comparable scan evidence."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .remediation import summarize_grype_reports


def apply_vulnerability_comparison(plan: dict, patch_job_root: Path, risk_metadata) -> None:
    """Update both snapshots from full reports, counting each patch job once.

    The historical baseline remains available if paired evidence is incomplete,
    but no after count is shown against that incomparable baseline.
    """
    before, after = plan["before"], plan["after"]
    images = plan.get("images", [])
    patches = {image["patch_job_id"]: image for image in images if image.get("patch_job_id")}
    complete_scope = bool(images) and all(image.get("patch_job_id") for image in images)
    for snapshot, field in ((before, "vulnerabilities_before"), (after, "vulnerabilities_after")):
        values = [None if field == "vulnerabilities_after" and image.get("patch_status") == "UNSUPPORTED"
                  else image.get(field) for image in patches.values()]
        total = (sum(values) if complete_scope and values and
                 all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values)
                 else None)
        snapshot["patchable_vulnerabilities"] = total
        snapshot["patchable_vulnerability_observations"] = total
        snapshot["patchable_comparison_note"] = "Fixable package vulnerabilities only (Grype --only-fixed); separate from full vulnerability totals."

    reports = {"before": [], "after": []}
    try:
        if not complete_scope:
            raise ValueError("Not all images have patch scan evidence")
        for patch_key in patches:
            if not isinstance(patch_key, str) or not re.fullmatch(r"[0-9a-f]{32}", patch_key):
                raise ValueError("Invalid patch evidence reference")
            for side in reports:
                path = patch_job_root / patch_key / "output" / f"grype-full-{side}.json"
                reports[side].append(json.loads(path.read_text(encoding="utf-8")))
        summaries = {side: summarize_grype_reports(rows, risk_metadata, observations=True)
                     for side, rows in reports.items()}
    except (OSError, ValueError, TypeError):
        note = ("Full before/after image scan evidence is incomplete; no comparable after total is available. "
                "Before retains the original scan baseline.")
        before["comparison_note"] = after["comparison_note"] = note
        for field in ("vulnerabilities", "kev", "epss_max", "cve_count", "vulnerability_observations"):
            after[field] = None
        return

    note = ("Full Grype package/image vulnerability observations across all patched images; "
            "shared images are counted once per patch job. KEV counts use the same observations.")
    for side, snapshot in (("before", before), ("after", after)):
        snapshot.update(summaries[side])
        snapshot["comparison_note"] = note
