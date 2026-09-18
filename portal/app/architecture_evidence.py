"""Lineage-aware Architecture verification derived from persisted evidence."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping


ARCHITECTURE_STATES = {"DECLARED", "VERIFIED", "PARTIALLY_VERIFIED", "N/A"}


def _value(item: Any, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _completed_key(run: Any) -> tuple[datetime, int]:
    completed = _value(run, "completed_at") or datetime.min
    if getattr(completed, "tzinfo", None) is not None:
        completed = completed.replace(tzinfo=None)
    return completed, int(_value(run, "id", 0) or 0)


def applicable_validation_run(
    runs: Iterable[Any], *, execution_id: int | None = None,
    artifact_revision_id: int | None = None,
) -> Any | None:
    """Select latest useful completed evidence for exactly one architecture subject."""
    candidates = []
    for run in runs:
        if str(_value(run, "phase", "")).upper() != "COMPLETE":
            continue
        if str(_value(run, "status", "")).upper() not in {"VERIFIED", "PARTIALLY_VERIFIED"}:
            continue
        if artifact_revision_id is not None:
            if int(_value(run, "artifact_revision_id", 0) or 0) != artifact_revision_id:
                continue
        elif execution_id is not None:
            if str(_value(run, "artifact_type", "ORIGINAL")).upper() != "ORIGINAL" or int(_value(run, "execution_id", 0) or 0) != execution_id:
                continue
        else:
            continue
        candidates.append(run)
    return max(candidates, key=_completed_key, default=None)


def architecture_verification(
    *, applicable: bool, declared_count: int, runs: Iterable[Any],
    execution_id: int | None = None, artifact_revision_id: int | None = None,
) -> dict[str, Any]:
    """Return exactly one of the four Architecture evidence states."""
    if not applicable:
        return {
            "state": "N/A", "label": "N/A", "run": None, "run_key": None,
            "expected": 0, "observed": 0, "missing": 0, "failed": 0,
            "reason": "This service does not contain an applicable Helm chart, so Kubernetes Deployment Validation does not apply.",
        }
    run = applicable_validation_run(runs, execution_id=execution_id, artifact_revision_id=artifact_revision_id)
    if run is None:
        return {
            "state": "DECLARED", "label": "Declared", "run": None, "run_key": None,
            "expected": declared_count, "observed": 0, "missing": 0, "failed": 0,
            "reason": "Architecture was derived from rendered Helm/Kubernetes evidence. Runtime verification has not been established for this artifact revision.",
        }
    diagnostics = _value(run, "diagnostics", {}) or {}
    summary = diagnostics.get("classification_summary", {}) if isinstance(diagnostics, Mapping) else {}
    comparison = _value(run, "comparison", {}) or {}
    expected = int(summary.get("expected_resources", len(comparison.get("matched", [])) + len(comparison.get("declared_only", []))) or 0)
    observed = int(summary.get("observed_expected", len(comparison.get("matched", []))) or 0)
    missing = int(summary.get("expected_only", len(comparison.get("declared_only", []))) or 0)
    failed = int(summary.get("failed", 0) or 0)
    status = str(_value(run, "status", "")).upper()
    state = "VERIFIED" if status == "VERIFIED" and not missing and not failed else "PARTIALLY_VERIFIED"
    return {
        "state": state, "label": "Verified" if state == "VERIFIED" else "Partially Verified",
        "run": run, "run_key": _value(run, "run_key"), "engine": _value(run, "engine", "kind"),
        "completed_at": _value(run, "completed_at"), "expected": expected, "observed": observed,
        "missing": missing, "failed": failed, "reason": _value(run, "reason", ""),
        "artifact_reference": _value(run, "artifact_reference"),
    }


def architecture_summary_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value.get(key) for key in (
        "state", "label", "run_key", "engine", "completed_at", "expected", "observed",
        "missing", "failed", "reason", "artifact_reference",
    )}
