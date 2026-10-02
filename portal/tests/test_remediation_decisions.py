from copy import deepcopy
import pytest
from app.remediation import AUTO, REVIEW, SAFE_AUTOMATIC, DECISION_REQUIRED, MANUAL_ONLY, resolve_decisions, plan_digest


def plan(category=DECISION_REQUIRED, editable=True):
    return {"configuration_changes": [{"finding_id": 1, "rule_id": "nonroot", "category": category,
        "classification": REVIEW, "editable": editable, "new_value": True,
        "field_path": "securityContext.runAsNonRoot", "proposed_value_source": "Hardening Policy"}], "images": []}


def test_automated_accepts_safe_without_manager_input():
    source = plan(SAFE_AUTOMATIC)
    result = resolve_decisions(source, "automated", {}, "manager")
    row = result["configuration_changes"][0]
    assert row["classification"] == AUTO
    assert row["approval"] == "automatic" and row["actor"] is None
    assert source["configuration_changes"][0]["classification"] == REVIEW


def test_automated_requires_explicit_review_decision():
    with pytest.raises(ValueError, match="Explicit decision"):
        resolve_decisions(plan(), "automated", {}, "manager")


def test_guided_can_leave_safe_unresolved():
    result = resolve_decisions(plan(SAFE_AUTOMATIC), "guided", {"1": {"action": "unresolved"}}, "manager")
    assert result["configuration_changes"][0]["classification"] == REVIEW


def test_manager_custom_value_has_typed_value_and_audit_source():
    result = resolve_decisions(plan(), "guided", {"1": {"action": "custom", "value": False}}, "manager")
    row = result["configuration_changes"][0]
    assert row["new_value"] is False and row["actor"] == "manager"
    assert row["proposed_value_source"] == "Explicit Service Manager input"
    assert row["timestamp"] and row["post_scan_result"] == "NOT RUN"


@pytest.mark.parametrize("value", ["false", 0, {}, None])
def test_custom_boolean_rejects_wrong_types(value):
    with pytest.raises(ValueError, match="boolean"):
        resolve_decisions(plan(), "guided", {"1": {"action": "custom", "value": value}}, "manager")


def test_manual_only_cannot_be_approved():
    assert resolve_decisions(plan(MANUAL_ONLY), "guided", {}, "manager")["decisions"][0]["decision"] == "unresolved"
    with pytest.raises(ValueError, match="Manual-only"):
        resolve_decisions(plan(MANUAL_ONLY), "guided", {"1": {"action": "proposed"}}, "manager")


def test_ambiguous_mapping_cannot_be_approved():
    with pytest.raises(ValueError, match="exact editable"):
        resolve_decisions(plan(editable=False), "guided", {"1": {"action": "proposed"}}, "manager")


def test_arbitrary_field_and_foreign_finding_rejected():
    for decisions in ({"1": {"action": "custom", "value": False, "field_path": "metadata.name"}}, {"9": {"action": "proposed"}}):
        with pytest.raises(ValueError):
            resolve_decisions(plan(), "guided", decisions, "manager")


def test_plan_digest_ignores_clock_but_binds_values():
    first = plan(); second = deepcopy(first)
    second["configuration_changes"][0]["timestamp"] = "later"
    assert plan_digest(first) == plan_digest(second)
    second["configuration_changes"][0]["new_value"] = False
    assert plan_digest(first) != plan_digest(second)
