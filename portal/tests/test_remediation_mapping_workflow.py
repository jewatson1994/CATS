"""Retained source convergence, fanout, and field-level summary evidence."""
from copy import deepcopy

import pytest
import yaml

from app import remediation
from app.remediation_mutations import MutationError
from app.remediation_sources import verify_rendered_changes, verify_rendered_scope
from app.remediation_summary import build_summary


def resource(name, privileged=True):
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": "default"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "app", "securityContext": {"privileged": privileged}}]}}}}


def change(name="web", value=False, finding_id="1"):
    return {"finding_id": finding_id, "rule_id": "KSV-0017",
            "classification": remediation.AUTO, "decision": "proposed",
            "resource": f"default/Deployment/{name}",
            "container_name": "app", "container_type": "containers",
            "field_path": "securityContext.privileged", "new_value": value,
            "source_mapping": {"values_file": "chart/values.yaml",
                               "values_key": ".Values.context.privileged", "ambiguous": False}}


def payload():
    return {"artifact_type": "helm", "rendered_resources": [resource("web"), resource("worker")],
            "helm_source_files": {"chart/values.yaml": "context:\n  privileged: true\nother: before\n"}}


@pytest.mark.parametrize("names", [("web", "web"), ("web", "worker")])
def test_identical_findings_or_targets_converge_on_one_source_write(monkeypatch, names):
    source = payload()
    rows = [change(name, finding_id=str(index)) for index, name in enumerate(names)]
    calls = []
    original = remediation.apply_mutation

    def observed(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(remediation, "apply_mutation", observed)
    candidate = remediation.candidate_files(source, {"configuration_changes": rows})
    assert len(calls) == 1
    assert yaml.safe_load(candidate["chart/values.yaml"])["context"]["privileged"] is False
    assert source["helm_source_files"]["chart/values.yaml"].endswith("other: before\n")
    assert rows == [change(name, finding_id=str(index)) for index, name in enumerate(names)]


def test_conflicting_values_at_same_retained_source_address_block():
    source = payload()
    original = deepcopy(source)
    with pytest.raises(MutationError, match="Conflicting accepted writes"):
        remediation.candidate_files(source, {"configuration_changes": [change("web"), change("worker", True)]})
    assert source == original


def test_shared_source_fanout_requires_every_affected_rendered_target():
    before = payload()["rendered_resources"]
    after = [resource("web", False), resource("worker", False)]
    accepted = [change("web"), change("worker", finding_id="2")]
    assert verify_rendered_changes(after, accepted)["status"] == "PASS"
    assert verify_rendered_scope(before, after, accepted)["status"] == "PASS"
    assert verify_rendered_scope(before, after, accepted[:1])["status"] == "FAIL"


def test_summary_shared_source_records_each_accepted_target_without_claiming_scan_resolution():
    source = payload()
    plan = {"configuration_changes": [change("web"), change("worker", finding_id="2")]}
    candidate = remediation.candidate_files(source, plan)
    summary = build_summary(plan, source["helm_source_files"], candidate, {},
                            source["rendered_resources"], [resource("web", False), resource("worker", False)])
    assert len(summary["configuration_changes"]) == 2
    assert all(row["applied"] and row["actual_value"] is False for row in summary["configuration_decisions"])
    assert not any(row["verified"] for row in summary["configuration_decisions"])


def test_summary_unrelated_file_field_change_does_not_count_as_applied():
    source = payload()
    before = source["helm_source_files"]
    after = {"chart/values.yaml": before["chart/values.yaml"].replace("other: before", "other: after")}
    summary = build_summary({"configuration_changes": [change()]}, before, after, {},
                            source["rendered_resources"], source["rendered_resources"])
    row = summary["configuration_decisions"][0]
    assert row["accepted"]
    assert row["actual_value"] is True
    assert not row["source_modified"]
    assert not row["applied"]
    assert not row["verified"]
    assert summary["configuration_changes"] == []
    assert summary["source_files"][0]["modified"]


def test_raw_duplicate_and_distinct_resource_targets_are_not_conflated():
    source = {"artifact_type": "raw", "rendered_resources": [resource("web"), resource("worker")]}
    rows = [change("web"), change("web", finding_id="2"), change("worker", finding_id="3")]
    for row in rows:
        row["source_mapping"] = {}
    files = remediation.candidate_files(source, {"configuration_changes": rows})
    rendered = list(yaml.safe_load_all(files["remediated-manifests.yaml"]))
    assert len(rendered) == 2
    assert all(not item["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] for item in rendered)
