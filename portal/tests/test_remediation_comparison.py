import json

import pytest

from app.remediation import summarize_grype_reports
from app.remediation_comparison import apply_vulnerability_comparison


def report(*rows):
    return {"matches": [{"vulnerability": {"id": cve, "severity": severity},
                         "artifact": {"name": package}} for cve, severity, package in rows]}


def write_pair(root, key, before, after):
    output = root / key / "output"
    output.mkdir(parents=True)
    for side, data in (("before", before), ("after", after)):
        (output / f"grype-full-{side}.json").write_text(json.dumps(data), encoding="utf-8")
    return output


def plan_for(*keys):
    return {"before": {"vulnerabilities": {"Critical": 99}, "kev": 99, "configuration_findings": 3},
            "after": {"vulnerabilities": {"Critical": 99}, "kev": 99, "configuration_findings": 1},
            "images": [{"patch_job_id": key, "vulnerabilities_before": 1, "vulnerabilities_after": 0}
                       for key in keys]}


def risk(cve):
    return cve == "CVE-1", 0.8


def test_observations_count_packages_and_images_without_changing_unique_default():
    reports = [report(("CVE-1", "High", "a"), ("CVE-1", "Critical", "b")),
               report(("CVE-1", "High", "a"))]
    unique = summarize_grype_reports(reports, risk)
    observed = summarize_grype_reports(reports, risk, observations=True)
    assert unique["cve_count"] == unique["kev"] == 1
    assert unique["vulnerabilities"]["Critical"] == 1
    assert unique["vulnerabilities"]["High"] == 0
    assert observed["vulnerability_observations"] == observed["kev"] == 3
    assert observed["vulnerabilities"]["Critical"] == 1
    assert observed["vulnerabilities"]["High"] == 2
    assert observed["cve_count"] == 1


def test_observations_preserve_negligible_severity():
    summary = summarize_grype_reports([report(("CVE-1", "Negligible", "a"))], risk, observations=True)
    assert summary["vulnerabilities"]["Negligible"] == 1
    assert summary["vulnerabilities"]["Unknown"] == 0


def test_comparison_uses_full_pairs_and_deduplicates_shared_patch_job(tmp_path):
    first, second = "a" * 32, "b" * 32
    write_pair(tmp_path, first, report(("CVE-1", "Critical", "a"), ("CVE-1", "High", "b")),
               report(("CVE-1", "High", "b")))
    write_pair(tmp_path, second, report(("CVE-1", "High", "a")), report(("CVE-1", "High", "a")))
    plan = plan_for(first, first, second)
    apply_vulnerability_comparison(plan, tmp_path, risk)
    assert plan["before"]["vulnerability_observations"] == plan["before"]["kev"] == 3
    assert plan["after"]["vulnerability_observations"] == plan["after"]["kev"] == 2
    assert plan["before"]["patchable_vulnerabilities"] == 2
    assert plan["after"]["patchable_vulnerabilities"] == 0
    assert plan["after"]["vulnerabilities"]["High"] == 2
    assert plan["after"]["configuration_findings"] == 1
    assert "only-fixed" in plan["after"]["patchable_comparison_note"]


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize("bad", [None, {}, {"matches": [{}]}, "invalid json"])
def test_missing_or_invalid_pair_never_compares_new_after_with_old_baseline(tmp_path, side, bad):
    key = "a" * 32
    output = write_pair(tmp_path, key, report(), report())
    path = output / f"grype-full-{side}.json"
    if bad is None:
        path.unlink()
    else:
        path.write_text(bad if isinstance(bad, str) else json.dumps(bad))
    plan = plan_for(key)
    apply_vulnerability_comparison(plan, tmp_path, risk)
    assert plan["before"]["vulnerabilities"] == {"Critical": 99}
    assert plan["after"]["vulnerabilities"] is None
    assert plan["after"]["kev"] is None
    assert plan["after"]["vulnerability_observations"] is None
    assert "incomplete" in plan["after"]["comparison_note"]


def test_completed_empty_pairs_are_zero(tmp_path):
    key = "a" * 32
    write_pair(tmp_path, key, report(), report())
    plan = plan_for(key)
    apply_vulnerability_comparison(plan, tmp_path, risk)
    assert plan["before"]["vulnerability_observations"] == plan["after"]["vulnerability_observations"] == 0


@pytest.mark.parametrize("missing_key", [None, "../outside", "b" * 32])
def test_partial_image_scope_never_shows_a_clean_after(tmp_path, missing_key):
    key = "a" * 32
    write_pair(tmp_path, key, report(), report())
    plan = plan_for(key, missing_key)
    apply_vulnerability_comparison(plan, tmp_path, risk)
    assert plan["after"]["vulnerabilities"] is None


def test_missing_patchable_count_is_not_zero(tmp_path):
    plan = plan_for("a" * 32)
    plan["images"][0].pop("vulnerabilities_after")
    apply_vulnerability_comparison(plan, tmp_path, risk)
    assert plan["after"]["patchable_vulnerabilities"] is None


def test_worker_records_both_full_reports_only_for_remediation(monkeypatch, tmp_path):
    from test_patching import run_worker, grype_report
    config = {"job_id": "full-pair", "source_mode": "oci", "source_image": "alpine:3.20",
              "output_mode": "download", "remediation_evidence": True}
    code, output, state, calls = run_worker(monkeypatch, tmp_path, config,
                                          grype_report([("CVE-1", "openssl", ["2.0"])]), grype_report([]))
    assert code == 0
    assert (output / "grype-full-before.json").is_file()
    assert (output / "grype-full-after.json").is_file()
    evidence = json.loads((output / "patch-result.json").read_text())["remediation_evidence"]
    assert evidence["grype_full_before"] == evidence["grype_full"] == "complete"
    full_calls = [command for command, _ in calls if command[0] == "grype" and "--only-fixed" not in command]
    assert len(full_calls) == 2
    assert full_calls[0][1].startswith("dir:") and full_calls[0][1].endswith("source-rootfs")
    assert full_calls[1][1].startswith("dir:") and full_calls[1][1].endswith("patched-rootfs")


def test_worker_invalid_full_before_evidence_is_unavailable(monkeypatch, tmp_path):
    from test_patching import run_worker, grype_report
    config = {"job_id": "invalid-pair", "source_mode": "oci", "source_image": "alpine:3.20",
              "output_mode": "download", "remediation_evidence": True}
    code, output, state, _ = run_worker(monkeypatch, tmp_path, config, {"matches": [{}]}, grype_report([]))
    assert code == 0
    evidence = json.loads((output / "patch-result.json").read_text())["remediation_evidence"]
    assert evidence["grype_full_before"] == "failed"
    assert not (output / "grype-full-before.json").exists()


def test_unchanged_image_uses_same_scan_method_and_has_no_added_findings(monkeypatch, tmp_path):
    from test_patching import run_worker, grype_report
    config = {"job_id": "unchanged-pair", "source_mode": "oci", "source_image": "alpine:3.20",
              "output_mode": "download", "remediation_evidence": True}
    unchanged = grype_report([])
    code, output, _, calls = run_worker(monkeypatch, tmp_path, config, unchanged, unchanged)
    assert code == 0
    result = json.loads((output / "patch-result.json").read_text())
    assert result["patch_status"] == "NO_APPLICABLE_FIXES"
    assert result["vulnerabilities_before"] == result["vulnerabilities_after"] == 0
    assert not any(command[0] == "copa" for command, _ in calls)
    scans = [command for command, _ in calls if command[0] == "grype"]
    assert len(scans) == 4
    assert all(command[1].startswith("dir:") for command in scans)
    assert scans[0][2:] == scans[2][2:] and scans[1][2:] == scans[3][2:]
    for label in ("source", "patched"):
        name = f"cats-{label}-unchanged-pair"
        assert any(command[:4] == ["docker", "create", "--name", name] for command, _ in calls)
        assert any(command[:3] == ["docker", "cp", f"{name}:/."] for command, _ in calls)
        assert any(command == ["docker", "rm", "--force", name] for command, _ in calls)
        assert not any(command[:2] in (["docker", "start"], ["docker", "restart"]) for command, _ in calls)
