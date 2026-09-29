import pytest
import yaml
import json
from types import SimpleNamespace

from app.remediation import versioned_charts, summarize_grype_reports
from app.main import _assert_bundle_sources_safe
from app import main as portal_main


def test_versioned_chart_preserves_source_and_creates_unique_semver_candidate():
    source = {"charts/app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.2.3\n"}
    candidate, mappings = versioned_charts(source, "R-ABC123")
    assert source["charts/app/Chart.yaml"].endswith("version: 1.2.3\n")
    version = yaml.safe_load(candidate["charts/app/Chart.yaml"])["version"]
    assert version.startswith("1.2.3-cats.rabc123.")
    assert mappings == [{"path": "charts/app/Chart.yaml", "name": "app",
                         "original_version": "1.2.3", "remediated_version": version}]


def test_identically_named_charts_get_distinct_package_versions():
    files = {path: "apiVersion: v2\nname: app\nversion: 1.2.3\n"
             for path in ("charts/one/Chart.yaml", "charts/two/Chart.yaml")}
    _, mappings = versioned_charts(files, "R-ABC123")
    assert len({item["remediated_version"] for item in mappings}) == 2


@pytest.mark.parametrize("content", [
    "name: ../escape\nversion: 1.2.3\n",
    "name: app\nversion: latest\n",
])
def test_invalid_chart_metadata_is_rejected(content):
    unchanged, mappings = versioned_charts({"Chart.yaml": content}, "R-ABC123")
    assert unchanged["Chart.yaml"] == content
    assert mappings[0]["package_status"] == "FAILED"


def test_one_invalid_chart_does_not_discard_valid_chart():
    files = {"bad/Chart.yaml": "name: ../bad\nversion: 1.0.0\n",
             "good/Chart.yaml": "name: good\nversion: 1.0.0\n"}
    candidate, mappings = versioned_charts(files, "R-ABC123")
    assert candidate["bad/Chart.yaml"] == files["bad/Chart.yaml"]
    assert yaml.safe_load(candidate["good/Chart.yaml"])["version"].startswith("1.0.0-cats.")
    assert [row.get("package_status") for row in mappings] == ["FAILED", None]


def test_transfer_bundle_refuses_secret_bearing_source():
    _assert_bundle_sources_safe({"values.yaml": "image: registry.internal/app:1\n"})
    with pytest.raises(ValueError):
        _assert_bundle_sources_safe({"values.yaml": "password: super-secret\n"})
    with pytest.raises(ValueError):
        _assert_bundle_sources_safe({"templates/secret.yaml": "kind: Secret\n"})


def test_chart_publication_uses_only_configured_oci_target(monkeypatch, tmp_path):
    archive = tmp_path / "app-1.2.3-cats.rabc123.tgz"
    archive.write_bytes(b"chart")
    chart = {"name": "app", "remediated_version": "1.2.3-cats.rabc123"}
    monkeypatch.setattr(portal_main, "get_global_configuration", lambda _db: {
        "oci_registries": json.dumps([{"endpoint": "https://registry.internal", "namespace": "charts",
                                       "use_for_remediation": True}]),
        "trusted_ca_certificates": "[]",
    })
    monkeypatch.setattr(portal_main.shutil, "which", lambda name: "/usr/bin/helm" if name == "helm" else None)
    calls = []
    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="Digest: sha256:" + "a" * 64 + "\n")
    monkeypatch.setattr(portal_main.subprocess, "run", fake_run)
    portal_main._publish_remediation_charts(None, [(archive, chart)])
    assert calls == [["/usr/bin/helm", "push", str(archive), "oci://registry.internal/charts"]]
    assert chart["publish_status"] == "PUBLISHED"
    assert chart["digest"] == "sha256:" + "a" * 64


def test_full_grype_summary_deduplicates_cves_and_correlates_risk():
    reports = [{"matches": [{"vulnerability": {"id": "CVE-2026-1", "severity": "High"}}]},
               {"matches": [{"vulnerability": {"id": "CVE-2026-1", "severity": "Critical"}},
                            {"vulnerability": {"id": "CVE-2026-2", "severity": "Medium"}}]}]
    summary = summarize_grype_reports(reports, lambda cve: (cve == "CVE-2026-1", 0.8 if cve.endswith("1") else 0.2))
    assert summary["vulnerabilities"]["Critical"] == 1
    assert summary["vulnerabilities"]["High"] == 0
    assert summary["kev"] == 1 and summary["epss_max"] == 0.8
