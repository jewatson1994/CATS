from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "report-to-portal.sh"


def test_helm_status_filter_uses_jq_boolean_predicate_not_undefined_in_arity():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'IN("render failed";' not in source
    assert 'as $status | ($status == "render failed"' in source


def test_large_helm_evidence_is_file_backed_not_passed_as_jq_arguments():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--argjson helm_warnings" not in source
    assert "--argjson helm_discovery" not in source
    assert "--argjson helm_chart_graph" not in source
    assert '--slurpfile helm_warnings_input "$HELM_RENDER_WARNINGS_FILE"' in source
    assert '--slurpfile helm_discovery_input "$HELM_DISCOVERY_FILE"' in source
    assert '--slurpfile helm_chart_graph_input "$HELM_CHART_GRAPH_FILE"' in source


def _scanner_findings_filter():
    source = SCRIPT.read_text(encoding="utf-8")
    return source.split("--arg raw \"$REPORT_RAW_FINDINGS\" '", 1)[1].split("' \"$RESULT\" > current-findings.json", 1)[0]


def _jq_command():
    import os
    import shutil
    import pytest
    if os.environ.get("JQ_DOCKER_IMAGE"):
        return ["docker", "run", "--rm", "-i", "--entrypoint", "jq", os.environ["JQ_DOCKER_IMAGE"]]
    executable = os.environ.get("JQ_BINARY") or shutil.which("jq")
    if not executable:
        pytest.skip("jq is required to run the scanner transformation")
    return [executable]


def test_scanner_preserves_exact_bounded_identity_evidence():
    import json
    import os
    import shutil
    import subprocess
    import pytest
    command = _jq_command()
    purl = "pkg:rpm/redhat/openssl@3.0.7-1.el9?arch=x86_64&epoch=1"
    distro = {"name": "redhat", "version": "9.4", "idLike": ["fedora"]}
    def render(value):
        result = subprocess.run([*command, "--argjson", "sbom_input", "[null]", "--argjson", "image_provenance", "[null]", "--arg", "image", "example/image:1", "--arg", "digest", "",
            "--arg", "raw", "true", _scanner_findings_filter()], input=json.dumps(value), text=True,
            capture_output=True, check=True)
        return json.loads(result.stdout)[0]["evidence"]
    value = {"distro": distro, "matches": [{"artifact": {"name": "openssl", "version": "3.0.7-1.el9",
        "type": "rpm", "purl": purl}, "vulnerability": {"id": "CVE-2026-12345"}}]}
    evidence = render(value)
    assert evidence["purl"] == purl
    assert evidence["scanner_distro"] == distro
    assert "csaf_product_context" not in evidence
    assert "distro" not in evidence
    value["matches"][0]["artifact"]["purl"] = "pkg:" + "x" * 1500
    value["distro"] = {"name": "x" * 4096}
    evidence = render(value)
    assert evidence["purl"] is None and evidence["scanner_distro"] is None
    value["matches"][0]["artifact"]["purl"] = {"unexpected": "object"}
    value["distro"] = "redhat9"
    evidence = render(value)
    assert evidence["purl"] is None and evidence["scanner_distro"] is None


def test_scanner_preserves_aliases_source_binary_and_image_provenance():
    import json
    import subprocess
    source = {"type": "image", "target": {"imageID": "sha256:image", "architecture": "amd64",
        "os": "linux", "labels": {"vendor": "Red Hat"}, "config": "not retained"}}
    related = [{"id": "CVE-2026-12345", "namespace": "nvd:cpe"}, {"id": "CVE-2026-12345"}]
    value = {"source": source, "matches": [{"artifact": {"name": "libexample", "version": "1.0-1",
        "type": "deb", "purl": "pkg:deb/ubuntu/libexample@1.0-1?arch=amd64&distro=ubuntu-22.04",
        "metadata": {"source": "example", "sourceVersion": "1.0", "architecture": "amd64",
                     "files": ["not identity"]}, "upstreams": [{"name": "example", "version": "1.0"}]},
        "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc"}, "relatedVulnerabilities": related,
        "matchDetails": [{"type": "exact-direct-match"}]}]}
    provenance = {"imageID": "sha256:inspect", "labels": {"com.redhat.component": "test-container"}}
    completed = subprocess.run([*_jq_command(), "--arg", "image", "example:1", "--arg", "digest", "sha256:abc",
        "--arg", "raw", "true", "--argjson", "sbom_input", "[null]", "--argjson", "image_provenance", json.dumps([provenance]),
        _scanner_findings_filter()], input=json.dumps(value), text=True, capture_output=True, check=True)
    finding = json.loads(completed.stdout)[0]
    evidence = finding["evidence"]
    assert finding["cve"] == "GHSA-aaaa-bbbb-cccc"
    assert finding["image_digest"] == "sha256:abc"
    assert evidence["aliases"] == ["CVE-2026-12345"]
    assert evidence["related_vulnerabilities"] == related
    assert evidence["scanner_artifact"]["metadata"]["source"] == "example"
    assert evidence["scanner_artifact"]["metadata"]["sourceVersion"] == "1.0"
    assert "files" not in evidence["scanner_artifact"]["metadata"]
    assert evidence["scanner_artifact"]["upstreams"] == [{"name": "example", "version": "1.0"}]
    assert evidence["scanner_source"]["target"]["labels"] == source["target"]["labels"]
    assert "config" not in evidence["scanner_source"]["target"]
    assert evidence["image_provenance"] == provenance
    assert "csaf_product_context" not in evidence


def test_scanner_links_only_unique_consistent_sbom_artifact_ids():
    import json
    import subprocess
    artifact = {"id": "syft-id", "name": "libssl3", "version": "3.0.2-0ubuntu1", "type": "deb",
                "purl": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1?arch=amd64&distro=ubuntu-22.04"}
    component = {**artifact, "metadata": {"source": "openssl", "sourceVersion": "3.0.2-0ubuntu1",
                                        "architecture": "amd64", "files": ["excluded"]}}
    value = {"matches": [{"artifact": artifact, "vulnerability": {"id": "CVE-2026-12345"}}]}
    distro = {"id": "ubuntu", "versionID": "22.04", "versionCodename": "jammy"}
    def render(components):
        sbom = {"artifacts": components, "distro": distro, "source": {"type": "directory", "name": "/rootfs"}}
        result = subprocess.run([*_jq_command(), "--argjson", "image_provenance", "[null]",
            "--argjson", "sbom_input", json.dumps([sbom]), "--arg", "image", "ubuntu:22.04",
            "--arg", "digest", "sha256:test", "--arg", "raw", "true", _scanner_findings_filter()],
            input=json.dumps(value), text=True, capture_output=True, check=True)
        return json.loads(result.stdout)[0]["evidence"]
    evidence = render([component])
    assert evidence["scanner_artifact"]["metadata"] is None
    assert evidence["sbom_artifact"]["metadata"]["source"] == "openssl"
    assert evidence["sbom_artifact"]["metadata"]["sourceVersion"] == "3.0.2-0ubuntu1"
    assert evidence["sbom_artifact"]["purl"] == artifact["purl"]
    assert "files" not in evidence["sbom_artifact"]["metadata"]
    assert evidence["sbom_distro"] == distro
    assert evidence["sbom_source"]["name"] == "/rootfs"
    assert render([{**component, "id": "other-id"}])["sbom_artifact"] is None
    assert render([component, component])["sbom_artifact"] is None
    assert render([{**component, "version": "other-version"}])["sbom_artifact"] is None
    assert render([{**component, "type": "rpm"}])["sbom_artifact"] is None
    assert render([{**component, "purl": artifact["purl"] + "&epoch=1"}])["sbom_artifact"] is None


def test_oversized_scanner_aliases_retain_overflow_evidence():
    import json
    import subprocess
    aliases = [{"id": "CVE-2026-" + str(10000 + index)} for index in range(1000)]
    value = {"matches": [{"artifact": {"name": "libtest", "version": "1.0", "type": "apk",
        "purl": "pkg:apk/wolfi/libtest@1.0?arch=x86_64&distro=wolfi"},
        "vulnerability": {"id": "CVE-2026-12345"}, "relatedVulnerabilities": aliases}]}
    result = subprocess.run([*_jq_command(), "--argjson", "sbom_input", "[null]",
        "--argjson", "image_provenance", "[null]", "--arg", "image", "example:1", "--arg", "digest", "",
        "--arg", "raw", "true", _scanner_findings_filter()], input=json.dumps(value), text=True,
        capture_output=True, check=True)
    evidence = json.loads(result.stdout)[0]["evidence"]
    assert evidence["aliases"] is None
    assert evidence["alias_count"] == 1000
    assert evidence["aliases_truncated"] is True


def test_oversized_alias_identifier_is_not_silently_discarded():
    import json
    import subprocess
    value = {"matches": [{"artifact": {"name": "libtest", "version": "1.0", "type": "apk"},
        "vulnerability": {"id": "CVE-2026-12345"},
        "relatedVulnerabilities": [{"id": "CVE-2026-" + "9" * 160}]}]}
    result = subprocess.run([*_jq_command(), "--argjson", "sbom_input", "[null]",
        "--argjson", "image_provenance", "[null]", "--arg", "image", "example:1", "--arg", "digest", "",
        "--arg", "raw", "true", _scanner_findings_filter()], input=json.dumps(value), text=True,
        capture_output=True, check=True)
    evidence = json.loads(result.stdout)[0]["evidence"]
    assert evidence["aliases"] == []
    assert evidence["alias_count"] == 1
    assert evidence["aliases_truncated"] is True


def test_real_package_database_fields_and_scanner_revision_are_preserved():
    import json
    import subprocess
    records = json.loads((Path(__file__).parent / "fixtures" / "identity" /
                          "retained-installed-packages.json").read_text(encoding="utf-8"))["records"]
    # One transformation covers multiple real package records; document fields are checked separately.
    sbom = {"artifacts": [record["artifact"] for record in records], "descriptor": {"name": "syft", "version": "1.31.0", "configuration": {"exclude": "private"}},
            "schema": {"version": "16.0.37", "url": "https://example.invalid/schema", "ignored": "private"}}
    value = {"descriptor": {"name": "grype", "version": "0.98.0", "timestamp": "2026-10-20T05:00:51.002735148Z", "configuration": {"ignore": "private"}},
             "matches": [{"artifact": {key: record["artifact"][key] for key in ("id", "name", "version", "type", "purl")},
                          "vulnerability": {"id": "CVE-2026-12345"}} for record in records]}
    result = subprocess.run([*_jq_command(), "--argjson", "image_provenance", "[null]",
        "--argjson", "sbom_input", json.dumps([sbom]), "--arg", "image", "example:1",
        "--arg", "digest", "sha256:test", "--arg", "raw", "true", _scanner_findings_filter()],
        input=json.dumps(value), text=True, capture_output=True, check=True)
    findings = json.loads(result.stdout)
    for record, finding in zip(records, findings):
        evidence = finding["evidence"]
        artifact = evidence["sbom_artifact"]
        assert artifact["metadata"] == record["artifact"]["metadata"]
        assert artifact["foundBy"] == record["artifact"]["foundBy"]
        assert artifact["metadataType"] == record["artifact"]["metadataType"]
        assert artifact["locations"] == record["artifact"]["locations"]
        assert evidence["sbom_descriptor"] == {"name": "syft", "version": "1.31.0"}
        assert evidence["scanner_descriptor"] == {"name": "grype", "version": "0.98.0", "timestamp": "2026-10-20T05:00:51.002735148Z"}
        assert evidence["sbom_schema"] == {"version": "16.0.37", "url": "https://example.invalid/schema"}
        assert "csaf_product_context" not in evidence
