from types import SimpleNamespace

from app.dependency_view import dependency_rows


def test_dependency_rows_deduplicate_components_and_correlate_only_exact_observations():
    execution = SimpleNamespace(id=7, raw_payload={"sbom_components": [
        {"name": "openssl", "version": "3.0", "image": "app:1", "purl": "pkg:apk/openssl@3.0",
         "ecosystem": "apk", "license_expression": "MIT OR Apache-2.0"},
        {"name": "openssl", "version": "3.0", "image": "app:1", "purl": "pkg:apk/openssl@3.0"},
        {"name": "openssl", "version": "3.0", "image": "app:2", "purl": "pkg:apk/openssl@3.0"},
    ]})
    observation = SimpleNamespace(execution_id=7, package="openssl", installed_version="3.0",
                                  image="app:1", fixed_version="3.1", evidence={"scanner": "Grype"})
    finding = SimpleNamespace(cve="CVE-2026-1234", severity="Critical", observations=[observation])
    match = SimpleNamespace(component_name="openssl", component_version="3.0",
                            component_purl="pkg:apk/openssl@3.0", image="app:1")
    rows = dependency_rows(execution, [match], [finding], lambda cve: (True, 0.91))
    assert len(rows) == 2
    first = next(row for row in rows if row["image"] == "app:1")
    other = next(row for row in rows if row["image"] == "app:2")
    assert first["license_expression"] == "MIT OR Apache-2.0"
    assert first["vulnerabilities"] == ["CVE-2026-1234"]
    assert first["severity_counts"]["Critical"] == 1
    assert first["kev"] and first["epss"] == 0.91
    assert first["fixed_versions"] == ["3.1"] and first["watchlisted"]
    assert not other["vulnerabilities"] and not other["watchlisted"]
