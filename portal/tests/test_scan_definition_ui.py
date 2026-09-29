from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import definition_routes, main


DEFINITION = b"""services:
  first:
    enabled: true
    sourceType: oci
    ociRepo: {url: 'oci://registry.example.test/charts/first', repoName: first, tag: 1.2.3}
  second:
    enabled: false
    sourceType: oci
    ociRepo: {url: 'oci://registry.example.test/charts/second', repoName: second, tag: 2.3.4}
"""


@pytest.mark.parametrize("extension", ["yaml", "yml"])
def test_public_scan_accepts_definition_and_preserves_mixed_inputs(monkeypatch, extension):
    acquired = []
    started = []

    def acquire(component, certificates):
        acquired.append(component)
        return component["reference"], {}, component["chart_name"], component["version"]

    monkeypatch.setattr(definition_routes, "acquire_component", acquire)
    monkeypatch.setattr(main, "_start_public_scan", lambda *args, **kwargs: started.append((args, kwargs)) or "test-job")
    response = TestClient(main.app).post(
        "/scan", data={"image_list": "docker.io/library/alpine:3.19", "chart_url": "https://charts.example.test/app.tgz"},
        files={"service_definition": (f"catalog.{extension}", DEFINITION, "application/yaml")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert len(acquired) == 2
    assert all(item["status"] == "normalized" for item in acquired)
    assert started[0][0][0] == "docker.io/library/alpine:3.19"
    assert started[0][0][2] == ["https://charts.example.test/app.tgz"]
    assert len(started[0][1]["definition_sources"]) == 2
    assert started[0][1]["definition_summary"]["counts"]["declared"] == 2


def test_public_scan_accepts_sibling_oci_fields(monkeypatch):
    acquired = []
    started = []
    definition = b"""services:
  nginx:
    enabled: true
    sourceType: oci
    ociRepo: {url: 'oci://registry-1.docker.io/bitnamicharts'}
    repoName: nginx
    tag: '25.1.1'
  redis:
    enabled: false
    sourceType: oci
    ociRepo: {url: 'oci://registry-1.docker.io/bitnamicharts'}
    repoName: redis
    tag: '28.1.0'
  postgresql:
    enabled: false
    sourceType: oci
    ociRepo: {url: 'oci://registry-1.docker.io/bitnamicharts'}
    repoName: postgresql
    tag: '18.11.3'
"""

    def acquire(component, _certificates):
        acquired.append(component)
        return component["reference"], {}, component["chart_name"], component["version"]

    monkeypatch.setattr(definition_routes, "acquire_component", acquire)
    monkeypatch.setattr(main, "_start_public_scan", lambda *args, **kwargs: started.append(kwargs) or "test-job")
    response = TestClient(main.app).post(
        "/scan", files={"service_definition": ("test-valid-versions.yml", definition, "application/yaml")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert [item["reference"] for item in acquired] == [
        "oci://registry-1.docker.io/bitnamicharts/nginx:25.1.1",
        "oci://registry-1.docker.io/bitnamicharts/redis:28.1.0",
        "oci://registry-1.docker.io/bitnamicharts/postgresql:18.11.3",
    ]
    assert started[0]["definition_sources"] == [item["reference"] for item in acquired]
    assert started[0]["definition_summary"]["counts"]["normalized"] == 3


def test_public_scan_reports_component_acquisition_failure(monkeypatch):
    def unavailable(_component, _certificates):
        raise HTTPException(400, detail="OCI Helm charts require Helm in the scanner image")

    monkeypatch.setattr(definition_routes, "acquire_component", unavailable)
    monkeypatch.setattr(main, "_start_public_scan", lambda *args, **kwargs: pytest.fail("scan must not start"))
    response = TestClient(main.app).post(
        "/scan", files={"service_definition": ("catalog.yml", DEFINITION, "application/yaml")},
    )
    assert response.status_code == 200
    assert "No service-definition components could be acquired" in response.text
    assert "first :: OCI Helm charts require Helm in the scanner image" in response.text
    assert "second :: OCI Helm charts require Helm in the scanner image" in response.text


@pytest.mark.parametrize("filename,body,message", [
    ("catalog.txt", DEFINITION, "YAML or YML"),
    ("catalog.yaml", b"services: [", "YAML"),
    ("catalog.yaml", b"unrelated: {url: 'https://example.test/chart.tgz'}", "service definition adapter"),
])
def test_public_scan_rejects_invalid_or_unrelated_yaml(monkeypatch, filename, body, message):
    monkeypatch.setattr(main, "_start_public_scan", lambda *args, **kwargs: pytest.fail("scan must not start"))
    response = TestClient(main.app).post("/scan", files={"service_definition": (filename, body, "application/yaml")})
    assert response.status_code == 200
    assert message.lower() in response.text.lower()


def test_public_scan_definition_size_limit(monkeypatch):
    monkeypatch.setenv("CATS_SERVICE_DEFINITION_MAX_BYTES", "16")
    monkeypatch.setattr(main, "_start_public_scan", lambda *args, **kwargs: pytest.fail("scan must not start"))
    response = TestClient(main.app).post(
        "/scan", files={"service_definition": ("catalog.yaml", DEFINITION, "application/yaml")},
    )
    assert response.status_code == 200
    assert "exceeds byte limit" in response.text


def test_public_scan_isolates_unresolved_definition_component(monkeypatch):
    started = []
    definition = b"""services:
  valid:
    sourceType: oci
    ociRepo: {url: 'oci://registry.example.test/charts/valid', repoName: valid, tag: 1.2.3}
  broken:
    sourceType: oci
    ociRepo: {url: 'oci://registry.example.test/charts/broken', repoName: broken, tag: latest}
"""
    monkeypatch.setattr(definition_routes, "acquire_component", lambda component, _: (component["reference"], {}, "valid", "1.2.3"))
    monkeypatch.setattr(main, "_start_public_scan", lambda *args, **kwargs: started.append(kwargs) or "test-job")
    response = TestClient(main.app).post(
        "/scan", files={"service_definition": ("catalog.yaml", definition, "application/yaml")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert len(started[0]["definition_sources"]) == 1
    assert "broken" in started[0]["definition_skipped"][0]


def test_scan_form_keeps_definition_between_helm_and_ingest():
    template = (Path(__file__).parents[1] / "app" / "templates" / "self_service.html").read_text(encoding="utf-8")
    assert template.index('name="chart_archives"') < template.index('name="service_definition"') < template.index('name="ingest_service_id"')
    assert 'accept=".yaml,.yml"' in template
