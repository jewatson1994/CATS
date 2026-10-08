"""Offline regressions for declared repositories and safe acquisition diagnostics."""
import io
import ssl
import urllib.error

import pytest
from fastapi import HTTPException

from app import main, scan_acquisition, definition_acquisition
from app.definition_acquisition import acquire_component
from app.helm_downloads import copy_bounded, close_downloads


INDEX = b"entries:\n  cert-manager:\n    - version: v1.20.2\n      urls: [charts/cert-manager-v1.20.2.tgz]\n"


def test_skip_entry_sanitizes_source_and_oci_reference():
    from app.oci_diagnostics import OciPullFailure
    source = "oci://user:password@registry.test/chart?token=secret#private"
    error = OciPullFailure("oci://registry.test/chart")
    error.diagnostic["attempted_reference"] = source
    entry = main._public_chart_skip_entry(source, error)
    assert "registry.test/chart" in entry
    for secret in ("user", "password", "token", "secret", "private"):
        assert secret not in entry


@pytest.mark.parametrize("repository,index", [
    ("https://charts.jetstack.io", "https://charts.jetstack.io/index.yaml"),
    ("https://charts.jetstack.io/", "https://charts.jetstack.io/index.yaml"),
    ("https://example.test/helm", "https://example.test/helm/index.yaml"),
    ("https://example.test/helm/", "https://example.test/helm/index.yaml"),
    ("https://example.test/helm/index.yaml", "https://example.test/helm/index.yaml"),
])
def test_declared_repository_requests_index_first(monkeypatch, repository, index):
    requests = []
    def fetch(url, certificates):
        requests.append(url)
        if url != index:
            raise HTTPException(400, "root returns HTTP 403")
        return INDEX, url
    monkeypatch.setattr(definition_acquisition, "_fetch_public_url", fetch)
    catalog = definition_acquisition._discover_helm_repository(repository, [])
    assert requests == [index]
    assert catalog["charts"][0]["latest"]["url"] == index.rsplit("/", 1)[0] + "/charts/cert-manager-v1.20.2.tgz"


def test_declared_cert_manager_flow_never_requires_root(monkeypatch):
    import tarfile
    package = io.BytesIO()
    with tarfile.open(fileobj=package, mode="w:gz") as bundle:
        metadata = b"name: cert-manager\nversion: v1.20.2\n"
        item = tarfile.TarInfo("cert-manager/Chart.yaml")
        item.size = len(metadata)
        bundle.addfile(item, io.BytesIO(metadata))
    requests = []
    def fetch(url, certificates=None):
        requests.append(url)
        if url == "https://charts.jetstack.io/index.yaml":
            content = INDEX
        elif url == "https://charts.jetstack.io/charts/cert-manager-v1.20.2.tgz":
            content = package.getvalue()
        else:
            raise HTTPException(400, "HTTP 403")
        return copy_bounded(io.BytesIO(content), len(content)), url
    monkeypatch.setattr(scan_acquisition, "_fetch_public_stream", fetch)
    result = acquire_component({"source_type": "helm", "repository": "https://charts.jetstack.io",
                                "chart_name": "cert-manager", "version": "v1.20.2"}, [])
    try:
        assert result[2:4] == ("cert-manager", "v1.20.2")
        assert len(requests) == 2
    finally:
        close_downloads(result[4])


def test_redirected_index_resolves_relative_and_absolute_packages(monkeypatch):
    monkeypatch.setattr(definition_acquisition, "_fetch_public_url", lambda *_: (
        b"entries:\n  demo:\n    - version: '1'\n      urls: [demo.tgz]\n    - version: '2'\n      urls: [https://cdn.example.test/demo.tgz]\n",
        "https://cdn.example.test/repository/index.yaml"))
    versions = definition_acquisition._discover_helm_repository("https://example.test/helm")["charts"][0]["versions"]
    assert [v["url"] for v in versions] == ["https://cdn.example.test/repository/demo.tgz", "https://cdn.example.test/demo.tgz"]


@pytest.mark.parametrize("content", [b"<html>forbidden</html>", b"entries: []", b"entries: [", b"\xff"])
def test_malformed_index_diagnostic(monkeypatch, content):
    monkeypatch.setattr(definition_acquisition, "_fetch_public_url", lambda *_: (content, "https://example.test/index.yaml"))
    with pytest.raises(HTTPException) as error:
        definition_acquisition._discover_helm_repository("https://example.test")
    assert "Malformed Helm index" in error.value.detail
    assert "stage=repository index retrieval" in error.value.detail


@pytest.mark.parametrize("name,version,expected", [("missing", "v1.20.2", "Requested chart missing"),
                                                   ("cert-manager", "missing", "Requested chart version missing")])
def test_chart_selection_distinguishes_missing_chart_and_version(monkeypatch, name, version, expected):
    monkeypatch.setattr(definition_acquisition, "_fetch_public_url", lambda *_: (INDEX, "https://example.test/index.yaml"))
    with pytest.raises(ValueError, match=expected):
        acquire_component({"source_type": "helm", "repository": "https://example.test",
                           "chart_name": name, "version": version}, [])


@pytest.mark.parametrize("reason,expected", [(ssl.SSLCertVerificationError("secret"), "TLS certificate verification"),
                                           (OSError("secret DNS"), "DNS/network failure")])
def test_transport_diagnostics_are_safe(monkeypatch, reason, expected):
    def fail(*args, **kwargs):
        raise urllib.error.URLError(reason)
    monkeypatch.setattr(main.urllib.request, "urlopen", fail)
    with pytest.raises(HTTPException) as error:
        main._fetch_public_stream("https://user:password@example.test/index.yaml?token=secret#private")
    detail = error.value.detail
    assert expected in detail and "stage=repository index retrieval" in detail
    assert "https://example.test/index.yaml" in detail
    assert all(secret not in detail for secret in ("password", "secret", "private", "user:"))


def test_additive_ca_context_preserves_default_verification(monkeypatch):
    class Context:
        def __init__(self):
            self.loaded = []
        def load_verify_locations(self, **kwargs):
            self.loaded.append(kwargs)
    context = Context()
    monkeypatch.setattr(main.ssl, "create_default_context", lambda: context)
    class Response(io.BytesIO):
        headers = {}
        def geturl(self):
            return "https://example.test/index.yaml"
    def open_url(request, **kwargs):
        assert kwargs["context"] is context
        return Response(INDEX)
    monkeypatch.setattr(main.urllib.request, "urlopen", open_url)
    stream, _ = main._fetch_public_stream("https://example.test/index.yaml", [{"pem": "administrator CA"}])
    stream.close()
    assert context.loaded == [{"cadata": "administrator CA"}]


def test_http_redirect_failure_records_safe_requested_and_final_urls(monkeypatch):
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError("https://user:password@cdn.example.test/index.yaml?token=secret", 302,
                                     "private response", {}, io.BytesIO(b"private body"))
    monkeypatch.setattr(main.urllib.request, "urlopen", fail)
    with pytest.raises(HTTPException) as error:
        main._fetch_public_stream("https://example.test/index.yaml?token=secret")
    detail = error.value.detail
    assert "redirect rejected" in detail and "redirected=yes" in detail
    assert "final=https://cdn.example.test/index.yaml" in detail
    assert not any(word in detail for word in ("password", "secret", "private"))


@pytest.mark.parametrize("source,expected", [
    ("https://example.test", "https://example.test/index.yaml"),
    ("https://example.test/helm/", "https://example.test/helm/index.yaml"),
    ("https://example.test/helm#cert-manager", "https://example.test/helm/index.yaml"),
])
def test_generic_repository_download_is_index_first(monkeypatch, source, expected):
    requests = []
    def fetch(url, certificates=None):
        requests.append(url)
        content = INDEX if url == expected else b"archive"
        return copy_bounded(io.BytesIO(content), len(content)), url
    monkeypatch.setattr(scan_acquisition, "_fetch_public_stream", fetch)
    archives = main._download_public_chart(source)
    close_downloads(archives)
    assert requests[0] == expected


def test_standard_redirect_policy_is_preserved():
    import urllib.request
    handler = urllib.request.HTTPRedirectHandler()
    request = urllib.request.Request("https://example.test/index.yaml")
    redirected = handler.redirect_request(request, None, 302, "", {}, "https://cdn.example.test/index.yaml")
    assert redirected.full_url == "https://cdn.example.test/index.yaml"
    with pytest.raises(urllib.error.HTTPError):
        handler.http_error_302(request, io.BytesIO(), 302, "", {"location": "file:///private/index.yaml"})


def test_malformed_entry_url_type_is_not_treated_as_character(monkeypatch):
    monkeypatch.setattr(definition_acquisition, "_fetch_public_url", lambda *_: (
        b"entries:\n  demo:\n    - version: '1'\n      urls: https://secret.example.test/chart.tgz\n",
        "https://example.test/index.yaml"))
    with pytest.raises(HTTPException, match="no chart versions"):
        definition_acquisition._discover_helm_repository("https://example.test")


def test_invalid_ca_material_is_not_exposed(monkeypatch):
    class Context:
        def load_verify_locations(self, **kwargs):
            raise ValueError("private certificate contents")
    monkeypatch.setattr(main.ssl, "create_default_context", lambda: Context())
    with pytest.raises(HTTPException) as error:
        main._fetch_public_stream("https://example.test/index.yaml", [{"pem": "private certificate contents"}])
    assert "stage=repository index retrieval" in error.value.detail
    assert "private" not in error.value.detail
