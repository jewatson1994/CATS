from io import BytesIO
import tarfile

import pytest
from fastapi import HTTPException

from app import main
from app.definition_routes import acquire_component
from app.helm_sources import normalize_chart_reference, oci_pull_arguments
from app.helm_archives import extract_chart


@pytest.mark.parametrize("reference", [
    "registry-1.docker.io/bitnamicharts/postgresql:15.5.38",
    "oci://registry-1.docker.io/bitnamicharts/postgresql:15.5.38",
])
def test_registry_reference(reference):
    assert normalize_chart_reference(reference) == "oci://registry-1.docker.io/bitnamicharts/postgresql:15.5.38"
    assert oci_pull_arguments(reference) == ["oci://registry-1.docker.io/bitnamicharts/postgresql", "--version", "15.5.38"]


@pytest.mark.parametrize("reference", ["https://charts.example.test/repo#chart", "http://charts.example.test/index.yaml"])
def test_http(reference):
    assert normalize_chart_reference(reference) == reference


@pytest.mark.parametrize("reference", ["ftp://charts.test/chart", "file:///tmp/chart", "random/string", "registry.test/../chart", "oci://u:p@registry.test/chart", "registry.test/chart?token=x"])
def test_invalid_source(reference):
    with pytest.raises(ValueError):
        normalize_chart_reference(reference)


def package(entries):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, value in entries:
            member = tarfile.TarInfo(name)
            member.size = len(value)
            archive.addfile(member, BytesIO(value))
    output.seek(0)
    return output


def test_spooled_chart(tmp_path):
    extract_chart(package([("app/Chart.yaml", b"name: app\nversion: 1.0.0")]), "app.tgz", tmp_path / "charts")
    assert len(list((tmp_path / "charts").rglob("Chart.yaml"))) == 1


def test_retained_chart_ignores_embedded_dependency_as_separate_root():
    archive = package([
        ("nginx/Chart.yaml", b"name: nginx\nversion: 25.1.1\n"),
        ("nginx/charts/common/Chart.yaml", b"name: common\nversion: 2.0.0\n"),
    ])
    source, count = main._retained_helm_sources([(archive, "nginx.tgz")])
    assert count == 1
    assert main._chart_identity(source) == ("nginx", "25.1.1")
    assert any("charts/common/Chart.yaml" in name for name in source)


def test_definition_acquires_oci_chart_with_embedded_dependency(monkeypatch):
    archive = package([
        ("nginx/Chart.yaml", b"name: nginx\nversion: 25.1.1\n"),
        ("nginx/charts/common/Chart.yaml", b"name: common\nversion: 2.0.0\n"),
    ])
    monkeypatch.setattr(main, "_download_public_chart", lambda *_: [(archive, "nginx.tgz")])
    reference = "oci://registry-1.docker.io/bitnamicharts/nginx:25.1.1"
    component = {"source_type": "oci", "reference": reference, "chart_name": "nginx", "version": "25.1.1"}
    source_url, source, name, version = acquire_component(component, [])
    assert source_url == reference
    assert (name, version) == ("nginx", "25.1.1")
    assert any("charts/common/Chart.yaml" in path for path in source)


def test_chart_identity_rejects_two_independent_roots():
    source = {
        "package-1/nginx/Chart.yaml": "name: nginx\nversion: 25.1.1\n",
        "package-2/redis/Chart.yaml": "name: redis\nversion: 28.1.0\n",
    }
    with pytest.raises(HTTPException, match="exactly one chart root"):
        main._chart_identity(source)


@pytest.mark.parametrize("variable,value,reason", [
    ("CATS_PUBLIC_MAX_CHART_BYTES", "1", "compressed"),
    ("CATS_PUBLIC_MAX_CHART_EXPANDED_BYTES", "1", "expanded"),
    ("CATS_PUBLIC_MAX_CHART_MEMBERS", "1", "member"),
])
def test_limits(tmp_path, monkeypatch, variable, value, reason):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=reason):
        extract_chart(package([("app/Chart.yaml", b"name: app"), ("app/values.yaml", b"{}")]), "app.tgz", tmp_path / "charts")
    assert not list((tmp_path / "charts").rglob("Chart.yaml"))


@pytest.mark.parametrize("path", ["../bad", "/bad", "C:/bad", "app/../../bad", "app\\bad"])
def test_rejection_is_atomic_and_sibling_survives(tmp_path, path):
    charts = tmp_path / "charts"
    extract_chart(package([("good/Chart.yaml", b"name: good")]), "good.tgz", charts)
    with pytest.raises(ValueError, match="unsafe"):
        extract_chart(package([("bad/Chart.yaml", b"name: bad"), (path, b"bad")]), "bad.tgz", charts)
    assert [p.read_text() for p in charts.rglob("Chart.yaml")] == ["name: good"]


def test_malformed(tmp_path):
    with pytest.raises(ValueError, match="could not be read"):
        extract_chart(b"not an archive", "bad.tgz", tmp_path / "charts")


def test_183_mib_archive_spooled_on_disk(tmp_path):
    # No giant in-memory byte string: emulate a large binary chart dependency.
    class Zeros:
        def read(self, size):
            return b"\0" * size
    archive_path = tmp_path / "large.tgz"
    with tarfile.open(archive_path, "w:gz", compresslevel=0) as archive:
        chart = b"apiVersion: v2\nname: large\nversion: 1.0.0\n"
        info = tarfile.TarInfo("large/Chart.yaml")
        info.size = len(chart)
        archive.addfile(info, BytesIO(chart))
        info = tarfile.TarInfo("large/files/payload.bin")
        info.size = 183 * 1024 * 1024
        archive.addfile(info, Zeros())
    assert archive_path.stat().st_size > 183 * 1024 * 1024
    with archive_path.open("rb") as spool:
        extract_chart(spool, "large.tgz", tmp_path / "charts")
    assert next((tmp_path / "charts").rglob("payload.bin")).stat().st_size == 183 * 1024 * 1024


@pytest.mark.parametrize("chunked", [False, True])
def test_request_limit_before_and_during_parsing(monkeypatch, chunked):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setenv("CATS_UPLOAD_REQUEST_MAX_BYTES", "32")
    data = [b"image_list=", b"x" * 64] if chunked else b"image_list=" + b"x" * 64
    response = TestClient(app).post("/scan", content=iter(data) if chunked else data, headers={"content-type": "application/x-www-form-urlencoded"})
    assert response.status_code == 413
