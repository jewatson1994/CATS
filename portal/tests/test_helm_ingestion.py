from io import BytesIO
import tarfile

import pytest
from fastapi import HTTPException

from app import main
from app.definition_routes import acquire_component
from app.helm_sources import normalize_chart_reference, oci_pull_arguments
from app.helm_archives import extract_chart
from app.helm_downloads import copy_bounded


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


def gzip_with_extra_header(data):
    """Add a legal gzip FEXTRA field without changing the compressed payload."""
    header = bytearray(data[:10])
    header[3] |= 0x04
    return bytes(header) + b"\x04\x00test" + data[10:]


@pytest.mark.parametrize("filename", ["app.tgz", "downloaded-chart", "app.tar.gz"])
def test_valid_gzip_extra_header_survives_download_spool(tmp_path, filename):
    original = package([("app/Chart.yaml", b"name: app\nversion: 1.0.0\n")]).getvalue()
    archive = gzip_with_extra_header(original)
    spool = copy_bounded(BytesIO(archive), len(archive))
    try:
        assert spool.read() == archive
        spool.seek(0)
        extract_chart(spool, filename, tmp_path / "charts")
    finally:
        spool.close()
    assert (next((tmp_path / "charts").glob("package-*/app/Chart.yaml"))).read_bytes() == b"name: app\nversion: 1.0.0\n"


def test_valid_gzip_extra_header_upload(tmp_path):
    archive = gzip_with_extra_header(package([("app/Chart.yaml", b"name: app\nversion: 1.0.0\n")]).getvalue())
    extract_chart(BytesIO(archive), "app.tgz", tmp_path / "charts")
    assert len(list((tmp_path / "charts").rglob("Chart.yaml"))) == 1


def test_url_and_upload_use_same_archive_reader(tmp_path, monkeypatch):
    archive = gzip_with_extra_header(package([
        ("test-chart/Chart.yaml", b"apiVersion: v2\nname: test-chart\nversion: 1.0.0\n"),
        ("test-chart/values.yaml", b"replicas: 1\n"),
        ("test-chart/templates/deployment.yaml", b"kind: Deployment\n"),
    ]).getvalue())
    monkeypatch.setattr(main, "_fetch_public_stream", lambda *_: (
        copy_bounded(BytesIO(archive), len(archive)), "https://charts.example.test/download"))
    [(download, filename)] = main._download_public_chart("https://charts.example.test/download")
    assert filename == "download"
    main._stage_public_chart(tmp_path / "url", download, filename)
    main._stage_public_chart(tmp_path / "upload", BytesIO(archive), "test-chart.tgz")
    for source in ("url", "upload"):
        chart = next((tmp_path / source / "charts").rglob("Chart.yaml"))
        assert chart.parent.name == "test-chart"
        assert (chart.parent / "values.yaml").exists()
        assert (chart.parent / "templates/deployment.yaml").exists()


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
    source_url, source, name, version, archives = acquire_component(component, [])
    assert source_url == reference
    assert (name, version) == ("nginx", "25.1.1")
    assert any("charts/common/Chart.yaml" in path for path in source)
    assert archives[0][0] is archive


def test_definition_latest_helm_resolves_catalog_and_checks_identity(monkeypatch):
    archive = package([("app/Chart.yaml", b"name: app\nversion: 2.1.0\n")])
    chosen = []
    monkeypatch.setattr(main, "_discover_helm_repository", lambda *_: {
        "charts": [{"name": "app", "latest": {"version": "2.1.0", "url": "https://charts.example.test/app-2.1.0.tgz"}}]})
    monkeypatch.setattr(main, "_download_public_chart", lambda url, _: chosen.append(url) or [(archive, "app.tgz")])
    component = {"source_type": "helm", "repository": "https://charts.example.test", "chart_name": "app", "version": "latest"}
    _, _, name, version, archives = acquire_component(component, [])
    assert chosen == ["https://charts.example.test/app-2.1.0.tgz"]
    assert (name, version) == ("app", "2.1.0")
    assert archives[0][0] is archive


def test_definition_latest_oci_uses_chart_identity(monkeypatch):
    archive = package([("app/Chart.yaml", b"name: app\nversion: 3.4.5\n")])
    monkeypatch.setattr(main, "_download_public_chart", lambda *_: [(archive, "app.tgz")])
    component = {"source_type": "oci", "reference": "oci://registry.example.test/charts/app:latest", "chart_name": "app", "version": "latest"}
    assert acquire_component(component, [])[3] == "3.4.5"


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
    with pytest.raises(ValueError, match="invalid, corrupt"):
        extract_chart(b"not an archive", "bad.tgz", tmp_path / "charts")


def test_empty_archive_has_specific_diagnostic(tmp_path):
    with pytest.raises(ValueError, match="archive is empty"):
        extract_chart(b"", "empty.tgz", tmp_path / "charts")


def test_corrupt_gzip_has_specific_diagnostic(tmp_path):
    with pytest.raises(ValueError, match="gzip or tar data is invalid"):
        extract_chart(b"\x1f\x8b\x08\x00garbage", "bad.tgz", tmp_path / "charts")


def test_missing_chart_yaml_has_specific_diagnostic(tmp_path):
    with pytest.raises(ValueError, match="does not contain a Chart.yaml"):
        extract_chart(package([("app/values.yaml", b"{}")]), "app.tgz", tmp_path / "charts")


def test_symlink_is_rejected_without_extraction(tmp_path):
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
        chart = b"name: app\nversion: 1.0.0\n"
        info = tarfile.TarInfo("app/Chart.yaml")
        info.size = len(chart)
        bundle.addfile(info, BytesIO(chart))
        link = tarfile.TarInfo("app/templates/outside")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        bundle.addfile(link)
    with pytest.raises(ValueError, match="unsafe link"):
        extract_chart(archive, "app.tgz", tmp_path / "charts")
    assert not list((tmp_path / "charts").rglob("Chart.yaml"))


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
