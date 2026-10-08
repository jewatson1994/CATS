from app import scan_acquisition
import io
import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import helm_downloads as downloads


@pytest.mark.parametrize("code, expected", [(401, "authentication"), (403, "proxy/firewall"),
                                            (404, "not found"), (429, "rate limit"), (502, "intermediary")])
def test_http_failure_is_specific_and_does_not_expose_secrets(monkeypatch, code, expected):
    from app import main
    import urllib.error
    body = io.BytesIO(b"private response")
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError("https://user:password@example.test/index.yaml?token=secret",
                                     code, "private reason", {}, body)
    monkeypatch.setattr(main.urllib.request, "urlopen", fail)
    with pytest.raises(HTTPException) as error:
        main._fetch_public_stream("https://example.test/index.yaml")
    assert f"HTTP {code}" in error.value.detail
    assert expected in error.value.detail
    assert not any(secret in error.value.detail for secret in ("password", "secret", "private"))
    assert body.closed


def test_bounded_copy_uses_small_reads_and_returns_seekable_disk_file():
    class Source(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= 1024 * 1024
            return super().read(size)
    result = downloads.copy_bounded(Source(b"abc"), 3)
    try:
        assert result.read() == b"abc"
        result.seek(0)
        assert result.read(1) == b"a"
    finally:
        result.close()
    assert result.closed


def test_over_limit_closes_temporary_file(monkeypatch):
    created = []
    real = downloads.tempfile.TemporaryFile
    def temporary(**kwargs):
        stream = real(**kwargs)
        created.append(stream)
        return stream
    monkeypatch.setattr(downloads.tempfile, "TemporaryFile", temporary)
    with pytest.raises(HTTPException) as error:
        downloads.copy_bounded(io.BytesIO(b"abcd"), 3)
    assert error.value.status_code == 413
    assert created[0].closed


def test_space_reserve_rejects_transfer(monkeypatch):
    monkeypatch.setenv("CATS_PUBLIC_HELM_TEMP_RESERVE_BYTES", "100")
    monkeypatch.setattr(downloads.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 99})())
    with pytest.raises(HTTPException) as error:
        downloads.copy_bounded(io.BytesIO(b"a"), 3)
    assert error.value.status_code == 507


def test_oci_timeout_removes_destination(monkeypatch):
    from app import main
    observed = []
    monkeypatch.setattr(main.shutil, "which", lambda name: "/usr/local/bin/helm")
    def run(command, **kwargs):
        destination = Path(command[command.index("--destination") + 1])
        observed.append(destination)
        (destination / "partial.tgz").write_bytes(b"partial")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])
    monkeypatch.setattr(main.subprocess, "run", run)
    with pytest.raises(HTTPException) as error:
        main._download_oci_chart("oci://example.test/chart")
    assert error.value.status_code == 408
    assert not observed[0].exists()


def test_http_archive_stream_and_redirect(monkeypatch):
    from app import main
    class Response(io.BytesIO):
        headers = {}
        def geturl(self):
            return "https://example.test/redirected.tgz"
    monkeypatch.setattr(main.urllib.request, "urlopen", lambda *args, **kwargs: Response(b"archive"))
    archives = main._download_public_chart("https://example.test/original")
    try:
        assert archives[0][1] == "redirected.tgz"
        assert isinstance(archives[0][0], downloads.DownloadedChart)
        assert archives[0][0].read() == b"archive"
    finally:
        downloads.close_downloads(archives)


def test_repository_failure_closes_previously_downloaded_archives(monkeypatch):
    from app import main
    package = downloads.copy_bounded(io.BytesIO(b"archive"), 100)
    index = downloads.copy_bounded(io.BytesIO(
        b"entries:\n  first:\n    - urls: [first.tgz]\n  second:\n    - urls: [second.tgz]\n"), 200)
    def fetch(url, certificates=None):
        if url.endswith("index.yaml"):
            return index, url
        if url.endswith("first.tgz"):
            return package, url
        raise HTTPException(400, detail="unreachable")
    monkeypatch.setattr(scan_acquisition, "_fetch_public_stream", fetch)
    with pytest.raises(HTTPException):
        main._download_public_chart("https://example.test/index.yaml")
    assert index.closed and package.closed


def test_retained_staging_failure_closes_all_owned_downloads(monkeypatch):
    from app import main
    first = downloads.copy_bounded(io.BytesIO(b"invalid"), 100)
    second = downloads.copy_bounded(io.BytesIO(b"invalid"), 100)
    with pytest.raises(HTTPException):
        main._retained_helm_sources([(first, "first.tgz"), (second, "second.tgz")])
    assert first.closed and second.closed


def test_helm_subprocess_excludes_worker_control_credentials(monkeypatch):
    from types import SimpleNamespace
    from app import scan_acquisition
    for name in ("CATS_SCAN_WORKER_TOKEN", "CATS_SCAN_PORTAL_URL", "CATS_PORTAL_API_TOKEN",
                 "DATABASE_URL", "CATS_CONFIG_ENCRYPTION_KEY"):
        monkeypatch.setenv(name, "private-value")
    monkeypatch.setenv("PATH", "tool-path")
    monkeypatch.setattr(scan_acquisition.shutil, "which", lambda _: "/fake/helm")
    environments = []
    def run(command, **kwargs):
        environments.append(kwargs["env"])
        destination = Path(command[command.index("--destination") + 1])
        (destination / "chart.tgz").write_bytes(b"chart")
        return SimpleNamespace(returncode=0, stderr="", stdout="")
    monkeypatch.setattr(scan_acquisition.subprocess, "run", run)
    archives = scan_acquisition._download_oci_chart("oci://example.test/chart:1")
    try:
        assert environments[0]["PATH"] == "tool-path"
        assert not any(key.startswith(("CATS_SCAN_", "CATS_PORTAL_")) for key in environments[0])
        assert "DATABASE_URL" not in environments[0]
        assert "CATS_CONFIG_ENCRYPTION_KEY" not in environments[0]
        assert archives[0][0].read() == b"chart"
    finally:
        downloads.close_downloads(archives)
