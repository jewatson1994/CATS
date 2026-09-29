import io
import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import helm_downloads as downloads


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
    monkeypatch.setattr(main, "_fetch_public_stream", fetch)
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
