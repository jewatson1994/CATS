from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import urllib.request

import pytest

from app import scan_intelligence, security_data


ARCHIVE = b"compressed Grype database fixture"
BUILT = "2026-10-19T00:32:50Z"
SCHEMA = "v6.1.10"
MIRROR = "https://mirror.example.test/grype/v6/"
NEXT_ARCHIVE = b"next compressed Grype database fixture"
NEXT_BUILT = "2026-10-20T00:32:50Z"


def listing(**overrides):
    fields = {
        "status": "active",
        "schemaVersion": SCHEMA,
        "built": BUILT,
        "path": "vulnerability-db_v6.1.10_2026-10-19T00:32:50Z_1792391955.tar.zst",
        "checksum": "sha256:" + hashlib.sha256(ARCHIVE).hexdigest(),
    }
    return json.dumps({**fields, **overrides}).encode()


@pytest.fixture
def native_import(tmp_path, monkeypatch):
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(security_data.shutil, "which", lambda name: "grype")
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: pytest.fail("Offline import attempted a download"))
    imports = []

    def run(command, env):
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        if command[1:3] == ["db", "import"]:
            payload = Path(command[3]).read_bytes()
            imports.append(payload)
            database_dir = Path(env["GRYPE_DB_CACHE_DIR"]) / "6"
            database_dir.mkdir()
            with closing(sqlite3.connect(database_dir / "vulnerability.db")) as connection, connection:
                connection.execute("CREATE TABLE source (archive BLOB)")
                connection.execute("INSERT INTO source VALUES (?)", (payload,))
            return ""
        assert command[1:] == ["db", "status", "-o", "json"]
        built = NEXT_BUILT if imports[-1] == NEXT_ARCHIVE else BUILT
        return json.dumps({"schemaVersion": SCHEMA, "built": built})

    monkeypatch.setattr(security_data, "_run", run)
    return imports


@pytest.fixture
def mirror(monkeypatch, native_import):
    files = {}
    requests = []

    def open_request(request, timeout):
        requests.append(request.full_url)
        return io.BytesIO(files[request.full_url])

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: SimpleNamespace(open=open_request))
    return files, requests


def test_grype_uploaded_pair_pins_verified_listing_and_database(tmp_path, native_import):
    assert security_data.refresh("grype", "", io.BytesIO(ARCHIVE), grype_listing=listing()) == BUILT
    assert native_import == [ARCHIVE]

    environment = {"CATS_SCAN_GRYPE_SOURCE": str(tmp_path / "cache"),
                   "CATS_SCAN_TRIVY_SOURCE": str(tmp_path / "trivy")}
    pinned = scan_intelligence.pin_databases(environment, tmp_path / "attempt")["grype"]
    assert pinned["status"] == "pinned"
    assert pinned["built_at"] == BUILT
    assert pinned["version"] == SCHEMA
    assert json.loads(Path(environment["GRYPE_DB_METADATA"]).read_bytes()) == json.loads(listing())
    database = Path(environment["GRYPE_DB_CACHE_DIR"]) / "6" / "vulnerability.db"
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT archive FROM source").fetchone() == (ARCHIVE,)


@pytest.mark.parametrize("invalid_listing", [
    pytest.param(listing(checksum="sha256:" + "0" * 64), id="different-archive"),
    pytest.param(listing(checksum="sha256:abc"), id="malformed-checksum"),
    pytest.param(b'{"checksum":', id="invalid-json"),
    pytest.param(b"[]", id="invalid-listing-type"),
    pytest.param(b" " * (1024 * 1024) + listing(), id="oversized-listing"),
])
def test_grype_invalid_pair_retains_archive_only_generation(tmp_path, native_import, invalid_listing):
    previous = b"previous archive-only database"
    assert security_data.refresh("grype", "", previous) == BUILT
    cache = tmp_path / "cache"
    pointer_before = (cache / scan_intelligence.POINTER).read_bytes()
    generation = json.loads(pointer_before)["generation"]

    with pytest.raises(ValueError):
        security_data.refresh("grype", "", ARCHIVE, grype_listing=invalid_listing)

    assert native_import == [previous]
    assert (cache / scan_intelligence.POINTER).read_bytes() == pointer_before
    assert [path.name for path in (cache / scan_intelligence.GENERATIONS).iterdir()] == [generation]


@pytest.mark.parametrize("changes", [
    {"built": "2026-10-18T00:32:50Z"},
    {"schemaVersion": "v6.1.9"},
])
def test_grype_listing_must_match_imported_database_metadata(tmp_path, native_import, changes):
    with pytest.raises(ValueError):
        security_data.refresh("grype", "", ARCHIVE, grype_listing=listing(**changes))
    assert native_import == [ARCHIVE]
    assert not (tmp_path / "cache" / scan_intelligence.POINTER).exists()


def test_grype_listing_without_uploaded_archive_cannot_trigger_refresh(tmp_path, native_import):
    with pytest.raises(ValueError):
        security_data.refresh("grype", "https://mirror.invalid/grype.tar.zst", grype_listing=listing())
    assert not native_import
    assert not (tmp_path / "cache" / scan_intelligence.POINTER).exists()


def test_grype_streamed_archive_enforces_upload_limit(tmp_path, monkeypatch, native_import):
    monkeypatch.setattr(security_data, "MAX_UPLOAD", len(ARCHIVE) - 1)
    with pytest.raises(ValueError):
        security_data.refresh("grype", "", io.BytesIO(ARCHIVE), grype_listing=listing())
    assert not native_import
    assert not (tmp_path / "cache" / scan_intelligence.POINTER).exists()


def test_grype_refresh_reads_current_mirror_listing_and_pins_matching_archive(tmp_path, mirror, native_import):
    files, requests = mirror
    source = MIRROR + "latest.json"
    builds = [(BUILT, ARCHIVE), (NEXT_BUILT, NEXT_ARCHIVE)]
    expected_requests = []
    for index, (built, archive) in enumerate(builds):
        name = f"vulnerability-db_v6.1.10_{built}.tar.zst"
        raw = listing(path=name, built=built, checksum="sha256:" + hashlib.sha256(archive).hexdigest())
        files.update({source: raw, MIRROR + name: archive})
        assert security_data.refresh("grype", source) == built
        expected_requests.extend([source, MIRROR + name])
        assert requests == expected_requests

        environment = {"CATS_SCAN_GRYPE_SOURCE": str(tmp_path / "cache"),
                       "CATS_SCAN_TRIVY_SOURCE": str(tmp_path / "trivy")}
        pinned = scan_intelligence.pin_databases(environment, tmp_path / f"attempt-{index}")["grype"]
        assert pinned["status"] == "pinned"
        assert pinned["built_at"] == built
        assert json.loads(Path(environment["GRYPE_DB_METADATA"]).read_bytes()) == json.loads(raw)
        with closing(sqlite3.connect(Path(environment["GRYPE_DB_CACHE_DIR"]) / "6" / "vulnerability.db")) as db:
            assert db.execute("SELECT archive FROM source").fetchone() == (archive,)
    assert native_import == [ARCHIVE, NEXT_ARCHIVE]


def test_grype_failed_mirror_checksum_retains_direct_archive_generation(tmp_path, mirror, native_import):
    files, requests = mirror
    direct = MIRROR + "previous.tar.zst"
    source = MIRROR + "latest.json"
    raw = listing()
    archive_url = MIRROR + json.loads(raw)["path"]
    files.update({direct: ARCHIVE, source: raw, archive_url: b"corrupt download"})
    assert security_data.refresh("grype", direct) == BUILT
    pointer = tmp_path / "cache" / scan_intelligence.POINTER
    previous = pointer.read_bytes()

    with pytest.raises(ValueError, match="(?i)checksum|sha-?256"):
        security_data.refresh("grype", source)
    assert requests == [direct, source, archive_url]
    assert native_import == [ARCHIVE]
    assert pointer.read_bytes() == previous


@pytest.mark.parametrize("path", [
    "https://other.example.test/database.tar.zst",
    "//other.example.test/database.tar.zst",
    "../database.tar.zst",
    "%2e%2e/database.tar.zst",
    "database.tar.zst?token=secret",
])
def test_grype_mirror_rejects_unsafe_archive_reference_before_fetch(tmp_path, mirror, native_import, path):
    files, requests = mirror
    source = MIRROR + "latest.json"
    files[source] = listing(path=path)

    with pytest.raises(ValueError):
        security_data.refresh("grype", source)
    assert requests == [source]
    assert not native_import
    assert not (tmp_path / "cache" / scan_intelligence.POINTER).exists()
