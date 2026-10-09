import concurrent.futures
import io
import json
import os
from pathlib import Path
import tarfile

import pytest

from app import scan_intelligence as intelligence
from app import security_data


def candidate(root, marker, scanner="grype"):
    root.mkdir()
    directory = root / ("6" if scanner == "grype" else "db")
    directory.mkdir()
    (directory / ("vulnerability.db" if scanner == "grype" else "trivy.db")).write_bytes(marker.encode())
    (directory / "metadata.json").write_text(json.dumps({"Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z"}))
    return root


def environment(root):
    return {"CATS_SCAN_GRYPE_SOURCE": str(root / "grype"), "CATS_SCAN_TRIVY_SOURCE": str(root / "trivy")}


def test_active_attempt_pins_old_generation_and_next_attempt_sees_import(tmp_path):
    source = tmp_path / "grype"
    first = intelligence.publish_generation(candidate(tmp_path / "first", "old"), source, "grype",
                                           {"schemaVersion": 6, "built": "2026-10-01T00:00:00Z"})
    old_env = environment(tmp_path)
    old = intelligence.pin_databases(old_env, tmp_path / "attempt-1")
    second = intelligence.publish_generation(candidate(tmp_path / "second", "new"), source, "grype",
                                            {"schemaVersion": 6, "built": "2026-10-02T00:00:00Z"})
    new_env = environment(tmp_path)
    new = intelligence.pin_databases(new_env, tmp_path / "attempt-2")
    assert (Path(old_env["GRYPE_DB_CACHE_DIR"]) / "6" / "vulnerability.db").read_bytes() == b"old"
    assert (Path(new_env["GRYPE_DB_CACHE_DIR"]) / "6" / "vulnerability.db").read_bytes() == b"new"
    assert old["grype"]["generation"] == first["generation"]
    assert new["grype"]["identity"] == second["identity"]
    assert new["grype"]["version"] == 6
    assert new["grype"]["built_at"] == "2026-10-02T00:00:00Z"
    assert intelligence.intelligence_status(old, environment(tmp_path))["grype"]["status"] == "superseded"
    assert intelligence.intelligence_status(new, environment(tmp_path))["grype"]["status"] == "current"
    assert new_env["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert new_env["TRIVY_SKIP_DB_UPDATE"] == "true"


def test_failed_publication_preserves_pointer_and_never_exposes_stage(tmp_path, monkeypatch):
    source = tmp_path / "grype"
    intelligence.publish_generation(candidate(tmp_path / "first", "old"), source, "grype", {})
    previous = (source / intelligence.POINTER).read_bytes()
    original = intelligence._atomic_json
    def failure(path, value):
        if path.name == intelligence.POINTER:
            raise OSError("simulated pointer failure")
        original(path, value)
    monkeypatch.setattr(intelligence, "_atomic_json", failure)
    with pytest.raises(OSError):
        intelligence.publish_generation(candidate(tmp_path / "second", "new"), source, "grype", {})
    assert (source / intelligence.POINTER).read_bytes() == previous
    env = environment(tmp_path)
    intelligence.pin_databases(env, tmp_path / "attempt")
    assert (Path(env["GRYPE_DB_CACHE_DIR"]) / "6" / "vulnerability.db").read_bytes() == b"old"
    assert not list((source / intelligence.GENERATIONS).glob(".staging-*"))


def test_generation_tampering_fails_closed(tmp_path):
    source = tmp_path / "grype"
    manifest = intelligence.publish_generation(candidate(tmp_path / "first", "old"), source, "grype", {})
    path = source / intelligence.GENERATIONS / manifest["generation"] / "data" / "6" / "vulnerability.db"
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity mismatch"):
        intelligence.pin_databases(environment(tmp_path), tmp_path / "attempt")


def test_concurrent_attempt_snapshots_cannot_mutate_each_other(tmp_path):
    source = tmp_path / "trivy"
    intelligence.publish_generation(candidate(tmp_path / "first", "original", "trivy"), source, "trivy", {})
    def pin(index):
        env = environment(tmp_path)
        intelligence.pin_databases(env, tmp_path / str(index))
        return Path(env["TRIVY_CACHE_DIR"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        first, second = list(executor.map(pin, range(2)))
    (first / "db" / "trivy.db").write_bytes(b"mutated by scanner")
    assert (second / "db" / "trivy.db").read_bytes() == b"original"
    assert intelligence._select(source, "trivy")[0].joinpath("db/trivy.db").read_bytes() == b"original"


def test_concurrent_imports_publish_complete_generations(tmp_path):
    stages = [candidate(tmp_path / str(index), str(index)) for index in range(4)]
    source = tmp_path / "grype"
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        manifests = list(executor.map(lambda stage: intelligence.publish_generation(stage, source, "grype", {}), stages))
    selected, current = intelligence._select(source, "grype")
    assert current["identity"] in {manifest["identity"] for manifest in manifests}
    assert intelligence._files(selected) == current["files"]
    assert len(list((source / intelligence.GENERATIONS).iterdir())) == 4


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-conflict retry")
def test_atomic_pointer_retries_sharing_conflict_without_removing_active_pointer(tmp_path, monkeypatch):
    pointer = tmp_path / intelligence.POINTER
    intelligence._atomic_json(pointer, {"generation": "old"})
    original = intelligence.os.replace
    calls = []
    def replace(source, destination):
        calls.append(destination)
        if len(calls) == 1:
            assert json.loads(pointer.read_text())["generation"] == "old"
            raise PermissionError("temporary Windows sharing conflict")
        return original(source, destination)
    monkeypatch.setattr(intelligence.os, "replace", replace)
    intelligence._atomic_json(pointer, {"generation": "new"})
    assert len(calls) == 2
    assert json.loads(pointer.read_text())["generation"] == "new"
    assert not list(tmp_path.glob(".cats-pointer-*"))


def test_unversioned_and_missing_intelligence_reported(tmp_path):
    candidate(tmp_path / "grype", "legacy")
    env = environment(tmp_path)
    provenance = intelligence.pin_databases(env, tmp_path / "attempt")
    assert provenance["grype"]["status"] == "legacy"
    assert len(provenance["grype"]["identity"]) == 64
    assert provenance["trivy"]["status"] == "unavailable"


def trivy_archive(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def test_trivy_offline_upload_native_validation_and_publication(tmp_path, monkeypatch):
    source = tmp_path / "trivy"
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(source))
    monkeypatch.setattr(security_data.shutil, "which", lambda name: name)
    commands = []
    monkeypatch.setattr(security_data, "_run", lambda command, env: commands.append((command, env)) or "{}")
    metadata = {"Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z"}
    upload = trivy_archive({"trivy.db": b"native-bbolt", "metadata.json": json.dumps(metadata).encode()})
    assert security_data.refresh("trivy", "", upload) == "2"
    assert len(commands) == 1
    assert "--offline-scan" in commands[0][0]
    assert "--skip-db-update" in commands[0][0]
    assert "--download-db-only" not in commands[0][0]
    selected, manifest = intelligence._select(source, "trivy")
    assert selected.joinpath("db/trivy.db").read_bytes() == b"native-bbolt"
    assert manifest["built_at"] == metadata["UpdatedAt"]


@pytest.mark.parametrize("name", ["../trivy.db", "/trivy.db", "db/../../trivy.db", "extra"])
def test_trivy_archive_rejects_unexpected_paths(tmp_path, name):
    with pytest.raises(ValueError, match="invalid member"):
        security_data._extract_trivy_database(trivy_archive({name: b"data"}), tmp_path)
