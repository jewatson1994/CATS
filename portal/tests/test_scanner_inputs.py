import pytest
from app.scanner_inputs import bind_scanner_snapshot, snapshot_digest


def test_snapshot_binds_private_bytes_and_enforces_scanner_environment(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "vulnerability.db").write_bytes(b"database")
    digest = snapshot_digest(source)
    env = {"CATS_PATCH_GRYPE_DB_SNAPSHOT": str(source), "CATS_PATCH_GRYPE_DB_DIGEST": digest,
           "GRYPE_DB_AUTO_UPDATE": "true", "GRYPE_DB_CACHE_DIR": "untrusted"}
    work = tmp_path / "work"
    work.mkdir()
    binding = bind_scanner_snapshot(env, work)
    assert binding.digest == digest
    assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert env["GRYPE_DB_CACHE_DIR"] == str(binding.root)
    assert "CATS_PATCH_GRYPE_DB_SNAPSHOT" not in env
    (source / "vulnerability.db").write_bytes(b"later update")
    binding.verify()
    (binding.root / "vulnerability.db").write_bytes(b"drift")
    with pytest.raises(RuntimeError, match="changed"):
        binding.verify()


def test_snapshot_identity_includes_file_names_and_bytes(tmp_path):
    (tmp_path / "a").write_bytes(b"one")
    first = snapshot_digest(tmp_path)
    (tmp_path / "a").rename(tmp_path / "b")
    assert snapshot_digest(tmp_path) != first
    second = snapshot_digest(tmp_path)
    (tmp_path / "b").write_bytes(b"two")
    assert snapshot_digest(tmp_path) != second


def test_snapshot_fails_closed_on_partial_configuration_or_bad_digest(tmp_path):
    assert bind_scanner_snapshot({}, tmp_path) is None
    with pytest.raises(ValueError):
        bind_scanner_snapshot({"CATS_PATCH_GRYPE_DB_DIGEST": "sha256:bad"}, tmp_path)
    with pytest.raises(ValueError):
        snapshot_digest(tmp_path)
    (tmp_path / "db").write_bytes(b"db")
    with pytest.raises(ValueError):
        bind_scanner_snapshot({"CATS_PATCH_GRYPE_DB_SNAPSHOT": str(tmp_path),
                               "CATS_PATCH_GRYPE_DB_DIGEST": "sha256:bad"}, tmp_path)


def test_snapshot_derives_identity_without_operator_digest(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "db").write_bytes(b"trusted database bytes")
    work = tmp_path / "work"
    work.mkdir()
    env = {"CATS_PATCH_GRYPE_DB_SNAPSHOT": str(source)}
    binding = bind_scanner_snapshot(env, work)
    assert binding.digest == snapshot_digest(binding.root) == snapshot_digest(source)
    binding.verify()


def test_snapshot_copy_drift_fails_before_scanning(tmp_path, monkeypatch):
    from app import scanner_inputs
    source = tmp_path / "source"
    source.mkdir()
    (source / "db").write_bytes(b"original")
    work = tmp_path / "work"
    work.mkdir()
    copytree = scanner_inputs.shutil.copytree
    def changed_copy(source, destination):
        result = copytree(source, destination)
        (destination / "db").write_bytes(b"changed during copy")
        return result
    monkeypatch.setattr(scanner_inputs.shutil, "copytree", changed_copy)
    env = {"CATS_PATCH_GRYPE_DB_SNAPSHOT": str(source)}
    with pytest.raises(RuntimeError, match="changed"):
        bind_scanner_snapshot(env, work)
    assert "GRYPE_DB_CACHE_DIR" not in env
