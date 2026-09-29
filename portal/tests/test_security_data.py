import json

import pytest

from app import security_data


def test_validated_feed_activation_retains_prior_data_on_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    old = tmp_path / "kev.json"
    old.write_text('{"vulnerabilities":[{"cveID":"CVE-2020-0001"}]}', encoding="utf-8")
    with pytest.raises(ValueError):
        security_data.refresh("kev", "", b'{"vulnerabilities":[]}')
    assert "CVE-2020-0001" in old.read_text(encoding="utf-8")
    version = security_data.refresh("kev", "", json.dumps({
        "dateReleased": "2026-09-01", "vulnerabilities": [{"cveID": "CVE-2026-0001"}]}).encode())
    assert version == "2026-09-01"
    assert "CVE-2026-0001" in old.read_text(encoding="utf-8")


def test_epss_validation_and_source_requirements(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    assert security_data.refresh("epss", "", b"cve,epss\nCVE-2026-0001,0.72\n") == "1 records"
    with pytest.raises(ValueError):
        security_data.refresh("epss", "", b"cve,epss\nCVE-2026-0001,2.0\n")
    assert "0.72" in (tmp_path / "epss.csv").read_text()
    with pytest.raises(ValueError):
        security_data.refresh("kev", "http://public.example.invalid/feed")
    with pytest.raises(ValueError, match="query strings"):
        security_data.refresh("kev", "https://mirror.example.invalid/feed?token=secret")


def test_database_directory_activation_preserves_previous_candidate(tmp_path, monkeypatch):
    destination = tmp_path / "active"
    destination.mkdir(); (destination / "version").write_text("old")
    staged = tmp_path / "staged"
    staged.mkdir(); (staged / "version").write_text("new")
    original = type(staged).rename
    def failing_rename(path, target):
        if path == staged:
            raise OSError("simulated activation failure")
        return original(path, target)
    monkeypatch.setattr(type(staged), "rename", failing_rename)
    with pytest.raises(OSError):
        security_data._activate_directory(staged, destination)
    assert (destination / "version").read_text() == "old"
