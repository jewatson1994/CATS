"""Workspace accounting remains accurate while image archives are released."""
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app import scan_worker
from test_scan_worker_coordination import worker_harness


def test_workspace_bytes_tolerates_removed_archives_and_ignores_links():
    regular = Mock()
    regular.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_size=123)
    removed = Mock()
    removed.lstat.side_effect = FileNotFoundError
    link = Mock()
    link.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK, st_size=9999)
    directory = Mock()
    directory.rglob.return_value = [regular, removed, link]
    assert scan_worker.workspace_bytes(directory) == 123


def test_workspace_bytes_does_not_hide_permission_errors():
    denied = Mock()
    denied.lstat.side_effect = PermissionError
    directory = Mock()
    directory.rglob.return_value = [denied]
    with pytest.raises(PermissionError):
        scan_worker.workspace_bytes(directory)


def test_disk_budget_failure_reports_phase_and_limit_and_stops_scanner(worker_harness, monkeypatch):
    module, worker, job, root, calls, uploaded, processes, _, _ = worker_harness
    budget = 1024 * 1024
    monkeypatch.setenv("CATS_SCAN_DISK_BYTES", str(budget))

    def measured_size(directory):
        # Wait for the real scanner to publish its phase before exceeding budget.
        marker = directory / "evidence" / "output" / "phase-generate_sboms.json"
        return budget + 1 if marker.exists() else 0

    monkeypatch.setattr(module, "workspace_bytes", measured_size)
    with pytest.raises(RuntimeError, match="Worker disk budget exceeded during generate_sboms"):
        worker.execute(job)
    failures = [kwargs["json"] for method, suffix, kwargs in calls if suffix.endswith("/failure")]
    assert len(failures) == 1
    assert failures[0]["category"] == "insufficient_storage"
    assert "1048577 bytes" in failures[0]["reason"]
    assert "CATS_SCAN_DISK_BYTES=1048576" in failures[0]["reason"]
    assert uploaded == []
    assert processes and all(process.poll() is not None for process in processes)
    assert not any(path.is_dir() for path in root.iterdir())
