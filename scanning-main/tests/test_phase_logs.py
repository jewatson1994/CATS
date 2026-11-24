"""The offline scanner uploads phase state only to the component intake endpoint."""
from io import BytesIO
import json
from pathlib import Path
import sys
import uuid

import pytest


@pytest.fixture
def phases(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import phase_logs
    return phase_logs


def test_retried_phase_upload_preserves_id_and_failure_status(tmp_path, phases, monkeypatch):
    run = uuid.uuid4().hex
    phases.record(tmp_path, "evaluate", run, None)
    phases.record(tmp_path, "evaluate", run, 7)
    (tmp_path / "unrelated.json").write_text('{"secret":"must-never-leave-the-runner"}')
    calls = []
    class Collector:
        def open(self, request, timeout):
            assert request.full_url == "https://hq.example/api/v1/component-logs/events"
            assert request.get_header("Authorization") == "Bearer cats-log-" + "a" * 43
            event = json.loads(request.data)
            calls.append(event)
            return BytesIO(json.dumps({"event_id": event["event_id"], "status": "duplicate"}).encode())
    monkeypatch.setattr(phases, "build_opener", lambda *args: Collector())
    for _ in range(2):
        assert phases.upload(tmp_path, "https://hq.example/api/v1/component-logs/events",
                             "cats-log-" + "a" * 43, None) == 2
    assert calls[:2] == calls[2:]
    assert [e["data"]["stage"] for e in calls[:2]] == ["started", "finished"]
    assert calls[1]["data"]["exit_code"] == 7
    assert "must-never-leave-the-runner" not in str(calls)


def test_wrong_endpoint_credentials_and_unrelated_payloads_are_rejected(tmp_path, phases, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["phase_logs", "upload", str(tmp_path)])
    monkeypatch.setenv("CATS_PORTAL_URL", "http://external.example")
    with pytest.raises(SystemExit):
        phases.main()
    with pytest.raises(ValueError, match="credential"):
        phases.upload(tmp_path, "https://hq.example/api/v1/component-logs/events", "cats_project_example", None)
    (tmp_path / "cats-phase-invalid.json").write_text('{"dump":"arbitrary file"}')
    with pytest.raises(ValueError, match="Invalid scanner phase"):
        phases.upload(tmp_path, "https://hq.example/api/v1/component-logs/events", "cats-log-" + "a" * 43, None)
