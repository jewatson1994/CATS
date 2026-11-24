"""Native collection uses runtime enrollment or outbound-only validator mTLS and stable event IDs."""
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from app import validator_logging as journal
from app import validator_log_poll as polling

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime-agent"))
from cats_runtime.local_logs import RuntimeEvents


def test_runtime_retry_after_restart_and_lost_ack(tmp_path):
    source = RuntimeEvents(tmp_path)
    source.record("transport_failed", True)
    source.record("report_accepted", False, sequence=7, password="private")
    bodies = []
    def request(method, path, body, token):
        assert method == "POST" and path == "/api/runtime/logs" and token == "agent-credential"
        bodies.append(body)
        if len(bodies) == 1:
            raise TimeoutError()
        return {"event_ids": [item["event_id"] for item in body["events"]]}
    client = SimpleNamespace(request=request)
    with pytest.raises(TimeoutError):
        source.flush(client, "agent-credential")
    resumed = RuntimeEvents(tmp_path)
    assert resumed.flush(client, "agent-credential") is False
    assert resumed.flush(client, "agent-credential") is False
    assert len(bodies) == 2 and bodies[0] == bodies[1]
    assert "private" not in json.dumps(bodies) and "agent-credential" not in json.dumps(bodies)


def test_validator_journal_reader_identity_and_commit_ack(monkeypatch, tmp_path):
    monkeypatch.setenv("CATS_VALIDATOR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", "a" * 64 + "," + "b" * 64)
    first, second = (SimpleNamespace(state=SimpleNamespace(client_identity=x * 64)) for x in ("a", "b"))
    with pytest.raises(HTTPException):
        journal._log_reader(first)
    monkeypatch.setenv("CATS_VALIDATOR_LOG_CLIENT_SHA256", "a" * 64)
    journal._log_reader(first)
    with pytest.raises(HTTPException):
        journal._log_reader(second)
    journal.event("audit", "validation_state", job_id="123", status="VERIFIED", password="private")
    journal.event("operational", "http_request", listener="admin", http_status=403)
    events = journal.batch()
    assert events == journal.batch() and len(events) == 2
    assert "private" not in json.dumps(events)
    journal.acknowledge([events[0]["event_id"]])
    journal.acknowledge([events[0]["event_id"]])
    assert journal.batch() == events[1:]


def test_validator_spool_overflow_reports_loss_and_retains_pending(monkeypatch, tmp_path):
    monkeypatch.setenv("CATS_VALIDATOR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("CATS_VALIDATOR_LOG_CAPACITY", "100")
    for n in range(103):
        journal.event("operational", "stdout", n=n)
    journal.event("audit", "validation_state", status="VERIFIED")
    batch = journal.batch()
    assert [e["data"]["n"] for e in batch] == list(range(100))
    journal.acknowledge([e["event_id"] for e in batch])
    audit, gap = journal.batch()
    assert audit["category"] == "audit" and audit["data"]["status"] == "VERIFIED"
    assert gap["data"]["dropped"] == 3


def test_validator_output_redacted_before_persistent_journal(monkeypatch, tmp_path):
    monkeypatch.setenv("CATS_VALIDATOR_STATE_DIR", str(tmp_path))
    text = ("INFO:     10.0.0.1 - \"GET /api/v1/component-logs HTTP/1.1\" 200 OK\n"
            "-----BEGIN PRIVATE KEY-----\nsecretbytes\n-----END PRIVATE KEY-----\n"
            "request password=badvalue\n")
    console = StringIO()
    journal.capture_output(BytesIO(text.encode()), console, "validator_server", "stderr")
    assert console.getvalue() == text
    event, = journal.batch()
    assert event["data"]["code"] == "container_output"
    assert all(secret not in str(event) for secret in ("badvalue", "secretbytes", "/api/v1/component-logs"))


def test_hq_validator_poll_pins_identity_and_only_acks_after_commit(monkeypatch):
    import hashlib
    from contextlib import nullcontext
    peer = b"authenticated validator certificate"
    config = {"endpoint": "https://validator.example:8443", "expected_validator_id": "abc",
              "server_fingerprint": hashlib.sha256(peer).hexdigest()}
    event = {"event_id": "record-1", "category": "operational", "data": {"code": "startup"}}
    actions = []
    class Connection:
        def __init__(self, host, port, context, timeout):
            assert (host, port) == ("validator.example", 8443)
            self.sock = SimpleNamespace(getpeercert=lambda binary: peer)
        def connect(self):
            pass
        def close(self):
            pass
        def request(self, method, path, body, headers):
            self.method = method
            if method == "POST":
                assert path == "/api/v1/component-logs/ack"
                assert json.loads(body) == {"event_ids": ["record-1"]}
            actions.append(method)
        def getresponse(self):
            result = {"accepted": True} if self.method == "POST" else {"validator_id": "abc", "events": [event]}
            return SimpleNamespace(status=200, read=lambda limit: json.dumps(result).encode())
    monkeypatch.setattr(polling, "_client_context", lambda config, folder: object())
    monkeypatch.setattr(polling.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(polling, "sources", lambda db: {"validator:abc": ("Lab", config)})
    monkeypatch.setattr(polling, "record_component_event", lambda db, source, name, item: actions.append("insert"))
    db = SimpleNamespace(commit=lambda: actions.append("commit"))
    polling.poll("validator:abc", "Lab", config, lambda: nullcontext(db))
    assert actions == ["GET", "insert", "commit", "POST"]
    actions.clear()
    def fail_commit():
        raise RuntimeError("HQ offline")
    db.commit = fail_commit
    with pytest.raises(RuntimeError):
        polling.poll("validator:abc", "Lab", config, lambda: nullcontext(db))
    assert actions == ["GET", "insert"]
    actions.clear()
    with pytest.raises(ValueError, match="fingerprint"):
        polling.poll("validator:abc", "Lab", {**config, "server_fingerprint": "0" * 64}, lambda: nullcontext(db))
    assert actions == []


def test_validator_native_endpoints_dont_generate_poll_feedback(monkeypatch, tmp_path):
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    app = FastAPI()
    journal.register(app)
    @app.middleware("http")
    async def inject_native_peer(request: Request, call_next):
        request.state.client_identity = "a" * 64
        return await call_next(request)
    journal.audit_request(app, "api")
    monkeypatch.setenv("CATS_VALIDATOR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", "a" * 64)
    journal.event("audit", "validation_state", phase="QUEUED")
    with TestClient(app) as client:
        response = client.get("/api/v1/component-logs")
        assert response.is_success
        event, = response.json()["events"]
        assert client.post("/api/v1/component-logs/ack", json={"event_ids": [event["event_id"]]}).is_success
        assert client.get("/api/v1/component-logs").json()["events"] == []
