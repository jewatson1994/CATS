from contextlib import closing
from datetime import datetime
import json
import os
from pathlib import Path
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

import msgpack
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import compose_log_collector as collector
from app.audit_forward_store import ComponentOperationalEvent
from app.component_log_ingest import ComponentLogReceipt, record_component_event
from app.database import Base


def frame(message, chunk="receipt", service="db", **attrs):
    data = {"container_id": "f" * 64, "source": "stderr", "log": message,
            "com.docker.compose.project": "cats-test", "com.docker.compose.service": service, **attrs}
    return ["cats.compose", msgpack.ExtType(0, struct.pack(">II", 1800000000, 123456789)), data, {"chunk": chunk}]


def queued(db):
    return [json.loads(row[0]) for row in db.execute("SELECT payload FROM queued ORDER BY id")]


def test_docker_protocol_ack_is_after_commit_and_redacted_spool_survives_restart(tmp_path):
    spool = tmp_path / "events.sqlite3"
    collector.initialize_spool(spool)
    limit = 1024 * 1024
    pkt = frame('test password=secret-input-at-source', **{"env": "metadata-secret"})
    with closing(collector.open_spool(spool)) as db:
        with pytest.raises(OSError, match="spool is full"):
            collector.capture(db, pkt, 1)
        assert not queued(db)
        assert collector.capture(db, pkt, limit) == "receipt"
        assert collector.capture(db, pkt, limit) == "receipt"
        assert collector.capture(db, frame("database ready", "another"), limit) == "another"
    with closing(collector.open_spool(spool)) as db:
        items = queued(db)
        assert len(items) == 2
        assert items[0]["category"] == "operational" and items[0]["data"]["service"] == "db"
        assert items[0]["data"]["message"].endswith("[REDACTED]")
        assert "secret" not in json.dumps(items)
        assert items[0]["timestamp"].endswith(".123456Z")
        assert items[0]["event_id"] != items[1]["event_id"]
    for candidate in tmp_path.iterdir():
        assert b"metadata-secret" not in candidate.read_bytes() and b"secret-input-at-source" not in candidate.read_bytes()


def test_receiver_filters_feedback_and_sensitive_data_without_suppressing_failures(tmp_path):
    path = tmp_path / "events.sqlite3"
    collector.initialize_spool(path)
    with closing(collector.open_spool(path)) as db:
        lines = [
            ("portal", 'INFO: host - "POST /api/v1/component-logs/events HTTP/1.1" 201 Created'),
            ("nginx", 'host - - [date] "POST /api/runtime/logs HTTP/1.1" 200 223'),
            ("nginx", 'host - - [date] "POST /api/v1/component-logs/ack HTTP/1.1" 200 15'),
            ("db", "timestamp [42] cats-log-collector cats@cats LOG: connection authorized"),
            ("db", "LOG: UPDATE component_log_receipts SET content_digest='dots'"),
            ("db", "LOG:  execute statement_1: SELECT 'database-secret'"),
            ("portal", 'INFO: host - "POST /api/v1/component-logs/events HTTP/1.1" 403 Forbidden'),
            ("nginx", 'host - - [date] "GET /auth/oidc/callback?code=secret-code HTTP/1.1" 303 15'),
            ("worker", "-----BEGIN PRIVATE KEY-----"),
            ("worker", "secret-key-body"),
            ("worker", "-----END PRIVATE KEY-----"),
            ("worker", "normal worker status"),
        ]
        for i, (component, line) in enumerate(lines):
            collector.capture(db, frame(line, str(i), service=component), 2**20)
        messages = [item["data"]["message"] for item in queued(db)]
        assert len(messages) == 7 and sum(m == "[REDACTED PRIVATE KEY]" for m in messages) == 3
        assert any("403 Forbidden" in m for m in messages) and "normal worker status" in messages
        assert "secret" not in str(messages)


def test_flush_uses_cats_receipts_and_waits_for_local_commit(tmp_path):
    path = tmp_path / "events.sqlite3"
    collector.initialize_spool(path)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine)
    with closing(collector.open_spool(path)) as local:
        packet = frame("nginx ready", service="nginx")
        collector.capture(local, packet, 2**20)
        def unavailable(*args):
            raise OSError("database unavailable")
        with pytest.raises(OSError):
            collector.flush(local, sessions, unavailable)
        assert len(queued(local)) == 1
        assert collector.flush(local, sessions, record_component_event)
        # A redelivered packet following a restart is also deduplicated at HQ.
        collector.capture(local, packet, 2**20)
        assert collector.flush(local, sessions, record_component_event)
        assert not queued(local)
    with sessions() as db:
        row = db.scalars(select(ComponentOperationalEvent)).one()
        assert row.source_name == "cats-test/nginx" and row.data["message"] == "nginx ready"
        assert db.scalars(select(ComponentLogReceipt)).one().event_id == row.event_id
    engine.dispose()


def test_fragments_reassemble_once_across_restart_before_redaction(tmp_path):
    path = tmp_path / "logs.db"
    collector.initialize_spool(path)
    def part(message, number, final):
        return frame(message, str(number), "scan-worker", partial_message="true", partial_id="fragmented",
                     partial_ordinal=str(number), partial_last=final)
    one = part("scan output token=exposed-fragment", 1, "false")
    two = part("-suffix then finished", 2, "true")
    with closing(collector.open_spool(path)) as db:
        collector.capture(db, one, 2**20)
        assert not queued(db)
        assert "exposed" not in str(db.execute("SELECT payload FROM parts").fetchone())
    assert all(b"exposed-fragment" not in file.read_bytes() for file in tmp_path.iterdir())
    collector.initialize_spool(path)
    with closing(collector.open_spool(path)) as db:
        for packet in (one, two, two):
            collector.capture(db, packet, 2**20)
        [event] = queued(db)
        assert event["data"]["message"] == "scan output token=[REDACTED] then finished"
        assert db.execute("SELECT count(*) FROM parts").fetchone()[0] == 0


@pytest.mark.skipif(sys.platform != "linux" or os.getenv("CATS_TEST_RECEIVERS") != "1",
                    reason="Requires a local Linux Docker Engine and the CI PostgreSQL service image")
def test_real_docker_fluent_driver_commits_stdout_and_stderr():
    # Keep the host socket short enough for Unix sockaddr_un on all Linux runners.
    with tempfile.TemporaryDirectory(prefix="cats-log-") as tmp:
        spool, sock = Path(tmp) / "spool.db", Path(tmp) / "input.sock"
        collector.initialize_spool(spool)
        with socketserver.ThreadingUnixStreamServer(str(sock), collector.DockerStream) as server:
            server.spool, server.max_bytes = spool, 2**20
            server.daemon_threads = True
            sock.chmod(0o600)
            listener = threading.Thread(target=server.serve_forever, daemon=True)
            listener.start()
            try:
                subprocess.run(["docker", "run", "--rm", "--pull=never", "--network=none", "--log-driver=fluentd",
                    "--label", "com.docker.compose.service=db-backup", "--label", "com.docker.compose.project=cats-ci",
                    "--log-opt", "tag=cats.compose", "--log-opt", "labels=com.docker.compose.service,com.docker.compose.project",
                    "--log-opt", f"fluentd-address=unix://{sock}", "--log-opt", "fluentd-request-ack=true",
                    "--log-opt", "fluentd-sub-second-precision=true", "--log-opt", "fluentd-async=true",
                    "--entrypoint", "/bin/sh", "postgres:16", "-c",
                    "echo cats-real-stdout; echo cats-real-stderr >&2; sleep 1"],
                    check=True, capture_output=True, timeout=45)
                with closing(collector.open_spool(spool)) as db:
                    deadline = time.monotonic() + 8
                    while len(queued(db)) < 2 and time.monotonic() < deadline:
                        time.sleep(0.1)
                    items = queued(db)
                assert {(item["data"]["stream"], item["data"]["message"]) for item in items} == {
                    ("stdout", "cats-real-stdout"), ("stderr", "cats-real-stderr")}
                assert all(i["data"]["project"] == "cats-ci" and i["data"]["service"] == "db-backup" for i in items)
                assert all(datetime.fromisoformat(i["timestamp"]).tzinfo is not None for i in items)
            finally:
                server.shutdown()
                listener.join(timeout=5)
