"""Bounded durable, independently retried runtime-agent status events."""
from contextlib import closing
from datetime import datetime, timezone
import json
import os
import re
import sqlite3
import sys
import threading
import uuid


class RuntimeEvents:
    def __init__(self, directory):
        self.path = directory / "operational.sqlite3"
        self.wake = threading.Event()
        self.stop = threading.Event()
        self.thread = None

    def connect(self):
        if self.path.is_symlink():
            raise OSError("Unsafe event journal")
        db = sqlite3.connect(self.path, timeout=0.2)
        db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS overflow (n INTEGER NOT NULL)")
        return db

    def record(self, code, warning, **fields):
        # Runtime status codes originate from AgentError or static call sites; never transmit exception text.
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", code):
            code = "runtime_operation_failed"
        data = {"code": code, "severity": "warning" if warning else "info"}
        for name in ("sequence", "workload_count", "error_count"):
            if type(fields.get(name)) is int:
                data[name] = fields[name]
        try:
            with closing(self.connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT count(*) FROM events").fetchone()[0] >= 2048:
                    db.execute("INSERT INTO overflow SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM overflow)")
                    db.execute("UPDATE overflow SET n=n+1")
                else:
                    self._insert(db, data)
            self.wake.set()
        except (OSError, sqlite3.Error):
            print("cats-runtime: local_log_journal_unavailable", file=sys.stderr)

    @staticmethod
    def _insert(db, data):
        identifier = str(uuid.uuid4())
        event = {"event_id": identifier, "timestamp": datetime.now(timezone.utc).isoformat(),
                 "category": "operational", "data": data}
        db.execute("INSERT INTO events VALUES (?,?)", (identifier, json.dumps(event)))

    def flush(self, client, token):
        with closing(self.connect()) as db:
            events = [json.loads(row[0]) for row in db.execute("SELECT payload FROM events ORDER BY rowid LIMIT 100")]
        if not events:
            return False
        ids = [event["event_id"] for event in events]
        response = client.request("POST", "/api/runtime/logs", {"events": events}, token)
        if not isinstance(response, dict) or response.get("event_ids") != ids:
            raise ValueError("Log acknowledgment did not match the sent events")
        with closing(self.connect()) as db, db:
            db.executemany("DELETE FROM events WHERE id=?", [(i,) for i in ids])
            loss = db.execute("SELECT n FROM overflow").fetchone()
            if loss:
                self._insert(db, {"code": "local_log_capacity_exceeded", "severity": "warning", "dropped": loss[0]})
                db.execute("DELETE FROM overflow")
        return len(events) == 100

    def start(self, client, token):
        if self.thread:
            return
        def run():
            delay = 2
            while not self.stop.is_set():
                self.wake.clear()
                try:
                    more = self.flush(client, token)
                except Exception:
                    # Retry on a separate thread; never log the failure into the same queue.
                    self.stop.wait(delay)
                    delay = min(delay * 2, 60)
                else:
                    delay = 2
                    if not more:
                        self.wake.wait(20)
        self.thread = threading.Thread(target=run, name="runtime-log-delivery", daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        self.wake.set()
