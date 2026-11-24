"""Receive Docker Fluent Forward messages on a private host socket and feed local CATS."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socketserver
import sqlite3
import stat
import struct
import sys
import tempfile
import threading
import time
import uuid

import msgpack
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .diagnostics import redact_audit_value


SOCKET = Path("/run/cats-log-input/ingest.sock")
SPOOL = Path("/var/lib/cats-component-logs/events.sqlite3")
SERVICE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
REQUEST = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD) ([^ "\r\n]+) HTTP/[0-9.]+" (\d{3})\b')
LOG_ROUTE = re.compile(r"/api/(?:v1/component-logs(?:/(?:ack|events))?|runtime/(?:agents/[^/]+/)?(?:logs|component-logs)(?:/events)?)/?$")
PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
PRIVATE_KEY_END = re.compile(r"-----END [^-\r\n]*PRIVATE KEY-----")
DB_INTERNAL = re.compile(r"\bcats-log-(?:collector|forwarder)\b|\b(?:audit_forward_\w+|component_log_\w+)\b", re.I)
DB_SQL = re.compile(r"\b(?:STATEMENT|DETAIL|QUERY|CONTEXT|(?:duration: [\d.]+ ms\s+)?(?:statement|execute [^:\r\n]+)):\s", re.I)
MAX_LINE_BYTES = 8 * 1024 * 1024


def is_successful_collection_access(message):
    request = REQUEST.search(message)
    return bool(request and request[2][0] == "2" and LOG_ROUTE.fullmatch(request[1].partition("?")[0]))


def open_spool(path):
    db = sqlite3.connect(path, timeout=15)
    db.execute("PRAGMA synchronous=FULL")
    return db


def _create_spool_key(path):
    # Incomplete Docker fragments can split a credential. Encrypt them until the
    # complete logical line can be redacted; never write their cleartext to disk.
    if path.exists():
        if len(path.read_bytes()) != 32:
            raise RuntimeError("Invalid component log spool key")
        return
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as keyfile:
            keyfile.write(AESGCM.generate_key(bit_length=256))
            keyfile.flush()
            os.fsync(keyfile.fileno())
        os.replace(temp, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temp).unlink(missing_ok=True)


def initialize_spool(path):
    with closing(open_spool(path)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        # Serialize initialization for this volume before inspecting or publishing
        # the key. No process can replace another reader's durable fragment key.
        db.execute("BEGIN IMMEDIATE")
        _create_spool_key(path.with_suffix(".key"))
        db.execute("CREATE TABLE IF NOT EXISTS queued (id INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, "
                   "source TEXT NOT NULL, name TEXT NOT NULL, payload TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS private_keys (stream TEXT PRIMARY KEY)")
        db.execute("CREATE TABLE IF NOT EXISTS parts (group_id TEXT, ordinal INTEGER, payload BLOB, "
                   "final INTEGER, PRIMARY KEY (group_id,ordinal))")
        db.execute("CREATE TABLE IF NOT EXISTS completed_parts (group_id TEXT PRIMARY KEY, at INTEGER NOT NULL)")
        db.execute("DELETE FROM completed_parts WHERE at < ?", (int(time.time()) - 86400,))
        db.commit()


def _clock(value):
    if isinstance(value, msgpack.ExtType) and value.code == 0 and len(value.data) == 8:
        seconds, nanos = struct.unpack(">II", value.data)
        if nanos >= 1_000_000_000:
            raise ValueError("invalid EventTime")
    elif type(value) is int:
        seconds, nanos = value, 0
    else:
        raise ValueError("invalid Docker timestamp")
    when = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanos // 1000)
    return when.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _clean_message(db, container, stream, service, line):
    if is_successful_collection_access(line):
        return None
    if service in {"db", "intelligence-db"}:
        # The logging pipeline's own SQL and connection chatter would generate more writes.
        if DB_INTERNAL.search(line):
            return None
        # PostgreSQL can print literal bind values or complete SQL in extended logs.
        if line.startswith(("\t", "    ")):
            return "[SQL continuation omitted]"
        sql = DB_SQL.search(line)
        if sql:
            line = line[:sql.start()] + "[SQL text or bind values omitted]"
    key = container + ":" + stream
    if PRIVATE_KEY_BEGIN.search(line) or db.execute("SELECT 1 FROM private_keys WHERE stream=?", (key,)).fetchone():
        if PRIVATE_KEY_END.search(line):
            db.execute("DELETE FROM private_keys WHERE stream=?", (key,))
        else:
            db.execute("INSERT OR IGNORE INTO private_keys(stream) VALUES (?)", (key,))
        return "[REDACTED PRIVATE KEY]"
    # Relative HTTP request targets can contain OIDC codes, presigned URLs or API credentials.
    line = re.sub(r'("(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) [^ "\r\n?]+)\?[^ "\r\n]*', r'\1?[REDACTED]', line)
    line = re.sub(r"(?i)\bSplunk\s+[a-z0-9_-]{12,}", "Splunk [REDACTED]", line)
    return redact_audit_value(line.replace("\0", r"\0"))


def _spool_room(db, incoming, maximum):
    used = db.execute("SELECT (page_count-freelist_count)*page_size FROM pragma_page_count, "
                      "pragma_freelist_count, pragma_page_size").fetchone()[0]
    if used + incoming + 2048 > maximum:
        raise OSError("component log spool is full")


def _join_partial(db, record, container, stream, max_bytes):
    group = record.get("partial_id", "")
    ordinal = record.get("partial_ordinal", "")
    final = record.get("partial_last")
    if (not isinstance(group, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", group)
            or not isinstance(ordinal, str) or not re.fullmatch(r"[1-9][0-9]{0,8}", ordinal)
            or final not in ("true", "false")):
        raise ValueError("invalid Docker fragment metadata")
    group = hashlib.sha256(f"{container}:{stream}:{group}".encode()).hexdigest()
    if db.execute("SELECT 1 FROM completed_parts WHERE group_id=?", (group,)).fetchone():
        return None, group
    oversized = db.execute("SELECT 1 FROM parts WHERE group_id=? AND ordinal=0", (group,)).fetchone()
    if not oversized:
        raw = record["log"].encode()
        size = db.execute("SELECT coalesce(sum(length(payload)),0) FROM parts WHERE group_id=?", (group,)).fetchone()[0]
        if size + len(raw) > MAX_LINE_BYTES:
            db.execute("DELETE FROM parts WHERE group_id=?", (group,))
            db.execute("INSERT INTO parts VALUES (?,0,?,0)", (group, b""))
            oversized = True
        else:
            _spool_room(db, len(raw) + 32, max_bytes)
            key_path = Path(db.execute("PRAGMA database_list").fetchone()[2]).with_suffix(".key")
            cipher = AESGCM(key_path.read_bytes())
            nonce = os.urandom(12)
            aad = f"{group}:{ordinal}".encode()
            db.execute("INSERT OR IGNORE INTO parts VALUES (?,?,?,?)", (
                group, int(ordinal), nonce + cipher.encrypt(nonce, raw, aad), final == "true"))
    if oversized:
        if final != "true":
            return None, group
        line = "[Docker log line exceeded the 8 MiB assembly limit]"
    else:
        count, last = db.execute("SELECT count(*),max(CASE WHEN final=1 THEN ordinal END) "
                                 "FROM parts WHERE group_id=?", (group,)).fetchone()
        if count != last:
            return None, group
        line = b"".join(cipher.decrypt(blob[:12], blob[12:], f"{group}:{part}".encode())
                        for part, blob in db.execute("SELECT ordinal,payload FROM parts "
                                                    "WHERE group_id=? ORDER BY ordinal", (group,))).decode()
    db.execute("DELETE FROM parts WHERE group_id=?", (group,))
    db.execute("DELETE FROM completed_parts WHERE at < ?", (int(time.time()) - 86400,))
    db.execute("INSERT INTO completed_parts VALUES (?,?)", (group, int(time.time())))
    return line, group


def _queue(db, source, name, stamp, identity, data):
    event = {"category": "operational", "timestamp": stamp, "event_id": identity, "data": data}
    db.execute("INSERT INTO queued(event_id,source,name,payload) VALUES (?,?,?,?) "
               "ON CONFLICT(event_id) DO NOTHING", (identity, source, name, json.dumps(event, ensure_ascii=False)))


def capture(db, packet, max_bytes):
    """Commit sanitized events before returning the Docker acknowledgment, including retries."""
    if not isinstance(packet, list) or len(packet) != 4 or packet[0] != "cats.compose":
        raise ValueError("unexpected Docker log envelope")
    _, clock, record, options = packet
    if not isinstance(record, dict) or not isinstance(options, dict):
        raise ValueError("invalid Docker log metadata")
    chunk = options.get("chunk")
    project, service = (record.get("com.docker.compose." + key) for key in ("project", "service"))
    container, stream, line = (record.get(key) for key in ("container_id", "source", "log"))
    if (not all(isinstance(v, str) and SERVICE_NAME.fullmatch(v) for v in (project, service))
            or not isinstance(container, str) or not re.fullmatch(r"[a-f0-9]{64}", container)
            or stream not in ("stdout", "stderr") or not isinstance(line, str)
            or not isinstance(chunk, str) or not re.fullmatch(r"[!-~]{1,128}", chunk)):
        raise ValueError("invalid Docker source or acknowledgment")
    stamp = _clock(clock)
    name = project + "/" + service
    source = "compose:" + hashlib.sha256(name.encode()).hexdigest()
    identity = hashlib.sha256((container + ":" + chunk).encode()).hexdigest()
    with db:
        db.execute("BEGIN IMMEDIATE")
        if record.get("partial_message") == "true":
            line, identity = _join_partial(db, record, container, stream, max_bytes)
        text = _clean_message(db, container, stream, service, line) if line is not None else None
        if text is not None:
            _spool_room(db, len(text.encode()), max_bytes)
            # Each part stays below the HQ JSON limit even after Unicode/control escaping.
            for pos in range(0, max(1, len(text)), 32000):
                data = {"project": project, "service": service, "container_id": container, "stream": stream,
                        "message": text[pos:pos + 32000]}
                if len(text) > 32000:
                    data.update(part=pos // 32000 + 1, parts=(len(text) + 31999) // 32000)
                _queue(db, source, name, stamp, f"compose:{identity}:{pos}", data)
    return chunk


def flush(db, session_factory, record_event):
    batch = db.execute("SELECT id,source,name,payload FROM queued ORDER BY id LIMIT 128").fetchall()
    if not batch:
        return False
    # Receipts in the destination transaction make an interruption between these commits safe.
    with session_factory.begin() as destination:
        for _, source, name, payload in batch:
            record_event(destination, source, name, json.loads(payload))
    with db:
        db.executemany("DELETE FROM queued WHERE id=?", ((row[0],) for row in batch))
    return True


def note(db, message):
    stamp = datetime.now(timezone.utc).isoformat()
    with db:
        _queue(db, "compose:collector", "CATS Compose log collector", stamp, "collector:" + uuid.uuid4().hex,
               {"service": "compose-log-collector", "message": message})


def _drain(path):
    from .component_log_ingest import record_component_event
    from .database import background_engine
    from sqlalchemy.orm import sessionmaker
    sessions = sessionmaker(bind=background_engine)
    failure = None
    with closing(open_spool(path)) as db:
        while True:
            try:
                work = flush(db, sessions, record_component_event)
                if failure:
                    note(db, "Local CATS log ingestion recovered")
                    failure = None
                if not work:
                    time.sleep(0.5)
            except Exception as exc:
                if failure != type(exc).__name__:
                    failure = type(exc).__name__
                    # Never put arbitrary SQL, URL or exception text into the log stream.
                    status = f"Local CATS log ingestion unavailable ({failure})"
                    print(status, file=sys.stderr, flush=True)
                    try:
                        note(db, status)
                    except sqlite3.Error:
                        pass
                time.sleep(3)


class DockerStream(socketserver.BaseRequestHandler):
    def handle(self):
        unpacker = msgpack.Unpacker(raw=False, unicode_errors="replace", max_buffer_size=2 * 1024 * 1024,
                                     max_array_len=8, max_map_len=64)
        try:
            with closing(open_spool(self.server.spool)) as db:
                while block := self.request.recv(65536):
                    unpacker.feed(block)
                    for packet in unpacker:
                        ack = capture(db, packet, self.server.max_bytes)
                        self.request.sendall(msgpack.packb({"ack": ack}, use_bin_type=True))
        except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError, msgpack.UnpackException):
            # A close before acknowledgment tells the Docker driver to retry the delivery.
            return


def main():
    import fcntl
    os.umask(0o077)
    SPOOL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    initialize_spool(SPOOL)
    socket_dir = SOCKET.parent.stat()
    if socket_dir.st_uid != os.geteuid() or socket_dir.st_mode & 0o022:
        raise RuntimeError("The collector socket directory must be owned by its user and protected from other writers")
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        request_queue_size = 128
    with SOCKET.with_suffix(".lock").open("ab") as lock:
        # A second process pointed at this input must never detach the active Unix socket.
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if SOCKET.exists():
            if not stat.S_ISSOCK(SOCKET.lstat().st_mode):
                raise RuntimeError("The collector socket path is occupied")
            SOCKET.unlink()
        with Server(str(SOCKET), DockerStream) as server:
            SOCKET.chmod(0o600)
            server.spool = SPOOL
            server.max_bytes = max(1, int(os.getenv("CATS_COMPONENT_LOG_SPOOL_MIB", "512"))) * 1024 * 1024
            with closing(open_spool(SPOOL)) as db:
                note(db, "CATS Compose log collector started")
            threading.Thread(target=_drain, args=(SPOOL,), daemon=True).start()
            server.serve_forever()


if __name__ == "__main__":
    main()
