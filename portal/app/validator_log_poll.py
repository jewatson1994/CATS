"""HQ-initiated collection from registered and manually configured validator appliances."""
import hashlib
import hmac
import http.client
import json
import logging
from pathlib import Path
import tempfile
import threading
import time
from urllib.parse import urlsplit

from sqlalchemy import select

from .component_log_ingest import record_component_event
from .database import SessionLocal
from .models import ManagedValidator, PortalSetting
from .validator_client import _client_context, _endpoint


log = logging.getLogger(__name__)


def sources(db):
    validators = db.scalars(select(ManagedValidator).where(
        ManagedValidator.enabled.is_(True), ManagedValidator.status.in_(("READY", "DEGRADED"))))
    result = {}
    for row in validators:
        if row.configuration and row.certificate.get("status") != "revoked":
            result["validator:" + row.id] = (row.name, dict(row.configuration))
    manual = db.scalar(select(PortalSetting.value).where(
        PortalSetting.key == "validator_configuration", PortalSetting.group_id.is_(None)))
    if manual:
        config = json.loads(manual)
        if (isinstance(config, dict) and config.get("endpoint") and not config.get("managed_validator_id")
                and config["endpoint"] not in [other["endpoint"] for _, other in result.values()]):
            key = hashlib.sha256(config["endpoint"].encode()).hexdigest()
            result["validator:manual:" + key] = ("Manual validator", config)
    return result


def poll(source_id, name, config, session_factory=SessionLocal):
    base = urlsplit(_endpoint(config))
    path = base.path.rstrip("/") + "/api/v1/component-logs"
    with tempfile.TemporaryDirectory() as folder:
        tls = _client_context(config, Path(folder))
        def exchange(method, suffix="", payload=None):
            connection = http.client.HTTPSConnection(base.hostname, base.port, context=tls, timeout=5)
            try:
                connection.connect()
                pin = config.get("server_fingerprint")
                if pin and not hmac.compare_digest(hashlib.sha256(connection.sock.getpeercert(True)).hexdigest(), pin):
                    raise ValueError("Validator certificate fingerprint changed")
                connection.request(method, path + suffix, json.dumps(payload).encode() if payload else None,
                                   {"Content-Type": "application/json"})
                reply = connection.getresponse()
                if reply.status == 404 and method == "GET":
                    return None  # Support rolling deployment to an older appliance.
                if reply.status != 200:
                    raise ValueError(f"Validator log request returned HTTP {reply.status}")
                data = reply.read(1_048_577)
                if len(data) > 1_048_576:
                    raise ValueError("Validator log batch exceeds the response limit")
                return json.loads(data)
            finally:
                connection.close()
        data = exchange("GET")
        if data is None:
            return
        if (not isinstance(data, dict) or not isinstance(data.get("events"), list) or len(data["events"]) > 100
                or config.get("expected_validator_id") and data.get("validator_id") != config["expected_validator_id"]):
            raise ValueError("Invalid validator log response")
        events = data["events"]
        if not events:
            return
        with session_factory() as db:
            if sources(db).get(source_id) != (name, config):
                return  # Configuration was revoked or replaced while the request was in flight.
            for item in events:
                record_component_event(db, source_id, name, item)
            db.commit()
        if exchange("POST", "/ack", {"event_ids": [item["event_id"] for item in events]}) != {"accepted": True}:
            raise ValueError("Invalid validator log acknowledgment")
        return len(events) == 100


def start_validator_log_poll():
    def run():
        while True:
            backlog = False
            try:
                with SessionLocal() as db:
                    configured = sources(db)
                for identity, (name, config) in configured.items():
                    try:
                        if poll(identity, name, config):
                            backlog = True
                    except Exception as error:
                        log.warning("Validator log collection failed source=%s error_type=%s", identity, type(error).__name__)
            except Exception as error:
                log.warning("Validator log registry unavailable error_type=%s", type(error).__name__)
            time.sleep(0.05 if backlog else 20)
    thread = threading.Thread(target=run, name="validator-log-poll", daemon=True)
    thread.start()
    return thread
