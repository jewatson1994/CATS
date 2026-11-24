import io
import json
import socket
import ssl
from unittest.mock import MagicMock
from urllib.error import HTTPError
from urllib.parse import parse_qs

import pytest

from app import audit_forward_transports as tx


EVENT = {"event_id": "audit:123", "timestamp": "2026-11-23T15:05:00Z", "category": "audit",
         "data": {"summary": "Áccess\nreview", "request_id": "a1"}}
AZURE = {"endpoint": "https://cats.eastus.ingest.monitor.azure.com",
         "rule_id": "dcr-" + "a" * 32, "stream": "Custom-CatsAudit",
         "tenant_id": "10000000-0000-4000-a000-000000000001", "client_id": "20000000-0000-4000-a000-000000000002"}


@pytest.mark.parametrize("kind,config", [
    ("syslog", {"host": "collector:6514"}), ("syslog", {"host": "collector", "port": 0}),
    ("syslog", {"host": "invalid\r\nexample"}), ("syslog", {"host": "collector", "transport": []}),
    ("splunk", {"url": "http://collector:8088"}), ("splunk", {"url": "https://user:pass@collector"}),
    ("splunk", {"url": "https://collector:99999"}), ("splunk", {"url": "https://collector?token=topsecret"}),
    ("splunk", {"url": "https://collector/path"}), ("splunk", {"url": "https://collector", "token": "private"}),
    ("splunk", {"url": "https://collector", "ca_pem": "-----BEGIN PRIVATE KEY-----"}),
    ("azure", {**AZURE, "endpoint": "https://collector.example"}),
    ("azure", {**AZURE, "rule_id": "../bad"}), ("azure", {**AZURE, "stream": "Custom-abc/../def"}),
    ("azure", {**AZURE, "tenant_id": "../bad"}), ("azure", {**AZURE, "cloud": "government"}),
])
def test_invalid_public_configuration(kind, config):
    with pytest.raises(ValueError):
        tx.validate_config(kind, config)


@pytest.mark.parametrize("transport,port", [("udp", 514), ("tcp", 514), ("tls", 6514)])
def test_syslog_default_ports(transport, port):
    assert tx.validate_config("syslog", {"host": "::1", "transport": transport})["port"] == port


@pytest.mark.parametrize("transport", ["udp", "tcp", "tls"])
def test_syslog_wire_format(monkeypatch, transport):
    sock, secure, context = MagicMock(), MagicMock(), MagicMock()
    sock.__enter__.return_value = sock
    secure.__enter__.return_value = secure
    context.wrap_socket.return_value = secure
    target = ("192.0.2.4", 8888)
    if transport == "udp":
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", target)])
        monkeypatch.setattr(socket, "socket", lambda *args: sock)
        sock.sendto.side_effect = lambda message, address: len(message)
    else:
        connect = MagicMock(return_value=sock)
        monkeypatch.setattr(socket, "create_connection", connect)
        monkeypatch.setattr(tx, "_tls_context", lambda ca: context)
    tx.send_event("syslog", {"host": "collector.example", "port": 8888, "transport": transport}, "", EVENT)
    if transport == "udp":
        message, address = sock.sendto.call_args.args
        assert address == target
    else:
        connect.assert_called_once_with(("collector.example", 8888), timeout=tx.TIMEOUT)
        if transport == "tls":
            context.wrap_socket.assert_called_once_with(sock, server_hostname="collector.example")
            sock.sendall.assert_not_called()
        sender = secure if transport == "tls" else sock
        count, message = sender.sendall.call_args.args[0].split(b" ", 1)
        assert int(count) == len(message)
    assert message.startswith(b"<134>1 2026-11-23T15:05:00.000000Z ")
    payload = message.split(b" CATS - cats-event - ", 1)[1]
    assert json.loads(payload) == EVENT
    assert b"\n" not in message


def test_udp_oversize_diagnostic_is_explicit_and_never_truncated():
    with pytest.raises(RuntimeError, match="exceeds a UDP datagram"):
        tx.send_event("syslog", {"host": "collector", "transport": "udp"}, "",
                      {**EVENT, "category": "diagnostic", "data": {"body": "x" * 66000}})


@pytest.mark.parametrize("kind,config,size", [
    ("syslog", {"host": "collector", "transport": "udp"}, 80_000), ("azure", AZURE, 1_100_000),
    ("splunk", {"url": "https://collector:8088"}, 4_200_000)])
def test_large_external_audits_reconstruct_after_retry(kind, config, size, monkeypatch):
    import base64
    from hashlib import sha256
    captured = []
    fail = True
    def collect(actual_kind, actual_config, secret, item):
        assert actual_kind == kind
        captured.append(item)
        if fail and item["data"]["index"] == 1:
            raise tx.DeliveryError("Test receiver rejected part")
    monkeypatch.setattr(tx, "_send_one", collect)
    detail = {"source_id": "validator:abc", "source_name": "Validator A", "source_event_id": "local-sequence-9",
              "description": "a" * size, "password": "discard-me"}
    event = {**EVENT, "data": {"action": "component.reported_audit", "detail": detail}}
    with pytest.raises(tx.DeliveryError, match="receiver rejected"):
        tx.send_event(kind, config, "token", event)
    attempted = captured.copy()
    captured.clear()
    fail = False
    tx.send_event(kind, config, "token", event)
    assert captured[:2] == attempted
    assert len(captured) == captured[0]["data"]["count"]
    assert all(len(tx._json(part)) < 60 * 1024 for part in captured)
    original = b"".join(base64.b64decode(part["data"]["content_b64"], validate=True) for part in captured)
    digest = sha256(original).hexdigest()
    assert [part["event_id"] for part in captured] == [f"fragment:{digest}:{i}" for i in range(len(captured))]
    for part in captured:
        assert part["data"]["source_event_id"] == "local-sequence-9"
        assert part["data"]["original_event_id"] == EVENT["event_id"] and part["data"]["source_id"] == "validator:abc"
    assert json.loads(original) == {**event, "data": {**event["data"], "detail": {**detail, "password": "[REDACTED]"}}}


def test_existing_fragment_passes_unchanged_and_is_never_split_again(monkeypatch):
    captured = []
    monkeypatch.setattr(tx, "_send_one", lambda kind, config, secret, item: captured.append(item))
    existing = {**EVENT, "event_id": "fragment:" + "a" * 64 + ":0",
                "data": {"format": "cats.event-fragment.v1", "content_b64": "abc"}}
    tx.send_event("syslog", {"host": "collector"}, "", existing)
    assert captured == [existing]
    with pytest.raises(tx.DeliveryError, match="Existing audit fragment"):
        tx.send_event("syslog", {"host": "collector"}, "", {**existing, "data": {**existing["data"], "content_b64": "x"*70000}})


def test_syslog_preserves_relayed_operational_severity(monkeypatch):
    socket_mock = MagicMock()
    socket_mock.__enter__.return_value = socket_mock
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: socket_mock)
    tx.send_event("syslog", {"host": "collector", "transport": "tcp"}, "",
                  {**EVENT, "category": "operational", "data": {"reported": {"reported": {"severity": "error"}}}})
    assert socket_mock.sendall.call_args.args[0].split(b" ", 1)[1].startswith(b"<131>1 ")


def test_splunk_envelope_and_embedded_failure(monkeypatch):
    calls = []
    def post(*args):
        calls.append(args)
        return {"code": 0} if len(calls) == 1 else {"code": 4, "text": "echoed secret"}
    monkeypatch.setattr(tx, "_post", post)
    config = {"url": "https://collector:8088/", "index": "cats"}
    tx.send_event("splunk", config, "key", EVENT)
    operation, url, body, headers, ca = calls[0]
    assert url == "https://collector:8088/services/collector/event"
    assert json.loads(body) == {"time": 1795446300.0, "event": EVENT, "source": "CATS", "sourcetype": "cats:audit", "index": "cats"}
    assert headers["Authorization"] == "Splunk key"
    with pytest.raises(RuntimeError, match="did not accept") as exc:
        tx.send_event("splunk", config, "key", EVENT)
    assert "echoed secret" not in str(exc.value)


@pytest.mark.parametrize("cloud,authority,suffix", [
    ("public", "login.microsoftonline.com", "com"), ("government", "login.microsoftonline.us", "us"),
    ("china", "login.partner.microsoftonline.cn", "cn")])
def test_azure_authentication_and_ingestion(monkeypatch, cloud, authority, suffix):
    monkeypatch.setattr(tx, "_tokens", {})
    posts = []
    def post(operation, url, body, headers, ca=None, expected=200):
        posts.append((url, body, headers, expected))
        return {"access_token": "bearer", "expires_in": "3600"} if operation == "Azure authentication" else {}
    monkeypatch.setattr(tx, "_post", post)
    base = "https://cats.region.ingest.monitor.azure." + suffix
    config = {**AZURE, "endpoint": base, "cloud": cloud}
    tx.send_event("azure", config, "a&/b", EVENT)
    tx.send_event("azure", config, "a&/b", EVENT)
    assert len(posts) == 3
    auth_url, form, headers, status = posts[0]
    assert auth_url == f"https://{authority}/{AZURE['tenant_id']}/oauth2/v2.0/token"
    assert parse_qs(form.decode()) == {"grant_type": ["client_credentials"], "client_id": [AZURE["client_id"]],
                                       "client_secret": ["a&/b"], "scope": [f"https://monitor.azure.{suffix}/.default"]}
    url, body, headers, status = posts[1]
    assert url == f"{base}/dataCollectionRules/{AZURE['rule_id']}/streams/Custom-CatsAudit?api-version=2023-01-01"
    assert json.loads(body) == [EVENT] and headers["Authorization"] == "Bearer bearer" and status == 204


def test_azure_expired_or_rejected_token_is_reacquired(monkeypatch):
    monkeypatch.setattr(tx, "_tokens", {})
    tokens = []
    def post(operation, *args, **kwargs):
        if operation == "Azure authentication":
            tokens.append(str(len(tokens)))
            return {"access_token": tokens[-1], "expires_in": 1000}
        if len(tokens) == 1:
            raise tx._HTTPFailure("Azure Logs Ingestion", 401)
        return {}
    monkeypatch.setattr(tx, "_post", post)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        tx.send_event("azure", AZURE, "secret", EVENT)
    tx.send_event("azure", AZURE, "secret", EVENT)
    assert len(tokens) == 2


def test_tls_verification_enabled_and_redirect_errors_safe(monkeypatch):
    context = tx._tls_context(None)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    redirect = tx._NoRedirect()
    assert redirect.redirect_request(None, None, 302, "", {}, "https://untrusted") is None
    class Redirect:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "echoed token", {}, io.BytesIO(b"response-secret"))
    monkeypatch.setattr(tx, "build_opener", lambda *handlers: Redirect())
    with pytest.raises(RuntimeError, match="HTTP 302") as error:
        tx.send_event("splunk", {"url": "https://collector"}, "private", EVENT)
    assert str(error.value) == "Splunk HEC returned HTTP 302"
