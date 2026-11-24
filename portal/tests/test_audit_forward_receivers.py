"""End-to-end wire tests. Set CATS_TEST_RECEIVERS=1 to require loopback network access."""
import errno
import http.client
import ipaddress
import json
import os
import socket
import ssl
import threading
from concurrent.futures import Future
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.audit_forward_transports import send_event


EVENT = {"event_id": "audit:345", "timestamp": "2026-11-23T15:05:00Z", "category": "audit",
         "data": {"detail": {"principal": "alice", "label": "résumé"}, "action": "release.approved"}}


@pytest.fixture(scope="module", autouse=True)
def require_loopback():
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            with socket.create_connection(listener.getsockname(), timeout=3):
                peer, _ = listener.accept()
                peer.close()
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM) and getattr(error, "winerror", None) != 10013:
            raise
        if os.environ.get("CATS_TEST_RECEIVERS") == "1":
            pytest.fail(f"Loopback sockets are required for receiver tests: {error}")
        pytest.skip("This environment denies loopback TCP connections")


@pytest.fixture(scope="module")
def receiver_tls(tmp_path_factory):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CATS test root")])

    def certificate(subject, key, is_ca):
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=10))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False, key_cert_sign=is_ca,
                                             crl_sign=is_ca, encipher_only=False, decipher_only=False), critical=True))
        if not is_ca:
            names = [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            cert = cert.add_extension(x509.SubjectAlternativeName(names), critical=False)
            cert = cert.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        return cert.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    folder = tmp_path_factory.mktemp("audit-forward-test-certs")
    chain_path, key_path = folder / "server.pem", folder / "key.pem"
    chain_path.write_bytes(certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]), server_key, False))
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(chain_path), str(key_path))
    return server, certificate(ca_name, ca_key, True).decode("ascii")


@contextmanager
def receiver(read, tls=None):
    received = Future()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        def run():
            try:
                client, _ = listener.accept()
                with client:
                    client.settimeout(5)
                    if tls:
                        with tls.wrap_socket(client, server_side=True) as stream:
                            received.set_result(read(stream))
                    else:
                        received.set_result(read(client))
            except Exception as error:
                received.set_exception(error)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1], received
        finally:
            thread.join(timeout=6)


@pytest.mark.parametrize("transport", ["tcp", "tls"])
def test_live_syslog_receiver(transport, receiver_tls):
    server, ca = receiver_tls
    def read(sock):
        with sock.makefile("rb") as stream:
            length = bytearray()
            while len(length) < 10:
                byte = stream.read(1)
                if byte == b" ":
                    break
                assert byte.isdigit()
                length.extend(byte)
            message = stream.read(int(length))
            assert len(message) == int(length)
            return message
    with receiver(read, server if transport == "tls" else None) as (port, received):
        config = {"host": "127.0.0.1", "port": port, "transport": transport}
        if transport == "tls":
            config["ca_pem"] = ca
        send_event("syslog", config, "", EVENT)
        message = received.result(timeout=5)
    assert message.startswith(b"<134>1 ")
    assert json.loads(message.split(b" CATS - cats-event - ", 1)[1]) == EVENT


def test_live_hec_receiver(monkeypatch, receiver_tls):
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    server, ca = receiver_tls
    def read(sock):
        with sock.makefile("rb") as stream:
            request = stream.readline().split()
            headers = http.client.parse_headers(stream)
            payload = json.loads(stream.read(int(headers["Content-Length"])))
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{"code":0}')
            return request, headers, payload
    with receiver(read, server) as (port, received):
        send_event("splunk", {"url": f"https://127.0.0.1:{port}", "ca_pem": ca}, "test-only-token", EVENT)
        request, headers, payload = received.result(timeout=5)
    assert request[:2] == [b"POST", b"/services/collector/event"]
    assert headers["Authorization"] == "Splunk test-only-token" and headers["Content-Type"] == "application/json"
    assert payload["event"] == EVENT


@pytest.mark.parametrize("kind", ["syslog", "splunk"])
def test_live_receiver_rejects_untrusted_ca(kind, receiver_tls, monkeypatch):
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    server, _ = receiver_tls
    with receiver(lambda sock: sock.recv(1), server) as (port, received):
        config = {"host": "127.0.0.1", "port": port} if kind == "syslog" else {"url": f"https://127.0.0.1:{port}"}
        with pytest.raises(RuntimeError, match="certificate verification failed"):
            send_event(kind, config, "test-only-token", EVENT)
        assert isinstance(received.exception(timeout=5), ssl.SSLError)
