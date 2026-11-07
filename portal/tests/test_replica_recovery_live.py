"""Opt-in recovery qualification against real PostgreSQL and TCP HTTP servers.

Set CATS_TEST_REPLICA_POSTGRES_URL to a disposable PostgreSQL database. Tests
create/drop only UUID test schemas. CATS_RECOVERY_EVIDENCE_DIR optionally retains
public JSON observations. No production registry or existing container is touched.

These controlled verified-format/sealed fixtures exercise the transaction and
serving boundaries; they do not claim a fresh publisher-signature/Harbor journey.
The proxy uses its real RegistryClient over verified TLS to a read-only fixture
registry, with no patched clocks, authorization, audit or content transport.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from threading import Thread
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
import requests
from sqlalchemy import func, select, text
import uvicorn

from app import models as m, oci_proxy as proxy
from app.oci_models import OCIPrincipal, OCIRepository, OCIUpstream
from app.replica_import import reconcile
from app.replica_integrity import seal_record, verify_record
from app.replica_models import ReplicaEvent, ReplicaRelease, ReplicaServiceState
from test_replica_authorization import grant
from test_replica_concurrency_postgres import postgres_override
from test_replica_import import verified
from test_replica_postgres import postgres_engines, postgres_replica


def report(name, value):
    destination = os.environ.get('CATS_RECOVERY_EVIDENCE_DIR')
    if destination:
        root = Path(destination)
        root.mkdir(parents=True, exist_ok=True)
        value = {'complete': True, 'observed_at': datetime.now(timezone.utc).isoformat(),
                 'scope': 'Controlled verified-format/sealed fixture; real PostgreSQL and TCP HTTP', **value}
        (root / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


@pytest.mark.parametrize('stage', ['after_projection', 'before_commit'])
def test_worker_process_kill_rolls_back_and_replays_once(postgres_replica, tmp_path, stage):
    f = postgres_replica
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    f.service.name = 'Recovered successor'
    f.origin.add(m.ServiceImage(service_id=f.service.id, image_reference='registry/new:1'))
    incoming = verified(f, 2)
    schema = f.db.scalar(text('SELECT current_schema()'))
    source_id = f.source.id
    f.db.commit()
    package = deepcopy(incoming)
    package['evidence'] = base64.b64encode(incoming['evidence']).decode()
    package_path, marker_path = tmp_path / 'package.json', tmp_path / 'paused.json'
    package_path.write_text(json.dumps({'incoming': package, 'source_id': source_id}), encoding='utf-8')
    environment = dict(os.environ, CATS_RECOVERY_SCHEMA=schema,
                       PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    # Credentials stay in the inherited environment, never command arguments.
    worker = subprocess.Popen([sys.executable, str(Path(__file__).with_name('replica_recovery_process.py')),
                               str(package_path), str(marker_path), stage], env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 40
        while not marker_path.exists() and worker.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        if not marker_path.exists():
            raise AssertionError('Activation worker did not reach kill boundary: ' +
                                 worker.communicate(timeout=5)[1].decode(errors='replace')[-2500:])
        # A separate database connection sees the committed predecessor while
        # the child has already flushed successor rows and holds its locks.
        f.db.expire_all()
        state = f.db.get(ReplicaServiceState, first['service_id'])
        assert state.active_release_id == first['release_id'] and state.high_sequence == 1
        assert f.db.get(m.Service, first['service_id']).name == 'Portable Service'
        assert f.db.scalar(select(func.count()).select_from(ReplicaRelease)) == 1
        f.db.commit()
        worker.kill()  # SIGKILL on POSIX, TerminateProcess on Windows: no rollback handler.
        worker.wait(timeout=10)
        assert worker.returncode != 0
        killed_code = worker.returncode
        f.db.expire_all()
        state = f.db.get(ReplicaServiceState, first['service_id'])
        assert state.active_release_id == first['release_id'] and state.high_sequence == 1
        assert f.db.get(m.Service, first['service_id']).name == 'Portable Service'
        assert f.db.scalar(select(func.count()).select_from(m.ServiceImage)) == 0
        assert f.db.scalar(select(func.count()).select_from(ReplicaRelease)) == 1
        assert f.db.scalar(select(func.count()).select_from(ReplicaEvent)) == 1
        assert f.db.scalar(select(func.count()).select_from(m.AuditEvent).where(
            m.AuditEvent.action == 'replica.activated')) == 1
        f.db.commit()
        recovery = subprocess.run([sys.executable, str(Path(__file__).with_name('replica_recovery_process.py')),
                                   str(package_path), str(marker_path), 'recover'], env=environment,
                                  capture_output=True, text=True, timeout=40)
        assert recovery.returncode == 0, recovery.stderr[-2500:]
        recovered = json.loads(recovery.stdout)
        assert recovered['status'] == 'activated'
        f.db.expire_all()
        assert reconcile(f.db, f.source, incoming, now=f.now)['status'] == 'unchanged'
        f.db.commit()
        state = f.db.get(ReplicaServiceState, first['service_id'])
        assert state.active_release_id == recovered['release_id'] and state.high_sequence == 2
        assert f.db.get(m.Service, first['service_id']).name == 'Recovered successor'
        assert f.db.scalar(select(func.count()).select_from(m.ServiceImage)) == 1
        assert f.db.scalar(select(func.count()).select_from(ReplicaRelease)) == 2
        assert f.db.scalar(select(func.count()).select_from(ReplicaEvent)) == 2
        assert f.db.scalar(select(func.count()).select_from(m.AuditEvent).where(
            m.AuditEvent.action == 'replica.activated')) == 2
        assert all(verify_record(row) for row in f.db.scalars(select(ReplicaRelease)))
        report('process-kill-' + stage, {'boundary': stage, 'worker_exit_code': killed_code,
            'predecessor_visible_during_activation': True, 'projection_rolled_back_after_os_kill': True,
            'fresh_worker_recovery': 'activated', 'second_replay': 'unchanged', 'release_count': 2,
            'activation_audit_count': 2, 'high_sequence': 2})
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.communicate(timeout=10)


@contextmanager
def live_proxy(fixture, monkeypatch):
    monkeypatch.setattr(proxy, 'SessionLocal', fixture.sessions)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        address = 'http://127.0.0.1:' + str(listener.getsockname()[1])
        server = uvicorn.Server(uvicorn.Config(proxy.app, log_level='error', lifespan='off', ws='none'))
        thread = Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        session = requests.Session()
        session.trust_env = False
        session.auth = ('robot', 'secret')
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.02)
            assert server.started, 'Live proxy did not start'
            yield session, address
        finally:
            session.close()
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), 'Live proxy did not stop'


@pytest.fixture
def live_registry(postgres_override, tmp_path):
    f = postgres_override
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'cats-recovery-loopback')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / 'fixture.crt', tmp_path / 'fixture.key'
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    requests_seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests_seen.append(self.path)
            content = {'/v2/team/nginx/manifests/' + f.old:
                (f.raw, 'application/vnd.oci.image.manifest.v1+json', f.old),
                '/v2/team/nginx/blobs/' + f.blob_digest:
                (f.blob, 'application/octet-stream', f.blob_digest)}.get(self.path)
            if content is None:
                self.send_error(404)
                return
            raw, media, digest = content
            self.send_response(200)
            self.send_header('Content-Type', media)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Docker-Content-Digest', digest)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    registry = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    registry.socket = context.wrap_socket(registry.socket, server_side=True)
    thread = Thread(target=registry.serve_forever, daemon=True)
    thread.start()
    with f.sessions() as db:
        upstream = db.get(OCIUpstream, db.get(OCIRepository, f.mapping_id).upstream_id)
        upstream.endpoint = 'https://127.0.0.1:' + str(registry.server_port)
        upstream.ca_pem = cert_pem.decode()
        db.commit()

    def stop():
        if thread.is_alive():
            registry.shutdown()
            registry.server_close()
            thread.join(timeout=5)

    try:
        yield f, requests_seen, stop
    finally:
        stop()
        key_path.unlink(missing_ok=True)


def pull(session, address, repository, digest, kind='manifests', method='GET'):
    return session.request(method, address + '/v2/' + repository + '/' + kind + '/' + digest, timeout=10)


def test_live_http_expiry_denies_cached_bytes_offline_after_restart(live_registry, monkeypatch):
    f, upstream_requests, stop_registry = live_registry
    deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
    with f.sessions() as db:
        release = db.get(ReplicaRelease, f.old_id)
        release.expires_at = deadline
        seal_record(release)
        db.get(ReplicaServiceState, f.service_id).active_release_id = f.old_id
        db.commit()
    with live_proxy(f, monkeypatch) as (http, address):
        assert pull(http, address, 'replica/nginx', f.old).content == f.raw
        assert pull(http, address, 'replica/nginx', f.blob_digest, 'blobs').content == f.blob
        allowed_at = datetime.now(timezone.utc)
        assert allowed_at < deadline
        stop_registry()
        while datetime.now(timezone.utc) <= deadline:
            time.sleep(.05)
        denied = pull(http, address, 'replica/nginx', f.old)
        assert denied.status_code == 403 and 'release_expired' in denied.text
    results = []
    with live_proxy(f, monkeypatch) as (http, address):
        for method in ('GET', 'HEAD'):
            for kind, digest, raw in (('manifests', f.old, f.raw), ('blobs', f.blob_digest, f.blob)):
                response = pull(http, address, 'replica/nginx', digest, kind, method)
                assert response.status_code == 403 and raw not in response.content
                results.append({'method': method, 'kind': kind, 'status': response.status_code})
    assert len(upstream_requests) == 2
    report('live-http-expiry', {'expires_at': deadline.isoformat(), 'allowed_at': allowed_at.isoformat(),
        'denied_at': datetime.now(timezone.utc).isoformat(), 'clock_patched': False,
        'registry_stopped_before_expiry': True, 'upstream_requests': len(upstream_requests),
        'proxy_restarted_after_expiry': True, 'post_restart_requests': results})


def test_live_http_shared_artifact_cannot_reuse_other_service_override(live_registry, monkeypatch):
    f, upstream_requests, stop_registry = live_registry
    with f.sessions() as db:
        other = m.Service(service_key='another-service', name='Another service')
        db.add(other)
        db.flush()
        original = db.get(ReplicaRelease, f.old_id)
        release = ReplicaRelease(service_id=other.id, publisher=original.publisher,
            source_release_id='another-release', sequence=1, manifest=deepcopy(original.manifest),
            manifest_digest=original.manifest_digest, artifacts=deepcopy(original.artifacts), evidence_state={},
            key_fingerprint=original.key_fingerprint, verified=True, complete=True,
            approved_at=original.approved_at, expires_at=original.expires_at, source_reference=original.source_reference)
        db.add(release)
        db.flush()
        seal_record(release)
        upstream_id = db.get(OCIRepository, f.mapping_id).upstream_id
        db.add(ReplicaServiceState(service_id=other.id, publisher=original.publisher,
            source_service_id='another-service', upstream_id=upstream_id, source_id=f.source_id,
            high_sequence=1, active_release_id=release.id))
        mapping = OCIRepository(public_repository='another/nginx', upstream_id=upstream_id,
            upstream_repository='team/nginx', service_id=other.id)
        db.add(mapping)
        db.flush()
        machine = db.scalar(select(OCIPrincipal))
        machine.repository_ids = [*machine.repository_ids, mapping.id]
        db.commit()
        other_service_id = other.id
    override_id = grant(f)
    with live_proxy(f, monkeypatch) as (http, address):
        # Prime both mapping-specific manifest/link caches and shared disk blobs.
        for repository in ('replica/nginx', 'another/nginx'):
            assert pull(http, address, repository, f.old).content == f.raw
            assert pull(http, address, repository, f.blob_digest, 'blobs').content == f.blob
        with f.sessions() as db:
            db.get(ReplicaServiceState, other_service_id).active_release_id = None
            db.commit()
        stop_registry()
        results = []
        for method in ('GET', 'HEAD'):
            for kind, digest, raw in (('manifests', f.old, f.raw), ('blobs', f.blob_digest, f.blob)):
                allowed = pull(http, address, 'replica/nginx', digest, kind, method)
                denied = pull(http, address, 'another/nginx', digest, kind, method)
                assert allowed.status_code == 200
                assert denied.status_code == 403 and raw not in denied.content
                if method == 'GET' and kind == 'manifests':
                    assert 'release_superseded' in denied.text
                results.append({'method': method, 'kind': kind,
                                'override_service_status': 200, 'other_service_status': 403})
    with f.sessions() as db:
        uses = list(db.scalars(select(m.AuditEvent).where(m.AuditEvent.action == 'local_override.used')))
        assert len(uses) == 6
        assert all(event.target_id == str(override_id) and event.detail['service_id'] == f.service_id
                   and event.detail['repository'] == 'replica/nginx' for event in uses)
    report('live-http-shared-artifact', {'shared_root': f.old, 'shared_blob': f.blob_digest,
        'override_id': override_id, 'both_mapping_caches_primed': True,
        'registry_stopped_before_isolation_checks': True, 'local_override_usage_audits': len(uses),
        'requests': results, 'upstream_requests': len(upstream_requests)})
