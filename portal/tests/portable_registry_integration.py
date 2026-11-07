"""Opt-in real HTTPS registry/Cosign check, run in three explicit phases.

This harness uses synthetic evidence but no mocked registry or signing operations.
Run `tls WORKSPACE` on the host, `publish WORKSPACE` with both private registries
reachable, stop the publisher registry, then `verify WORKSPACE` on the replica.
Registry containers must mount WORKSPACE/tls and use the generated certificate.
"""
import argparse
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
from types import SimpleNamespace
from zipfile import ZipFile

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def tls(root):
    folder = root / 'tls'
    folder.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATS isolated registry test')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('publisher.test'), x509.DNSName('replica.test')]), False)
        .sign(key, hashes.SHA256()))
    (folder / 'registry.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / 'registry.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    print('Created temporary TLS certificate for the two isolated registries.')


def context(root):
    from app import release_oci, signing, cyber_release_publication, portable_release
    os.environ['CATS_CONFIG_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
    env = dict(os.environ, SSL_CERT_FILE=str(root / 'tls' / 'registry.crt'))
    return release_oci, signing, cyber_release_publication, portable_release, env


def publish(root):
    oci, signing, publication, portable, env = context(root)
    from app import main, release_validity, portable_release_capture
    from app.models import Service
    from app.database import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    key = root / 'signer'
    subprocess.run(['cosign', 'generate-key-pair', '--output-key-prefix', str(key)],
        env=dict(env, COSIGN_PASSWORD='isolated-test-only'), check=True, capture_output=True)
    settings = signing.store_keys(key.with_suffix('.key').read_bytes(), key.with_suffix('.pub').read_bytes(),
                                 'isolated-test-only', True)
    fingerprint = settings['fingerprint']
    db = SimpleNamespace(scalars=lambda query: [SimpleNamespace(key='image_signing', value=json.dumps(settings))])
    source = oci._Client('publisher.test:5000', 'input/application', env)
    children = []
    for architecture in ('amd64', 'arm64'):
        config = source.upload(portable.canonical({'architecture': architecture, 'os': 'linux',
            'rootfs': {'type': 'layers', 'diff_ids': []}}), 'application/vnd.oci.image.config.v1+json')
        layer = source.upload(('test filesystem ' + architecture).encode(), 'application/vnd.oci.image.layer.v1.tar')
        content = portable.canonical({'schemaVersion': 2, 'mediaType': oci.MANIFEST_TYPE, 'config': config, 'layers': [layer]})
        digest = oci._digest(content)
        assert source.request('PUT', source.api + '/manifests/' + digest, body=content, media_type=oci.MANIFEST_TYPE)[0] == 201
        children.append({'mediaType': oci.MANIFEST_TYPE, 'digest': digest, 'size': len(content),
                         'platform': {'os': 'linux', 'architecture': architecture}})
    content = portable.canonical({'schemaVersion': 2, 'mediaType': oci.INDEX_TYPE, 'manifests': children})
    index_digest = oci._digest(content)
    assert source.request('PUT', source.api + '/manifests/' + index_digest, body=content, media_type=oci.INDEX_TYPE)[0] == 201
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        service = Service(service_key='registry-integration', name='Registry integration evidence')
        session.add(service)
        session.flush()
        state = portable_release_capture.capture(session, service, {})
    engine.dispose()
    evidence = root / 'evidence.zip'
    with ZipFile(evidence, 'w') as archive:
        archive.writestr('replica-service.json', portable.canonical(state))
        archive.writestr('original-scanner-output.json', '{"matches":[]}')
    chart = root / 'application.tgz'
    with tarfile.open(chart, 'w:gz') as archive:
        content = b'apiVersion: v2\nname: application\nversion: 1.0.0\n'
        member = tarfile.TarInfo('application/Chart.yaml')
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    destination = {'id': 'test:1', 'name': 'Isolated publisher', 'endpoint': 'https://publisher.test:5000',
                   'namespace': 'approved', 'ca_pem': (root / 'tls' / 'registry.crt').read_text()}
    now = datetime.now(timezone.utc)
    validity = release_validity.new_validity(now)
    metadata = {'format': portable.FORMAT, 'kind': 'release', 'service_uuid': state['service_key'],
        'release_uuid': '1', 'release_sequence': 1, 'supersedes_release_uuid': None,
        'revoked_at': None, **validity}
    snapshot = {'service_id': 1, 'service_key': state['service_key'], 'evidence': {'path': str(evidence),
        'digest': publication.file_digest(evidence)}, 'artifacts': [
        {'kind': 'image', 'reference': 'publisher.test:5000/input/application@' + index_digest, 'digest': index_digest},
        {'kind': 'chart', 'name': 'application', 'path': str(chart), 'digest': publication.file_digest(chart)}],
        'destination': destination, 'signing_fingerprint': fingerprint, 'approval_validity': validity, 'portable_release': metadata}
    approval = SimpleNamespace(id=1, release_key='integration-1', snapshot=snapshot,
        snapshot_digest=oci._digest(publication.canonical(snapshot)), status='approved', decided_by_id=1,
        decided_at=now, decision_rationale='Synthetic real-registry integration fixture', revoked_at=None)
    receipt = publication.publish(db, approval, destination, lambda value: None)
    original = portable.fetch_release(receipt['release']['reference'], env, [fingerprint])
    assert original['verified'] and original['complete'] and len(original['artifacts']) == 2
    assert len(original['artifacts'][0]['manifests']) == 3
    assert publication.publish(db, approval, destination, lambda value: None)['release'] == receipt['release']
    approval.revoked_at = datetime.now(timezone.utc)
    approval.revocation_reason = 'Synthetic withdrawal for replication check'
    revocation = publication.publish_revocation(db, approval, destination, {**metadata, 'kind': 'revocation',
        'release_sequence': 2, 'target_release_uuid': metadata['release_uuid'], 'revoked_by_id': 1,
        'revoked_at': approval.revoked_at.isoformat(), 'reason': approval.revocation_reason}, lambda value: None)
    transport = publication._Transport(root / 'mirror-layout', env)
    for item in [*receipt['artifacts'], receipt['release'], revocation['release']]:
        _, repository, digest = oci._reference(item['reference'])
        origin, replica = oci._Client('publisher.test:5000', repository, env), oci._Client('replica.test:5000', repository, env)
        descriptor = transport.graph(origin, digest, replica)
        transport.tag(replica, descriptor, item['tag'])
        for kind in ('signature', 'attestation'):
            if item.get(kind):
                # Copy immutable attachment descriptors explicitly; no referrers
                # API or mutable Cosign discovery tag is needed on the replica.
                transport.graph(origin, item[kind]['digest'], replica)
    (root / 'expected.json').write_text(json.dumps({'fingerprint': fingerprint,
        'release': receipt['release'], 'revocation': revocation['release'], 'state': state,
        'index': index_digest, 'manifest': receipt['manifest']}))
    print(json.dumps({'phase': 'published-and-copied', 'real_cosign': True, 'https_registries': 2,
        'multiarchitecture_children': 2, 'helm_charts': 1, 'immutable_signature_fallback': True, 'retry_same_digest': True}))
    return receipt


def verify(root):
    oci, _, _, portable, env = context(root)
    expected = json.loads((root / 'expected.json').read_text())
    # The orchestration stops the publisher before this process starts.
    try:
        oci._Client('publisher.test:5000', 'input/application', env).request('GET', 'https://publisher.test:5000/v2/')
    except Exception:
        pass
    else:
        raise AssertionError('Publisher must be unavailable for this phase')
    references = list(portable.discover_release_references('replica.test:5000', 'approved/*', env))
    assert len(references) == 2
    release = portable.fetch_release(references[0], env, [expected['fingerprint']])
    revoke = portable.fetch_release(references[1], env, [expected['fingerprint']])
    assert release['verified'] and release['complete'] and release['state'] == expected['state']
    assert release['manifest'] == expected['manifest']
    assert release['artifacts'][0]['digest'] == expected['index']
    assert revoke['verified'] and revoke['complete'] and revoke['manifest']['portable']['release_sequence'] == 2
    try:
        portable.fetch_release(references[0], env, ['sha256:' + '0' * 64])
    except ValueError:
        pass
    else:
        raise AssertionError('Untrusted publisher must be rejected')
    # Deleting a child manifest simulates partial replication. The intact signed
    # parent, evidence package and image index must never report complete.
    artifact = release['artifacts'][0]
    child = next(value for value in artifact['manifests'] if value != artifact['digest'])
    client = oci._Client('replica.test:5000', artifact['repository'], env)
    assert client.request('DELETE', client.api + '/manifests/' + child)[0] == 202
    try:
        portable.fetch_release(references[0], env, [expected['fingerprint']])
    except (ValueError, oci._RegistryError):
        pass
    else:
        raise AssertionError('Missing multiarchitecture child must be rejected')
    print(json.dumps({'phase': 'replica-verified', 'publisher_unavailable': True, 'real_cosign': True,
        'signed_revocation': True, 'full_evidence_equal': True, 'untrusted_key_rejected': True,
        'missing_child_rejected': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('tls', 'publish', 'verify'))
    parser.add_argument('workspace', type=Path)
    args = parser.parse_args()
    globals()[args.phase](args.workspace.resolve())
