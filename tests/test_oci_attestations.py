import base64
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from app import oci_attestations as attest

REFERENCE = 'registry.example/team/image@sha256:' + 'a' * 64
EVIDENCE = {'scan.json': 'sha256:' + 'b' * 64}


@pytest.fixture
def verifier(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = attest.signing.public_key(pem)[1]
    statement = {'_type': 'https://in-toto.io/Statement/v0.1',
        'subject': [{'name': 'registry.example/team/image', 'digest': {'sha256': 'a' * 64}}],
        'predicateType': attest.PREDICATE_TYPES['scan'],
        'predicate': attest._predicate(REFERENCE, 'scan', EVIDENCE)}
    calls = []
    def command(args, env):
        calls.append((args, env))
        payload = base64.b64encode(json.dumps(statement).encode()).decode()
        return SimpleNamespace(stdout=json.dumps({'payloadType': 'application/vnd.in-toto+json', 'payload': payload}))
    monkeypatch.setattr(attest.shutil, 'which', lambda _: 'cosign')
    monkeypatch.setattr(attest.signing, '_command', command)
    return pem, fingerprint, statement, calls


def test_verified_typed_binding_offline_and_clean_environment(verifier):
    pem, fingerprint, _, calls = verifier
    result = attest.verify_attestation(REFERENCE, 'scan', EVIDENCE, pem, fingerprint,
                                      {'COSIGN_REPOSITORY': 'attacker', 'PATH': 'tools'})
    assert result['status'] == 'verified'
    assert '--offline' in calls[0][0] and '--insecure-ignore-tlog=true' in calls[0][0]
    assert calls[0][1] == {'PATH': 'tools'}


@pytest.mark.parametrize('field', ['subject', 'purpose', 'evidence', 'type', 'empty', 'extra-subject'])
def test_mismatched_signed_claims_denied(verifier, field):
    pem, fingerprint, statement, _ = verifier
    if field == 'subject': statement['subject'][0]['digest']['sha256'] = 'c' * 64
    if field == 'purpose': statement['predicate']['purpose'] = 'cyber-approval'
    if field == 'evidence': statement['predicate']['evidence']['scan.json'] = 'sha256:' + 'c' * 64
    if field == 'type': statement['predicateType'] = attest.PREDICATE_TYPES['patch']
    if field == 'empty': statement['subject'] = []
    if field == 'extra-subject': statement['subject'].append(statement['subject'][0])
    with pytest.raises(attest.AttestationError):
        attest.verify_attestation(REFERENCE, 'scan', EVIDENCE, pem, fingerprint)


@pytest.mark.parametrize('fingerprint', ['', None, 'sha256:' + '0' * 64])
def test_trust_required(verifier, fingerprint):
    pem, _, _, calls = verifier
    with pytest.raises(attest.AttestationError):
        attest.verify_attestation(REFERENCE, 'scan', EVIDENCE, pem, fingerprint)
    assert not calls


@pytest.mark.parametrize('reference,purpose,evidence', [
    ('registry/image:latest', 'scan', EVIDENCE),
    (REFERENCE, 'arbitrary', EVIDENCE), (REFERENCE, 'scan', {}),
    (REFERENCE, 'scan', {'report': 'verified'}),
])
def test_invalid_requests_denied(reference, purpose, evidence):
    with pytest.raises(attest.AttestationError):
        attest._predicate(reference, purpose, evidence)


def test_publication_uses_existing_key_and_verifies_readback(verifier):
    pem, fingerprint, _, calls = verifier
    config = {'signing_enabled': True, 'signing_public_key': pem.decode(), 'signing_fingerprint': fingerprint}
    secrets = {attest.signing.SECRET_ENV[0]: base64.b64encode(b'private-test-key').decode(),
               attest.signing.SECRET_ENV[1]: 'secret'}
    result = attest.attest_and_verify(REFERENCE, 'scan', EVIDENCE, (config, secrets))
    assert result['status'] == 'verified'
    assert calls[0][0][1] == 'attest' and '--tlog-upload=false' in calls[0][0]
    assert calls[0][1]['COSIGN_PASSWORD'] == 'secret'
    assert calls[1][0][1] == 'verify-attestation' and 'COSIGN_PASSWORD' not in calls[1][1]
    assert not Path(calls[0][0][calls[0][0].index('--key') + 1]).exists()


def test_cosign_failure_is_sanitized(verifier, monkeypatch):
    pem, fingerprint, _, _ = verifier
    def fail(*args): raise RuntimeError('private password secret')
    monkeypatch.setattr(attest.signing, '_command', fail)
    with pytest.raises(attest.AttestationError, match='^Attestation verification failed$'):
        attest.verify_attestation(REFERENCE, 'scan', EVIDENCE, pem, fingerprint)


def test_patch_evidence_uses_retained_bytes_and_technical_purposes(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ('before', 'after', 'archive')]
    for path, content in zip(paths, (b'before scan', b'after scan', b'archive bytes')):
        path.write_bytes(content)
    calls = []
    def publish(reference, purpose, evidence, material, env):
        calls.append((reference, purpose, evidence))
        return {'status': 'verified', 'purpose': purpose}
    monkeypatch.setattr(attest, 'attest_and_verify', publish)
    receipts = attest.attest_patch_evidence(REFERENCE, *paths, ({}, {}))
    assert [r['purpose'] for r in receipts] == ['scan', 'patch']
    import hashlib
    assert calls[0][2] == {'grype-after.json': 'sha256:' + hashlib.sha256(b'after scan').hexdigest()}
    assert len(calls[1][2]) == 3


def test_changed_retained_patch_evidence_denies_completion(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ('before', 'after', 'archive')]
    for path in paths: path.write_bytes(b'evidence')
    def publish(*args):
        paths[1].write_bytes(b'changed')
        return {'status': 'verified'}
    monkeypatch.setattr(attest, 'attest_and_verify', publish)
    with pytest.raises(attest.AttestationError, match='changed'):
        attest.attest_patch_evidence(REFERENCE, *paths, ({}, {}))
