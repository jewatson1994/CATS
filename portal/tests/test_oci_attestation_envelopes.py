"""Offline DSSE authentication and exact retained-claim binding."""
import base64
import copy
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding

from app import oci_attestations as attestations, signing


DIGEST = 'sha256:' + 'a' * 64
SOURCE = 'source.example/approved/application@' + DIGEST
EVIDENCE = {'approval.json': 'sha256:' + 'b' * 64}
RECEIPT = {'subject': SOURCE, 'purpose': 'cyber-approval',
           'predicate_type': attestations.PREDICATE_TYPES['cyber-approval'], 'evidence': EVIDENCE}


def statement():
    return {'_type': 'https://in-toto.io/Statement/v0.1',
            'subject': [{'name': SOURCE.split('@')[0], 'digest': {'sha256': 'a' * 64}}],
            'predicateType': RECEIPT['predicate_type'],
            'predicate': attestations._predicate(SOURCE, 'cyber-approval', EVIDENCE)}


def envelope(key, claim=None, *, payload=None, raw_signature=False):
    payload = payload if payload is not None else json.dumps(claim or statement()).encode()
    payload_type = b'application/vnd.in-toto+json'
    # Construct PAE independently from the production verifier.
    signed = b'DSSEv1 28 application/vnd.in-toto+json ' + str(len(payload)).encode() + b' ' + payload
    if raw_signature:
        signed = payload
    if isinstance(key, ec.EllipticCurvePrivateKey):
        signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        signature = key.sign(signed)
    return {'payloadType': payload_type.decode(), 'payload': base64.b64encode(payload).decode(),
            'signatures': [{'keyid': 'untrusted-hint', 'sig': base64.b64encode(signature).decode()}]}


def public_material(key):
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, signing.public_key(pem)[1]


@pytest.fixture(scope='module')
def key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize('factory', [lambda: ec.generate_private_key(ec.SECP256R1()),
    lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    ed25519.Ed25519PrivateKey.generate], ids=['ecdsa', 'rsa', 'ed25519'])
@pytest.mark.parametrize('statement_type', ['https://in-toto.io/Statement/v0.1',
                                           'https://in-toto.io/Statement/v1'])
def test_real_signatures_verify_original_reference_offline(factory, statement_type, monkeypatch):
    key = factory()
    claim = statement()
    claim['_type'] = statement_type
    monkeypatch.setattr(signing, '_command', lambda *a, **k: pytest.fail('Must not invoke Cosign'))
    result = attestations.verify_envelope(json.dumps(envelope(key, claim)), DIGEST,
                                          *public_material(key), RECEIPT)
    assert result == {**RECEIPT, 'status': 'verified', 'key_fingerprint': public_material(key)[1],
                      'generator': 'cosign', 'transparency_log': False}


def test_receipt_retains_signed_source_after_registry_relocation(key):
    raw = json.dumps(envelope(key))
    decoded = attestations.decode_envelope(raw, DIGEST)
    assert decoded['subject'] == SOURCE
    assert decoded['statement']['predicate']['subject'] == SOURCE
    relocated_receipt = dict(RECEIPT, subject=SOURCE.replace('source.example', 'replica.example'))
    with pytest.raises(attestations.AttestationError):
        attestations.verify_envelope(raw, DIGEST, *public_material(key), relocated_receipt)


@pytest.mark.parametrize('field,value', [
    ('subject', SOURCE.replace('approved/application', 'other/application')),
    ('purpose', 'release'), ('predicate_type', attestations.PREDICATE_TYPES['release']),
    ('evidence', {'approval.json': 'sha256:' + 'c' * 64}),
])
def test_exact_expected_receipt_claims_are_required(key, field, value):
    receipt = dict(RECEIPT, **{field: value})
    with pytest.raises(attestations.AttestationError):
        attestations.verify_envelope(json.dumps(envelope(key)), DIGEST, *public_material(key), receipt)
    receipt = dict(RECEIPT)
    del receipt[field]
    with pytest.raises(attestations.AttestationError):
        attestations.verify_envelope(json.dumps(envelope(key)), DIGEST, *public_material(key), receipt)


def test_wrong_key_and_wrong_fingerprint_fail_independently(key):
    raw = json.dumps(envelope(key))
    other = ec.generate_private_key(ec.SECP256R1())
    pem, fingerprint = public_material(key)
    for material in [(pem, public_material(other)[1]), public_material(other), (pem, '')]:
        with pytest.raises(attestations.AttestationError):
            attestations.verify_envelope(raw, DIGEST, *material)


def test_signature_authenticates_exact_payload_and_dsse_domain(key):
    value = envelope(key)
    claim = statement()
    claim['predicate']['evidence']['approval.json'] = 'sha256:' + 'c' * 64
    value['payload'] = base64.b64encode(json.dumps(claim).encode()).decode()
    for tampered in [value, envelope(key, raw_signature=True)]:
        with pytest.raises(attestations.AttestationError):
            attestations.verify_envelope(json.dumps(tampered), DIGEST, *public_material(key))


def test_multisignature_requires_a_signature_from_the_pinned_key(key):
    value = envelope(key)
    invalid = envelope(ec.generate_private_key(ec.SECP256R1()))['signatures'][0]
    value['signatures'].insert(0, invalid)
    assert attestations.verify_envelope(json.dumps(value), DIGEST, *public_material(key))['status'] == 'verified'
    value['signatures'] = [invalid]
    with pytest.raises(attestations.AttestationError):
        attestations.verify_envelope(json.dumps(value), DIGEST, *public_material(key))


@pytest.mark.parametrize('mutation', [
    lambda claim: claim.update(_type='https://example.com/unknown'),
    lambda claim: claim.update(predicateType=attestations.PREDICATE_TYPES['release']),
    lambda claim: claim.update(subject=[]),
    lambda claim: claim['subject'].append(copy.deepcopy(claim['subject'][0])),
    lambda claim: claim['subject'][0].update(name=7),
    lambda claim: claim['subject'][0].update(digest={'sha256': 'c' * 64}),
    lambda claim: claim['subject'][0]['digest'].update(sha512='d' * 128),
    lambda claim: claim['predicate'].update(schemaVersion=True),
    lambda claim: claim['predicate'].update(schemaVersion=1.0),
    lambda claim: claim['predicate'].update(extra='unsigned-policy'),
    lambda claim: claim['predicate'].update(purpose=[]),
    lambda claim: claim['predicate'].update(purpose='unsupported'),
    lambda claim: claim['predicate'].update(subject='source.example/image:latest'),
    lambda claim: claim['predicate'].update(subject=SOURCE[:-64] + 'c' * 64),
    lambda claim: claim['predicate'].update(evidence={}),
    lambda claim: claim['predicate'].update(evidence={'approval.json': True}),
])
def test_even_authentic_signatures_cannot_bypass_subject_and_predicate_rules(key, mutation):
    claim = statement()
    mutation(claim)
    with pytest.raises(ValueError):
        attestations.decode_envelope(json.dumps(envelope(key, claim)), DIGEST)


@pytest.mark.parametrize('change', [
    {'payloadType': 'application/json'}, {'payloadType': []}, {'payload': ''}, {'payload': 42},
    {'payload': 'e30=\n'}, {'payload': 'e30==='}, {'payload': 'e31='}, {'payload': '%%%='},
    {'signatures': []}, {'signatures': {}}, {'signatures': [None]},
    {'signatures': [{'sig': ''}]}, {'signatures': [{'sig': 'c2ln\n'}]},
    {'signatures': [{'sig': 'c2ln', 'keyid': []}]},
    {'signatures': [{'sig': 'c2ln'}] * 65},
])
def test_invalid_envelope_types_and_encodings_are_rejected(key, change):
    value = envelope(key)
    value.update(change)
    with pytest.raises(ValueError):
        attestations.decode_envelope(json.dumps(value), DIGEST)


def test_duplicate_keys_and_non_json_constants_are_rejected_at_every_layer(key):
    raw = json.dumps(envelope(key))
    duplicate_outer = raw.replace('{', '{"payloadType":"ignored",', 1)
    payload = json.dumps(statement()).encode()
    duplicate_inner = payload.replace(b'{', b'{"predicateType":"ignored",', 1)
    duplicate_nested = payload.replace(b'"schemaVersion": 1', b'"schemaVersion": 1, "schemaVersion": 1')
    for malformed in [duplicate_outer, json.dumps(envelope(key, payload=duplicate_inner)),
                      json.dumps(envelope(key, payload=duplicate_nested)),
                      json.dumps(envelope(key, payload=payload.replace(b'"schemaVersion": 1',
                                                                      b'"schemaVersion": NaN')))]:
        with pytest.raises(ValueError):
            attestations.decode_envelope(malformed, DIGEST)


def test_raw_bounds_wrong_subject_and_non_object_statements(key):
    raw = json.dumps(envelope(key)).encode()
    assert attestations.decode_envelope(raw + b' ' * (1024 * 1024 - len(raw)), DIGEST)['subject'] == SOURCE
    for malformed in [None, {}, b'', b' ' * (1024 * 1024 + 1), b'[]', b'\xff',
                      json.dumps(envelope(key, payload=b'[]')),
                      json.dumps(envelope(key, payload=b'null')),
                      json.dumps(envelope(key, payload=b'[' * 2000 + b']' * 2000))]:
        with pytest.raises(ValueError):
            attestations.decode_envelope(malformed, DIGEST)
    for subject in ['sha256:' + 'c' * 64, 'a' * 64, None, []]:
        with pytest.raises(ValueError):
            attestations.decode_envelope(raw, subject)


def test_urlsafe_dsse_encoding_is_supported(key):
    value = envelope(key)
    for signature in value['signatures']:
        signature['sig'] = base64.urlsafe_b64encode(base64.b64decode(signature['sig'])).decode()
    value['payload'] = base64.urlsafe_b64encode(base64.b64decode(value['payload'])).decode()
    assert attestations.verify_envelope(json.dumps(value), DIGEST, *public_material(key))['status'] == 'verified'


def test_legacy_attestation_tags_are_exact():
    assert attestations.ATTESTATION_TYPE == 'application/vnd.dsse.envelope.v1+json'
    tag = 'sha256-' + 'a' * 64 + '.att'
    assert attestations.legacy_attestation_subject(tag) == DIGEST
    for invalid in [tag + '\n', tag.replace('.att', '.sig'), tag.upper(), 'repo:' + tag, None, 42]:
        assert attestations.legacy_attestation_subject(invalid) is None
