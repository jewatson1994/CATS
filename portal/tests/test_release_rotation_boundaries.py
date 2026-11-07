"""Real EC signatures for supported continuity bounds and backup recovery.

Registry transport and native Cosign coverage are exercised by the opt-in
qualification drivers. No private signing key is retained by these tests.
"""
import base64
from copy import deepcopy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from app import release_key_rotation as rotation, signing
from app.secrets import encrypt_secret
from test_replica_import import replica_import
from test_release_key_rotation import rotation_keys


native_sign = rotation._sign


def new_key():
    key = ec.generate_private_key(ec.SECP256R1())
    public, fingerprint = signing.public_key(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return dict(enabled=True, public_key=public, fingerprint=fingerprint,
                private_key=encrypt_secret(base64.b64encode(private).decode()), password='')


def transition(first, second, cutovers, chain=()):
    certificate = dict(format=rotation.FORMAT,
        publisher_root=chain[0]['certificate']['publisher_root'] if chain else first['fingerprint'],
        generation=len(chain) + 1, previous_digest=rotation.digest(chain[-1]) if chain else None,
        from_fingerprint=first['fingerprint'], to_fingerprint=second['fingerprint'],
        from_public_key=first['public_key'], to_public_key=second['public_key'], service_cutovers=cutovers)
    return [*chain, dict(certificate=certificate, from_signature=rotation._sign(certificate, first),
                        to_signature=rotation._sign(certificate, second))]


def test_thirty_two_transitions_succeed_and_thirty_third_is_rejected(replica_import, rotation_keys):
    first = current = rotation_keys[0]
    for _ in range(rotation.MAX_CHAIN):
        current = rotation.prepare_configuration(replica_import.origin, current, new_key())
    root, keys = rotation.validate_chain(current['signing_key_chain'])
    assert root == first['fingerprint'] and len(keys) == 33
    with pytest.raises(ValueError, match='transition limit reached'):
        rotation.prepare_configuration(replica_import.origin, current, new_key())


def test_ten_thousand_service_cutovers_succeed_and_next_is_rejected(rotation_keys):
    first, second, _ = rotation_keys
    cutovers = {f'service-{index:05d}': 2 for index in range(rotation.MAX_SERVICES)}
    chain = transition(first, second, cutovers)
    assert rotation.validate_chain(chain)[0] == first['fingerprint']
    invalid = deepcopy(chain)
    invalid[0]['certificate']['service_cutovers']['one-too-many'] = 2
    with pytest.raises(ValueError, match='service sequence cutover'):
        rotation.validate_chain(invalid)


def test_combined_byte_limit_applies_before_count_limits(rotation_keys):
    first = rotation_keys[0]
    cutovers = {f'{index:05d}-' + 's' * 114: 2 for index in range(rotation.MAX_SERVICES)}
    chain = []
    while True:
        second = new_key()
        candidate = transition(first, second, cutovers, chain)
        if len(rotation.canonical(candidate)) > rotation.MAX_BYTES:
            break
        rotation.validate_chain(candidate)
        chain, first = candidate, second
    assert len(candidate) < rotation.MAX_CHAIN
    assert all(len(entry['certificate']['service_cutovers']) == rotation.MAX_SERVICES for entry in candidate)
    with pytest.raises(ValueError, match='exceeds its limit'):
        rotation.validate_chain(candidate)


def test_lost_current_key_blocks_transition_and_authorized_backup_restores_it(replica_import, rotation_keys):
    first, second, third = rotation_keys
    current = rotation.prepare_configuration(replica_import.origin, first, second)
    lost = {**current, 'private_key': ''}
    with pytest.raises(ValueError, match='key'):
        native_sign({}, lost)
    # Re-uploading the backed-up same key retains the authenticated chain.
    restored = rotation.prepare_configuration(replica_import.origin, lost, second)
    assert restored['signing_key_chain'] == current['signing_key_chain']
    successor = rotation.prepare_configuration(replica_import.origin, restored, third)
    root, keys = rotation.validate_chain(successor['signing_key_chain'])
    assert root == first['fingerprint'] and keys[-1] == third['fingerprint']
