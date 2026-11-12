"""Registry TLS inherits configured trust without replacing roots or weakening TLS."""
from datetime import datetime, timedelta, timezone
import json
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
from sqlalchemy import create_engine, delete, insert, select, update
from sqlalchemy.orm import Session

from app import oci_transport, trusted_ca
from app.models import PortalSetting


@pytest.fixture
def trust_db():
    engine = create_engine('sqlite://')
    PortalSetting.__table__.create(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


def setting(db, value, *, key='trusted_ca_certificates', group_id=None):
    db.execute(insert(PortalSetting.__table__).values(
        key=key, group_id=group_id, value=value))
    db.commit()


def test_configured_certificates_only_use_global_setting_without_promoting_groups(trust_db):
    db = trust_db
    assert trusted_ca.configured_certificates(db) == []
    setting(db, json.dumps([{'pem': 'group-only-private-certificate'}]), group_id=7)
    setting(db, json.dumps([{'pem': 'legacy-group-certificate'}]),
            key='group:8:trusted_ca_certificates', group_id=8)
    before = list(db.execute(select(PortalSetting.__table__)).mappings())
    assert trusted_ca.configured_certificates(db) == []
    assert list(db.execute(select(PortalSetting.__table__)).mappings()) == before


def test_configured_certificates_read_updates_and_removal_without_restart(trust_db, authorities):
    db = trust_db
    first = [{'fingerprint': 'first', 'pem': authorities['configured'][0]}]
    second = [{'fingerprint': 'second', 'pem': authorities['custom'][0]}]
    setting(db, json.dumps(first))
    received = trusted_ca.configured_certificates(db)
    assert received == first
    received.clear()
    assert trusted_ca.configured_certificates(db) == first
    db.execute(update(PortalSetting.__table__).where(
        PortalSetting.key == 'trusted_ca_certificates').values(value=json.dumps(second)))
    db.commit()
    assert trusted_ca.configured_certificates(db) == second
    db.execute(delete(PortalSetting.__table__))
    db.commit()
    assert trusted_ca.configured_certificates(db) == []


@pytest.mark.parametrize('value', [
    '', 'PRIVATE-INVALID-JSON', 'null', '{}', '["PRIVATE-CERTIFICATE"]', '[null]',
    '[{}]', '[{"pem": null}]', '[{"pem": 123}]', '[{"pem": ""}]',
    '[{"pem": "   "}]', '[{"pem": "PRIVATE-NOT-A-PEM-CERTIFICATE"}]',
])
def test_malformed_configured_trust_fails_with_fixed_safe_message(trust_db, value):
    setting(trust_db, value)
    with pytest.raises(ValueError) as failure:
        trusted_ca.configured_certificates(trust_db)
    assert str(failure.value)
    assert 'PRIVATE' not in str(failure.value)
    if value:
        assert value not in str(failure.value)
    # Every malformed payload gets the same diagnostic, independent of its bytes.
    trust_db.execute(update(PortalSetting.__table__).values(value='PRIVATE-OTHER-JSON'))
    trust_db.commit()
    with pytest.raises(ValueError) as other:
        trusted_ca.configured_certificates(trust_db)
    assert str(other.value) == str(failure.value)


@pytest.fixture(scope='module')
def authorities():
    result = {}
    for name in ('system', 'configured', 'custom'):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATS test ' + name)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
                    critical=True).sign(key, hashes.SHA256()))
        result[name] = (cert.public_bytes(serialization.Encoding.PEM).decode(),
                        cert.public_bytes(serialization.Encoding.DER))
    return result


def context_capture(monkeypatch, authorities):
    real_default = ssl.create_default_context
    contexts = []
    def create_default_context(*args, **kwargs):
        context = real_default(*args, **kwargs)
        context.load_verify_locations(cadata=authorities['system'][0])
        contexts.append(context)
        return context
    monkeypatch.setattr(oci_transport.ssl, 'create_default_context', create_default_context)
    return contexts


@pytest.mark.parametrize('custom', [False, True])
def test_registry_context_keeps_system_and_configured_roots_with_optional_custom_ca(
        monkeypatch, authorities, custom):
    contexts = context_capture(monkeypatch, authorities)
    config = {'endpoint': 'https://registry.example', 'trusted_ca_certificates': [
        {'fingerprint': 'configured', 'pem': authorities['configured'][0]}]}
    if custom:
        config['ca_pem'] = authorities['custom'][0]
    oci_transport.RegistryClient(config)
    context = contexts[-1]
    accepted = set(context.get_ca_certs(binary_form=True))
    assert authorities['system'][1] in accepted
    assert authorities['configured'][1] in accepted
    assert (authorities['custom'][1] in accepted) is custom
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_registry_without_added_trust_retains_verified_system_context(monkeypatch, authorities):
    contexts = context_capture(monkeypatch, authorities)
    oci_transport.RegistryClient({'endpoint': 'https://registry.example'})
    context = contexts[-1]
    accepted = set(context.get_ca_certs(binary_form=True))
    assert authorities['system'][1] in accepted
    assert authorities['configured'][1] not in accepted
    assert authorities['custom'][1] not in accepted
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize('field', ['trusted_ca_certificates', 'ca_pem'])
def test_invalid_ca_never_falls_back_to_unverified_registry_connection(monkeypatch, authorities, field):
    contexts = context_capture(monkeypatch, authorities)
    invalid = '-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----'
    config = {'endpoint': 'https://registry.example',
              'trusted_ca_certificates': [{'pem': authorities['configured'][0]}],
              'ca_pem': authorities['custom'][0]}
    config[field] = [{'pem': invalid}] if field == 'trusted_ca_certificates' else invalid
    with pytest.raises((ssl.SSLError, ValueError)):
        oci_transport.RegistryClient(config)
    assert all(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
               for context in contexts)
