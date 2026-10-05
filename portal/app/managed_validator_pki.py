"""Dedicated managed-validator PKI; persisted keys use HQ authenticated encryption."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .secrets import encrypt_secret, decrypt_secret


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def _issue(key, issuer, issuer_key, name, now, *, ca=False, hostname=None, client=False):
    builder = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
    if hostname:
        try:
            alternative = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            alternative = x509.DNSName(hostname)
        builder = builder.add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def create_identity(validator_id, hostname, endpoint):
    """Return private persistence, transient deployment and safe public sections.

    A distinct CA for each validator prevents another enrolled host/client from
    authenticating with this host. Re-enrollment revokes old trust by replacing
    the complete CA and client allowlist; no global CA or browser PEM entry.
    """
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', str(validator_id)):
        raise ValueError('Invalid validator identity')
    parsed = urlsplit(endpoint)
    if (parsed.scheme != 'https' or parsed.hostname != hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
        raise ValueError('Validator certificate hostname must match the HTTPS endpoint')
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError('Invalid validator endpoint port') from exc
    if not hostname or any(ord(c) < 33 for c in hostname):
        raise ValueError('Invalid validator certificate hostname')
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name('CATS validator CA ' + str(validator_id))
    ca = _issue(ca_key, ca_name, ca_key, 'CATS validator CA ' + str(validator_id), now, ca=True)
    server_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    server = _issue(server_key, ca.subject, ca_key, str(validator_id), now, hostname=hostname)
    client = _issue(client_key, ca.subject, ca_key, 'CATS HQ ' + str(validator_id), now, client=True)
    ca_pem, client_pem, server_pem = _pem_cert(ca), _pem_cert(client), _pem_cert(server)
    fingerprint = lambda cert: hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    configuration = {'endpoint': endpoint.rstrip('/'), 'ca_certificate': ca_pem,
        'client_certificate': client_pem, 'client_key': encrypt_secret(_pem_key(client_key)),
        'expected_validator_id': str(validator_id), 'server_fingerprint': fingerprint(server)}
    return {'configuration': configuration,
        'persistence': {'ca_key': encrypt_secret(_pem_key(ca_key)),
                        'server_key': encrypt_secret(_pem_key(server_key)), 'server_certificate': server_pem},
        'deployment': {'validator_certificate': server_pem, 'validator_key': _pem_key(server_key),
                       'client_ca': ca_pem, 'client_fingerprint': fingerprint(client)},
        'public': {'validator_id': str(validator_id), 'server_fingerprint': fingerprint(server),
                   'client_fingerprint': fingerprint(client), 'expires_at': server.not_valid_after_utc.isoformat()}}


def deployment_identity(configuration, persistence):
    """Decrypt server material only inside a bounded bootstrap operation."""
    client = x509.load_pem_x509_certificate(configuration['client_certificate'].encode())
    return {'validator_certificate': persistence['server_certificate'],
            'validator_key': decrypt_secret(persistence['server_key']),
            'client_ca': configuration['ca_certificate'],
            'client_fingerprint': hashlib.sha256(client.public_bytes(serialization.Encoding.DER)).hexdigest()}
