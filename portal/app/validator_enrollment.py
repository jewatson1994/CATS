"""Dedicated, persistent validator trust, with host-bound internal CSR signing."""
from datetime import datetime, timedelta, timezone
import ipaddress
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from sqlalchemy import select, text
from .models import ValidatorTrustDomain
from .secrets import encrypt_secret, decrypt_secret

def pem(value):
    return value.public_bytes(serialization.Encoding.PEM).decode()

def key_pem(value):
    return value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode()

def host_name(host):
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host.lower())

def trust_domain(db):
    # Called in a fresh transaction: serialize across HQ workers, not just threads.
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(485018035651)'))
    elif db.get_bind().dialect.name == 'sqlite' and not db.in_transaction():
        db.execute(text('BEGIN IMMEDIATE'))
    current = db.scalar(select(ValidatorTrustDomain).where(ValidatorTrustDomain.active.is_(True)))
    if current:
        return current
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATS HQ Validator CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
          .not_valid_after(now+timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
          .sign(key, hashes.SHA256()))
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    client = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATS HQ')]))
              .issuer_name(name).public_key(client_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365))
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), True)
              .sign(key, hashes.SHA256()))
    current = ValidatorTrustDomain(id=uuid.uuid4().hex, certificate=pem(ca),
        encrypted_key=encrypt_secret(key_pem(key)), client_certificate=pem(client),
        encrypted_client_key=encrypt_secret(key_pem(client_key)))
    db.add(current); db.flush()
    return current

def sign_csr(domain, validator, csr_text, *, authorized_attempt):
    if (not authorized_attempt or authorized_attempt.validator_id != validator.id or
            authorized_attempt.status != 'RUNNING' or authorized_attempt.action not in {'provision','reenroll','upgrade','rotate'}):
        raise ValueError('An active authorized enrollment attempt is required')
    if authorized_attempt.action != 'rotate' and authorized_attempt.host_fingerprint != validator.ssh_fingerprint:
        raise ValueError('Enrollment host identity changed')
    if len(csr_text) > 65536:
        raise ValueError('CSR exceeds size limit')
    csr = x509.load_pem_x509_csr(csr_text.encode())
    if not csr.is_signature_valid:
        raise ValueError('Invalid CSR signature')
    public = csr.public_key()
    if not ((isinstance(public, rsa.RSAPublicKey) and public.key_size >= 2048) or
            (isinstance(public, ec.EllipticCurvePublicKey) and public.key_size >= 256)):
        raise ValueError('Unsupported or weak validator public key')
    expected_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, validator.id)])
    names = {host_name(validator.host), x509.UniformResourceIdentifier('urn:cats:validator:'+validator.id)}
    if csr.subject != expected_subject or set(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) != names:
        raise ValueError('CSR does not match the authorized validator identity and host')
    if any(ext.oid != x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME for ext in csr.extensions):
        raise ValueError('Unexpected CSR extensions')
    now = datetime.now(timezone.utc)
    ca = x509.load_pem_x509_certificate(domain.certificate.encode())
    key = serialization.load_pem_private_key(decrypt_secret(domain.encrypted_key).encode(), password=None)
    expires = min(now+timedelta(days=90), ca.not_valid_after_utc)
    cert = (x509.CertificateBuilder().subject_name(expected_subject).issuer_name(ca.subject).public_key(public)
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(expires)
            .add_extension(x509.SubjectAlternativeName(list(names)), False)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), True)
            .add_extension(x509.KeyUsage(True,False,isinstance(public,rsa.RSAPublicKey),False,False,False,False,False,False),True)
            .sign(key, hashes.SHA256()))
    metadata = {'status':'active','serial':str(cert.serial_number),'fingerprint':cert.fingerprint(hashes.SHA256()).hex(),
                'issued_at':now.isoformat(),'expires_at':expires.isoformat(),'trust_domain_id':domain.id,
                'validator_id':validator.id,'host':validator.host}
    return pem(cert), metadata

def operational_configuration(domain, validator, metadata):
    host = '['+validator.host+']' if ':' in validator.host else validator.host
    return {'endpoint':f'https://{host}:{validator.api_port}', 'ca_certificate':domain.certificate,
            'client_certificate':domain.client_certificate,'client_key':domain.encrypted_client_key,
            'server_fingerprint':metadata['fingerprint'],'expected_validator_id':validator.id}
