"""Authenticated streaming source storage; plaintext exists only in job scratch."""
import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .discovery_limits import limit

MAGIC = b'CATS-DISCOVERY\x01'
CHUNK = 1024 * 1024


class SourceStorageError(ValueError):
    pass


def storage_key():
    try:
        encoded = os.environ.get('CATS_CONFIG_ENCRYPTION_KEY', '').strip().encode('ascii')
        raw = base64.b64decode(encoded, altchars=b'-_', validate=True)
        if len(raw) != 32:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise SourceStorageError('Discovery source encryption is not configured') from None
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'cats-discovery-source-v1').derive(raw)


@contextmanager
def encrypted_writer(path, identity):
    """Write ciphertext incrementally; commit authentication tag only on success."""
    key = storage_key()
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC + identity.encode('ascii'))
    with Path(path).open('xb') as stream:
        stream.write(MAGIC + nonce)
        class Writer:
            def write(self, data):
                stream.write(encryptor.update(data))
        yield Writer()
        stream.write(encryptor.finalize())
        stream.write(encryptor.tag)


@contextmanager
def decrypted_source(path, identity, expected_hash, check=lambda: None):
    """Authenticate fully before exposing a temporary plaintext file."""
    path = Path(path)
    key = storage_key()
    maximum = limit('UPLOAD_BYTES')
    overhead = len(MAGIC) + 12 + 16
    size = path.stat().st_size
    if size < overhead or (maximum > 0 and size > maximum + overhead):
        raise SourceStorageError('Encrypted discovery source is invalid or exceeds limits')
    with tempfile.TemporaryDirectory(prefix='cats-discovery-decrypted-') as temporary:
        target = Path(temporary) / path.name
        try:
            with path.open('rb') as source, target.open('xb') as output:
                target.chmod(0o600)
                if source.read(len(MAGIC)) != MAGIC:
                    raise SourceStorageError('Discovery source is not encrypted')
                nonce = source.read(12)
                source.seek(-16, 2)
                tag = source.read(16)
                source.seek(len(MAGIC) + 12)
                decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
                decryptor.authenticate_additional_data(MAGIC + identity.encode('ascii'))
                digest = hashlib.sha256()
                remaining = size - overhead
                while remaining:
                    check()
                    chunk = source.read(min(CHUNK, remaining))
                    if not chunk:
                        raise SourceStorageError('Encrypted discovery source is truncated')
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    output.write(plaintext)
                    digest.update(plaintext)
                output.write(decryptor.finalize())
                if digest.hexdigest() != expected_hash:
                    raise SourceStorageError('Discovery source integrity check failed')
            check()
            yield target
        except InvalidTag:
            raise SourceStorageError('Discovery source authentication failed') from None
