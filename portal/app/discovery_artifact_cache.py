"""Encrypted disk cache; eviction is storage policy, never an ingestion limit."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .discovery_sources import storage_key
from .compose_ingestion import MAX_TOTAL


def read_cached(directory, identity, expected):
    if directory is None:
        return None
    path = Path(directory) / (identity + '.artifact')
    output = None
    try:
        if path.is_symlink() or not path.is_file() or not 28 <= path.stat().st_size <= MAX_TOTAL + 28:
            return None
        output = tempfile.TemporaryFile()
        hasher = hashlib.sha256()
        with path.open('rb') as stream:
            nonce = stream.read(12)
            stream.seek(-16, 2)
            tag = stream.read(16)
            remaining = stream.tell() - 28
            stream.seek(12)
            decryptor = Cipher(algorithms.AES(storage_key()), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(identity.encode())
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    raise ValueError('Truncated cache')
                remaining -= len(chunk)
                plain = decryptor.update(chunk)
                hasher.update(plain)
                output.write(plain)
            tail = decryptor.finalize()
            hasher.update(tail)
            output.write(tail)
        if hasher.hexdigest() != expected:
            raise ValueError('Cache checksum mismatch')
        output.seek(0)
        return output
    except Exception:
        if output is not None:
            output.close()
        return None


def write_cached(directory, identity, data):
    if directory is None:
        return
    source = io.BytesIO(data) if isinstance(data, bytes) else data
    temporary = None
    try:
        source.seek(0, 2)
        size = source.tell()
        source.seek(0)
        if size + 28 > MAX_TOTAL:
            return
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        entries = sorted(directory.glob('*.artifact'), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in entries)
        for entry in entries:
            if total + size + 28 <= MAX_TOTAL:
                break
            total -= entry.stat().st_size
            entry.unlink()
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(storage_key()), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(identity.encode())
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(nonce)
            while chunk := source.read(65536):
                stream.write(encryptor.update(chunk))
            stream.write(encryptor.finalize())
            stream.write(encryptor.tag)
        temporary.replace(directory / (identity + '.artifact'))
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    finally:
        source.seek(0)
