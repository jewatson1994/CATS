"""Bounded encrypted reuse of artifacts authorized by the current mirror manifest."""
import hashlib
import os
from pathlib import Path
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .discovery_sources import storage_key
from .compose_ingestion import MAX_TOTAL

def read_cached(directory, identity, expected):
    if directory is None:
        return None
    path = Path(directory) / (identity + '.artifact')
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TOTAL + 28:
            return None
        raw = path.read_bytes()
        data = AESGCM(storage_key()).decrypt(raw[:12], raw[12:], identity.encode())
        return data if hashlib.sha256(data).hexdigest() == expected else None
    except Exception:
        return None

def write_cached(directory, identity, data):
    if directory is None or len(data) > MAX_TOTAL:
        return
    temporary = None
    try:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        entries = sorted(directory.glob('*.artifact'), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in entries)
        for entry in entries:
            if total + len(data) + 28 <= MAX_TOTAL:
                break
            total -= entry.stat().st_size
            entry.unlink()
        nonce = os.urandom(12)
        raw = nonce + AESGCM(storage_key()).encrypt(nonce, data, identity.encode())
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
        temporary.replace(directory / (identity + '.artifact'))
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
