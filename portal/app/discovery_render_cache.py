"""Bounded encrypted render reuse. Every renderer-visible file participates in identity."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .discovery_sources import storage_key

class RenderCache:
    def __init__(self, runner, directory, scope, version, maximum=64 * 1024 * 1024):
        self.runner, self.directory = runner, Path(directory)
        self.scope, self.version, self.maximum = scope, version, maximum
        self.hits = self.misses = self.scoped_renders = 0

    def identity(self, tool, args, cwd):
        base = Path(cwd).resolve()
        version = self.version(tool)
        if version == 'unavailable':
            return None
        digest = hashlib.sha256()
        normalized = [str(arg).replace(str(base), '/source') for arg in args]
        digest.update(json.dumps([self.scope, tool, version, normalized, 'render-cache-v2']).encode())
        total = 0
        for path in sorted(base.rglob('*')):
            if path.is_symlink():
                return None
            if not path.is_file():
                continue
            total += path.stat().st_size
            if total > 256 * 1024 * 1024:
                return None
            digest.update(path.relative_to(base).as_posix().encode() + b'\0')
            content = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    content.update(chunk)
            digest.update(content.digest())
        return digest.hexdigest()

    def __call__(self, tool, args, cwd):
        from .discovery_render_inputs import render_inputs
        try:
            with render_inputs(tool, args, cwd) as (selected_args, selected_cwd, scoped):
                self.scoped_renders += int(scoped)
                return self._cached_call(tool, selected_args, selected_cwd)
        except OSError:
            return self.runner(tool, args, cwd)

    def _cached_call(self, tool, args, cwd):
        identity = self.identity(tool, args, cwd)
        key = storage_key()
        path = self.directory / (str(identity) + '.cache')
        if identity and path.is_file() and not path.is_symlink():
            try:
                if path.stat().st_size <= self.maximum:
                    raw = path.read_bytes()
                    result = json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], identity.encode()))
                    self.hits += 1
                    return result
            except Exception:
                pass  # Corrupt or expired encryption keys cause a fresh render.
        self.misses += 1
        result = self.runner(tool, args, cwd)
        if identity:
            raw = json.dumps(result).encode()
            if len(raw) + 28 <= self.maximum:
                self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                # Worker-private scratch cache is bounded; eviction never affects evidence.
                entries = sorted(self.directory.glob('*.cache'), key=lambda p: p.stat().st_mtime)
                size = sum(p.stat().st_size for p in entries)
                for entry in entries:
                    if size + len(raw) + 28 <= self.maximum:
                        break
                    size -= entry.stat().st_size
                    entry.unlink()
                nonce = os.urandom(12)
                with tempfile.NamedTemporaryFile(dir=self.directory, delete=False) as output:
                    temporary = Path(output.name)
                    output.write(nonce + AESGCM(key).encrypt(nonce, raw, identity.encode()))
                temporary.replace(path)
        return result
