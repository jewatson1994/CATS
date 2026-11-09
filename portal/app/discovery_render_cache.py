"""Bounded encrypted render reuse. Every renderer-visible file participates in identity."""
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
from contextlib import ExitStack
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .discovery_sources import storage_key


def cache_directory():
    return Path(os.getenv('CATS_DISCOVERY_RENDER_CACHE_DIR', '').strip() or
                str(Path(tempfile.gettempdir()) / 'cats-discovery-render-cache'))


def remove_source_cache(source_id):
    """Remove encrypted render outputs only for this retained original source."""
    if not isinstance(source_id, str) or not re.fullmatch(r'[a-f0-9]{32}', source_id):
        return
    directory = cache_directory()
    if directory.is_symlink():
        raise OSError('Render cache directory cannot be a symbolic link')
    try:
        directory.stat()
    except FileNotFoundError:
        return
    pattern = re.compile(re.escape(source_id) + r'-(?:[a-f0-9]{64}\.cache|[a-zA-Z0-9_-]+\.pending)')
    # Unlike glob, scandir surfaces access errors so deletion cannot falsely succeed.
    with os.scandir(directory) as entries:
        for entry in entries:
            if pattern.fullmatch(entry.name) and not entry.is_dir(follow_symlinks=False):
                Path(entry.path).unlink(missing_ok=True)


class RenderCache:
    def __init__(self, runner, directory, scope, version, maximum=64 * 1024 * 1024, *, source_id=None):
        if source_id is not None and not re.fullmatch(r'[a-f0-9]{32}', source_id):
            raise ValueError('Invalid render cache source identity')
        self.runner, self.directory = runner, Path(directory)
        self.scope, self.version, self.maximum = scope, version, maximum
        self.prefix = source_id + '-' if source_id else ''
        self.hits = self.misses = self.scoped_renders = 0
        self._last_path = None

    def identity(self, tool, args, cwd):
        base = Path(cwd).resolve()
        version = self.version(tool)
        if version == 'unavailable':
            return None
        digest = hashlib.sha256()
        normalized = [str(arg).replace(str(base), '/source') for arg in args]
        digest.update(json.dumps([self.scope, tool, version, normalized, 'render-cache-v3']).encode())
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
        self._last_path = None
        with ExitStack() as stack:
            try:
                selected_args, selected_cwd, scoped = stack.enter_context(render_inputs(tool, args, cwd))
            except OSError:
                return self.runner(tool, args, cwd)
            self.scoped_renders += int(scoped)
            return self._cached_call(tool, selected_args, selected_cwd)

    def invalidate_last(self):
        """Discard a native success that the caller could not parse as evidence."""
        path, self._last_path = self._last_path, None
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _successful(result):
        return (isinstance(result, dict) and isinstance(result.get('stdout'), str)
                and result.get('returncode', 0) == 0 and not result.get('error'))

    def _cached_call(self, tool, args, cwd):
        try:
            identity = self.identity(tool, args, cwd)
        except OSError:
            identity = None
        key = storage_key()
        path = self.directory / (self.prefix + str(identity) + '.cache')
        self._last_path = path if identity else None
        if identity:
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError()
                if path.stat().st_size <= self.maximum:
                    raw = path.read_bytes()
                    result = json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], identity.encode()))
                    if self._successful(result):
                        self.hits += 1
                        return result
            except Exception:
                pass  # Corrupt or expired encryption keys cause a fresh render.
        self.misses += 1
        result = self.runner(tool, args, cwd)
        if identity and self._successful(result):
            temporary = None
            try:
                raw = json.dumps(result).encode()
                if len(raw) + 28 > self.maximum:
                    return result
                self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                # Cache is bounded and optional; eviction never affects evidence.
                entries = sorted(self.directory.glob('*.cache'), key=lambda p: p.stat().st_mtime)
                size = sum(p.stat().st_size for p in entries)
                for entry in entries:
                    if size + len(raw) + 28 <= self.maximum:
                        break
                    size -= entry.stat().st_size
                    entry.unlink()
                nonce = os.urandom(12)
                with tempfile.NamedTemporaryFile(dir=self.directory, prefix=self.prefix, suffix='.pending', delete=False) as output:
                    temporary = Path(output.name)
                    output.write(nonce + AESGCM(key).encrypt(nonce, raw, identity.encode()))
                temporary.replace(path)
            except (OSError, TypeError, ValueError):
                # A cache failure must not fail or repeat an already successful render.
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        pass
        return result
