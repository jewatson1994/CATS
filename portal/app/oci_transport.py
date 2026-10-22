"""Read-only OCI transport and verified disk cache. Authorization belongs to callers."""
from __future__ import annotations
import base64
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
REPOSITORY = re.compile(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z')
ACCEPT = ', '.join(('application/vnd.oci.image.manifest.v1+json', 'application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.docker.distribution.manifest.list.v2+json'))
CHUNK = 1024 * 1024

class RegistryError(ValueError):
    def __init__(self, message='Registry request failed', status=502):
        self.status = status
        super().__init__(message)

def _digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise RegistryError('Invalid SHA-256 digest', 400)
    return value.split(':')[1]

def _origin(url):
    try:
        p = urlsplit(url)
        if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment or p.port == 0:
            raise ValueError()
        return p.scheme, p.hostname.lower(), p.port or 443
    except ValueError:
        raise RegistryError('Registry URLs must use credential-free HTTPS', 400) from None

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

class ContentCache:
    """Atomic content-addressed cache; serialized writers bound total disk use.

    Files are rehashed on every cache hit. Lock files survive process crashes;
    OS locks do not. Incomplete downloads are removed on the next write.
    """
    def __init__(self, root, max_bytes=10 * 1024**3, max_blob_bytes=4 * 1024**3):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes, self.max_blob_bytes = int(max_bytes), int(max_blob_bytes)
        if min(self.max_bytes, self.max_blob_bytes) <= 0:
            raise ValueError('Cache limits must be positive')
        self._mutex = threading.RLock()

    @contextmanager
    def _lock(self):
        with self._mutex, (self.root / '.lock').open('a+b') as lock:
            if os.name == 'nt':
                import msvcrt
                lock.seek(0)
                if not lock.read(1):
                    lock.write(b'0'); lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == 'nt':
                    lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def get(self, digest):
        name = _digest(digest)
        with self._lock():
            path = self.root / name
            if not path.is_file() or path.is_symlink():
                return None
            h = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(CHUNK), b''):
                    h.update(chunk)
            if h.hexdigest() != name or path.stat().st_size > min(self.max_bytes, self.max_blob_bytes):
                path.unlink(missing_ok=True)
                return None
            os.utime(path, None)
            return path

    def store(self, digest, stream, max_bytes=None):
        name = _digest(digest)
        limit = min(self.max_bytes, self.max_blob_bytes, max_bytes or self.max_blob_bytes)
        with self._lock():
            for stale in self.root.glob('.download-*'):
                stale.unlink(missing_ok=True)
            entries = sorted((p for p in self.root.iterdir() if re.fullmatch('[0-9a-f]{64}', p.name)), key=lambda p: p.stat().st_mtime)
            used = sum(p.stat().st_size for p in entries)
            handle, temporary = tempfile.mkstemp(prefix='.download-', dir=self.root)
            h, size = hashlib.sha256(), 0
            try:
                with os.fdopen(handle, 'wb') as output:
                    while True:
                        chunk = stream.read(min(CHUNK, limit - size + 1))
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > limit:
                            raise RegistryError('Registry blob exceeds size limit', 413)
                        while used + size > self.max_bytes and entries:
                            victim = entries.pop(0)
                            used -= victim.stat().st_size
                            victim.unlink()
                        h.update(chunk); output.write(chunk)
                    output.flush(); os.fsync(output.fileno())
                if h.hexdigest() != name:
                    raise RegistryError('Registry blob digest verification failed')
                target = self.root / name
                os.replace(temporary, target)
                return target
            finally:
                Path(temporary).unlink(missing_ok=True)

class RegistryClient:
    def __init__(self, config):
        self.base = str(config['endpoint']).rstrip('/')
        self.origin = _origin(self.base)
        if urlsplit(self.base).path or urlsplit(self.base).query:
            raise RegistryError('Registry endpoint must be an HTTPS origin', 400)
        context = ssl.create_default_context()
        if config.get('ca_pem'):
            context.load_verify_locations(cadata=config['ca_pem'])
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
        self.auth_origins = {self.origin} | {_origin(x) for x in config.get('token_realms', [])}
        self.redirect_origins = {self.origin} | {_origin(x) for x in config.get('redirect_origins', [])}
        self.basic = ''
        if config.get('username'):
            self.basic = 'Basic ' + base64.b64encode((config['username'] + ':' + config.get('password', '')).encode()).decode()
        self.timeout = float(config.get('timeout', 45))
        self.max_manifest = int(config.get('max_manifest_bytes', 4 * CHUNK))
        self.max_blob = int(config.get('max_blob_bytes', 4 * 1024**3))
        if min(self.timeout, self.max_manifest, self.max_blob) <= 0:
            raise RegistryError('Registry limits must be positive', 400)

    def _open(self, url, authorization='', allowed=None):
        allowed = allowed or self.redirect_origins
        previous = _origin(url)
        for _ in range(6):
            current = _origin(url)
            if current not in allowed:
                raise RegistryError('Registry redirect is outside approved origins')
            if current != previous:
                authorization = ''
            headers = {'Accept': ACCEPT, 'Accept-Encoding': 'identity'}
            if authorization:
                headers['Authorization'] = authorization
            try:
                return self.opener.open(urllib.request.Request(url, headers=headers), timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308):
                    location = exc.headers.get('Location', '')
                    exc.close()
                    if not location:
                        raise RegistryError('Registry redirect has no location') from None
                    previous, url = current, urljoin(url, location)
                    continue
                if current != self.origin and allowed == self.redirect_origins:
                    status = exc.code; exc.close()
                    raise RegistryError('Registry redirected request failed', status) from None
                raise
            except (OSError, ValueError):
                raise RegistryError('Registry connection failed') from None
        raise RegistryError('Registry redirect limit exceeded')

    def _token(self, repository, challenge):
        scheme, _, parameters = challenge.partition(' ')
        if scheme.lower() != 'bearer':
            raise RegistryError('Registry authentication failed', 401)
        fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(parameters))
        realm = fields.get('realm', '')
        if _origin(realm) not in self.auth_origins:
            raise RegistryError('Registry token service is outside approved origins')
        p = urlsplit(realm)
        query = [(k, v) for k, v in parse_qsl(p.query) if k not in ('scope', 'service', 'account')]
        query.append(('scope', f'repository:{repository}:pull'))
        if fields.get('service'):
            query.append(('service', fields['service']))
        url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ''))
        with self._open(url, self.basic, self.auth_origins) as response:
            raw = self._read(response, CHUNK)
        try:
            data = json.loads(raw)
            token = data.get('token') or data.get('access_token')
            if not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ValueError()
        except (ValueError, AttributeError):
            raise RegistryError('Registry token service returned invalid credentials') from None
        return 'Bearer ' + token

    def _request(self, repository, suffix):
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
            raise RegistryError('Invalid registry repository', 400)
        url = self.base + '/v2/' + repository + suffix
        try:
            try:
                return self._open(url, self.basic)
            except urllib.error.HTTPError as exc:
                challenge, status = exc.headers.get('WWW-Authenticate', ''), exc.code
                exc.close()
                if status != 401:
                    raise RegistryError('Registry request rejected', status) from None
                token = self._token(repository, challenge)
                return self._open(url, token)
        except urllib.error.HTTPError as exc:
            status = exc.code; exc.close()
            raise RegistryError('Registry request rejected', status) from None

    @staticmethod
    def _read(response, limit):
        try:
            raw = response.read(limit + 1)
        except (OSError, http.client.HTTPException):
            raise RegistryError('Registry response was interrupted') from None
        if len(raw) > limit:
            raise RegistryError('Registry metadata exceeds size limit', 413)
        return raw

    def fetch_manifest(self, repository, reference):
        if not isinstance(reference, str) or not (DIGEST.fullmatch(reference) or re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', reference)):
            raise RegistryError('Invalid manifest reference', 400)
        with self._request(repository, '/manifests/' + reference) as response:
            raw = self._read(response, self.max_manifest)
            media_type = response.headers.get('Content-Type', '').split(';')[0]
            claimed = response.headers.get('Docker-Content-Digest')
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        if (DIGEST.fullmatch(reference) and reference != digest) or (claimed and claimed != digest):
            raise RegistryError('Registry manifest digest verification failed')
        return raw, media_type, digest

    def fetch_blob(self, repository, digest, cache):
        _digest(digest)
        if not REPOSITORY.fullmatch(repository):
            raise RegistryError('Invalid registry repository', 400)
        cached = cache.get(digest)
        if cached is not None and cached.stat().st_size <= self.max_blob:
            return cached
        with self._request(repository, '/blobs/' + digest) as response:
            try:
                return cache.store(digest, response, self.max_blob)
            except (OSError, http.client.HTTPException):
                raise RegistryError('Registry blob transfer failed') from None

    def referrers(self, repository, digest):
        _digest(digest)
        suffix = '/referrers/' + digest
        prefix = '/v2/' + repository
        descriptors, seen, total = [], set(), 0
        for _ in range(100):
            if suffix in seen:
                raise RegistryError('Registry referrers pagination loop')
            seen.add(suffix)
            with self._request(repository, suffix) as response:
                raw = self._read(response, self.max_manifest - total)
                link = response.headers.get('Link', '')
            total += len(raw)
            try:
                document = json.loads(raw)
                if not isinstance(document, dict) or not isinstance(document.get('manifests'), list):
                    raise ValueError()
            except ValueError:
                raise RegistryError('Registry returned an invalid referrers index') from None
            descriptors.extend(document['manifests'])
            next_link = re.search(r'<([^>]+)>\s*;\s*rel=["\']?next(?:["\']|\s|,|$)', link)
            if not next_link:
                document['manifests'] = descriptors
                return document
            next_url = urljoin(self.base + prefix + suffix, next_link.group(1))
            parts = urlsplit(next_url)
            if _origin(next_url) != self.origin or parts.path != prefix + '/referrers/' + digest:
                raise RegistryError('Registry referrers pagination left the approved resource')
            suffix = parts.path[len(prefix):] + ('?' + parts.query if parts.query else '')
        raise RegistryError('Registry referrers page limit exceeded')
