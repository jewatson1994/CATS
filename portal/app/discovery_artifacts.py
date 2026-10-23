"""Administrator-configured archive mirrors for deployment artifacts.

Only exact kind/reference/version triples resolve. The manifest is trusted server
configuration, never an uploaded document or a discovery option. Archives are
snapshots of Helm charts, OCI source artifacts, or Git trees; this module never
runs Git or executes hooks. Local resolution is offline; HTTPS retrieval requires
an explicitly configured separate administrator manifest and never uses fallback URLs.

Manifest: {"version": 1, "artifacts": [{"kind": "helm", "reference":
"oci://registry.example/chart", "version": "1.2.3", "path": "chart.tgz",
"sha256": "<64 hexadecimal characters>"}]}. Paths are relative to its directory.
Administrators should mount this directory read-only and restrict its writers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
import re
import stat
import ssl
import tempfile
import time
import io
from urllib import request, error
from urllib.parse import urlsplit

from . import compose_ingestion as compose
from .discovery_limits import limit, staging_limits

MAX_MANIFEST = 1024 * 1024
MAX_ARTIFACTS = 500
KINDS = frozenset({'helm', 'oci', 'git'})


class ArtifactResolutionError(ValueError):
    """Fixed-text error that does not expose references, paths, or credentials."""


def _identity(kind, reference, version):
    if not isinstance(kind, str) or kind not in KINDS or any(not isinstance(v, str) or not v or len(v) > 2048
                              or any(ord(c) < 32 for c in v) for v in (reference, version)):
        raise ArtifactResolutionError('Invalid artifact identity.')
    # Credentials and URL query/fragment tokens are never supported.
    try:
        url = urlsplit(reference)
        if url.username or url.password or url.query or url.fragment:
            raise ArtifactResolutionError('Credential-bearing artifact references are not supported.')
    except ValueError:
        raise ArtifactResolutionError('Invalid artifact identity.') from None
    return kind, reference, version


def _bounded_read(path, limit):
    try:
        if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > limit:
            raise ArtifactResolutionError('Artifact input is not a bounded regular file.')
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ArtifactResolutionError('Artifact input exceeds size limits.')
        return data
    except OSError:
        raise ArtifactResolutionError('Artifact input is unavailable.') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactResolutionError('Duplicate mirror manifest fields.')
        result[key] = value
    return result


@dataclass(frozen=True)
class ResolvedArtifact:
    payload: object = field(repr=False)
    archive_name: str
    sha256: str
    kind: str
    identity_hash: str
    source: str = 'admin-local-mirror'

    @property
    def data(self):
        """Compatibility accessor; staging consumes the file-backed payload directly."""
        if isinstance(self.payload, bytes):
            return self.payload
        self.payload.seek(0)
        return self.payload.read()

    @property
    def provenance(self):
        return {'source': self.source, 'kind': self.kind,
                'sha256': self.sha256, 'identity_hash': self.identity_hash,
                'integrity': 'verified'}

    def stage(self, root: Path, *, check=None) -> dict:
        """Use a fresh scratch directory; safe extraction rejects unsafe members."""
        try:
            source = io.BytesIO(self.payload) if isinstance(self.payload, bytes) else self.payload
            source.seek(0)
            staged = compose.stage_uploads(Path(root), [(source, self.archive_name)],
                                           **staging_limits(), check=check)
        except compose.ComposeInputError as exc:
            raise ArtifactResolutionError('Artifact archive could not be safely staged. ' + str(exc)) from None
        return {**staged, 'provenance': self.provenance}


class LocalArtifactResolver:
    """Construct only from an administrator-selected manifest outside uploads."""

    def __init__(self, manifest_path: Path | str):
        manifest = Path(manifest_path).absolute()
        if any(p.is_symlink() for p in (manifest, *manifest.parents)):
            raise ArtifactResolutionError('Mirror links are not allowed.')
        self._root = manifest.parent.resolve()
        try:
            document = json.loads(_bounded_read(manifest, MAX_MANIFEST), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError, RecursionError):
            raise ArtifactResolutionError('Invalid mirror manifest.') from None
        if (not isinstance(document, dict) or set(document) != {'version', 'artifacts'}
                or type(document['version']) is not int or document['version'] != 1
                or not isinstance(document['artifacts'], list)
                or len(document['artifacts']) > MAX_ARTIFACTS):
            raise ArtifactResolutionError('Invalid mirror manifest.')
        self._entries = {}
        for entry in document['artifacts']:
            if not isinstance(entry, dict) or set(entry) != {'kind', 'reference', 'version', 'path', 'sha256'}:
                raise ArtifactResolutionError('Invalid mirror artifact entry.')
            if not isinstance(entry['kind'], str):
                raise ArtifactResolutionError('Invalid artifact identity.')
            key = _identity(entry['kind'], entry['reference'], entry['version'])
            if key in self._entries:
                raise ArtifactResolutionError('Duplicate mirror artifact identity.')
            digest, name = entry['sha256'], entry['path']
            if not isinstance(digest, str) or not re.fullmatch('[0-9a-fA-F]{64}', digest):
                raise ArtifactResolutionError('Invalid artifact checksum.')
            if not isinstance(name, str) or not name.lower().endswith(('.zip', '.tar', '.tgz', '.tar.gz')):
                raise ArtifactResolutionError('Only local artifact archives are supported.')
            try:
                compose._inside(self._root, name)
            except compose.ComposeInputError:
                raise ArtifactResolutionError('Unsafe mirror artifact path.') from None
            self._entries[key] = (name, digest.lower())

    def resolve(self, kind: str, reference: str, version: str) -> ResolvedArtifact:
        key = _identity(kind, reference, version)
        if key not in self._entries:
            raise ArtifactResolutionError('Exact artifact version is not configured in the local mirror.')
        name, expected = self._entries[key]
        try:
            path = compose._inside(self._root, name)
        except compose.ComposeInputError:
            raise ArtifactResolutionError('Unsafe mirror artifact path.') from None
        data = tempfile.TemporaryFile()
        try:
            if not stat.S_ISREG(path.stat().st_mode):
                raise ArtifactResolutionError('Artifact input is not a regular file.')
            maximum = limit('UPLOAD_BYTES')
            if maximum and path.stat().st_size > maximum:
                raise ArtifactResolutionError('Artifact input exceeds size limits.')
            size = 0
            hasher = hashlib.sha256()
            with path.open('rb') as stream:
                while chunk := stream.read(65536):
                    size += len(chunk)
                    if maximum and size > maximum:
                        raise ArtifactResolutionError('Artifact input exceeds size limits.')
                    hasher.update(chunk)
                    data.write(chunk)
            digest = hasher.hexdigest()
            if digest != expected:
                raise ArtifactResolutionError('Artifact checksum verification failed.')
            data.seek(0)
        except Exception as exc:
            data.close()
            if isinstance(exc, OSError):
                raise ArtifactResolutionError('Artifact input is unavailable.') from None
            raise
        identity_hash = hashlib.sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest()
        suffix = '.tar.gz' if name.lower().endswith('.tar.gz') else Path(name).suffix.lower()
        return ResolvedArtifact(data, 'artifact' + suffix, digest, kind, identity_hash)



class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ArtifactResolutionError('Artifact redirects are not allowed.')


def _https_origin(value, *, origin_only=False):
    """Require a canonical, credential-free HTTPS origin or archive URL."""
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) <= 32 for c in value):
        raise ArtifactResolutionError('Invalid HTTPS artifact location.')
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or '?' in value or '#' in value
                or '\\' in value or '%' in parsed.netloc
                or parsed.port not in (None, 443) and not 1 <= parsed.port <= 65535):
            raise ValueError()
        origin = 'https://' + parsed.netloc
        if origin_only and value != origin:
            raise ValueError()
    except ValueError:
        raise ArtifactResolutionError('Invalid HTTPS artifact location.') from None
    return origin


class ApprovedHTTPSArtifactResolver:
    """Opt-in archive retrieval from exact administrator-approved HTTPS URLs.

    Version 2 manifest: {"version": 2, "allowed_origins": ["https://mirror.example"],
    "artifacts": [{"kind": "helm", "reference": "oci://registry.example/chart",
    "version": "1.2.3", "url": "https://mirror.example/chart.tgz", "sha256": "..."}]}.
    Origins may intentionally include private enterprise hosts; administrators must
    restrict DNS and worker egress accordingly. Untrusted inputs only select exact
    identities and never supply URLs. No ambient proxies, credentials or redirects.
    """

    def __init__(self, manifest_path, *, ca_file=None, cache_directory=None):
        manifest = Path(manifest_path).absolute()
        if any(p.is_symlink() for p in (manifest, *manifest.parents)):
            raise ArtifactResolutionError('Mirror links are not allowed.')
        try:
            document = json.loads(_bounded_read(manifest, MAX_MANIFEST), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError, RecursionError):
            raise ArtifactResolutionError('Invalid mirror manifest.') from None
        if (not isinstance(document, dict)
                or set(document) != {'version', 'allowed_origins', 'artifacts'}
                or type(document['version']) is not int or document['version'] != 2
                or not isinstance(document['allowed_origins'], list)
                or not 1 <= len(document['allowed_origins']) <= MAX_ARTIFACTS
                or not isinstance(document['artifacts'], list)
                or len(document['artifacts']) > MAX_ARTIFACTS):
            raise ArtifactResolutionError('Invalid HTTPS mirror manifest.')
        origins = {_https_origin(origin, origin_only=True) for origin in document['allowed_origins']}
        self._entries = {}
        for entry in document['artifacts']:
            if not isinstance(entry, dict) or set(entry) != {'kind', 'reference', 'version', 'url', 'sha256'}:
                raise ArtifactResolutionError('Invalid HTTPS artifact entry.')
            key = _identity(entry['kind'], entry['reference'], entry['version'])
            if key in self._entries:
                raise ArtifactResolutionError('Duplicate mirror artifact identity.')
            if _https_origin(entry['url']) not in origins:
                raise ArtifactResolutionError('Artifact origin is not approved.')
            name = urlsplit(entry['url']).path
            if not name.lower().endswith(('.zip', '.tar', '.tgz', '.tar.gz')):
                raise ArtifactResolutionError('Only artifact archives are supported.')
            digest = entry['sha256']
            if not isinstance(digest, str) or not re.fullmatch('[0-9a-fA-F]{64}', digest):
                raise ArtifactResolutionError('Invalid artifact checksum.')
            self._entries[key] = (entry['url'], digest.lower(), name)
        try:
            context = ssl.create_default_context()
            if ca_file:
                context.load_verify_locations(cafile=ca_file)
        except (OSError, ssl.SSLError):
            raise ArtifactResolutionError('Artifact TLS configuration is invalid.') from None
        self._opener = request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=context), _NoRedirect())
        self._cache = {}
        self._disk_cache = Path(cache_directory) if cache_directory else None
        self.cache_hits = 0

    def resolve(self, kind, reference, version):
        key = _identity(kind, reference, version)
        if key not in self._entries:
            raise ArtifactResolutionError('Exact artifact version is not configured in the approved mirror.')
        if key in self._cache:
            return self._cache[key]
        url, expected, name = self._entries[key]
        from .discovery_artifact_cache import read_cached, write_cached
        cache_id = hashlib.sha256(json.dumps([key, url, expected]).encode()).hexdigest()
        cached = read_cached(self._disk_cache, cache_id, expected)
        if cached is not None:
            maximum = limit('UPLOAD_BYTES')
            cached.seek(0, 2)
            if maximum and cached.tell() > maximum:
                cached.close()
                raise ArtifactResolutionError('Artifact input exceeds size limits.')
            cached.seek(0)
            self.cache_hits += 1
            identity_hash = hashlib.sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest()
            suffix = '.tar.gz' if name.lower().endswith('.tar.gz') else Path(name).suffix.lower()
            return ResolvedArtifact(cached, 'artifact' + suffix, expected, kind, identity_hash,
                                    'admin-approved-https-mirror')
        data = tempfile.TemporaryFile()
        hasher = hashlib.sha256()
        started = time.monotonic()
        maximum = limit('UPLOAD_BYTES')
        size = 0
        try:
            with self._opener.open(request.Request(url, headers={'Accept-Encoding': 'identity'}), timeout=10) as response:
                if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                    raise ArtifactResolutionError('Artifact response is not supported.')
                length = response.headers.get('Content-Length')
                if length is not None and (not length.isdigit() or (maximum and int(length) > maximum)):
                    raise ArtifactResolutionError('Artifact input exceeds size limits.')
                while True:
                    if time.monotonic() - started > 30:
                        raise ArtifactResolutionError('Artifact retrieval time limit exceeded.')
                    chunk = response.read1(65536)
                    if time.monotonic() - started > 30:
                        raise ArtifactResolutionError('Artifact retrieval time limit exceeded.')
                    if not chunk:
                        break
                    size += len(chunk)
                    if maximum and size > maximum:
                        raise ArtifactResolutionError('Artifact input exceeds size limits.')
                    hasher.update(chunk)
                    data.write(chunk)
            digest = hasher.hexdigest()
            if digest != expected:
                raise ArtifactResolutionError('Artifact checksum verification failed.')
            data.seek(0)
        except Exception as exc:
            data.close()
            if isinstance(exc, ArtifactResolutionError):
                raise
            if isinstance(exc, (OSError, error.URLError, HTTPException, ValueError)):
                raise ArtifactResolutionError('Approved artifact retrieval failed.') from None
            raise
        identity_hash = hashlib.sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest()
        suffix = '.tar.gz' if name.lower().endswith('.tar.gz') else Path(name).suffix.lower()
        result = ResolvedArtifact(data, 'artifact' + suffix, digest, kind, identity_hash,
                                  'admin-approved-https-mirror')
        write_cached(self._disk_cache, cache_id, data)
        self._cache[key] = result
        return result


class ArtifactResolverChain:
    """Prefer configured local entries, never retry integrity failures online."""
    def __init__(self, local, remote):
        self.local, self.remote = local, remote

    def resolve(self, kind, reference, version):
        key = _identity(kind, reference, version)
        if key in self.local._entries:
            return self.local.resolve(*key)
        return self.remote.resolve(*key)
