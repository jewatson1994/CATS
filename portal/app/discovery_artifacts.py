"""Administrator-configured, read-only offline mirrors for deployment artifacts.

Only exact kind/reference/version triples resolve. The manifest is trusted server
configuration, never an uploaded document or a discovery option. Archives are
snapshots of Helm charts, OCI source artifacts, or Git trees; this module never
runs Git, contacts a registry, executes hooks, or falls back to the network.

Manifest: {"version": 1, "artifacts": [{"kind": "helm", "reference":
"oci://registry.example/chart", "version": "1.2.3", "path": "chart.tgz",
"sha256": "<64 hexadecimal characters>"}]}. Paths are relative to its directory.
Administrators should mount this directory read-only and restrict its writers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from . import compose_ingestion as compose

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
    data: bytes = field(repr=False)
    archive_name: str
    sha256: str
    kind: str
    identity_hash: str

    @property
    def provenance(self):
        return {'source': 'admin-local-mirror', 'kind': self.kind,
                'sha256': self.sha256, 'identity_hash': self.identity_hash,
                'integrity': 'verified'}

    def stage(self, root: Path) -> dict:
        """Use a fresh scratch directory; safe extraction rejects unsafe members."""
        try:
            staged = compose.stage_uploads(Path(root), [(self.data, self.archive_name)])
        except compose.ComposeInputError:
            raise ArtifactResolutionError('Artifact archive could not be safely staged.') from None
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
        data = _bounded_read(path, compose.MAX_TOTAL)
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise ArtifactResolutionError('Artifact checksum verification failed.')
        identity_hash = hashlib.sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest()
        suffix = '.tar.gz' if name.lower().endswith('.tar.gz') else Path(name).suffix.lower()
        return ResolvedArtifact(data, 'artifact' + suffix, digest, kind, identity_hash)

