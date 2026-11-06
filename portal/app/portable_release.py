"""OCI-native extension of Cyber Approved Releases, independent of a source CATS.

Tags are discovery hints only. The signed manifest, pinned publisher key and
immutable OCI descriptors are authoritative. Every referenced graph is fetched
and hash-checked before any caller is allowed to activate the release.
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import re
import tempfile
from urllib.parse import urljoin, urlsplit
from zipfile import ZipFile, BadZipFile

from . import release_oci as oci, release_signing, release_validity, signing

FORMAT = 'cats-replica-release-v1'
ARTIFACT_TYPE = 'application/vnd.cats.approved-release.v1'
CAPTURE_NAME = 'replica-service.json'
# Empty categories are meaningful: omission must not silently erase evidence.
_CAPTURE_LISTS = (
    'risk_assessments', 'risk_decisions', 'vex_disposition_evaluations',
    'service_artifact_assignments', 'cyber_approvals', 'release_revisions',
    'discovery_distributions', 'finding_classifications', 'finding_classification_state',
    'finding_classification_changes', 'risk_policy_versions', 'vex_observation_dispositions',
    'vex_finding_dispositions', 'release_revision_states', 'global_artifacts',
    'global_artifact_locations', 'artifact_patch_lineage', 'vex_documents',
    'vex_statements', 'vex_sources', 'finding_decisions', 'observation_decisions',
)
_TAG = re.compile(r'(?:release|revocation)-[0-9]+-[A-Za-z0-9_-]+\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def load_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field in portable release')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def validate_metadata(value):
    if not isinstance(value, dict) or value.get('format') != FORMAT:
        raise ValueError('This release has no signed replica identity. Request Cyber approval again.')
    for field in ('service_uuid', 'release_uuid'):
        if not isinstance(value.get(field), str) or not value[field] or len(value[field]) > 240:
            raise ValueError('Invalid portable release identity')
    if type(value.get('release_sequence')) is not int or value['release_sequence'] < 1:
        raise ValueError('Invalid signed release sequence')
    if value.get('kind', 'release') not in ('release', 'revocation'):
        raise ValueError('Unsupported portable release event')
    if value.get('kind') == 'revocation' and (not isinstance(value.get('target_release_uuid'), str) or not value['target_release_uuid']):
        raise ValueError('Revocation must name an exact release')
    supersedes = value.get('supersedes_release_uuid')
    if supersedes is not None and (not isinstance(supersedes, str) or not supersedes
                                  or (value.get('kind', 'release') == 'release' and supersedes == value['release_uuid'])):
        raise ValueError('Invalid supersession identity')
    return value


def release_tag(metadata):
    validate_metadata(metadata)
    suffix = metadata['release_uuid']
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', suffix):
        raise ValueError('Invalid portable release tag identity')
    return f"{metadata.get('kind', 'release')}-{metadata['release_sequence']:020d}-{suffix}"


def evidence_capture(content, *, max_bytes=1024**3):
    try:
        with ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)) or CAPTURE_NAME not in names:
                raise ValueError('Complete frozen service evidence is missing. Request Cyber approval again.')
            if sum(member.file_size for member in members) > max_bytes:
                raise ValueError('Expanded release evidence exceeds configured byte limit')
            for member in members:
                if (member.flag_bits & 1 or member.filename.startswith(('/', '\\'))
                        or '\\' in member.filename or '..' in member.filename.split('/')
                        or ((member.external_attr >> 16) & 0o170000) not in (0, 0o100000, 0o040000)):
                    raise ValueError('Unsafe release evidence archive member')
            state = load_json(archive.read(CAPTURE_NAME))
    except (BadZipFile, KeyError) as exc:
        raise ValueError('Complete frozen service evidence is unavailable') from exc
    if (not isinstance(state, dict) or state.get('format') != 'cats-replica-service-v1'
            or not isinstance(state.get('records'), dict)
            or any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                   for rows in state['records'].values())
            or len(state['records'].get('services', [])) != 1
            or state.get('counts') != {name: len(rows) for name, rows in state['records'].items()}):
        raise ValueError('Invalid complete service evidence capture')
    from . import service_transfer
    service_transfer.validate_state(state, {'schema_version': 2,
        'counts': state['counts'], 'service_key': state.get('service_key')})
    extension = state.get('extension')
    if (not isinstance(extension, dict)
            or any(not isinstance(extension.get(name), list)
                   or any(not isinstance(row, dict) for row in extension[name])
                   for name in _CAPTURE_LISTS)
            or not isinstance(extension.get('approval_context'), dict)
            or not isinstance(state.get('actors'), dict)
            or not isinstance(state.get('activity'), list)):
        raise ValueError('Complete frozen contextual evidence is missing or invalid')
    display = extension.get('display')
    if (not isinstance(display, dict)
            or any(not isinstance(display.get(name), dict)
                   for name in ('services_row', 'cyber_row', 'configuration'))
            or not display.get('services_row') or not display.get('cyber_row')
            or not isinstance(display.get('captured_at'), str)):
        raise ValueError('Complete frozen dashboard evidence is missing or invalid')
    try:
        captured_at = datetime.fromisoformat(display['captured_at'].replace('Z', '+00:00'))
        if captured_at.tzinfo is None:
            raise ValueError('Frozen dashboard capture time must include a timezone')
    except ValueError as exc:
        raise ValueError('Invalid frozen dashboard capture time') from exc
    return state


def discover_releases(repository, env):
    """List all discovery tags with bounded pages, following same-repository Link."""
    host, name, _ = oci._reference(repository + '@sha256:' + '0' * 64)
    client = oci._Client(host, name, env, pull_only=True)
    url, seen, results = client.api + '/tags/list?n=100', set(), []
    while url:
        if url in seen:
            raise ValueError('Registry tag pagination cycle')
        seen.add(url)
        _, headers, content = client.request('GET', url)
        document = load_json(content)
        tags = document.get('tags') or []
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise ValueError('Invalid registry tag listing')
        for tag in tags:
            if _TAG.fullmatch(tag):
                _, _, data = client.request('GET', client.api + '/manifests/' + tag)
                digest = oci._digest(data)
                results.append({'tag': tag, 'digest': digest, 'reference': repository + '@' + digest})
        link = headers.get('Link', '') if hasattr(headers, 'get') else ''
        next_links = re.findall(r'<([^>]+)>\s*;\s*rel=["\']?next["\']?', link)
        if len(next_links) > 1 or (link and not next_links):
            raise ValueError('Unsupported registry pagination link')
        url = urljoin(url, next_links[0]) if next_links else None
        if url and (urlsplit(url).scheme != 'https' or urlsplit(url).netloc != urlsplit(client.api).netloc
                    or urlsplit(url).path != urlsplit(client.api).path + '/tags/list'
                    or urlsplit(url).fragment):
            raise ValueError('Registry pagination left the configured repository')
    return sorted({item['reference']: item for item in results}.values(),
                  key=lambda row: (int(row['tag'].split('-', 2)[1]), row['tag']))


class _Graph:
    def __init__(self, env):
        self.env = env
        self.total = 0
        self.limit = int(env.get('CATS_CYBER_RELEASE_MAX_BYTES', str(20 * 1024**3)))
        self.blob_limit = int(env.get('CATS_CYBER_RELEASE_BLOB_MAX_BYTES', str(1024**3)))
        if self.limit <= 0 or self.blob_limit <= 0:
            raise ValueError('Release verification byte limits must be positive')
        self.verified = {}

    def checked(self, data, descriptor):
        if (not isinstance(descriptor, dict) or not oci._DIGEST.fullmatch(str(descriptor.get('digest', '')))
                or type(descriptor.get('size')) is not int or descriptor['size'] < 0
                or not isinstance(descriptor.get('mediaType'), str)
                or len(data) != descriptor['size'] or oci._digest(data) != descriptor['digest']):
            raise ValueError('Incomplete or corrupt replicated OCI content')
        self.total += len(data)
        if self.total > self.limit:
            raise ValueError('Release verification exceeds configured byte limit')

    def graph(self, client, digest, expected=None, depth=0, ancestors=()):
        if depth > 32 or digest in ancestors:
            raise ValueError('Invalid OCI graph nesting')
        key = (client.api, digest)
        if key in self.verified:
            result = self.verified[key]
            if expected and any(result['descriptor'][k] != expected[k] for k in ('digest', 'size', 'mediaType')):
                raise ValueError('OCI descriptor mismatch')
            return result
        _, headers, data = client.request('GET', client.api + '/manifests/' + digest)
        document = load_json(data)
        descriptor = {'digest': digest, 'size': len(data), 'mediaType': document.get('mediaType') or headers.get_content_type()}
        self.checked(data, expected or descriptor)
        if expected and expected['mediaType'] != descriptor['mediaType']:
            raise ValueError('OCI descriptor media type mismatch')
        children = document.get('manifests', [])
        layers = document.get('layers', [])
        if not isinstance(children, list) or not isinstance(layers, list):
            raise ValueError('Invalid OCI artifact graph')
        blobs = ([document['config']] if 'config' in document else []) + layers
        if not children and not blobs:
            raise ValueError('Empty OCI artifact graph')
        manifests, blob_ids, contents = {digest}, set(), {}
        for child in children:
            result = self.graph(client, child['digest'], child, depth + 1, (*ancestors, digest))
            manifests.update(result['manifests'])
            blob_ids.update(result['blobs'])
        for blob in blobs:
            if type(blob.get('size')) is not int or blob['size'] < 0 or blob['size'] > self.blob_limit:
                raise ValueError('OCI blob exceeds configured byte limit')
            if blob.get('mediaType') == 'application/vnd.dev.cosign.simplesigning.v1+json' and blob['size'] > 1024 * 1024:
                raise ValueError('OCI signature payload exceeds configured byte limit')
            _, _, content = client.request('GET', client.api + '/blobs/' + blob['digest'], limit=blob['size'])
            self.checked(content, blob)
            blob_ids.add(blob['digest'])
            # Only small signature/config blobs need to survive graph verification.
            if blob.get('mediaType') == 'application/vnd.dev.cosign.simplesigning.v1+json':
                contents[blob['digest']] = content
        result = {'descriptor': descriptor, 'document': document,
                  'manifests': sorted(manifests), 'blobs': sorted(blob_ids), 'contents': contents}
        self.verified[key] = result
        return result


def _verify_blob(content, signature, public, fingerprint):
    with tempfile.TemporaryDirectory(prefix='cats-portable-verify-') as temporary:
        root = Path(temporary)
        paths = [root / name for name in ('release-manifest.json', 'release-manifest.sig', 'release-public-key.pem')]
        for path, data in zip(paths, (content, signature, public)):
            path.write_bytes(data)
        result = release_signing.verify_release_manifest(*paths, expected_fingerprint=fingerprint)
        if result.get('status') != 'verified':
            raise ValueError('Portable release signature verification failed')


def fetch_release(reference, env, trusted_fingerprints, *, repository_prefix=None):
    """Return verified immutable evidence; never writes service or policy state.

Repository paths are preserved by default when a registry is replicated. A
configured repository_prefix explicitly replaces the signed source namespace.
All reads remain on the configured local registry, including signatures.
Expiration is returned, not extended; the activation/proxy policy enforces it.
"""
    host, repository, digest = oci._reference(reference)
    client = oci._Client(host, repository, env, pull_only=True)
    graph = _Graph(env)
    root = graph.graph(client, digest)
    document = root['document']
    if document.get('artifactType') != ARTIFACT_TYPE:
        raise ValueError('Not a CATS portable approved release')
    files = {}
    for item in document.get('layers', []):
        name = item.get('annotations', {}).get('org.opencontainers.image.title')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in files:
            raise ValueError('Invalid portable release file inventory')
        _, _, content = client.request('GET', client.api + '/blobs/' + item['digest'], limit=item['size'])
        graph.checked(content, item)
        files[name] = content
    if not {'release-manifest.json', 'release-manifest.sig', 'release-public-key.pem'} <= files.keys():
        raise ValueError('Incomplete signed release documents')
    _, fingerprint = signing.public_key(files['release-public-key.pem'])
    if fingerprint not in trusted_fingerprints:
        raise ValueError('Release publisher is not independently trusted')
    _verify_blob(files['release-manifest.json'], files['release-manifest.sig'], files['release-public-key.pem'], fingerprint)
    manifest = load_json(files['release-manifest.json'])
    metadata = validate_metadata(manifest.get('portable'))
    if manifest.get('signing_fingerprint') != fingerprint:
        raise ValueError('Signed publisher identity mismatch')
    result = {'manifest': manifest, 'portable_release': metadata, 'files': files,
              'reference': reference, 'digest': digest, 'key_fingerprint': fingerprint,
              'artifacts': [], 'evidence': None, 'state': None}
    if metadata.get('kind') == 'revocation':
        revoked_at = datetime.fromisoformat(metadata.get('revoked_at', ''))
        if revoked_at.utcoffset() is None or not metadata.get('reason') or not metadata.get('revoked_by_id'):
            raise ValueError('Invalid signed revocation')
        approved_at, expires_at = release_validity.dates(manifest.get('approval', {}))
        if (revoked_at < approved_at or metadata.get('approved_at') != manifest['approval']['approved_at']
                or metadata.get('expires_at') != manifest['approval']['expires_at']):
            raise ValueError('Invalid signed revocation chronology')
        result.update(verified=True, complete=True, revoked_at=revoked_at, approved_at=approved_at, expires_at=expires_at)
        return result
    approval = manifest.get('approval', {})
    start, end = release_validity.dates(approval)
    if (approval.get('status') != 'approved' or not approval.get('decided_by_id')
            or datetime.fromisoformat(approval.get('decided_at', '')) != start
            or metadata.get('approved_at') != approval['approved_at']
            or metadata.get('expires_at') != approval['expires_at'] or metadata.get('revoked_at')):
        raise ValueError('Invalid signed Cyber authorization')
    evidence = files.get('evidence.zip')
    if not evidence or oci._digest(evidence) != manifest.get('evidence', {}).get('digest'):
        raise ValueError('Complete signed release evidence is missing or corrupt')
    if 'evidence.zip.sig' not in files:
        raise ValueError('Evidence signature was not replicated')
    _verify_blob(evidence, files['evidence.zip.sig'], files['release-public-key.pem'], fingerprint)
    state = evidence_capture(evidence, max_bytes=graph.limit)
    if state['service_key'] != metadata['service_uuid'] or state['records']['services'][0]['service_key'] != metadata['service_uuid']:
        raise ValueError('Service capture identity differs from signed release')
    if 'candidate' in manifest:
        candidate = files.get('candidate.zip')
        if not candidate or oci._digest(candidate) != manifest['candidate'].get('digest'):
            raise ValueError('Approved candidate evidence was not replicated')
    inventory = manifest.get('artifacts')
    if not isinstance(inventory, list) or not inventory:
        raise ValueError('Complete approved artifact inventory is missing')
    identities = set()
    source_namespace = str(manifest.get('destination', {}).get('namespace') or 'cyber-approved').strip('/')
    for artifact in inventory:
        _, original_repository, artifact_digest = oci._reference(artifact.get('reference'))
        if artifact.get('digest') != artifact_digest or artifact.get('kind') not in ('image', 'chart'):
            raise ValueError('Signed artifact identity mismatch')
        local_repository = original_repository
        if repository_prefix is not None:
            if not original_repository.startswith(source_namespace + '/'):
                raise ValueError('Artifact is outside the signed publication namespace')
            local_repository = repository_prefix.strip('/') + original_repository[len(source_namespace):]
        oci._reference(host + '/' + local_repository + '@' + artifact_digest)
        identity = (local_repository, artifact_digest)
        if identity in identities:
            raise ValueError('Duplicate approved artifact inventory entry')
        identities.add(identity)
        artifact_client = oci._Client(host, local_repository, env, pull_only=True)
        actual = graph.graph(artifact_client, artifact_digest)
        signature = artifact.get('signature') or {}
        signature_digest = signature.get('digest', '')
        if not oci._DIGEST.fullmatch(signature_digest):
            raise ValueError('Signed artifact signature descriptor is missing')
        signature_graph = graph.graph(artifact_client, signature_digest)
        verified = False
        annotations = release_validity.annotations(manifest['release_key'], approval)
        for layer in signature_graph['document'].get('layers', []):
            detached = layer.get('annotations', {}).get('dev.cosignproject.cosign/signature')
            payload = signature_graph['contents'].get(layer['digest'])
            if not detached or payload is None:
                continue
            payload_document = load_json(payload)
            if (payload_document.get('critical', {}).get('image', {}).get('docker-manifest-digest') != artifact_digest
                    or any(payload_document.get('optional', {}).get(k) != v for k, v in annotations.items())):
                continue
            try:
                _verify_blob(payload, detached.encode(), files['release-public-key.pem'], fingerprint)
                verified = True
                break
            except ValueError:
                continue
        if not verified:
            raise ValueError('Replicated artifact signature is not valid for this release')
        result['artifacts'].append({**artifact, 'repository': local_repository,
            'reference': host + '/' + local_repository + '@' + artifact_digest,
            'manifests': actual['manifests'], 'blobs': actual['blobs'],
            'media_type': actual['descriptor']['mediaType']})
    result.update(evidence=evidence, state=state, approved_at=start, expires_at=end, verified=True, complete=True)
    return result


def discover_release_references(host, repository, env):
    """Yield immutable discoveries from one repository or explicit project/* scope."""
    if not repository.endswith('/*'):
        yield from (row['reference'] for row in discover_releases(host + '/' + repository, env))
        return
    prefix = repository[:-2].rstrip('/')
    oci._reference(host + '/' + prefix + '@sha256:' + '0' * 64)
    client = oci._Client(host, prefix, env, pull_only=True)
    url, seen, names = client.base + '/v2/_catalog?n=100', set(), set()
    while url:
        if url in seen:
            raise ValueError('Registry catalog pagination cycle')
        seen.add(url)
        _, headers, data = client.request('GET', url)
        repositories = load_json(data).get('repositories')
        if not isinstance(repositories, list) or any(not isinstance(name, str) for name in repositories):
            raise ValueError('Invalid registry repository catalog')
        names.update(name for name in repositories if name.startswith(prefix + '/') and name.endswith('/releases'))
        link = headers.get('Link', '') if hasattr(headers, 'get') else ''
        links = re.findall(r'<([^>]+)>\s*;\s*rel=["\']?next["\']?', link)
        if len(links) > 1 or (link and not links):
            raise ValueError('Unsupported registry catalog pagination')
        url = urljoin(url, links[0]) if links else None
        if url and (urlsplit(url).scheme != 'https' or urlsplit(url).netloc != urlsplit(client.base).netloc
                    or urlsplit(url).path != '/v2/_catalog' or urlsplit(url).fragment):
            raise ValueError('Registry catalog pagination left configured origin')
    for name in sorted(names):
        yield from (row['reference'] for row in discover_releases(host + '/' + name, env))
