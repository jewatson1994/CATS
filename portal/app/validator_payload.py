"""Fail-closed, disconnected managed-validator payload validation."""
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath

REQUIRED = {'kind', 'kubectl', 'helm', 'validator', 'node_image', 'self_test_image', 'self_test_chart'}
SUPPORTED_UBUNTU = ('22.04', '24.04')

def payload_catalog(path, expected_sha256):
    """Read an externally pinned catalog; each entry pins a separate platform release."""
    root = Path(path)
    name = 'catalog.json' if (root / 'catalog.json').exists() else 'manifest.json'
    source = root / name
    if root.is_symlink() or source.is_symlink() or source.stat().st_size > 1024 * 1024:
        raise ValueError('Invalid payload catalog')
    raw = source.read_bytes()
    if not re.fullmatch(r'[a-f0-9]{64}', expected_sha256) or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('Payload catalog does not match externally trusted digest')
    value = json.loads(raw)
    if name == 'manifest.json':
        return [{'os': value.get('os'), 'os_version': value.get('os_version'),
                 'architecture': value.get('architecture'), 'path': '.', 'sha256': expected_sha256}]
    entries = value.get('payloads')
    if value.get('format') != 1 or not isinstance(entries, list) or not entries:
        raise ValueError('Invalid payload catalog format')
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict): raise ValueError('Invalid catalog entry')
        platform = (entry.get('os'), entry.get('os_version'), entry.get('architecture'))
        if platform[0] != 'ubuntu' or platform[1] not in SUPPORTED_UBUNTU or platform[2] not in ('amd64', 'arm64') or platform in seen:
            raise ValueError('Unsupported or duplicate catalog platform')
        seen.add(platform)
        relative = entry.get('path', '')
        if not isinstance(relative, str): raise ValueError('Unsafe catalog payload path')
        p = PurePosixPath(relative)
        if not isinstance(relative, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', relative) or p.is_absolute() or '..' in p.parts or p.as_posix() != relative or relative == '.':
            raise ValueError('Unsafe catalog payload path')
        if not re.fullmatch(r'[a-f0-9]{64}', str(entry.get('sha256', ''))):
            raise ValueError('Invalid catalog manifest digest')
    return entries

def select_payload(path, expected_sha256, facts=None):
    root = Path(path)
    entries = payload_catalog(root, expected_sha256)
    if facts is not None:
        entries = [e for e in entries if all(e[k] == facts.get(k) for k in ('os', 'os_version', 'architecture'))]
    if len(entries) != 1:
        raise ValueError('Exactly one trusted payload matching the detected OS/version/architecture is required')
    entry = entries[0]
    selected = root / entry['path']
    manifest = validate_payload(selected, entry['sha256'])
    if any(manifest[k] != entry[k] for k in ('os', 'os_version', 'architecture')):
        raise ValueError('Payload platform differs from catalog')
    return selected, manifest, entry['sha256']

def validate_payload(path, expected_sha256=None):
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Payload must be a real directory')
    manifest_path = root / 'manifest.json'
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError('Invalid manifest')
    expected_sha256 = expected_sha256 or os.getenv('CATS_VALIDATOR_PAYLOAD_SHA256', '')
    if expected_sha256:
        if not re.fullmatch(r'[a-f0-9]{64}', expected_sha256) or hashlib.sha256(manifest_path.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError('Payload does not match externally trusted manifest digest')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('format') != 1 or manifest.get('os') != 'ubuntu' or manifest.get('os_version') not in SUPPORTED_UBUNTU or manifest.get('architecture') not in ('amd64', 'arm64'):
        raise ValueError('Unsupported payload platform or format')
    if not isinstance(manifest.get('payload_version'), str) or not manifest['payload_version'].strip():
        raise ValueError('Payload version required')
    for key in ('node_image_reference', 'self_test_image_reference'):
        if not re.fullmatch(r'[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}', str(manifest.get(key, ''))):
            raise ValueError('Digest-pinned image reference required')
    assets = manifest.get('assets', {})
    if not isinstance(assets, dict) or any(not isinstance(v, str) for v in assets.values()):
        raise ValueError('Invalid assets')
    if not isinstance(manifest.get('packages'), list) or any(not isinstance(v, str) for v in manifest['packages']):
        raise ValueError('Invalid packages')
    if not REQUIRED.issubset(assets) or not manifest.get('packages'):
        raise ValueError('Required offline assets or packages missing')
    if any(not isinstance(v, str) or not v.strip() for v in manifest.get('versions', {}).values()) or not REQUIRED.issubset(manifest.get('versions', {})):
        raise ValueError('Explicit asset versions required')
    files = manifest.get('files', {})
    if not isinstance(files, dict) or not files:
        raise ValueError('Payload file manifest required')
    for name, entry in files.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('size'), int) or entry['size'] <= 0 or not re.fullmatch(r'[a-f0-9]{64}', str(entry.get('sha256', ''))):
            raise ValueError('Invalid file manifest entry')
        p = PurePosixPath(name)
        if p.as_posix() != name or name == 'manifest.json' or p.is_absolute() or '..' in p.parts or '\\' in name or not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
            raise ValueError('Unsafe payload path')
        local = root.joinpath(*p.parts)
        if any(part.is_symlink() for part in [local, *local.parents] if part != root.parent):
            raise ValueError('Payload symlinks forbidden')
        if not local.is_file() or local.stat().st_size != entry.get('size'):
            raise ValueError('Payload file missing or wrong size')
        digest = hashlib.sha256()
        with local.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != entry.get('sha256'):
            raise ValueError('Payload checksum mismatch')
    referenced = set(assets.values()) | set(manifest['packages'])
    if not referenced.issubset(files):
        raise ValueError('Unverified asset reference')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p != manifest_path}
    if actual != set(files) or any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Unmanifested files or symlinks')
    if not all(str(name).endswith('.deb') for name in manifest['packages']):
        raise ValueError('Offline Ubuntu packages must be deb archives')
    return manifest
