"""Exact unified runtime preparation, only called by the privileged worker.

No public pulls or mutable tag identities. Local Docker storage is the primary
dependency cache; explicitly approved internal digest references may fill it.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager

from .managed_validator_bootstrap import BootstrapError
from .managed_validator_release import load_release
from .deployment_validation import ValidationConfig
from . import validator_release_recipe as recipe

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@contextmanager
def cache_lock(root):
    root.mkdir(parents=True, exist_ok=True)
    # Worker production runtime is Linux. flock releases on process death.
    with (root / '.cache.lock').open('a') as lock:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == 'posix':
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def prune_cache(root, *, reserve=0, keep=None):
    """Bound owned cache artifacts, leaving recently used archives safe to upload."""
    moment = time.time()
    budget = int(os.getenv('CATS_PROVISIONING_CACHE_MAX_BYTES', str(32 * 1024**3)))
    retention = 7 * 86400
    candidates = []
    total = 0
    package_root = root / 'packages'
    if package_root.is_dir() and not package_root.is_symlink():
        for package in package_root.iterdir():
            if package.is_symlink() or not re.fullmatch('[a-f0-9]{64}\\.(deb|partial)', package.name):
                continue
            age = moment - package.stat().st_mtime
            if age > retention or (package.suffix == '.partial' and age > 7200):
                package.unlink()
            else:
                total += package.stat().st_size
    for path in root.iterdir():
        if path.is_symlink():
            continue
        age = moment - path.stat().st_mtime
        if path.is_dir() and path.name.startswith('.prepare-') and age > 7200:
            shutil.rmtree(path)
        elif path.is_dir() and re.fullmatch('[a-f0-9]{64}', path.name):
            size = sum(item.stat().st_size for item in path.rglob('*') if item.is_file() and not item.is_symlink())
            if path != keep and age > retention:
                shutil.rmtree(path)
            else:
                total += size
                if path != keep and age > 7200:
                    candidates.append((path.stat().st_mtime, path, size))
    for _, path, size in sorted(candidates):
        if total + reserve <= budget:
            break
        shutil.rmtree(path)
        total -= size
    if total + reserve > budget:
        raise BootstrapError('Provisioning cache budget is exhausted; increase CATS_PROVISIONING_CACHE_MAX_BYTES or allow cached releases to age out.')


def docker(*args):
    try:
        return subprocess.run(['docker', *args], check=True, capture_output=True,
                              text=True, timeout=1800).stdout
    except (subprocess.SubprocessError, OSError):
        raise BootstrapError('Provisioning Docker operation failed; check the worker image cache and daemon. No public registry fallback was attempted.') from None


def approved_reference(reference):
    allowed = set(filter(None, os.getenv('CATS_PROVISIONING_INTERNAL_REGISTRIES', '').split(',')))
    host = reference.split('/')[0]
    if host not in allowed or host in {'docker.io', 'registry-1.docker.io', 'ghcr.io', 'quay.io'} or not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', reference):
        raise BootstrapError('Dependency acquisition requires an approved internal registry and an immutable @sha256 reference.')
    return reference


def resolve_image(reference, source=None):
    try:
        row = json.loads(docker('image', 'inspect', reference))[0]
    except BootstrapError:
        if not source:
            raise BootstrapError('Missing dependency: ' + reference + '. Import this exact image into the provisioning worker Docker cache or configure its digest-pinned source in approved internal Harbor.') from None
        source = approved_reference(source)
        if '@sha256:' in reference and reference.split('@')[1] != source.split('@')[1]:
            raise BootstrapError('Internal mirror digest does not match the required dependency pin.')
        docker('pull', source)
        row = json.loads(docker('image', 'inspect', source))[0]
    if not DIGEST.fullmatch(row.get('Id', '')) or row.get('Architecture') != 'amd64' or row.get('Os') != 'linux':
        raise BootstrapError('Validator dependency must be an identified linux/amd64 image.')
    if DIGEST.fullmatch(reference) and row['Id'] != reference:
        raise BootstrapError('Cached image identity does not match the requested runtime.')
    if '@sha256:' in reference and not any(item.endswith('@' + reference.split('@')[1]) for item in row.get('RepoDigests', [])):
        raise BootstrapError('Cached dependency has no matching immutable repository digest.')
    return row


def prepare_release(expected=None, progress=lambda stage: None, selected=lambda image: None):
    root = Path(os.getenv('CATS_PROVISIONING_CACHE', '/app/data/validator-releases'))
    with cache_lock(root):
        return _prepare_release(expected, progress, selected)


def _prepare_release(expected, progress, selected):
    staged = os.getenv('CATS_MANAGED_VALIDATOR_RELEASE_DIR', '')
    if staged and (Path(staged) / 'manifest.json').is_file():
        release = load_release(staged)
        if expected and release['cats_image']['image_id'] != expected:
            raise BootstrapError('Staged release changed since this operation started.')
        selected(release['cats_image']['image_id'])
        return release
    progress('RESOLVING_INPUTS')
    runtime = expected or os.getenv('CATS_PROVISIONING_CATS_IMAGE', '')
    if runtime and not (DIGEST.fullmatch(runtime) or re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', runtime)):
        raise BootstrapError('CATS_PROVISIONING_CATS_IMAGE must be an immutable image ID or repository digest.')
    if not runtime:
        # Docker records the exact image used to create this unified CATS worker.
        runtime = json.loads(docker('container', 'inspect', os.environ.get('HOSTNAME', '')))[0]['Image']
    cats = resolve_image(runtime, os.getenv('CATS_PROVISIONING_CATS_SOURCE'))
    selected(cats['Id'])  # Persist the exact runtime before lengthy preparation.
    node = resolve_image(ValidationConfig.kind_node_image, os.getenv('CATS_PROVISIONING_NODE_SOURCE'))
    # Feed the recipe the verified local base ID, including when a mirror filled it.
    recipe_identity = hashlib.sha256(Path(recipe.__file__).read_bytes()).hexdigest()
    inputs = {'cats_image_id': cats['Id'], 'node_image_id': node['Id'],
              'node_pin': ValidationConfig.kind_node_image, 'architecture': 'amd64',
              'recipe_sha256': recipe_identity, 'schema': 1}
    key = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    root = Path(os.getenv('CATS_PROVISIONING_CACHE', '/app/data/validator-releases'))
    root.mkdir(parents=True, exist_ok=True)
    result = root / key
    prune_cache(root, keep=result)
    if result.exists():
        progress('VERIFYING_RELEASE')
        if json.loads((result / 'provenance.json').read_text()) != inputs:
            raise BootstrapError('Cached validator provenance does not match the selected inputs.')
        release = load_release(result)
        result.touch()
        return release
    # Full final archives plus staging require a deliberately conservative budget.
    required = max(2 * (cats.get('Size', 0) + node.get('Size', 0)), 2 * 1024**3)
    prune_cache(root, reserve=required, keep=result)
    if shutil.disk_usage(root).free < required:
        raise BootstrapError('Insufficient provisioning cache space for the exact image archives.')
    progress('PREPARING_PAYLOAD')
    temporary = Path(tempfile.mkdtemp(prefix='.prepare-', dir=root))
    try:
        recipe.prepare(temporary / 'release', cats['Id'], node_image=node['Id'])
        (temporary / 'release' / 'provenance.json').write_text(json.dumps(inputs, sort_keys=True))
        progress('VERIFYING_RELEASE')
        load_release(temporary / 'release')
        try:
            (temporary / 'release').rename(result)
        except FileExistsError:
            # Another worker may have published the identical provenance first.
            if json.loads((result / 'provenance.json').read_text()) != inputs:
                raise BootstrapError('Concurrent cache publication has different provenance.') from None
    finally:
        shutil.rmtree(temporary)
    return load_release(result)
