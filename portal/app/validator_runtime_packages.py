"""Pinned offline Docker package acquisition and installation for managed Ubuntu."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import urllib.parse
import urllib.request
from .managed_validator_bootstrap import BootstrapError


def packages_for(facts):
    from .validator_on_demand import cache_lock
    root = Path(os.getenv('CATS_PROVISIONING_CACHE', '/app/data/validator-releases'))
    with cache_lock(root):
        return _packages_for(facts)


def _packages_for(facts):
    """Fetch approved .debs into CATS cache before modifying any remote host."""
    try:
        catalog = json.loads(os.getenv('CATS_PROVISIONING_DOCKER_PACKAGES', '{}'))
        packages = catalog[f"ubuntu-{facts['os_version']}-amd64"]
    except (KeyError, ValueError, TypeError):
        raise BootstrapError('Missing dependency: Docker 28+ Ubuntu packages and their dependency closure. Configure CATS_PROVISIONING_DOCKER_PACKAGES with SHA256-pinned .deb URLs on an approved internal HTTPS package source, or install Docker 28+ on the target.') from None
    if not isinstance(packages, list) or not packages or len(packages) > 100:
        raise BootstrapError('Invalid pinned Docker package catalog.')
    root = Path(os.getenv('CATS_PROVISIONING_CACHE', '/app/data/validator-releases')) / 'packages'
    root.mkdir(parents=True, exist_ok=True)
    allowed = set(filter(None, os.getenv('CATS_PROVISIONING_INTERNAL_PACKAGE_HOSTS', '').split(',')))
    result = []
    for record in packages:
        digest = record.get('sha256', '')
        if not re.fullmatch('[a-f0-9]{64}', digest):
            raise BootstrapError('Docker packages require immutable SHA256 pins.')
        path = root / (digest + '.deb')
        if not path.exists():
            from .validator_on_demand import prune_cache
            prune_cache(root.parent, reserve=512 * 1024**2)
            url = urllib.parse.urlsplit(record.get('url', ''))
            if url.scheme != 'https' or url.hostname not in allowed or url.username or url.password:
                raise BootstrapError('Docker package source must be approved internal HTTPS without URL credentials.')
            # Redirects are forbidden: the allowlist is an acquisition boundary.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            temporary = path.with_suffix('.partial')
            try:
                with urllib.request.build_opener(NoRedirect).open(url.geturl(), timeout=60) as source, temporary.open('wb') as destination:
                    size = 0
                    while chunk := source.read(1024**2):
                        size += len(chunk)
                        if size > 512 * 1024**2:
                            raise BootstrapError('Docker package exceeds the 512 MiB acquisition limit.')
                        destination.write(chunk)
                if file_hash(temporary) != digest:
                    raise BootstrapError('Docker package SHA256 verification failed.')
                temporary.replace(path)
            except BootstrapError:
                raise
            except Exception:
                raise BootstrapError('Pinned Docker package unavailable from the approved internal source.') from None
            finally:
                temporary.unlink(missing_ok=True)
        if path.is_symlink() or file_hash(path) != digest:
            raise BootstrapError('Cached Docker package SHA256 verification failed.')
        path.touch()
        result.append((path, digest))
    return result


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def install(ssh, packages):
    paths = []
    checks = []
    for index, (path, digest) in enumerate(packages):
        name = f'docker-{index}.deb'
        ssh._upload(name, path=path)
        remote = shlex.quote(ssh.workspace + '/' + name)
        paths.append(remote)
        checks.append('[ "$(sha256sum ' + remote + ' | cut -d " " -f1)" = ' + shlex.quote(digest) + ' ]')
    arguments = ' '.join(paths)
    # Never apt update/install: dpkg cannot access public repositories. Its dry
    # run proves the complete package closure before changing host packages.
    ssh._run('\n'.join(checks) + '\ndpkg --dry-run --install ' + arguments, sudo=True, timeout=120)
    ssh._run('DEBIAN_FRONTEND=noninteractive dpkg --install ' + arguments + '\nsystemctl enable --now docker', sudo=True, timeout=900)
