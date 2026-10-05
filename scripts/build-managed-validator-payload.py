"""Assemble a disconnected validator payload from explicitly acquired local assets.
Run with --help. This tool never fetches packages or images.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'portal'))
from app.validator_payload import REQUIRED, validate_payload


def assemble(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError('Output must not exist; existing payloads are never overwritten')
    specification = json.loads((source / 'specification.json').read_text())
    # specification references only local staged relative paths.
    assets = specification['assets']
    names = set(assets.values()) | set(specification['packages'])
    for name in names:
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name or not re.fullmatch(r'[A-Za-z0-9_./-]+', name) or name == 'manifest.json':
            raise ValueError('Unsafe source path')
        path = source / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source):
            raise ValueError('Unsafe or missing source asset')
        if any(p.is_symlink() for p in path.parents if p != source.parent):
            raise ValueError('Source symlinks forbidden')
    # Check application archive before publishing hashes. Wheels must be a closure,
    # validated separately with pip --no-index on the supported OS/architecture.
    with tarfile.open(source / assets['validator']) as archive:
        members = archive.getmembers()
        if any(m.issym() or m.islnk() or m.isdev() or m.name.startswith('/') or '..' in Path(m.name).parts for m in members):
            raise ValueError('Unsafe validator application archive')
        archive_names = {m.name.removeprefix('./') for m in members if m.isfile()}
        if not {'requirements.txt', 'validator_server.py'}.issubset(archive_names) or not any(n.startswith('wheels/') and n.endswith('.whl') for n in archive_names) or not any(n.startswith('app/') for n in archive_names):
            raise ValueError('Application archive requires launcher, app, requirements and wheels')
    with tarfile.open(source / assets['self_test_chart']) as archive:
        members = archive.getmembers()
        if any(m.issym() or m.islnk() or m.isdev() or m.name.startswith('/') or '..' in Path(m.name).parts for m in members):
            raise ValueError('Unsafe self-test chart archive')
        if 'Chart.yaml' not in {m.name.removeprefix('./') for m in members}:
            raise ValueError('Chart.yaml must be at archive root')
    destination.mkdir(parents=True)
    try:
        manifest = {k: v for k, v in specification.items() if k != 'files'}
        manifest['format'] = 1
        manifest['files'] = {}
        for name in sorted(names):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
            digest = hashlib.sha256()
            with target.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            manifest['files'][name] = {'size': target.stat().st_size, 'sha256': digest.hexdigest()}
        (destination/'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n')
        validate_payload(destination, expected_sha256=hashlib.sha256((destination/'manifest.json').read_bytes()).hexdigest())
    except Exception:
        # Preserve partial output for inspection; it is never considered valid.
        raise
    return hashlib.sha256((destination/'manifest.json').read_bytes()).hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Staging directory containing specification.json and local assets')
    parser.add_argument('destination', help='New output directory')
    args = parser.parse_args()
    print(assemble(args.source, args.destination))
