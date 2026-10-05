"""Seal locally qualified managed-validator assets during an image build; never downloads."""
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'portal'))

def seal_release(source, seal, cats_version):
    """Validate qualified release inputs with the runtime verifier, then seal them."""
    from app.validator_payload_builds import validate_release, load_release_platform
    source, seal = Path(source), Path(seal)
    digest = hashlib.sha256((source / 'release.json').read_bytes()).hexdigest()
    release = validate_release(source, digest)
    if not cats_version or release['cats_version'] != cats_version:
        raise ValueError('Qualified assets must match the explicit CATS_VERSION build argument')
    platforms = {(p['os'], p['os_version'], p['architecture']) for p in release['platforms']}
    if ('ubuntu', '22.04', 'amd64') not in platforms:
        raise ValueError('Release requires qualified Ubuntu 22.04 amd64 assets')
    for entry in release['platforms']:
        load_release_platform(source, digest, entry)
    if seal.exists():
        raise ValueError('Release seal already exists')
    seal.parent.mkdir(parents=True, exist_ok=True)
    seal.write_text(digest + '\n', encoding='ascii')
    return digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('seal')
    parser.add_argument('--cats-version', required=True)
    args = parser.parse_args()
    print(seal_release(args.source, args.seal, args.cats_version))
