"""Extract scan identity from retained native Syft OCI bytes or Docker inspection.

Missing or contradictory evidence yields no verified identity. In particular an
index repository digest is never substituted for the manifest actually scanned.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
MANIFEST_TYPES = {'application/vnd.oci.image.manifest.v1+json',
                  'application/vnd.docker.distribution.manifest.v2+json'}


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _platform(config):
    parts = [config.get('os'), config.get('architecture')]
    if config.get('variant'):
        parts.append(config['variant'])
    if any(not isinstance(v, str) or not re.fullmatch(r'[a-z0-9_.-]+', v) for v in parts):
        raise ValueError('Missing or invalid platform')
    return '/'.join(parts)


def image_identity(image, document, provenance=None):
    try:
        source = document.get('source', {})
        metadata = source.get('metadata', {})
        if source.get('type') == 'image' and metadata.get('manifest') and metadata.get('config'):
            raw = base64.b64decode(metadata['manifest'], validate=True)
            config_raw = base64.b64decode(metadata['config'], validate=True)
            manifest, config = json.loads(raw), json.loads(config_raw)
            digest = _digest(raw)
            media = manifest.get('mediaType')
            descriptor = manifest['config']
            if (digest != metadata.get('manifestDigest') or media != metadata.get('mediaType')
                    or descriptor.get('digest') != _digest(config_raw)
                    or descriptor.get('size') != len(config_raw)
                    or metadata.get('imageID') != _digest(config_raw)
                    or metadata.get('os') != config.get('os')
                    or metadata.get('architecture') != config.get('architecture')):
                raise ValueError('Contradictory native OCI evidence')
            platform = _platform(config)
        else:
            # Directory SBOMs use the exact image inspected before filesystem
            # materialization. Older Docker engines omit Descriptor: no guessing.
            if source.get('type') != 'directory' or not isinstance(provenance, dict):
                return None
            descriptor = provenance.get('descriptor') or {}
            digest, media = descriptor.get('digest'), descriptor.get('mediaType')
            if (not provenance.get('imageID') or not DIGEST.fullmatch(provenance['imageID'])
                    or not any(isinstance(r, str) and r.endswith('@' + str(digest))
                               for r in provenance.get('repoDigests', []))):
                return None
            platform = _platform(provenance)
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or media not in MANIFEST_TYPES:
            return None
        if '@' in image and image.rsplit('@', 1)[1] != digest:
            return None
        return {'image': image, 'digest': digest, 'platform': platform, 'media_type': media}
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def merge_overview(sboms, overview):
    identities = {}
    for mapping in sorted(Path(sboms).glob('*.image')):
        try:
            image = mapping.read_text().strip()
            document = json.loads(mapping.with_suffix('.json').read_text())
            provenance_path = mapping.with_suffix('.provenance')
            provenance = json.loads(provenance_path.read_text()) if provenance_path.exists() else None
            identity = image_identity(image, document, provenance)
            if identity:
                if image in identities:
                    identities[image] = None  # ambiguous duplicate mappings fail closed
                else:
                    identities[image] = identity
        except (OSError, ValueError):
            continue
    # Declared inventory remains useful architecture evidence but must never be
    # mistaken for scanner-verified immutable identity.
    result = dict(overview)
    if result.get('images'):
        result['declared_images'] = result['images']
    result['images'] = [value for value in identities.values() if value]
    return result


if __name__ == '__main__':
    folder, overview_path = sys.argv[1:]
    path = Path(overview_path)
    path.write_text(json.dumps(merge_overview(folder, json.loads(path.read_text()))), encoding='utf-8')
