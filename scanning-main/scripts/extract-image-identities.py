"""Extract scan identity from retained native Syft OCI bytes or Docker inspection.

Missing or contradictory evidence yields no verified identity. In particular an
index repository digest is never substituted for the manifest actually scanned.
"""
import json
from pathlib import Path
import sys

# Keep the CLI importable by callers that load the script by file path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sbom_identity import image_identity, _digest

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
