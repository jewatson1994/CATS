import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit
from app.package_identity_resolution import resolve_package_identity
from app.embedded_intelligence import _manifest, PACKAGE_DIR, PINNED_KEY
sys.path.insert(0, '/opt/cats/scanning/scripts')
from sbom_identity import package_identity, PACKAGE_METADATA_FIELDS
expected = json.loads(Path('/checks/source-manifest.json').read_text(encoding='utf-8-sig'))
verified = {}
for relative, digest in expected.items():
    if relative.startswith('portal/app/'):
        packaged = Path('/app/app') / relative[len('portal/app/'):]
    elif relative.startswith('scanning-main/scripts/'):
        packaged = Path('/opt/cats/scanning/scripts') / relative[len('scanning-main/scripts/'):]
    else:
        continue
    actual = hashlib.sha256(packaged.read_bytes()).hexdigest()
    assert actual == digest, (relative, actual, digest)
    verified[relative] = actual
assert os.environ['CATS_VERSION'] == '2026.10.20.3'
manifest = _manifest(PACKAGE_DIR, PINNED_KEY)
fixtures = json.loads(Path('/checks/retained-installed-packages.json').read_text(encoding='utf-8-sig'))['records']
now = datetime.now(timezone.utc)
results = []
for fixture in fixtures:
    artifact = fixture['artifact']
    purl = artifact['purl']
    qualifiers = parse_qs(urlsplit(purl).query)
    observed = {'context': {'purl': purl, 'product_id': purl, 'version': artifact['version'], 'distro': qualifiers['distro'][0]},
        'raw_purl': purl, 'raw_installed_version': artifact['version'], 'image_digest': fixture['image_digest'],
        'sbom_descriptor': fixture['descriptor'], 'sbom_schema': fixture['schema'],
        'sbom_distro': fixture['distro'], 'sbom_artifact': copy.deepcopy(artifact),
        'source': fixture['source'], 'observed_at': fixture['captured_at']}
    original = copy.deepcopy(observed)
    result = resolve_package_identity(observed, now=now)
    assert observed == original and result['observed_identity'] == original
    assert result['candidates'][0]['kind'] == 'exact_observed'
    assert result['candidates'][0]['context'] == original['context']
    derived = [c for c in result['candidates'] if c['kind'] == 'authoritative_resolved']
    source = [c for c in derived if c['relationship'] == 'installed_binary_to_source']
    if artifact['type'] == 'rpm':
        assert not derived
        assert result['reasons'] == ['source_rpm_epoch_and_vendor_product_context_unverified']
        assert result['relationships'][0]['details']['source_epoch'] is None
    else:
        assert len(source) == 1
        assert source[0]['context']['version'] == (artifact['metadata']['sourceVersion'] or artifact['version'])
    preserved = package_identity(artifact)
    assert json.loads(preserved['package_metadata']) == {k:v for k,v in artifact['metadata'].items() if k in PACKAGE_METADATA_FIELDS}
    assert preserved['package_metadata_type'] == artifact['metadataType']
    assert preserved['package_found_by'] == artifact['foundBy']
    results.append({'capture': fixture['capture'], 'name': artifact['name'], 'outcome': result['outcome'], 'candidate_count': len(result['candidates']), 'source_purls': [c['context']['purl'] for c in source]})
base = fixtures[0]
a = base['artifact']
purl = a['purl']
identity = {'context': {'purl': purl, 'product_id': purl, 'version': a['version'], 'distro': 'ubuntu-22.04'},
    'raw_installed_version': a['version'], 'image_digest': base['image_digest'], 'sbom_descriptor': base['descriptor'],
    'sbom_distro': base['distro'], 'sbom_artifact': a, 'observed_at': base['captured_at']}
negative = []
for case in ('missing_cataloger', 'source_conflict', 'distro_conflict', 'future_evidence', 'expired_evidence'):
    changed = copy.deepcopy(identity)
    if case == 'missing_cataloger': changed['sbom_artifact'].pop('foundBy')
    elif case == 'source_conflict': changed['sbom_artifact']['metadata']['sourceVersion'] = '0-invalid'
    elif case == 'distro_conflict': changed['sbom_distro']['versionCodename'] = 'noble'
    elif case == 'future_evidence': changed['observed_at'] = (now + timedelta(days=1)).isoformat()
    elif case == 'expired_evidence': changed['evidence_valid_until'] = now.isoformat()
    result = resolve_package_identity(changed, now=now)
    assert len(result['candidates']) == 1 and result['candidates'][0]['context'] == identity['context']
    assert result['reasons']
    negative.append({'case': case, 'outcome': result['outcome'], 'reasons': result['reasons']})
print(json.dumps({'release_version': os.environ['CATS_VERSION'], 'packaged_source_files_verified': len(verified), 'source_sha256': verified,
    'embedded_intelligence': {'version': manifest['version'], 'sequence': manifest['sequence'], 'payload_sha256': manifest['payload_sha256'], 'counts': manifest.get('counts'), 'source_count': len(manifest['sources'])},
    'retained_metadata_cases': results, 'negative_resolution_cases': negative}, indent=2))