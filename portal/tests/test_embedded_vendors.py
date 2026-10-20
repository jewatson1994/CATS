"""Offline SUSE acquisition and exact product-scope regression tests."""
import collections
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from app.vex_intelligence import _matches, _parse

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/embedded_vendors.py'
spec = importlib.util.spec_from_file_location('embedded_vendors_test', SCRIPT)
vendors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendors)

# Product/status excerpt captured 2026-10-19 from this CC-BY-4.0 SUSE document.
# Only products relevant to one real assertion remain; the complete production
# document stays in the external acquisition cache. Names/PURLs are unmodified.
URL = 'https://ftp.suse.com/pub/projects/security/csaf-vex/2023/cve-2015-4588.json'
PURL = 'pkg:rpm/suse/libwmf@0_2-7?upstream=libwmf-0:0_2-7.src.rpm'
PRODUCT = 'SUSE Linux Enterprise Desktop 15 SP3:libwmf-0_2-7'
SCOPE = {'publisher': 'https://www.suse.com/', 'products': [{'cpe': 'cpe:/o:suse:sled:15:sp3'}]}
DATE = '2026-10-19T00:17:25Z'


@pytest.fixture
def document():
    return {'document': {'category': 'csaf_vex', 'csaf_version': '2.0',
        'publisher': {'category': 'vendor', 'namespace': 'https://www.suse.com/', 'name': 'SUSE Product Security Team'},
        'notes': [{'category': 'legal_disclaimer', 'text': vendors.LICENSE_NOTICE}],
        'tracking': {'id': 'CVE-2015-4588', 'version': '12', 'current_release_date': DATE, 'status': 'interim'}},
        'product_tree': {'full_product_names': [
            {'name': 'SUSE Linux Enterprise Desktop 15 SP3', 'product_id': 'SUSE Linux Enterprise Desktop 15 SP3',
             'product_identification_helper': {'cpe': 'cpe:/o:suse:sled:15:sp3'}},
            {'name': 'libwmf-0_2-7', 'product_id': 'libwmf-0_2-7',
             'product_identification_helper': {'cpe': 'cpe:2.3:a:wvware:libwmf:0_2:*:*:*:*:*:*:*', 'purl': PURL}}],
            'relationships': [{'category': 'default_component_of',
                'full_product_name': {'name': 'libwmf-0_2-7 as component of SUSE Linux Enterprise Desktop 15 SP3', 'product_id': PRODUCT},
                'product_reference': 'libwmf-0_2-7', 'relates_to_product_reference': 'SUSE Linux Enterprise Desktop 15 SP3'}]},
        'vulnerabilities': [{'cve': 'CVE-2015-4588', 'product_status': {'known_not_affected': [PRODUCT]}}]}


def run_emit(tmp_path, document, *, limit=1024*1024, raw=None):
    path = tmp_path / 'input.json'
    path.write_bytes(raw if raw is not None else vendors.canonical(document))
    records, exclusions = [], collections.Counter()
    state = {'documents': [(path, {'url': URL, 'acquired_at': DATE})], 'max_canonical_bytes': limit, 'metrics': {}}
    metrics = vendors.emit_vendor_records(state, records.append, _parse, exclusions)
    return records, exclusions, metrics


def test_official_suse_excerpt_requires_exact_product_context(tmp_path, document):
    records, exclusions, metrics = run_emit(tmp_path, document)
    assert not exclusions
    assert records[0]['raw'] == document
    assert records[0]['url'] == URL
    cve, identity, status, *_ = _parse(vendors.canonical(records[0]['raw']))[-1][0]
    assert (cve, status) == ('CVE-2015-4588', 'not_affected')
    assert identity['purl'] == PURL
    assert identity['csaf_product_context'] == SCOPE
    assert _matches(identity, {'purl': PURL, 'csaf_product_context': SCOPE})
    assert not _matches(identity, {'purl': PURL})
    assert not _matches(identity, {'purl': PURL, 'version': '0_2-8', 'csaf_product_context': SCOPE})
    wrong_scope = copy.deepcopy(SCOPE)
    wrong_scope['products'][0]['cpe'] = 'cpe:/o:suse:sled:15:sp4'
    assert not _matches(identity, {'purl': PURL, 'csaf_product_context': wrong_scope})
    assert not _matches(identity, {'purl': PURL.split('?')[0], 'csaf_product_context': SCOPE})
    assert metrics['versioned_status_not_affected'] == 1
    assert metrics['product_context_statements'] == 1


def test_recommended_status_is_preserved_as_supplemental_only(tmp_path, document):
    # Synthetic status change to the real identity tests the separate category.
    document['vulnerabilities'][0]['product_status'] = {'recommended': [PRODUCT]}
    records, exclusions, metrics = run_emit(tmp_path, document)
    assert not exclusions
    assert len(records) == 2
    assert _parse(vendors.canonical(records[0]['raw']))[-1] == []
    advisory = records[1]
    assert advisory['kind'] == 'advisory'
    assert advisory['product'] is None
    assert advisory['data']['status'] == 'recommended'
    assert advisory['data']['affected_identities'][0]['csaf_product_context'] == SCOPE
    assert advisory['data']['raw'] == document
    assert metrics['recommended_product_identities'] == 1
    assert metrics['normalized_statements'] == 0


@pytest.mark.parametrize('change', ['license', 'publisher'])
def test_unreviewed_document_authority_or_license_is_excluded(tmp_path, document, change):
    if change == 'license':
        document['document']['notes'][0]['text'] = 'All rights reserved'
    else:
        document['document']['publisher']['namespace'] = 'https://other.example/'
    records, exclusions, _ = run_emit(tmp_path, document)
    assert records == []
    assert exclusions['suse_unreviewed_document_license_or_authority'] == 1


def test_duplicate_json_keys_and_oversize_documents_are_excluded(tmp_path, document):
    raw = vendors.canonical(document)
    duplicate = raw[:-1] + b',"vulnerabilities":[]}'
    records, exclusions, _ = run_emit(tmp_path, document, raw=duplicate)
    assert records == []
    assert exclusions['suse_invalid_document'] == 1
    records, exclusions, _ = run_emit(tmp_path, document, limit=len(raw)-1)
    assert records == []
    assert exclusions['suse_canonical_size_above_limit'] == 1


def test_selection_cross_checks_indexes_and_directory_deterministically():
    paths = ['2023/cve-2023-1234.json', '2023/cve-2023-2345.json', '2023/cve-2023-3456.json']
    changes = '\n'.join(f'{p},2026-10-{day:02d}T00:00:00Z' for p, day in zip(paths, [1, 3, 9]))
    dirs = {'2023': ''.join(f'<a href="{p.split("/")[1]}">x</a>' for p in paths[:2])}
    selected, metrics = vendors.select_paths('\n'.join(paths), changes, dirs, 1)
    assert selected == [paths[1]]
    assert metrics['index_missing_from_directories'] == 1
    assert metrics['not_selected_document_limit'] == 1
    with pytest.raises(ValueError, match='Invalid'):
        vendors.select_paths('../evil.json', changes, dirs, 2)
    with pytest.raises(ValueError, match='limit'):
        vendors.select_paths('\n'.join(paths), changes, dirs, True)


def test_prepare_pins_data_license_and_returns_reviewable_metadata(tmp_path, monkeypatch, document):
    license_bytes = b'test license bytes, never production intelligence'
    monkeypatch.setattr(vendors, 'LICENSE_SHA256', hashlib.sha256(license_bytes).hexdigest())
    relative = '2023/cve-2015-4588.json'
    payloads = {'suse-vex-index.txt': relative.encode(),
        'suse-vex-changes.csv': (relative + ',' + DATE).encode(),
        'suse-vex-directory-2023.html': b'<a href="cve-2015-4588.json">CVE</a>',
        'LICENSE-suse.txt': license_bytes, 'suse-vex-2023-cve-2015-4588.json': vendors.canonical(document)}
    def acquire(name, url):
        path = tmp_path / name
        path.write_bytes(payloads[name])
        return path, {'url': url, 'sha256': hashlib.sha256(payloads[name]).hexdigest(), 'bytes': len(payloads[name]), 'acquired_at': DATE}
    sources, state = vendors.prepare_vendor_sources(acquire, max_documents=1)
    assert sources[0]['trusted'] is True
    assert sources[0]['authoritative_prefixes'] == ['pkg:rpm/suse/']
    assert sources[0]['selection']['selected_documents'] == 1
    assert sources[1]['trusted'] is False
    assert sources[1]['category'] == 'advisory'
    assert state['license_files']['LICENSE-suse.txt'].read_bytes() == license_bytes
    monkeypatch.setattr(vendors, 'LICENSE_SHA256', '0'*64)
    with pytest.raises(ValueError, match='license changed'):
        vendors.prepare_vendor_sources(acquire, max_documents=1)
