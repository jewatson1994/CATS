"""Whole-document Red Hat acquisition and licensing regression tests."""
import collections
import importlib.util
import io
import json
import tarfile
import sys
from pathlib import Path
import pytest

zstandard = pytest.importorskip('zstandard')
SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'embedded_redhat.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('embedded_redhat_under_test', SCRIPT)
redhat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redhat)


def source_document():
    return {'document': {'notes': [{'category': 'legal_disclaimer', 'text': redhat.LEGAL_NOTICE}],
        'publisher': {'namespace': 'https://www.redhat.com'}}, 'synthetic_test_only': True,
        'vulnerabilities': [{'cve': 'CVE-2026-12345', 'product_status': {'fixed': ['test']}}]}


def make_state(tmp_path, members):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w') as archive:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    target = tmp_path / 'archive.tar.zst'
    target.write_bytes(zstandard.ZstdCompressor().compress(payload.getvalue()))
    return {'archive': target, 'archive_meta': {'acquired_at': '2026-10-19T00:00:00+00:00'}, 'source': {},
            'max_canonical_bytes': 262144}


def parse_stub(raw):
    return (json.loads(raw), [])


def test_retains_entire_original_object_and_excludes_unsafe_names(tmp_path):
    data = source_document()
    raw = json.dumps(data, indent=4).encode()
    state = make_state(tmp_path, [('2026/cve-2026-12345.json', raw), ('../outside.json', raw)])
    rows, excluded = [], collections.Counter()
    result = redhat.emit_records(state, rows.append, parse_stub, excluded)
    assert rows[0]['raw'] == data
    assert rows[0]['url'] == redhat.BASE_URL + '2026/cve-2026-12345.json'
    assert rows[0]['upstream_sha256'] == redhat.hashlib.sha256(raw).hexdigest()
    assert result['retained_documents'] == 1
    assert result['documents_without_normalized_statements'] == 1
    assert excluded['redhat_non_cve_member'] == 1
    assert state['source']['selection'] == result


def test_whole_documents_excluded_above_cap_without_truncation(tmp_path):
    data = source_document()
    state = make_state(tmp_path, [('2026/cve-2026-12345.json', json.dumps(data).encode())])
    state['max_canonical_bytes'] = 30
    rows, excluded = [], collections.Counter()
    redhat.emit_records(state, rows.append, parse_stub, excluded)
    assert rows == []
    assert excluded['redhat_canonical_size_above_limit'] == 1


def test_changed_redistribution_notice_fails_closed(tmp_path):
    data = source_document()
    data['document']['notes'][0]['text'] = 'Changed test-only license terms'
    state = make_state(tmp_path, [('2026/cve-2026-12345.json', json.dumps(data).encode())])
    with pytest.raises(ValueError, match='redistribution notice changed'):
        redhat.emit_records(state, lambda _: pytest.fail('Unreviewed data emitted'), parse_stub, collections.Counter())


def test_duplicate_json_key_never_normalizes_to_authoritative_statement(tmp_path):
    data = b'{"document":{},"document":{}}'
    state = make_state(tmp_path, [('2026/cve-2026-12345.json', data)])
    excluded = collections.Counter()
    redhat.emit_records(state, lambda _: pytest.fail('Ambiguous document emitted'), parse_stub, excluded)
    assert excluded['redhat_invalid_json'] == 1


def test_archive_locator_cannot_escape_publisher_scope(tmp_path):
    index = tmp_path / 'index.txt'
    index.write_text('../other/archive.tar.zst')
    def acquire(name, url):
        assert name == 'redhat-archive-latest.txt'
        return index, {}
    with pytest.raises(ValueError, match='archive locator'):
        redhat.prepare_sources(acquire)


def test_archive_decompression_bound_applies_before_non_regular_skip(tmp_path, monkeypatch):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w') as archive:
        info = tarfile.TarInfo('ignored-link')
        info.type = tarfile.SYMTYPE
        info.linkname = '../outside'
        archive.addfile(info)
    state = make_state(tmp_path, [])
    state['archive'].write_bytes(zstandard.ZstdCompressor().compress(payload.getvalue()))
    monkeypatch.setattr(redhat, 'MAX_ARCHIVE_BYTES', -1)
    with pytest.raises(ValueError, match='decompression bound'):
        redhat.emit_records(state, lambda _: pytest.fail('Nonregular member emitted'), parse_stub, collections.Counter())
