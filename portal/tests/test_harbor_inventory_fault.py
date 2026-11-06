import hashlib
import json

import pytest

from harbor_inventory_fault import change, paths
from harbor_inventory_qualification import LABEL, marker


@pytest.fixture
def fixture(tmp_path):
    root, storage = tmp_path / 'workspace', tmp_path / 'storage'
    root.mkdir()
    content = b'unique successor test layer'
    identity = 'sha256:' + hashlib.sha256(content).hexdigest()
    old, new = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64
    target = 'https://harbor-target.test:8443'
    expected = {'label': LABEL, 'source': 'https://harbor-source.test:8443', 'target': target,
        'namespace': 'qualification/staging',
        'omission': {'kind': 'blob', 'index': 100, 'digest': identity, 'size': len(content),
                     'repository': 'qualification/staging/service/image-100', 'parent_digest': new},
        'images': [{'index': 0, 'digest': old, 'marker_layer': {'digest': old}},
                   {'index': 100, 'digest': new, 'marker_layer': {'digest': identity},
                    'expected_stdout': marker(100).decode()}],
        'receipts': {'first': {'artifacts': [{'digest': old}]},
                     'successor': {'artifacts': [{'digest': new}]}}}
    (root / 'expected.json').write_text(json.dumps(expected))
    data = storage / 'docker/registry/v2/blobs/sha256' / identity[7:9] / identity[7:] / 'data'
    data.parent.mkdir(parents=True)
    data.write_bytes(content)
    link = storage / 'docker/registry/v2/repositories' / expected['omission']['repository'] / '_layers/sha256' / identity[7:] / 'link'
    link.parent.mkdir(parents=True)
    link.write_text(identity)
    return root, storage, target, data, content


def test_quarantine_and_restore_preserve_exact_bytes_and_ownership(fixture):
    root, storage, target, data, content = fixture
    change(root, storage, target, 'quarantine')
    assert not data.exists()
    report = json.loads((root / 'target-omission.json').read_text())
    assert report['quarantined_at'] and not report['restored_at']
    with pytest.raises(AssertionError, match='already be quarantined'):
        change(root, storage, target, 'quarantine')
    change(root, storage, target, 'restore')
    assert data.read_bytes() == content
    assert json.loads((root / 'target-omission.json').read_text())['restored_at']


def test_wrong_target_and_baseline_layer_never_mutate(fixture):
    root, storage, target, data, content = fixture
    with pytest.raises(AssertionError, match='exact disposable'):
        change(root, storage, 'https://different.test', 'quarantine')
    expected = json.loads((root / 'expected.json').read_text())
    expected['receipts']['first']['artifacts'].append({'digest': expected['omission']['parent_digest']})
    (root / 'expected.json').write_text(json.dumps(expected))
    with pytest.raises(AssertionError, match='baseline intact'):
        change(root, storage, target, 'quarantine')
    assert data.read_bytes() == content


def test_restore_refuses_changed_quarantined_content(fixture):
    root, storage, target, data, content = fixture
    change(root, storage, target, 'quarantine')
    held = paths(root, storage, target)[3]
    held.write_bytes(b'changed')
    with pytest.raises(AssertionError, match='layer changed'):
        change(root, storage, target, 'restore')
    assert not data.exists()
    held.write_bytes(content)
    change(root, storage, target, 'restore')


def test_restore_refuses_unrelated_ownership_record(fixture):
    root, storage, target, data, _ = fixture
    change(root, storage, target, 'quarantine')
    record = root / 'target-omission.json'
    report = json.loads(record.read_text())
    report['target'] = 'https://different.test'
    record.write_text(json.dumps(report))
    with pytest.raises(AssertionError, match='ownership record changed'):
        change(root, storage, target, 'restore')
    assert not data.exists()


def test_shared_layer_outside_owned_namespace_never_mutates(fixture):
    root, storage, target, data, content = fixture
    expected = json.loads((root / 'expected.json').read_text())
    identity = expected['omission']['digest']
    link = storage / 'docker/registry/v2/repositories/unrelated/image/_layers/sha256' / identity[7:] / 'link'
    link.parent.mkdir(parents=True)
    link.write_text(identity)
    with pytest.raises(AssertionError, match='only owned repository links'):
        change(root, storage, target, 'quarantine')
    assert data.read_bytes() == content
