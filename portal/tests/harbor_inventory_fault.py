"""Reversibly omit one successor-only test layer in an owned Harbor target.

Run only with the explicitly mounted disposable target registry volume. Restore
in a finally/cleanup path; this never removes an image or changes signed data.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from harbor_graph_qualification import host, require, write_json
from harbor_inventory_qualification import LABEL, marker


def paths(workspace, storage, confirmed_target):
    expected = json.loads((workspace / 'expected.json').read_text(encoding='utf-8'))
    require(expected['label'] == LABEL and confirmed_target == expected['target']
            and host(expected['target']) != host(expected['source']),
            'Confirm the exact disposable qualification target')
    target = expected['omission']
    require(target['kind'] == 'blob' and target['index'] == 100
            and re.fullmatch(r'sha256:[a-f0-9]{64}', target['digest']),
            'Only the fixed successor-only marker layer may be omitted')
    require(expected['namespace'].startswith('qualification/')
            and target['repository'].startswith(expected['namespace'] + '/'),
            'The target must belong to this qualification subtree')
    images = {item['index']: item for item in expected['images']}
    image = images[100]
    require(image['marker_layer']['digest'] == target['digest']
            and image['digest'] == target['parent_digest']
            and image['expected_stdout'] == marker(100).decode()
            and all(item['marker_layer']['digest'] != target['digest']
                    for index, item in images.items() if index < 100),
            'Omission must be unique to the successor corpus')
    first = expected['receipts']['first']['artifacts']
    successor = expected['receipts']['successor']['artifacts']
    require(not any(item['digest'] == image['digest'] for item in first)
            and any(item['digest'] == image['digest'] for item in successor),
            'Omission must leave the entire active baseline intact')
    checksum = target['digest'][7:]
    volume = storage.resolve()
    data = volume / 'docker/registry/v2/blobs/sha256' / checksum[:2] / checksum / 'data'
    held = data.with_name('data.cats-staging-inventory-held')
    require(data.resolve().is_relative_to(volume) and held.resolve().is_relative_to(volume)
            and not any(path.is_symlink() for path in (data, held, *data.parents)),
            'Unsafe registry storage path')
    return expected, target, data, held


def change(workspace, storage, confirmed_target, phase):
    require(phase in ('quarantine', 'restore'), 'Unknown fault phase')
    expected, target, data, held = paths(workspace, storage, confirmed_target)
    record = workspace / 'target-omission.json'
    if phase == 'quarantine':
        repositories = storage.resolve() / 'docker/registry/v2/repositories'
        links = list(repositories.glob('**/_layers/sha256/' + target['digest'][7:] + '/link'))
        require(links and all(
            link.resolve().is_relative_to(repositories)
            and not any(path.is_symlink() for path in (link, *link.parents))
            and link.relative_to(repositories).as_posix().startswith(expected['namespace'] + '/')
            and link.read_text().strip() == target['digest'] for link in links),
            'Test layer must have only owned repository links')
        require(data.is_file() and not held.exists(), 'Layer must exist and not already be quarantined')
        content = data.read_bytes()
        require('sha256:' + hashlib.sha256(content).hexdigest() == target['digest']
                and len(content) == target['size'], 'Stored test layer fails integrity verification')
        report = {'format': 'cats-staging-inventory-omission-v1', 'target': expected['target'],
                  'object': target, 'bytes': len(content), 'mechanism': 'same-directory reversible layer rename',
                  'owned_repository_link_count': len(links),
                  'prepared_at': datetime.now(timezone.utc).isoformat(), 'quarantined_at': None,
                  'restored_at': None}
        write_json(record, report)
        data.rename(held)
        report['quarantined_at'] = datetime.now(timezone.utc).isoformat()
    else:
        require(held.is_file() and not data.exists() and record.is_file(),
                'No exclusively quarantined layer to restore')
        report = json.loads(record.read_text(encoding='utf-8'))
        require(report['target'] == expected['target'] and report['object'] == target,
                'Quarantine ownership record changed')
        require('sha256:' + hashlib.sha256(held.read_bytes()).hexdigest() == target['digest'],
                'Quarantined layer changed')
        held.rename(data)
        report['restored_at'] = datetime.now(timezone.utc).isoformat()
    write_json(record, report)
    print(json.dumps({'phase': phase, 'digest': target['digest'], 'bytes': target['size']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('quarantine', 'restore'))
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--registry-storage', required=True, type=Path)
    parser.add_argument('--confirm-target', required=True)
    args = parser.parse_args()
    change(args.workspace.resolve(), args.registry_storage, args.confirm_target, args.phase)


if __name__ == '__main__':
    main()
