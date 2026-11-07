"""Reversibly omit one successor-only test layer in an owned Harbor target.

Run only with the explicitly mounted disposable target registry volume. Restore
in a finally/cleanup path; this never removes an image or changes signed data.
Shared global blobs require the explicit repository-link mechanism, which only
omits the owned repository's layer membership and preserves every other link.
Registries with cached repository descriptors may still serve that blob after
the link is held. The caller must also quarantine and restore only the exact
repository-scoped cached descriptor, never flush a shared cache, and prove the
omission through the normal target HTTP route before relying on the fault.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from harbor_graph_qualification import host, require, write_json
from harbor_inventory_qualification import LABEL, marker


MECHANISMS = {
    'blob-data': 'same-directory reversible layer rename',
    'repository-link': 'same-directory reversible repository layer link rename',
}


def safe_path(path, root):
    return (path.resolve().is_relative_to(root.resolve())
            and not any(item.is_symlink() for item in (path, *path.parents)))


def blob_path(storage, identity):
    checksum = identity[7:]
    return storage.resolve() / 'docker/registry/v2/blobs/sha256' / checksum[:2] / checksum / 'data'


def paths(workspace, storage, confirmed_target, mechanism='blob-data'):
    require(mechanism in MECHANISMS, 'Unknown fault mechanism')
    require(safe_path(workspace / 'expected.json', workspace)
            and safe_path(workspace / 'target-omission.json', workspace)
            and not any(item.is_symlink() for item in (storage, *storage.parents)),
            'Unsafe qualification workspace or registry storage path')
    expected = json.loads((workspace / 'expected.json').read_text(encoding='utf-8'))
    require(expected['label'] == LABEL and confirmed_target == expected['target']
            and host(expected['target']) != host(expected['source']),
            'Confirm the exact disposable qualification target')
    target = expected['omission']
    require(target['kind'] == 'blob' and target['index'] == 100
            and re.fullmatch(r'sha256:[a-f0-9]{64}', target['digest']),
            'Only the fixed successor-only marker layer may be omitted')
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9._-]*', part)
                for value in (expected['namespace'], target['repository']) for part in value.split('/'))
            and expected['namespace'].startswith('qualification/')
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
    data = (blob_path(storage, target['digest']) if mechanism == 'blob-data' else
            volume / 'docker/registry/v2/repositories' / target['repository'] / '_layers/sha256' / checksum / 'link')
    held = data.with_name(data.name + '.cats-staging-inventory-held')
    require(safe_path(data, volume) and safe_path(held, volume)
            and safe_path(blob_path(storage, target['digest']), volume),
            'Unsafe registry storage path')
    return expected, target, data, held


def change(workspace, storage, confirmed_target, phase, mechanism='blob-data'):
    require(phase in ('quarantine', 'restore'), 'Unknown fault phase')
    expected, target, data, held = paths(workspace, storage, confirmed_target, mechanism)
    record = workspace / 'target-omission.json'
    if mechanism == 'repository-link':
        global_data = blob_path(storage, target['digest'])
        require(global_data.is_file(), 'Shared test layer must remain present')
        content = global_data.read_bytes()
        require('sha256:' + hashlib.sha256(content).hexdigest() == target['digest']
                and len(content) == target['size'], 'Stored test layer fails integrity verification')
    if phase == 'quarantine':
        repositories = storage.resolve() / 'docker/registry/v2/repositories'
        if mechanism == 'blob-data':
            links = list(repositories.glob('**/_layers/sha256/' + target['digest'][7:] + '/link'))
            require(links and all(
                safe_path(link, repositories)
                and link.relative_to(repositories).as_posix().startswith(expected['namespace'] + '/')
                and link.read_text().strip() == target['digest'] for link in links),
                'Test layer must have only owned repository links')
        else:
            links = [data]
        require(data.is_file() and not held.exists(), 'Layer must exist and not already be quarantined')
        content = data.read_bytes()
        if mechanism == 'blob-data':
            require('sha256:' + hashlib.sha256(content).hexdigest() == target['digest']
                    and len(content) == target['size'], 'Stored test layer fails integrity verification')
        else:
            require(content.strip() == target['digest'].encode('ascii'), 'Repository layer link differs from test digest')
        report = {'format': 'cats-staging-inventory-omission-v1', 'target': expected['target'],
                  'object': target, 'bytes': target['size'], 'mechanism': MECHANISMS[mechanism],
                  'storage_path': data.relative_to(storage.resolve()).as_posix(),
                  'held_path': held.relative_to(storage.resolve()).as_posix(),
                  'quarantined_content_sha256': hashlib.sha256(content).hexdigest(),
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
        require(report['format'] == 'cats-staging-inventory-omission-v1'
                and report['target'] == expected['target'] and report['object'] == target
                and report['mechanism'] == MECHANISMS[mechanism]
                and report['storage_path'] == data.relative_to(storage.resolve()).as_posix()
                and report['held_path'] == held.relative_to(storage.resolve()).as_posix(),
                'Quarantine ownership record changed')
        content = held.read_bytes()
        require(hashlib.sha256(content).hexdigest() == report['quarantined_content_sha256']
                and (('sha256:' + hashlib.sha256(content).hexdigest() == target['digest']
                      and len(content) == target['size']) if mechanism == 'blob-data' else
                     content.strip() == target['digest'].encode('ascii')),
                'Quarantined layer changed')
        held.rename(data)
        report['restored_at'] = datetime.now(timezone.utc).isoformat()
    write_json(record, report)
    print(json.dumps({'phase': phase, 'digest': target['digest'], 'bytes': target['size'], 'mechanism': mechanism}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('quarantine', 'restore'))
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--registry-storage', required=True, type=Path)
    parser.add_argument('--confirm-target', required=True)
    parser.add_argument('--mechanism', choices=tuple(MECHANISMS), default='blob-data')
    args = parser.parse_args()
    change(args.workspace, args.registry_storage, args.confirm_target, args.phase, args.mechanism)


if __name__ == '__main__':
    main()
