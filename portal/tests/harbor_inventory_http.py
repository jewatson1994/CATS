"""Opt-in 100-image qualification against a real HTTP/PostgreSQL replica.

The publisher driver supplies expected.json. This verifier uses normal signed-in
administration, sync and proxy APIs only. The caller owns Harbor replication,
failure injection/restoration, source shutdown and any fresh blob-cache volume.
Private sessions/principal credentials stay in workspace/http/replica-state.json.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.parse import quote, urlsplit

import requests

import nginx_replica_workflow as workflow
from nginx_replica_acceptance import (
    _base, _digest, _override_url, _require, assert_disconnected, assert_override_admin_denied,
    assert_override_uses, assert_root_denied,
    exact_override_payload, pull_graph, revoke_override, verify_evidence,
)
from nginx_workflow_integration import API, load, save


def now():
    return datetime.now(timezone.utc).isoformat()


def public_receipt(value):
    result = copy.deepcopy(value)

    def project(item):
        if isinstance(item, dict):
            return {key: project(child) for key, child in item.items() if key != 'path'}
        if isinstance(item, list):
            return [project(child) for child in item]
        return item

    result['manifest'] = project(result['manifest'])
    return result


def validate_expected(expected, *, successor=False):
    _require(isinstance(expected, dict), 'Publisher expected.json is required')
    _require(_base(expected['source']) != _base(expected['target']), 'Source and target must differ')
    _digest(expected['trusted_fingerprint'])
    images = expected['images']
    counts = {123} if successor else {100, 123}
    _require(len(images) in counts and [item['index'] for item in images] == list(range(len(images))),
             'Expected ordered 100-image baseline or complete 123-image corpus')
    roots = [_digest(item['digest']) for item in images]
    _require(len(set(roots)) == len(images), 'Every corpus image must have a distinct immutable root')
    _require(expected['first_indices'] == list(range(100))
             and expected['successor_indices'] == list(range(23, 123)),
             'Qualification requires exactly 77 retained, 23 retired and 23 replacement images')
    labels = ('first', 'successor') if successor else ('first',)
    for label in labels:
        receipt = expected['receipts'][label]
        _require(receipt.get('status') == 'published'
                 and receipt.get('verification_status') == receipt.get('signature_status') == 'verified',
                 'Use actual completed verified production publication receipts')
        actual = [item['digest'] for item in receipt['artifacts'] if item['kind'] == 'image']
        wanted = {roots[index] for index in expected[label + '_indices']}
        _require(len(actual) == 100 and set(actual) == wanted, 'Receipt inventory differs from expected 100 roots')
        _require(receipt['manifest']['signing_fingerprint'] == expected['trusted_fingerprint'],
                 'Publication signer differs from the independently retained pin')
        _require(workflow.reference_repository(receipt['release']['reference']) == expected['release_repository'],
                 'Release discovery repository differs from the retained exact scope')
    if successor:
        first = expected['receipts']['first']['manifest']['portable']
        second = expected['receipts']['successor']['manifest']['portable']
        _require(second['supersedes_release_uuid'] == first['release_uuid'],
                 'Successor must explicitly identify the retained first release')


def binding(expected):
    return {key: expected[key] for key in ('source', 'target', 'namespace', 'service_key',
                                         'trusted_fingerprint', 'release_repository')} | {
        'first_release_digest': expected['receipts']['first']['release']['digest'],
        'first_root_digests': [item['digest'] for item in expected['images'][:100]]}


def persist(root, state, report):
    workflow.persist(root, state, report)


def publisher_urls(expected, supplied=None):
    """Additional health probes cannot replace the actual source registry."""
    source = _base(expected['source']) + '/v2/'
    urls = list(dict.fromkeys([source, *(supplied or [])]))
    for url in urls:
        _base(url)
    return urls


def source_probes(root, state, report, urls, ca, *, offline, label):
    _require(urls, 'Explicit source publisher probe URLs are required')
    if offline:
        online = report.get('source_online', {})
        _require(online.get('urls') == urls and online.get('reachable') is True,
                 'Offline proof requires the same successfully contacted source endpoints from baseline')
    with requests.Session() as session:
        session.trust_env = False
        session.verify = str(ca)
        if offline:
            observations = assert_disconnected(session, urls)
        else:
            observations = []
            for url in urls:
                _base(url)  # Validate credentials/query policy without changing the endpoint path.
                response = session.get(url, timeout=15, allow_redirects=False)
                try:
                    _require(response.status_code in (200, 401), 'Source online baseline must answer normally')
                    observations.append({'url': url, 'status': response.status_code})
                finally:
                    response.close()
    report[label] = {'checked_at': now(), 'urls': urls, 'reachable': not offline, 'probes': observations}
    persist(root, state, report)
    return report[label]


def sync_job(api, root, state, report, label, *, rejected=False, timeout=3600):
    queued = api.post('/api/replica/sync', {'source_id': state['source_id']})['jobs']
    _require(len(queued) == 1, 'Exactly one explicitly scoped sync job is required')
    identity, deadline, previous = queued[0]['id'], time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        job = next((item for item in api.get('/api/replica/status')['jobs'] if item['id'] == identity), None)
        _require(job is not None, 'Submitted sync job must remain visible')
        if job['status'] != previous:
            print(f'{label} sync {identity}: {job["status"]}', flush=True)
            previous = job['status']
        if job['status'] in {'completed', 'failed', 'cancelled'}:
            break
        time.sleep(3)
    else:
        raise TimeoutError('Inventory synchronization exceeded the explicit one-hour bound')
    result = job.get('result') or {}
    report[label + '_sync'] = {key: job.get(key) for key in
                              ('id', 'status', 'result', 'error', 'created_at', 'completed_at')}
    persist(root, state, report)
    if rejected:
        _require(job['status'] == 'failed' and result.get('failed', 0) >= 1,
                 'Incomplete candidate must produce an actual rejected release and terminal failed sync')
    else:
        _require(job['status'] == 'completed' and result.get('failed', 0) == 0,
                 'Complete release must synchronize without any rejected candidate')
    return job


def target_omission(expected, ca):
    """Prove missing target content, then reject it with the production verifier.

    The public job API deliberately sanitizes worker exception details. Its
    terminal failure is checked separately; it cannot establish this cause.
    These reads do not use or populate the replica's proxy blob cache.
    """
    from app import portable_release as portable, release_oci as oci

    target = expected['omission']
    image = expected['images'][100]
    marker = image['marker_layer']
    _require(target['kind'] == 'blob' and target['index'] == 100
             and target['parent_digest'] == image['digest']
             and all(target[key] == marker[key] for key in ('digest', 'size', 'mediaType')),
             'The omission must identify the exact successor-only marker descriptor')
    _require(target['repository'].startswith(expected['namespace'] + '/')
             and any(item['digest'] == image['digest']
                     and workflow.reference_repository(item['reference']) == target['repository']
                     for item in expected['receipts']['successor']['artifacts']),
             'The parent must be a published successor image in this exact fixture')
    registry = urlsplit(_base(expected['target'])).netloc
    parent_reference = registry + '/' + target['repository'] + '@' + target['parent_digest']
    host, repository, parent_digest = oci._reference(parent_reference)
    env = {**os.environ, 'SSL_CERT_FILE': str(ca)}
    client = oci._Client(host, repository, env, pull_only=True)
    status, _, parent = client.request('GET', client.api + '/manifests/' + parent_digest)
    _require(status == 200 and oci._digest(parent) == parent_digest,
             'Omitted layer parent must remain reachable and match its immutable digest')
    document = portable.load_json(parent)
    _require(any(all(layer.get(key) == marker[key] for key in ('digest', 'size', 'mediaType'))
                 for layer in document.get('layers', [])),
             'The reachable parent must reference the exact omitted marker')
    proof = {'checked_at': now(), 'target': expected['target'], 'object': target,
             'parent': {'status': status, 'bytes': len(parent), 'digest': oci._digest(parent)},
             'source_reads': 0}
    try:
        status, headers, body = client.request('GET', client.api + '/blobs/' + target['digest'],
                                                limit=max(marker['size'] * 2, 65536))
    except oci._RegistryError as error:
        _require(error.status == 404, 'Omitted layer must be absent, not denied or unreachable')
        proof['blob'] = {'status': 404, 'bytes': None, 'digest': None,
                         'body_observation': 'Registry client discards error response bodies.'}
    else:
        _require(status == 200 and (len(body) != marker['size'] or oci._digest(body) != marker['digest']),
                 'Omitted layer must be absent or demonstrably corrupt')
        proof['blob'] = {'status': status, 'bytes': len(body), 'digest': oci._digest(body),
                         'content_length': headers.get('Content-Length'),
                         'empty_body_for_nonempty_blob': len(body) == 0 and marker['size'] > 0}
    receipt = expected['receipts']['successor']
    reference = registry + '/' + expected['release_repository'] + '@' + receipt['release']['digest']
    _require(receipt['target_reference'] == reference, 'Successor verification must stay on the pinned target')
    try:
        portable.fetch_release(reference, env, [expected['trusted_fingerprint']])
    except oci._RegistryError as error:
        _require(error.status == 404 and proof['blob']['status'] == 404,
                 'Production verification failed for an unrelated registry error')
        proof['production_verification'] = {'rejected': True, 'http_status': 404,
            'reason': 'Referenced target OCI content is unavailable (HTTP 404).'}
    except ValueError as error:
        _require(str(error) == 'Incomplete or corrupt replicated OCI content',
                 'Production verification failed for an unrelated validation error')
        proof['production_verification'] = {'rejected': True, 'reason': str(error)}
    else:
        raise AssertionError('Production verification accepted the incomplete successor')
    proof['sync_error_scope'] = 'The job API sanitizes error text; content cause is independently verified here.'
    return proof


def exact_release(api, state, expected, label, status):
    release = workflow.release_for(api, state, public_receipt(expected['receipts'][label]))
    artifacts = workflow.images(release)
    wanted = {expected['images'][index]['digest'] for index in expected[label + '_indices']}
    _require(len(artifacts) == 100 and {item['digest'] for item in artifacts} == wanted,
             'Imported release must contain exactly its expected 100 images')
    _require(release['status'] == status, 'Imported lifecycle does not match qualification phase')
    return release


def active_inventory(api, state, expected, label, release, total):
    releases = api.get('/api/replica/releases?service_key=' + quote(state['service_key'], safe=''))['releases']
    _require(len(releases) == total and len({item['service_id'] for item in releases}) == 1,
             'History must retain the expected releases under one stable local service')
    active = [item for item in releases if item['status'] == 'active']
    _require(len(active) == 1 and active[0]['id'] == release['id'], 'Exactly the expected release may be active')
    service = [item for item in api.get('/api/replica/status')['services']
               if item['service_key'] == state['service_key']]
    _require(len(service) == 1 and service[0]['active_release_id'] == release['id']
             and service[0]['service_id'] == release['service_id'], 'Replica service points at a different release')
    return {'service_id': release['service_id'], 'active_release_id': release['id'],
            'active_image_count': 100, 'active_root_digests': sorted(item['digest'] for item in workflow.images(release)),
            'history_count': len(releases), 'history': [{key: item[key] for key in
                ('id', 'service_id', 'source_release_id', 'manifest_digest', 'status')} for item in releases]}


def pull_inventory(session, stack, release, expected, label):
    artifacts = {item['digest']: item for item in workflow.images(release)}
    graphs = []
    for position, index in enumerate(expected[label + '_indices'], 1):
        image = expected['images'][index]
        artifact = artifacts[image['digest']]
        graph = pull_graph(session, stack['proxy_url'], artifact['proxy_repositories'][0], artifact['digest'])
        marker = image['marker_layer']
        _require(any(item['digest'] == marker['digest'] and item['size'] == marker['size'] for item in graph['blobs']),
                 'Downloaded image does not contain its distinct expected marker layer')
        graphs.append({'index': index, **graph})
        if position % 10 == 0:
            print(f'{label}: fully downloaded and hash-verified {position}/100 image graphs', flush=True)
    return {'release_id': release['id'], 'complete': True, 'image_count': len(graphs), 'graphs': graphs,
            'verified_bytes': sum(item['verified_bytes'] for item in graphs), 'completed_at': now()}


def retired_artifacts(first, expected):
    retired = {expected['images'][index]['digest'] for index in range(23)}
    result = [item for item in workflow.images(first) if item['digest'] in retired]
    _require(len(result) == 23, 'Exactly 23 source images must be retired')
    return sorted(result, key=lambda item: item['digest'])


def cold_cache_proof(path, stack, report):
    _require(path is not None and path.is_file(), 'Complete phase requires caller-recorded fresh empty blob-cache proof')
    raw = path.read_bytes()
    proof = json.loads(raw.decode('utf-8-sig'))
    _require(proof.get('format') == 'cats-inventory-cold-cache-v1'
             and proof.get('replica_project') == stack['project']
             and proof.get('cache_directory') == '/var/cache/cats-oci'
             and type(proof.get('file_count')) is int and proof['file_count'] == 0
             and proof.get('prior_volume_retained') is True
             and isinstance(proof.get('cache_volume'), str) and proof['cache_volume'],
             'Cold-cache proof must identify this replica and a retained-prior, empty replacement blob volume')
    checked = datetime.fromisoformat(proof['checked_at'])
    recovered = datetime.fromisoformat(report['recovered_at'])
    _require(checked.tzinfo is not None and recovered.tzinfo is not None,
             'Cold-cache proof timestamps require explicit timezone offsets')
    _require(recovered <= checked <= datetime.now(timezone.utc), 'Cold-cache proof must follow recovery and precede pulls')
    if report.get('successor_pull_started_at'):
        previous_attempt = datetime.fromisoformat(report['successor_pull_started_at'])
        _require(previous_attempt.tzinfo is not None and checked > previous_attempt,
                 'A repeated pull requires an empty-cache observation after the preceding pull attempt')
    return {key: proof[key] for key in ('format', 'checked_at', 'replica_project', 'cache_volume',
                                      'cache_directory', 'file_count', 'prior_volume_retained')} | {
        'proof_sha256': hashlib.sha256(raw).hexdigest(),
        'scope': 'Empty blob cache; PostgreSQL manifest cache is retained and may serve previously pulled manifests.'}


def override_checks(api, root, stack, state, report, first, expected, machine):
    retired = retired_artifacts(first, expected)
    selected = retired[0]
    local = workflow.local_cyber(api, root, state, report)
    results = []
    try:
        for duration in ('fixed', 'indefinite'):
            expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat() if duration == 'fixed' else None
            payload = exact_override_payload(first['id'], selected['digest'], expires_at=expiry,
                mission_impact='Verify disconnected continuity for one retired image in the isolated 100-image qualification.',
                justification='Exercise exact release and digest scope while all other retired images remain denied.',
                risk_acceptance='Local Cyber accepts superseded-release risk for this isolated check and revokes immediately.')
            report['administrator_separation'] = assert_override_admin_denied(
                api.session, api.base, api.csrf, state['service_key'], payload)
            response = local.session.post(_override_url(local.base, state['service_key']),
                json=payload, headers={'X-CSRF-Token': local.csrf}, timeout=30, allow_redirects=False)
            try:
                creation_status, grant = response.status_code, response.json()
            finally:
                response.close()
            _require(isinstance(grant, dict) and type(grant.get('id')) is int and grant['id'] > 0,
                     'Override creation did not return a usable cleanup identity; inspect the local override list')
            outcome = {'duration': duration, 'created': grant}
            results.append(outcome)
            report['override_checks'] = results
            try:
                _require(creation_status == 200 and grant.get('release_id') == payload['release_id']
                         and grant.get('digests') == [payload['digest']]
                         and grant.get('denial_condition') == payload['denial_condition']
                         and grant.get('status') == 'active', 'Override did not preserve the exact requested scope')
                persist(root, state, report)
                _require(bool(grant.get('expires_at')) == (duration == 'fixed'), 'Override duration changed unexpectedly')
                outcome['pull'] = pull_graph(machine, stack['proxy_url'], selected['proxy_repositories'][0], selected['digest'])
                outcome['uses'] = assert_override_uses(local.session, local.base, state['service_key'], grant['id'],
                    release_id=first['id'], digest=selected['digest'], principal_id=state['machine']['id'])
                outcome['other_retired_denials'] = [assert_root_denied(machine, stack['proxy_url'],
                    item['proxy_repositories'][0], item['digest']) for item in retired[1:]]
            finally:
                outcome['revoked'] = revoke_override(local.session, local.base, local.csrf, state['service_key'],
                    grant['id'], 'Isolated inventory qualification finished; restore successor-only enforcement.')
                persist(root, state, report)
            outcome['warm_cache_denied_after_revocation'] = assert_root_denied(
                machine, stack['proxy_url'], selected['proxy_repositories'][0], selected['digest'])
            persist(root, state, report)
    finally:
        local.session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--replica-workspace', type=Path, required=True)
    parser.add_argument('--ca', type=Path, required=True)
    parser.add_argument('--phase', choices=('setup', 'baseline', 'incomplete', 'recover', 'complete'), required=True)
    parser.add_argument('--api-url')
    parser.add_argument('--proxy-url')
    parser.add_argument('--publisher-url', action='append')
    parser.add_argument('--require-source-offline', action='store_true')
    parser.add_argument('--cold-cache-proof', type=Path)
    args = parser.parse_args()
    expected = load(args.workspace, 'expected.json')
    validate_expected(expected, successor=args.phase in {'incomplete', 'recover', 'complete'})
    root = args.workspace.resolve() / 'http'
    root.mkdir(exist_ok=True)
    state, report = load(root, 'replica-state.json', {}), load(root, 'replica-acceptance.json', {})
    identity = binding(expected)
    _require(not state.get('input_binding') or state['input_binding'] == identity,
             'This HTTP workspace belongs to a different publication or registry scope')
    state['input_binding'] = identity
    report.setdefault('format', 'cats-harbor-inventory-http-v1')
    report['qualification_type'] = 'Synthetic 123-image inventory fixture, actual signed production publication and real Harbor/replica HTTP.'
    report['input_binding'] = identity
    stack = load(args.replica_workspace, 'stack.json')
    stack = {**stack, 'replica_url': args.api_url or stack['replica_url'],
             'proxy_url': args.proxy_url or stack['proxy_url']}
    urls = publisher_urls(expected, args.publisher_url)
    for label, filename in (('first', 'source-receipt.json'), ('successor', 'patched-receipt.json')):
        if label in expected['receipts']:
            save(root, filename, public_receipt(expected['receipts'][label]))
    (root / 'tls').mkdir(exist_ok=True)
    (root / 'tls' / 'registry.crt').write_bytes(args.ca.read_bytes())
    api = API(stack['replica_url'])
    password = stack['replica_admin_new_password'] if state.get('password_changed') else stack['replica_admin_password']
    api.login(stack['replica_admin_username'], password, stack['replica_admin_new_password'])
    state['password_changed'] = True
    persist(root, state, report)
    try:
        if args.phase == 'setup':
            workflow.setup(api, root, state, expected, expected['target'], report)
        elif args.phase == 'baseline':
            source_probes(root, state, report, urls, args.ca, offline=False, label='source_online')
            sync_job(api, root, state, report, 'baseline')
            first = exact_release(api, state, expected, 'first', 'active')
            state.update(service_id=first['service_id'], source_release_id=first['id'])
            report['baseline_inventory'] = active_inventory(api, state, expected, 'first', first, 1)
            workflow.configure_principal(api, root, state, report)
            with workflow.machine_session(state) as machine:
                report['source_pull'] = pull_inventory(machine, stack, first, expected, 'first')
            report['baseline_at'] = now()
        elif args.phase == 'incomplete':
            _require(report.get('source_pull', {}).get('complete'), 'Baseline full pull must precede incomplete successor test')
            if args.require_source_offline:
                source_probes(root, state, report, urls, args.ca, offline=True, label='offline_before_incomplete')
            report['target_omission'] = target_omission(expected, args.ca)
            persist(root, state, report)
            sync_job(api, root, state, report, 'incomplete', rejected=True)
            first = exact_release(api, state, expected, 'first', 'active')
            report['incomplete_inventory'] = active_inventory(api, state, expected, 'first', first, 1)
            _require(report['incomplete_inventory'] == report['baseline_inventory'],
                     'Incomplete successor changed the last verified release or its complete inventory')
            report['incomplete_preserved_baseline'] = True
        elif args.phase == 'recover':
            _require(report.get('incomplete_preserved_baseline'), 'First demonstrate that incomplete successor preserves the baseline')
            if args.require_source_offline:
                source_probes(root, state, report, urls, args.ca, offline=True, label='offline_before_recovery')
            sync_job(api, root, state, report, 'recovery')
            first = exact_release(api, state, expected, 'first', 'superseded')
            successor = exact_release(api, state, expected, 'successor', 'active')
            _require(first['id'] == state['source_release_id'] and first['service_id'] == successor['service_id'] == state['service_id'],
                     'Recovery changed the original release identity or local service')
            state['patched_release_id'] = successor['id']
            report['successor_inventory'] = active_inventory(api, state, expected, 'successor', successor, 2)
            old = {item['digest'] for item in workflow.images(first)}
            new = {item['digest'] for item in workflow.images(successor)}
            report['replacement'] = {'retained': len(old & new), 'retired': len(old - new), 'new': len(new - old)}
            _require(report['replacement'] == {'retained': 77, 'retired': 23, 'new': 23}, 'Successor replacement cardinalities differ')
            workflow.configure_principal(api, root, state, report)
            with workflow.machine_session(state) as machine:
                report['retired_denials'] = [assert_root_denied(machine, stack['proxy_url'],
                    item['proxy_repositories'][0], item['digest']) for item in retired_artifacts(first, expected)]
            report['recovered_at'] = now()
        else:
            _require(report.get('recovered_at'), 'Recover the complete successor before final offline pulls')
            source_probes(root, state, report, urls, args.ca, offline=True, label='offline_before_complete')
            cold = cold_cache_proof(args.cold_cache_proof, stack, report)
            _require(cold['proof_sha256'] not in state.get('attempted_cold_proofs', []),
                     'A repeated complete attempt requires a newly established empty blob cache proof')
            first = exact_release(api, state, expected, 'first', 'superseded')
            successor = exact_release(api, state, expected, 'successor', 'active')
            state.setdefault('attempted_cold_proofs', []).append(cold['proof_sha256'])
            report['cold_blob_cache'] = cold
            report.update(complete=False, completed_at=None)
            report['successor_pull_started_at'] = now()
            persist(root, state, report)
            with workflow.machine_session(state) as machine:
                report['successor_pull'] = pull_inventory(machine, stack, successor, expected, 'successor')
                persist(root, state, report)
                override_checks(api, root, stack, state, report, first, expected, machine)
            report['evidence'] = {label: verify_evidence(api.session, api.base, release['id'],
                public_receipt(expected['receipts'][label])) for label, release in (('first', first), ('successor', successor))}
            final = exact_release(api, state, expected, 'successor', 'active')
            report['final_inventory'] = active_inventory(api, state, expected, 'successor', final, 2)
            _require(report['final_inventory'] == report['successor_inventory'], 'Local overrides changed imported release state')
            source_probes(root, state, report, urls, args.ca, offline=True, label='offline_after_complete')
            report.update(complete=True, completed_at=now())
        persist(root, state, report)
        print('Inventory HTTP qualification phase completed: ' + args.phase, flush=True)
    finally:
        api.session.close()


if __name__ == '__main__':
    main()
