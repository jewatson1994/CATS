"""Opt-in replica acceptance using actual nginx publication receipts and HTTP APIs.

The caller provisions the isolated stack, copies each actual receipt with
nginx_replica_acceptance.py, and stops the publisher before sync-patched. This
driver never runs Docker, edits database rows, or invents scanner evidence.
Private resumable credentials stay in replica-state.json; replica-acceptance.json
contains only public identities, byte verification results and enforcement proof.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import secrets
import time
from urllib.parse import quote

import requests

from nginx_workflow_integration import API, assign, load, save
from nginx_replica_acceptance import (
    _require, assert_disconnected, assert_override_admin_denied, assert_override_uses,
    assert_root_denied, create_exact_override, exact_override_payload, pull_graph,
    revoke_override, verify_evidence, verify_manifest_binding,
)


def receipt(root, label):
    value = load(root, label + '-receipt.json')
    _require(isinstance(value, dict) and value.get('status') == 'published'
             and value.get('verification_status') == 'verified'
             and value.get('signature_status') == 'verified',
             f'{label} requires an actual completed verified publication receipt')
    _require(value.get('artifacts') and value.get('manifest', {}).get('portable'),
             f'{label} publication is missing its actual image inventory or signed metadata')
    return value


def reference_repository(reference):
    location, digest = reference.rsplit('@', 1)
    host, repository = location.split('/', 1)
    _require(host and repository and digest.startswith('sha256:'), 'Invalid immutable receipt reference')
    return repository


def persist(root, state, report):
    save(root, 'replica-state.json', state)
    save(root, 'replica-acceptance.json', report)


def publisher_probes(stack, supplied):
    return supplied or [stack['full_url'].rstrip('/') + '/login']


def disconnected(stack, supplied):
    with requests.Session() as session:
        session.trust_env = False
        return assert_disconnected(session, publisher_probes(stack, supplied))


def setup(api, root, state, workflow, target_registry, report):
    original = receipt(root, 'source')
    repository = reference_repository(original['release']['reference'])
    trusted = workflow['trusted_fingerprint']
    _require(original['manifest']['signing_fingerprint'] == trusted,
             'Publisher trust pin must match independently configured source signer')
    name = 'nginx acceptance local registry'
    upstreams = api.get('/api/oci/upstreams')
    upstream = next((item for item in upstreams if item['name'] == name), None)
    if upstream is None:
        upstream = api.post('/api/oci/upstreams', {
            'name': name, 'endpoint': target_registry,
            'ca_pem': (root / 'tls' / 'registry.crt').read_text(encoding='utf-8'),
            'enabled': True})
    _require(upstream['endpoint'].rstrip('/') == target_registry.rstrip('/')
             and upstream['enabled'] and upstream['ca_configured'],
             'Existing local registry must match the explicit target and configured CA')
    sources = api.get('/api/replica/sources')['sources']
    source = next((item for item in sources if item['name'] == 'nginx acceptance source'), None)
    if source is None:
        source = api.post('/api/replica/sources', {
            'name': 'nginx acceptance source', 'upstream_id': upstream['id'],
            'repository': repository, 'trusted_publishers': [trusted],
            'poll_seconds': 86400, 'enabled': True})
    _require(source['upstream_id'] == upstream['id'] and source['repository'] == repository
             and source['trusted_publishers'] == [trusted] and source['enabled'],
             'Existing source must preserve the exact registry, repository and trust pin')
    state.update(upstream_id=upstream['id'], source_id=source['id'],
                 releases_repository=repository, service_key=workflow['service_key'])
    report['setup'] = {'upstream_id': upstream['id'], 'target_registry': target_registry,
                       'source_id': source['id'], 'repository': repository,
                       'trusted_publisher': trusted}
    persist(root, state, report)
    print('Replica local registry and independently pinned publisher configured.', flush=True)


def release_for(api, state, original):
    releases = api.get('/api/replica/releases?service_key=' + quote(state['service_key'], safe=''))['releases']
    identity = original['manifest']['portable']['release_uuid']
    selected = [item for item in releases if item['source_release_id'] == identity]
    _require(len(selected) == 1, 'Expected exactly one imported actual source release')
    release = selected[0]
    context = api.get('/api/replica/releases/' + str(release['id']) + '/context')
    verify_manifest_binding(context, release['id'], original)
    _require(all(release.get(key) == context['release'].get(key) for key in
                 ('id', 'service_id', 'source_release_id', 'publisher', 'source_reference', 'manifest_digest')),
             'Replica release listing differs from its verified signed context')
    return release


def sync(api, root, stack, state, label, report, supplied_probes):
    original = receipt(root, label)
    if label == 'patched':
        _require(report.get('source_pull', {}).get('complete'),
                 'Source must be completely pulled before supersession')
        report['publisher_unavailable_before_successor_sync'] = disconnected(stack, supplied_probes)
        persist(root, state, report)
    queued = api.post('/api/replica/sync', {'source_id': state['source_id']})['jobs']
    _require(len(queued) == 1, 'Expected exactly one explicitly selected replica sync job')
    identity = queued[0]['id']
    deadline, previous = time.monotonic() + 1800, None
    while time.monotonic() < deadline:
        jobs = api.get('/api/replica/status')['jobs']
        job = next((item for item in jobs if item['id'] == identity), None)
        _require(job is not None, 'Replica sync job disappeared from recent status')
        status = job['status']
        if status != previous:
            print(f'{label} replica synchronization: {status}', flush=True)
            previous = status
        if status in {'failed', 'cancelled'}:
            raise RuntimeError(f'{label} replica synchronization failed: {job.get("error")}')
        if status == 'completed':
            _require((job.get('result') or {}).get('failed', 0) == 0,
                     'Replica synchronization rejected at least one signed release')
            break
        time.sleep(5)
    else:
        raise TimeoutError('Replica synchronization exceeded 30 minutes')
    release = release_for(api, state, original)
    _require(release['status'] == 'active', f'{label} release was not activated')
    state['service_id'] = release['service_id']
    state[label + '_release_id'] = release['id']
    report[label + '_sync'] = {'job_id': identity, 'result': job.get('result'),
                              'release_id': release['id'], 'source_release_id': release['source_release_id'],
                              'manifest_digest': release['manifest_digest'], 'status': release['status']}
    persist(root, state, report)
    return release


def configure_principal(api, root, state, report):
    repositories = api.get('/api/oci/repositories')
    unrelated_name = 'acceptance-unapproved/' + state['service_key']
    unrelated = next((item for item in repositories if item['public_repository'] == unrelated_name), None)
    if unrelated is None:
        unrelated = api.post('/api/oci/repositories', {
            'public_repository': unrelated_name, 'upstream_repository': state['releases_repository'],
            'service_id': state['service_id'], 'upstream_id': state['upstream_id'],
            'policy': {}, 'enabled': True})
        repositories.append(unrelated)
    _require(unrelated['service_id'] == state['service_id']
             and unrelated['upstream_id'] == state['upstream_id']
             and unrelated['upstream_repository'] == state['releases_repository'],
             'Unapproved-document route must retain its explicit local service and repository')
    grants = sorted(item['id'] for item in repositories if item['service_id'] == state['service_id']
                    and item['upstream_id'] == state['upstream_id'] and item['enabled'] and not item['suspended'])
    _require(grants, 'Importer did not establish local image routes')
    if not state.get('machine'):
        machine = api.post('/api/oci/principals', {
            'name': 'nginx-acceptance-' + secrets.token_hex(5), 'repository_ids': grants, 'enabled': True})
        _require(machine.get('secret'), 'New machine principal did not return its one-time secret')
        state['machine'] = machine
        persist(root, state, report)
    else:
        machine = state['machine']
        response = api.request('PUT', '/api/oci/principals/' + str(machine['id']),
                               json={'repository_ids': grants}, headers={'X-CSRF-Token': api.csrf})
        machine.update(response.json())
        response.close()
    _require(unrelated.get('pull_repository'), 'Unapproved-document route must expose a service-scoped pull path')
    state['unapproved_repository'] = unrelated['pull_repository']
    report['machine'] = {key: machine[key] for key in ('id', 'name', 'repository_ids', 'expires_at')}
    persist(root, state, report)


def machine_session(state):
    session = requests.Session()
    session.trust_env = False
    session.auth = (state['machine']['name'], state['machine']['secret'])
    return session


def images(release):
    result = [item for item in release['artifacts'] if item['kind'] == 'image']
    _require(result, 'Actual nginx release contains no image artifact')
    for item in result:
        _require(item.get('proxy_repositories'), 'Imported image has no local proxy route')
    return result


def full_pull(session, stack, release):
    graphs = [pull_graph(session, stack['proxy_url'], item['proxy_repositories'][0], item['digest'])
              for item in images(release)]
    return {'release_id': release['id'], 'complete': True, 'graphs': graphs,
            'verified_bytes': sum(item['verified_bytes'] for item in graphs)}


def local_cyber(api, root, state, report):
    if not state.get('local_cyber'):
        state['local_cyber'] = {'username': 'nginx-local-cyber-' + secrets.token_hex(5),
                                'password': secrets.token_urlsafe(30),
                                'new_password': secrets.token_urlsafe(30)}
        persist(root, state, report)
    credentials = state['local_cyber']
    page = api.page('/admin')
    if not any(item['username'] == credentials['username'] for item in page['users']):
        api.form('/admin/users', username=credentials['username'], display_name='Nginx acceptance Local Cyber',
                 password=credentials['password'])
    assign(api, credentials['username'], 'Local Cyber', service_id=state['service_id'])
    page = api.page('/admin')
    row = next(item for item in page['user_rows'] if item['user']['username'] == credentials['username'])
    service_name = next(item['name'] for item in page['services'] if item['id'] == state['service_id'])
    assignments = row['assignments']
    _require(len(assignments) == 1 and assignments[0]['role'] == 'Local Cyber'
             and assignments[0]['active'] and assignments[0]['source'] == 'local'
             and assignments[0]['service'] == service_name
             and assignments[0]['service'] != 'All services',
             'Acceptance Local Cyber user must have exactly one active service-scoped local assignment')
    local = API(api.base)
    password = credentials['new_password'] if credentials.get('password_changed') else credentials['password']
    local.login(credentials['username'], password, credentials['new_password'])
    credentials['password_changed'] = True
    report['local_cyber'] = {'user_id': row['user']['id'], 'service_id': state['service_id'],
                             'assignment': assignments[0]}
    persist(root, state, report)
    return local


def verify(api, root, stack, state, report, supplied_probes):
    _require(report.get('source_pull', {}).get('complete') and report.get('patched_sync'),
             'Run sync-source and disconnected sync-patched before verification')
    report['publisher_unavailable_before_verification'] = disconnected(stack, supplied_probes)
    source_receipt, patched_receipt = receipt(root, 'source'), receipt(root, 'patched')
    source, patched = release_for(api, state, source_receipt), release_for(api, state, patched_receipt)
    _require(source['status'] == 'superseded' and patched['status'] == 'active',
             'Source must be superseded while the actual patched successor is active')
    _require(patched_receipt['manifest']['portable']['supersedes_release_uuid'] == source['source_release_id'],
             'Actual successor must explicitly supersede the imported source release')
    approved_members = {digest for item in patched['artifacts'] for digest in [item['digest'], *item['manifests']]}
    previous = next((item for item in images(source) if item['digest'] not in approved_members), None)
    _require(previous is not None, 'Patch must produce a changed root; unchanged shared digests remain authorized')
    configure_principal(api, root, state, report)
    old_repository, old_digest = previous['proxy_repositories'][0], previous['digest']
    with machine_session(state) as machine:
        report['superseded_denial'] = assert_root_denied(machine, stack['proxy_url'], old_repository, old_digest)
        if not report.get('patched_first_pull'):
            _require(not any(item['digest'] in {graph['root_digest'] for graph in report['source_pull']['graphs']}
                             for item in images(patched)), 'Patched root was already pulled as the original image')
            first_attempt = not state.get('patched_pull_attempted_at')
            state.setdefault('patched_pull_attempted_at', datetime.now(timezone.utc).isoformat())
            persist(root, state, report)
            report['patched_first_pull'] = full_pull(machine, stack, patched)
            report['patched_first_pull']['first_proxy_request_for_patched_roots'] = first_attempt
            report['patched_first_pull']['initial_attempt_at'] = state['patched_pull_attempted_at']
            persist(root, state, report)
        payload = exact_override_payload(source['id'], old_digest,
            mission_impact='Disconnected acceptance requires the previously approved nginx image for continuity verification.',
            justification='Exercise an exact superseded image exception after real successor publication and source disconnection.',
            risk_acceptance='Local Cyber explicitly accepts superseded approval risk for this isolated test; revoke immediately after verification.',
            expires_at=None)
        report['administrator_separation'] = assert_override_admin_denied(
            api.session, api.base, api.csrf, state['service_key'], payload)
        local = local_cyber(api, root, state, report)
        try:
            grant = create_exact_override(local.session, local.base, local.csrf, state['service_key'], payload)
            _require(grant.get('expires_at') is None, 'Requested indefinite override gained an expiry')
            state['override_id'] = grant['id']
            report['override_created'] = grant
            persist(root, state, report)
            try:
                report['override_pull'] = pull_graph(machine, stack['proxy_url'], old_repository, old_digest)
                report['override_usage'] = assert_override_uses(local.session, local.base, state['service_key'], grant['id'],
                    release_id=source['id'], digest=old_digest, principal_id=state['machine']['id'])
                report['unrelated_digest_denial'] = assert_root_denied(machine, stack['proxy_url'],
                    state['unapproved_repository'], source_receipt['release']['digest'],
                    reason='Artifact does not belong to this verified replica repository')
                report['unrelated_digest_kind'] = 'actual signed release-document OCI root outside approved image inventory'
            finally:
                report['override_revoked'] = revoke_override(local.session, local.base, local.csrf,
                    state['service_key'], grant['id'], 'Acceptance verification finished; restore normal successor-only enforcement.')
                persist(root, state, report)
        finally:
            local.session.close()
        report['revoked_warm_cache_denial'] = assert_root_denied(machine, stack['proxy_url'], old_repository, old_digest)
        report['patched_remains_allowed'] = full_pull(machine, stack, patched)
    report['evidence'] = {
        'source': verify_evidence(api.session, api.base, source['id'], source_receipt),
        'patched': verify_evidence(api.session, api.base, patched['id'], patched_receipt)}
    source_after, patched_after = release_for(api, state, source_receipt), release_for(api, state, patched_receipt)
    _require(source_after['status'] == 'superseded' and patched_after['status'] == 'active',
             'Local override changed imported publisher approval status')
    report['publisher_status_preserved'] = {'source': source_after['status'], 'patched': patched_after['status']}
    report['publisher_unavailable_after_verification'] = disconnected(stack, supplied_probes)
    report['complete'] = True
    report['completed_at'] = datetime.now(timezone.utc).isoformat()
    persist(root, state, report)
    print('Disconnected pulls, signed evidence, exact Local Cyber override and immediate revocation verified.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('setup', 'sync-source', 'sync-patched', 'verify'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--target-registry', default='https://replica.test:5000')
    parser.add_argument('--publisher-url', action='append', help='Explicit unavailable publisher probe URL; defaults to full_url/login')
    args = parser.parse_args()
    root = args.workspace.resolve()
    stack, workflow = load(root, 'stack.json'), load(root, 'workflow-state.json')
    _require(isinstance(stack, dict) and isinstance(workflow, dict), 'Explicit runtime stack and actual workflow state are required')
    state, report = load(root, 'replica-state.json', {}), load(root, 'replica-acceptance.json', {})
    report.setdefault('format', 'cats-real-nginx-replica-acceptance-v1')
    report['complete'] = False
    report['current_phase'] = args.phase
    api = API(stack['replica_url'])
    password = stack['replica_admin_new_password'] if state.get('password_changed') else stack['replica_admin_password']
    api.login(stack['replica_admin_username'], password, stack['replica_admin_new_password'])
    state['password_changed'] = True
    persist(root, state, report)
    try:
        if args.phase == 'setup':
            setup(api, root, state, workflow, args.target_registry, report)
        elif args.phase in {'sync-source', 'sync-patched'}:
            label = args.phase.removeprefix('sync-')
            release = sync(api, root, stack, state, label, report, args.publisher_url)
            if label == 'source':
                configure_principal(api, root, state, report)
                with machine_session(state) as machine:
                    report['source_pull'] = full_pull(machine, stack, release)
                persist(root, state, report)
                print('Original approved nginx graph completely downloaded and verified.', flush=True)
        else:
            verify(api, root, stack, state, report, args.publisher_url)
    finally:
        api.session.close()


if __name__ == '__main__':
    main()
