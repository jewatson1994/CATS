"""Opt-in Harbor qualification using retained, actually scanned nginx releases.

Use a dedicated --workspace (for example harbor-acceptance/replica). ``prepare``
creates only that replica's Compose/state files; ``up`` starts its three services.
The caller seeds Harbor and operates Harbor replication separately. Run setup,
sync-source, sync-patched, verify, then restart-check. Before sync-patched, stop
the source Harbor and original publisher. Neither receipts nor database rows are
rewritten, and no scanner evidence is synthesized. Credentials stay private.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from urllib.parse import quote, urlsplit

import requests

import nginx_replica_workflow as workflow
from nginx_replica_acceptance import _digest, _require, assert_root_denied
from nginx_workflow_integration import API, load, save, wait_for


def now():
    return datetime.now(timezone.utc).isoformat()


def registry_url(value):
    parsed = urlsplit(value)
    _require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
             and not parsed.password and parsed.path in ('', '/')
             and not parsed.query and not parsed.fragment, 'Use a credential-free HTTPS registry origin')
    return value.rstrip('/')


def publisher_portal_url(previous, template):
    # The replica joins multiple Compose networks. A service alias such as
    # "portal" can resolve an unrelated deployment on the shared Harbor bridge.
    name = template['services']['portal'].get('container_name') or previous['project'] + '-portal-1'
    _require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name),
             'The original publisher must have a unique valid container identity')
    return 'http://' + name + ':8000/login'


def prepare(args):
    root, original = args.workspace.resolve(), args.original_workspace.resolve()
    _require(root != original and original not in root.parents,
             'Use a separate qualification workspace outside the original acceptance')
    _require(not (root / 'stack.json').exists(), 'Workspace is already prepared; use its existing phases')
    _require(args.network and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', args.network),
             'Supply the existing Harbor bridge network name')
    ca, bundle = args.ca_file.resolve(), args.ca_bundle.resolve()
    _require(ca.is_file() and bundle.is_file(), 'Harbor CA and public CA bundle must already exist')
    source_url, target_url = registry_url(args.source_registry), registry_url(args.target_registry)
    _require(source_url != target_url, 'Source and target Harbor must differ')
    previous = load(original, 'stack.json')
    baseline = load(original, 'workflow-state.json')
    completed = load(original, 'replica-acceptance.json')
    _require(completed.get('complete') is True, 'The original real nginx acceptance must be complete')
    receipts = {label: workflow.receipt(original, label) for label in ('source', 'patched')}
    trusted = baseline['trusted_fingerprint']
    _require(completed['setup']['trusted_publisher'] == trusted and all(
        item['manifest']['signing_fingerprint'] == trusted for item in receipts.values()),
        'Receipt publishers must match the independently retained signer trust pin')
    _require(receipts['patched']['manifest']['portable']['supersedes_release_uuid'] ==
             receipts['source']['manifest']['portable']['release_uuid'], 'Actual successor lineage is required')
    template = load(original, 'compose.json')
    old_network = template['networks']['default']['name']
    root.mkdir(parents=True, exist_ok=True)
    (root / 'tls').mkdir(exist_ok=True)
    (root / 'tls' / 'registry.crt').write_bytes(ca.read_bytes())
    (root / 'tls' / 'ca-bundle.crt').write_bytes(bundle.read_bytes() + b'\n' +
                                               (original / 'tls' / 'registry.crt').read_bytes())
    project = 'cats-harbor-replica-' + secrets.token_hex(5)
    database_password = secrets.token_urlsafe(32)
    initial_password, final_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    encryption_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    services = {name: copy.deepcopy(template['services'][name]) for name in
                ('replica-db', 'replica-portal', 'replica-proxy')}
    for name, service in services.items():
        service.pop('container_name', None)
        service['restart'] = 'no'
        service['networks'] = {'default': {}}
        environment = service['environment']
        if name == 'replica-db':
            environment['POSTGRES_PASSWORD'] = database_password
            service['networks']['default']['aliases'] = ['qualification-db']
            service['volumes'] = ['replica_db:/var/lib/postgresql/data']
            continue
        environment.update(DATABASE_URL='postgresql+psycopg://cats:' + database_password + '@qualification-db:5432/cats',
                           PGPASSWORD=database_password, CATS_BOOTSTRAP_USERNAME='harbor-replica-admin',
                           CATS_BOOTSTRAP_PASSWORD=initial_password, CATS_CONFIG_ENCRYPTION_KEY=encryption_key)
        service['networks']['harbor'] = {}
        if name == 'replica-proxy':
            service['networks']['original_publisher'] = {}
        service['ports'] = ['127.0.0.1:' + ('18897:8000' if name == 'replica-portal' else '15897:5000')]
        service['volumes'] = [
            'replica_evidence:/var/lib/cats' + (':ro' if name == 'replica-proxy' else ''),
            'replica_cache:/var/cache/cats-oci',
            *[{'type': 'bind', 'source': str(root / 'tls' / name).replace('\\', '/'),
               'target': '/run/acceptance-tls/' + name, 'read_only': True}
              for name in ('registry.crt', 'ca-bundle.crt')]]
        _require(service.get('cap_drop') == ['ALL'] and 'no-new-privileges:true' in service.get('security_opt', []),
                 'Replica capability isolation must be retained')
    compose = {'services': services, 'networks': {
        'default': {'name': project + '_private', 'internal': True},
        'harbor': {'external': True, 'name': args.network},
        'original_publisher': {'external': True, 'name': old_network}},
        'volumes': {name: {'name': project + '_' + name} for name in
                    ('replica_db', 'replica_evidence', 'replica_cache')}}
    stack = {'project': project, 'compose_file': str(root / 'replica-compose.json'),
             'replica_url': 'http://127.0.0.1:18897', 'proxy_url': 'http://127.0.0.1:15897',
             'full_url': previous['full_url'], 'replica_admin_username': 'harbor-replica-admin',
             'replica_admin_password': initial_password, 'replica_admin_new_password': final_password,
             'source_registry': source_url, 'target_registry': target_url,
             'publisher_probes': [{'name': 'source_harbor', 'url': source_url + '/v2/'},
                                  {'name': 'original_registry', 'url': 'https://publisher.test:5000/v2/'},
                                  {'name': 'original_cats', 'url': publisher_portal_url(previous, template)}]}
    save(root, 'replica-compose.json', compose)
    save(root, 'stack.json', stack)
    save(root, 'workflow-state.json', {'service_key': baseline['service_key'], 'trusted_fingerprint': trusted})
    for label, value in receipts.items():
        save(root, label + '-receipt.json', value)
    save(root, 'harbor-qualification.json', {'format': 'cats-harbor-nginx-qualification-v1', 'complete': False,
        'prepared_at': now(), 'source_registry': source_url, 'target_registry': target_url,
        'input_receipt_sha256': {label: hashlib.sha256((original / (label + '-receipt.json')).read_bytes()).hexdigest()
                                for label in receipts}, 'trusted_publisher': trusted,
        'isolation': {'project': project, 'volumes': list(compose['volumes']),
                      'replica_loopback_port': 18897, 'proxy_loopback_port': 15897}})
    print('Prepared fresh replica credentials, isolated storage, and unchanged signed receipt content.', flush=True)


def compose_call(root, stack, *arguments, script=None, timeout=240):
    expected = (root / 'replica-compose.json').resolve()
    _require(Path(stack['compose_file']).resolve() == expected
             and re.fullmatch(r'cats-harbor-replica-[0-9a-f]{10}', stack['project']),
             'Docker actions require this driver\'s dedicated replica project')
    result = subprocess.run(['docker', 'compose', '-p', stack['project'], '-f', str(expected), *arguments],
                            input=script, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        save(root, 'docker-last-error.json', {'action': list(arguments), 'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('Dedicated replica Docker action failed; details retained privately in docker-last-error.json')
    return result.stdout


def inside(root, stack, script):
    return json.loads(compose_call(root, stack, 'exec', '-T', 'replica-proxy', 'python', '-', script=script))


def probes(root, stack, proof, label, *, offline):
    entries = stack['publisher_probes'] + [{'name': 'target_harbor', 'url': stack['target_registry'] + '/v2/'}]
    result = inside(root, stack, """import json, requests
from datetime import datetime, timezone
s = requests.Session()
s.trust_env = False
result = []
for item in ENTRIES:
    row = dict(item, checked_at=datetime.now(timezone.utc).isoformat())
    try:
        response = s.get(item['url'], verify='/run/acceptance-tls/ca-bundle.crt',
                         timeout=10, allow_redirects=False)
        row.update(reachable=True, status=response.status_code)
        response.close()
    except requests.exceptions.SSLError:
        raise
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as error:
        row.update(reachable=False, error_type=type(error).__name__)
    result.append(row)
print(json.dumps(result))
""".replace('ENTRIES', repr(entries)))
    target = next(row for row in result if row['name'] == 'target_harbor')
    _require(target['reachable'] and target['status'] in (200, 401), 'Target Harbor must remain reachable with valid TLS')
    if offline:
        _require(all(not row['reachable'] for row in result if row['name'] != 'target_harbor'),
                 'Source Harbor, original registry and original CATS must all be unavailable from the replica')
    else:
        source = next(row for row in result if row['name'] == 'source_harbor')
        _require(source['reachable'] and source['status'] in (200, 401), 'Source Harbor must have a valid online baseline')
    proof[label] = {'checked_at': now(), 'from_service': 'replica-proxy', 'probes': result}
    save(root, 'harbor-qualification.json', proof)
    return result


def cache_proof(api, root, stack, state, proof, label):
    source = workflow.release_for(api, state, workflow.receipt(root, 'source'))
    patched = workflow.release_for(api, state, workflow.receipt(root, 'patched'))
    roots = [item['digest'] for item in workflow.images(patched)]
    old_blobs = {digest for item in workflow.images(source) for digest in item['blobs']}
    unique_blobs = sorted({digest for item in workflow.images(patched) for digest in item['blobs']} - old_blobs)
    _require(len(roots) == 1 and unique_blobs, 'Actual patch must contain one root and new blobs for the cold proof')
    for digest in [*roots, *unique_blobs]:
        _digest(digest)
    result = inside(root, stack, """import json, os
from pathlib import Path
from sqlalchemy import text
from app.database import engine
with engine.connect() as connection:
    result = {
        'manifest_rows': connection.scalar(text('SELECT count(*) FROM oci_manifests WHERE digest=:digest'), {'digest': ROOT}),
        'object_links': connection.scalar(text('SELECT count(*) FROM oci_object_links WHERE root_digest=:digest'), {'digest': ROOT})}
cache = Path(os.environ.get('CATS_OCI_CACHE_DIR', '/var/cache/cats-oci'))
result['patched_only_blobs'] = [{'digest': digest, 'present': (cache / digest.split(':', 1)[1]).exists()} for digest in BLOBS]
print(json.dumps(result))
""".replace('ROOT', repr(roots[0])).replace('BLOBS', repr(unique_blobs)))
    if label == 'cold':
        _require(result['manifest_rows'] == result['object_links'] == 0
                 and all(not item['present'] for item in result['patched_only_blobs']),
                 'Patched root and its new blobs were already cached before the first pull')
    else:
        _require(result['manifest_rows'] > 0 and result['object_links'] > 0
                 and all(item['present'] for item in result['patched_only_blobs']),
                 'Complete patched pull did not populate the expected cache records and bytes')
    proof[label] = {'checked_at': now(), 'patched_digest': roots[0], **result}
    save(root, 'harbor-qualification.json', proof)


def login(root, stack, state, report):
    api = API(stack['replica_url'])
    password = stack['replica_admin_new_password'] if state.get('password_changed') else stack['replica_admin_password']
    api.login(stack['replica_admin_username'], password, stack['replica_admin_new_password'])
    state['password_changed'] = True
    workflow.persist(root, state, report)
    return api


def restart_check(root, stack, state, report, proof):
    _require(report.get('complete') is True and proof.get('complete') is True,
             'Finish the disconnected pull and override qualification before the persistence check')
    original_first_pull = copy.deepcopy(report['patched_first_pull'])
    compose_call(root, stack, 'restart', 'replica-db', 'replica-portal', 'replica-proxy')
    compose_call(root, stack, 'up', '-d', '--wait', '--wait-timeout', '180')
    api = login(root, stack, state, report)
    try:
        probes(root, stack, proof, 'offline_after_restart', offline=True)
        before = {label: workflow.release_for(api, state, workflow.receipt(root, label)) for label in ('source', 'patched')}
        queued = api.post('/api/replica/sync', {'source_id': state['source_id']})['jobs']
        _require(len(queued) == 1, 'Replay must queue exactly one source job')
        identity = queued[0]['id']
        job = wait_for(lambda: next(item for item in api.get('/api/replica/status')['jobs'] if item['id'] == identity),
                       lambda item: item['status'], {'completed'}, {'failed', 'cancelled'}, 'Harbor replay', timeout=1800)
        _require(job['result']['failed'] == 0 and job['result']['activated'] == 0
                 and job['result']['unchanged'] >= 2, 'Replaying Harbor releases changed the imported state')
        after = {label: workflow.release_for(api, state, workflow.receipt(root, label)) for label in ('source', 'patched')}
        for label in before:
            _require(all(before[label][key] == after[label][key] for key in
                         ('id', 'manifest_digest', 'source_release_id', 'status', 'source_reference')),
                     'Restart/replay changed a retained signed release identity')
        rows = api.get('/api/replica/releases?service_key=' + quote(state['service_key'], safe=''))['releases']
        _require(len(rows) == 2 and after['source']['status'] == 'superseded' and after['patched']['status'] == 'active',
                 'Restart/replay duplicated releases or changed publisher approval status')
        grants = api.get('/api/services/' + quote(state['service_key'], safe='') + '/local-overrides')['overrides']
        grant = next(item for item in grants if item['id'] == report['override_revoked']['id'])
        _require(grant['status'] == 'revoked', 'Override revocation did not survive restart')
        with workflow.machine_session(state) as machine:
            old = workflow.images(after['source'])[0]
            denial = assert_root_denied(machine, stack['proxy_url'], old['proxy_repositories'][0], old['digest'])
            pulled = workflow.full_pull(machine, stack, after['patched'])
        _require(report['patched_first_pull'] == original_first_pull, 'Persistence check replaced first-pull proof')
        proof['restart_replay'] = {'checked_at': now(), 'job_id': identity, 'result': job['result'],
            'release_count': len(rows), 'revoked_override_id': grant['id'], 'warm_superseded_denial': denial,
            'patched_pull': pulled, 'first_pull_evidence_preserved': True, 'complete': True}
        save(root, 'harbor-qualification.json', proof)
    finally:
        api.session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('prepare', 'up', 'setup', 'online-proof',
                        'sync-source', 'sync-patched', 'verify', 'restart-check'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--original-workspace', type=Path)
    parser.add_argument('--network')
    parser.add_argument('--ca-file', type=Path)
    parser.add_argument('--ca-bundle', type=Path)
    parser.add_argument('--source-registry', default='https://harbor-source.test:8443')
    parser.add_argument('--target-registry', default='https://harbor-target.test:8443')
    args = parser.parse_args()
    if args.phase == 'prepare':
        _require(all((args.original_workspace, args.ca_file, args.ca_bundle)),
                 'prepare requires original workspace, CA file and CA bundle')
        prepare(args)
        return
    root = args.workspace.resolve()
    stack, proof = load(root, 'stack.json'), load(root, 'harbor-qualification.json')
    _require(isinstance(stack, dict) and isinstance(proof, dict), 'Prepare this dedicated workspace first')
    if args.phase == 'up':
        compose_call(root, stack, 'up', '-d', '--wait', '--wait-timeout', '180')
        print('Dedicated Harbor qualification replica is healthy.', flush=True)
        return
    if args.phase == 'online-proof':
        probes(root, stack, proof, 'online', offline=False)
        return
    state, report = load(root, 'replica-state.json', {}), load(root, 'replica-acceptance.json', {})
    report.setdefault('format', 'cats-real-nginx-replica-acceptance-v1')
    if args.phase == 'restart-check':
        restart_check(root, stack, state, report, proof)
        return
    api = login(root, stack, state, report)
    try:
        if args.phase == 'setup':
            workflow.setup(api, root, state, load(root, 'workflow-state.json'), stack['target_registry'], report)
        elif args.phase == 'sync-source':
            probes(root, stack, proof, 'online', offline=False)
            release = workflow.sync(api, root, stack, state, 'source', report, None)
            workflow.configure_principal(api, root, state, report)
            with workflow.machine_session(state) as machine:
                report['source_pull'] = workflow.full_pull(machine, stack, release)
            workflow.persist(root, state, report)
        elif args.phase == 'sync-patched':
            probes(root, stack, proof, 'offline_before_successor_sync', offline=True)
            workflow.sync(api, root, stack, state, 'patched', report, None)
            if not proof.get('cold'):
                cache_proof(api, root, stack, state, proof, 'cold')
        else:
            _require(proof.get('cold') and proof.get('offline_before_successor_sync'),
                     'Record source disconnection and a truly cold patched graph before verification')
            probes(root, stack, proof, 'offline_before_first_pull', offline=True)
            workflow.verify(api, root, stack, state, report, None)
            _require(proof['cold']['checked_at'] < report['patched_first_pull']['initial_attempt_at'],
                     'Cold-cache proof must precede the retained first patched pull')
            cache_proof(api, root, stack, state, proof, 'warm')
            probes(root, stack, proof, 'offline_after_verification', offline=True)
            proof.update(complete=True, completed_at=now())
            save(root, 'harbor-qualification.json', proof)
        print('Harbor qualification phase completed: ' + args.phase, flush=True)
    finally:
        api.session.close()


if __name__ == '__main__':
    main()
