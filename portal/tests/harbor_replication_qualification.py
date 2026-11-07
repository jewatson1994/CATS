"""Opt-in Harbor replication controller; private state stays in --workspace.

The seed command moves retained real nginx receipts into SOURCE Harbor only.
Every source-to-target transfer is performed by Harbor's replication jobservice.
The companion graph and nginx drivers independently verify the target contents.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import time
from urllib.parse import quote

import requests

from nginx_workflow_integration import load, save


class Harbor:
    def __init__(self, endpoint, username, password, ca):
        self.base = endpoint.rstrip('/') + '/api/v2.0'
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = (username, password)
        self.session.verify = str(ca)

    def request(self, method, path, **kwargs):
        response = self.session.request(method, self.base + path, timeout=120, **kwargs)
        token = response.headers.get('X-Harbor-CSRF-Token')
        if token:
            self.session.headers['X-Harbor-CSRF-Token'] = token
        # Harbor may issue the CSRF token only with its explicit rejection.
        # Retry once only when it confirms this request was not executed.
        if response.status_code == 403 and token:
            try:
                errors = response.json().get('errors', [])
            except ValueError:
                errors = []
            if any(error.get('code') == 'FORBIDDEN' and
                   error.get('message') == 'CSRF token not found in request' for error in errors):
                response = self.session.request(method, self.base + path, timeout=120, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f'Harbor {method} {path}: {response.status_code}: {response.text[:1000]}')
        return response

    def get(self, path):
        return self.request('GET', path).json()

    def post(self, path, value):
        return self.request('POST', path, json=value)

    def pages(self, path):
        result = []
        for page in range(1, 1001):
            response = self.request('GET', path + ('&' if '?' in path else '?') + f'page={page}&page_size=100')
            items = response.json()
            result.extend(items)
            if len(items) < 100:
                return result
        raise RuntimeError('Harbor pagination exceeded the explicit acceptance bound')


def clients(root):
    stack = load(root, 'harbor-stack.json')
    ca = Path(stack['ca_file'])
    return stack, {side: Harbor(stack[side]['url'], stack[side]['username'],
                                stack[side]['password'], ca) for side in ('source', 'target')}


def fields(value, names):
    """Allowlist report fields; never serialize API credential dictionaries."""
    return {name: value[name] for name in names if name in value}


def registry_report(value):
    if not value:
        return None
    result = fields(value, ('id', 'name', 'type', 'url', 'status', 'insecure', 'creation_time', 'update_time'))
    certificate = value.get('ca_certificate') or ''
    result.update(ca_configured=bool(certificate),
                  ca_certificate_sha256=hashlib.sha256(certificate.encode()).hexdigest() if certificate else None,
                  insecure_field_present='insecure' in value,
                  credential_type=(value.get('credential') or {}).get('type'))
    return result


def policy_report(value):
    result = fields(value, ('id', 'name', 'description', 'enabled', 'override', 'replicate_deletion',
        'dest_namespace', 'dest_namespace_replace_count', 'speed', 'copy_by_chunk',
        'single_active_replication', 'creation_time', 'update_time'))
    result['filters'] = [fields(item, ('type', 'value', 'decoration')) for item in value.get('filters', [])]
    trigger = value.get('trigger') or {}
    result['trigger'] = fields(trigger, ('type',))
    if 'trigger_settings' in trigger:
        result['trigger']['trigger_settings'] = fields(trigger['trigger_settings'], ('cron',))
    for name in ('src_registry', 'dest_registry'):
        result[name] = registry_report(value.get(name))
    return result


def retention_report(value):
    result = fields(value, ('id', 'algorithm'))
    result['scope'] = fields(value.get('scope') or {}, ('level', 'ref'))
    trigger = value.get('trigger') or {}
    result['trigger'] = fields(trigger, ('kind',))
    result['trigger']['settings'] = fields(trigger.get('settings') or {}, ('cron',))
    result['rules'] = []
    for rule in value.get('rules', []):
        selected = fields(rule, ('id', 'priority', 'disabled', 'action', 'template'))
        selected['params'] = {key: item for key, item in (rule.get('params') or {}).items()
                              if type(item) in (int, float, bool)}
        selected['tag_selectors'] = [fields(item, ('kind', 'decoration', 'pattern'))
                                     for item in rule.get('tag_selectors', [])]
        selected['scope_selectors'] = {key: [fields(item, ('kind', 'decoration', 'pattern')) for item in items]
                                       for key, items in (rule.get('scope_selectors') or {}).items()}
        result['rules'].append(selected)
    return result


def inspect_configuration(root, stack=None, apis=None):
    """Read actual settings into a separate report; never race execution history."""
    if stack is None or apis is None:
        stack, apis = clients(root)
    state = load(root, 'replication-state.json')
    snapshot = {'format': 'cats-harbor-configuration-v1', 'adapter': 'harbor', 'instances': {},
                'checked_at': datetime.now(timezone.utc).isoformat(), 'read_only': True}
    metadata_fields = ('public', 'retention_id', 'auto_scan', 'severity', 'prevent_vul',
                       'enable_content_trust', 'enable_content_trust_cosign', 'reuse_sys_cve_allowlist')
    for side, api in apis.items():
        info, health = api.get('/systeminfo'), api.get('/health')
        robot = api.get('/robots/' + str(int(state[side]['id'])))
        permissions = [{**fields(item, ('kind', 'namespace')),
                        'access': [fields(access, ('resource', 'action', 'effect'))
                                   for access in item.get('access', [])]} for item in robot.get('permissions', [])]
        instance = {'version': info['harbor_version'], 'health': health, 'registry': stack[side]['registry'],
                    'robot': fields(robot, ('id', 'name', 'level', 'disable', 'duration', 'expires_at')),
                    'robot_permissions': permissions, 'projects': []}
        for project in api.pages('/projects'):
            if project['name'] not in ('approved', 'qualification'):
                continue
            detail = api.get('/projects/' + str(int(project['project_id'])))
            metadata = fields(detail.get('metadata') or {}, metadata_fields)
            retention_id = metadata.get('retention_id')
            retention = api.get('/retentions/' + str(int(retention_id))) if retention_id else None
            instance['projects'].append({'id': detail['project_id'], 'name': detail['name'], 'metadata': metadata,
                'retention': {'configured': retention is not None,
                              'policy': retention_report(retention) if retention is not None else None}})
        scoped = Harbor(stack[side]['url'], state[side]['username'], state[side]['password'], stack['ca_file'])
        try:
            instance['robot_repository_inventory'] = {}
            for project in instance['projects']:
                rows = scoped.pages('/projects/' + quote(project['name'], safe='') + '/repositories')
                instance['robot_repository_inventory'][project['name']] = [
                    fields(item, ('name', 'artifact_count')) for item in rows]
        finally:
            scoped.session.close()
        snapshot['instances'][side] = instance
    source = apis['source']
    snapshot['registry'] = registry_report(source.get('/registries/' + str(int(state['registry_id']))))
    snapshot['policies'] = {name: policy_report(source.get('/replication/policies/' + str(int(identity))))
                            for name, identity in state['policies'].items()}
    save(root, 'harbor-configuration.json', snapshot)
    print('Actual Harbor robots, projects, retention, registry and policies inspected without mutation.')
    return snapshot


def setup(root):
    stack, apis = clients(root)
    state = load(root, 'replication-state.json', {})
    report = load(root, 'harbor-replication.json', {'executions': []})
    report['format'] = 'cats-harbor-replication-qualification-v1'
    report['adapter'] = 'harbor'
    report['instances'] = {}
    for side, api in apis.items():
        info = api.get('/systeminfo')
        health = api.get('/health')
        if health['status'] != 'healthy':
            raise RuntimeError(f'{side} Harbor is not healthy')
        report['instances'][side] = {'version': info['harbor_version'], 'health': health,
                                     'registry': stack[side]['registry']}
        projects = api.pages('/projects')
        for name in ('approved', 'qualification'):
            if not any(p['name'] == name for p in projects):
                api.post('/projects', {'project_name': name, 'metadata': {'public': 'true'}})
        if side not in state:
            permissions = [{'kind': 'project', 'namespace': name, 'access': [
                {'resource': 'repository', 'action': 'pull'},
                {'resource': 'repository', 'action': 'push'},
                {'resource': 'artifact', 'action': 'read'},
                {'resource': 'artifact', 'action': 'list'},
                {'resource': 'tag', 'action': 'create'},
                {'resource': 'tag', 'action': 'list'}]} for name in ('approved', 'qualification')]
            robot = api.post('/robots', {'name': 'cats-qualification', 'description': 'Disposable qualification only',
                'level': 'system', 'duration': 1, 'permissions': permissions}).json()
            state[side] = {'username': robot['name'], 'password': robot['secret'], 'id': robot['id']}
            save(root, 'replication-state.json', state)
        report['instances'][side]['projects'] = [
            {'name': p['name'], 'metadata': p.get('metadata')} for p in api.pages('/projects')
            if p['name'] in ('approved', 'qualification')]
    if report['instances']['source']['version'] != report['instances']['target']['version']:
        raise AssertionError('Qualification requires identical Harbor versions')
    source = apis['source']
    if 'registry_id' not in state:
        target = state['target']
        response = source.post('/registries', {'name': 'cats-target', 'type': 'harbor',
            'url': 'https://' + stack['target']['registry'], 'insecure': False,
            'ca_certificate': Path(stack['ca_file']).read_text(),
            'credential': {'type': 'basic', 'access_key': target['username'], 'access_secret': target['password']}})
        state['registry_id'] = int(response.headers['Location'].rsplit('/', 1)[1])
        save(root, 'replication-state.json', state)
    state.setdefault('policies', {})
    for namespace in ('approved', 'qualification', 'interruption'):
        if namespace not in state['policies']:
            policy = {'name': 'cats-' + namespace, 'description': 'Complete service subtree, all tags and Cosign signatures',
                'dest_registry': {'id': state['registry_id']}, 'dest_namespace': '',
                'dest_namespace_replace_count': 0, 'trigger': {'type': 'manual'},
                'filters': [{'type': 'name', 'value': 'qualification/interruption'
                             if namespace == 'interruption' else namespace + '/**'}],
                'replicate_deletion': False, 'override': True, 'enabled': True}
            if namespace == 'interruption':
                # Harbor's API measures this setting in kilobytes per second.
                policy['speed'] = 1024
            response = source.post('/replication/policies', policy)
            state['policies'][namespace] = int(response.headers['Location'].rsplit('/', 1)[1])
            save(root, 'replication-state.json', state)
    docker = root / 'docker'
    docker.mkdir(exist_ok=True)
    save(docker, 'config.json', {'auths': {stack[side]['registry']: {
        'auth': base64.b64encode((state[side]['username'] + ':' + state[side]['password']).encode()).decode()}
        for side in ('source', 'target')}})
    snapshot = inspect_configuration(root, stack, apis)
    report = load(root, 'harbor-replication.json', {'executions': []})
    report.update(format='cats-harbor-replication-qualification-v1', adapter='harbor',
                  instances=snapshot['instances'], policies=snapshot['policies'], registry=snapshot['registry'],
                  configuration_checked_at=snapshot['checked_at'])
    report['configured_at'] = datetime.now(timezone.utc).isoformat()
    save(root, 'harbor-replication.json', report)
    print('Healthy Harbor pair, scoped robots, TLS-verified endpoint and complete-subtree rules configured.')


def scoped_arguments(alias, repository_prefix):
    if (not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', alias)
            or alias in {'approved', 'qualification', 'interruption'}):
        raise ValueError('Scoped policy requires a new lowercase alias, distinct from the built-in policies')
    segment = r'[a-z0-9]+(?:[._-][a-z0-9]+)*'
    if (len(repository_prefix) > 240
            or not re.fullmatch(r'(?:approved|qualification)/' + segment + r'(?:/' + segment + r')*', repository_prefix)):
        raise ValueError('Repository prefix must be a literal service subtree in approved/ or qualification/')


def verify_scoped_policy(policy, registry_id, repository_prefix):
    filters = [fields(item, ('type', 'value')) for item in policy.get('filters', [])]
    if (filters != [{'type': 'name', 'value': repository_prefix + '/**'}]
            or any(item.get('decoration') not in (None, '', 'matches') for item in policy.get('filters', []))
            or (policy.get('dest_registry') or {}).get('id') != registry_id
            or policy.get('dest_namespace') not in ('', None)
            or policy.get('dest_namespace_replace_count', 0) != 0
            # Harbor omits false-valued optional fields from policy responses.
            or policy.get('replicate_deletion', False) is not False
            or policy.get('enabled') is not True
            or policy.get('override') is not True
            or (policy.get('trigger') or {}).get('type') != 'manual'):
        raise RuntimeError('Scoped Harbor policy no longer matches its retained exact subtree and destination')


def validate_qualification_robots(stack, apis, state, repository_prefix):
    """Check retained test credentials without changing robots or their scopes."""
    project = repository_prefix.split('/', 1)[0]
    checked = {}
    for side in ('source', 'target'):
        credentials = state[side]
        robot = apis[side].get('/robots/' + str(int(credentials['id'])))
        expiry = robot.get('expires_at')
        if robot.get('disable'):
            raise RuntimeError(f'{side} qualification robot is disabled; restore authorized test credentials before setup-scoped')
        if type(expiry) is not int or expiry < -1:
            raise RuntimeError(f'{side} qualification robot expiration could not be verified; inspect its authorized Harbor configuration')
        if expiry != -1 and expiry <= time.time():
            expired = datetime.fromtimestamp(expiry, timezone.utc).isoformat()
            raise RuntimeError(f'{side} qualification robot expired at {expired}; renew or replace the authorized test credentials before setup-scoped')
        scoped = Harbor(stack[side]['url'], credentials['username'], credentials['password'], stack['ca_file'])
        try:
            scoped.get('/projects/' + quote(project, safe='') + '/repositories?page=1&page_size=1')
        except Exception:
            raise RuntimeError(f'{side} qualification robot failed its repository read check; verify its stored secret, expiration, project permission and TLS before setup-scoped') from None
        finally:
            scoped.session.close()
        checked[side] = dict(id=robot['id'], expires_at=expiry, repository_read_verified=True)
    return checked


def setup_scoped(root, alias, repository_prefix):
    """Add one isolated subtree policy using the already configured project robots."""
    scoped_arguments(alias, repository_prefix)
    state = load(root, 'replication-state.json')
    policies, scopes = state['policies'], state.setdefault('policy_scopes', {})
    if alias in policies and scopes.get(alias) != repository_prefix:
        raise ValueError('Existing policy alias must not be repurposed for another subtree')
    stack, apis = clients(root)
    robots = validate_qualification_robots(stack, apis, state, repository_prefix)
    source = apis['source']
    if alias not in policies:
        suffix = hashlib.sha256(repository_prefix.encode()).hexdigest()[:12]
        name = f'cats-scoped-{alias}-{suffix}'
        existing = [item for item in source.pages('/replication/policies') if item.get('name') == name]
        if len(existing) > 1:
            raise RuntimeError('Scoped Harbor policy name unexpectedly matches multiple policies')
        policy = {'name': name,
                  'description': 'Isolated qualification subtree, all tags and Cosign signatures',
                  'dest_registry': {'id': state['registry_id']}, 'dest_namespace': '',
                  'dest_namespace_replace_count': 0, 'trigger': {'type': 'manual'},
                  'filters': [{'type': 'name', 'value': repository_prefix + '/**'}],
                  'replicate_deletion': False, 'override': True, 'enabled': True}
        if existing:
            identity = int(existing[0]['id'])
            verify_scoped_policy(source.get('/replication/policies/' + str(identity)),
                                 state['registry_id'], repository_prefix)
        else:
            response = source.post('/replication/policies', policy)
            identity = int(response.headers['Location'].rsplit('/', 1)[1])
        policies[alias] = identity
        scopes[alias] = repository_prefix
        save(root, 'replication-state.json', state)
    actual = source.get('/replication/policies/' + str(int(policies[alias])))
    verify_scoped_policy(actual, state['registry_id'], repository_prefix)
    report = load(root, 'harbor-replication.json', {'executions': []})
    report.setdefault('policies', {})[alias] = policy_report(actual)
    report.setdefault('policy_scopes', {})[alias] = repository_prefix
    report['robot_preflight'] = robots
    save(root, 'harbor-replication.json', report)
    print(f'Harbor scoped policy {alias} verified for {repository_prefix}/**.')


def replicate(root, namespace, label, interrupt_after=None):
    state = load(root, 'replication-state.json')
    if namespace not in state['policies']:
        matches = [alias for alias, prefix in state.get('policy_scopes', {}).items() if prefix == namespace]
        if len(matches) != 1:
            raise ValueError('Replication requires a configured policy alias or exact scoped repository prefix')
        namespace = matches[0]
    _, apis = clients(root)
    source = apis['source']
    prefix = state.get('policy_scopes', {}).get(namespace)
    if prefix is not None:
        scoped_arguments(namespace, prefix)
        actual = source.get('/replication/policies/' + str(int(state['policies'][namespace])))
        verify_scoped_policy(actual, state['registry_id'], prefix)
    response = source.post('/replication/executions', {'policy_id': state['policies'][namespace]})
    identity = int(response.headers['Location'].rsplit('/', 1)[1])
    deadline = time.monotonic() + 1800
    interrupt_at = time.monotonic() + interrupt_after if interrupt_after is not None else None
    stop_requested = False
    active_before_stop = []
    previous = None
    while time.monotonic() < deadline:
        execution = source.get(f'/replication/executions/{identity}')
        status = execution['status']
        if status != previous:
            print(f'Harbor replication {identity}: {status}', flush=True)
            previous = status
        if status in {'Succeed', 'Failed', 'Stopped'}:
            break
        if interrupt_at is not None and time.monotonic() >= interrupt_at and not stop_requested:
            active = [task for task in source.pages(f'/replication/executions/{identity}/tasks')
                      if task['status'] in {'InProgress', 'Running'}]
            if active:
                active_before_stop = [fields(task, ('id', 'status', 'start_time')) for task in active]
                source.request('PUT', f'/replication/executions/{identity}')
                stop_requested = True
        time.sleep(3)
    else:
        raise TimeoutError(f'Harbor replication {identity} exceeded 30 minutes')
    tasks = source.pages(f'/replication/executions/{identity}/tasks')
    folder = root / 'logs'
    folder.mkdir(exist_ok=True)
    logs = []
    for task in tasks:
        response = source.request('GET', f'/replication/executions/{identity}/tasks/{task["id"]}/log')
        filename = f'execution-{identity}-task-{task["id"]}.log'
        (folder / filename).write_text(response.text, encoding='utf-8')
        logs.append(filename)
    report = load(root, 'harbor-replication.json')
    report['executions'].append({'label': label, 'namespace': namespace,
                                 'execution': execution, 'tasks': tasks, 'logs': logs,
                                 'stop_requested': stop_requested, 'active_tasks_before_stop': active_before_stop})
    save(root, 'harbor-replication.json', report)
    if interrupt_after is not None:
        if (not stop_requested or not active_before_stop or status not in {'Stopped', 'Failed'}
                or not tasks or all(t['status'] == 'Succeed' for t in tasks)):
            raise AssertionError('Interruption test requires an observed active task, explicit stop and incomplete execution')
        print(f'Harbor execution {identity} interrupted with incomplete tasks; logs retained.')
        return
    if status != 'Succeed' or not tasks or any(t['status'] != 'Succeed' for t in tasks):
        raise AssertionError(f'Harbor replication {identity} did not successfully copy every task; see retained logs')
    print(f'Harbor execution {identity} successfully completed {len(tasks)} tasks; logs retained.')


def seed(root, original, label, source_host, harbor_host):
    from app import release_oci, cyber_release_publication as publication
    from nginx_replica_acceptance import copy_receipt
    receipt = load(original, label + '-receipt.json')
    env = dict(os.environ)
    result = copy_receipt(receipt, root / 'seed-layouts', env, source_host, harbor_host)
    # Preserve standard Cosign discovery tags on source Harbor so its adapter
    # can discover signature artifacts. Target writes are exclusively Harbor jobs.
    transport = publication._Transport(root / ('seed-signatures-' + label), env)
    for item in [*receipt['artifacts'], receipt['release']]:
        if item.get('signature'):
            _, repository, digest = release_oci._reference(item['reference'])
            client = release_oci._Client(harbor_host, repository, env)
            signature = item['signature']['digest']
            descriptor = transport.graph(client, signature, client)
            transport.tag(client, descriptor, digest.replace(':', '-') + '.sig')
    save(root, label + '-seed.json', result)
    print(f'Actual {label} nginx receipt seeded into source Harbor; target untouched.')


def transfer_probe(root, harbor_host):
    """A labeled, non-release OCI fixture gives cancellation time to act."""
    import io
    import tarfile
    from app import release_oci as oci, portable_release as portable
    client = oci._Client(harbor_host, 'qualification/interruption', dict(os.environ))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        member = tarfile.TarInfo('synthetic-transfer-probe')
        member.size = 32 * 1024 * 1024
        # A fresh blob ensures repeated tests exercise transfer rather than a
        # destination's existing content-addressed object cache.
        archive.addfile(member, io.BytesIO(os.urandom(32) + b'\0' * (member.size - 32)))
    content = stream.getvalue()
    layer = client.upload(content, 'application/vnd.oci.image.layer.v1.tar')
    config = client.upload(portable.canonical({'architecture': 'amd64', 'os': 'linux',
        'rootfs': {'type': 'layers', 'diff_ids': [oci._digest(content)]}}),
        'application/vnd.oci.image.config.v1+json')
    manifest = portable.canonical({'schemaVersion': 2, 'mediaType': oci.MANIFEST_TYPE,
                                  'config': config, 'layers': [layer]})
    status, _, _ = client.request('PUT', client.api + '/manifests/synthetic-transfer-probe',
                                  body=manifest, media_type=oci.MANIFEST_TYPE)
    if status != 201:
        raise AssertionError('Transfer probe publication failed')
    save(root, 'transfer-probe.json', {'synthetic': True, 'purpose': 'Harbor in-progress cancellation',
        'repository': 'qualification/interruption', 'digest': oci._digest(manifest), 'layer': layer})
    print('Labeled 32 MiB OCI transfer fixture published to source Harbor only.')


def verify_probe(root, harbor_host):
    from app import release_oci as oci, cyber_release_publication as publication
    import uuid
    expected = load(root, 'transfer-probe.json')
    client = oci._Client(harbor_host, expected['repository'], dict(os.environ), pull_only=True)
    transport = publication._Transport(root / ('probe-verification-' + uuid.uuid4().hex), dict(os.environ))
    descriptor = transport.graph(client, expected['digest'])
    if descriptor['digest'] != expected['digest']:
        raise AssertionError('Recovered Harbor transfer changed its immutable root')
    result = {'synthetic': True, 'target': harbor_host, 'digest': descriptor['digest'],
              'layer': expected['layer'], 'complete_graph_verified': True,
              'checked_at': datetime.now(timezone.utc).isoformat()}
    save(root, 'transfer-probe-verified.json', result)
    print('Recovered Harbor transfer graph downloaded and hash-verified from target.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('setup', 'setup-scoped', 'inspect', 'replicate', 'seed', 'transfer-probe', 'verify-probe'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--namespace', default='approved', help='Configured policy alias or exact scoped repository prefix')
    parser.add_argument('--repository-prefix', help='Literal approved/ or qualification/ service subtree for setup-scoped')
    parser.add_argument('--label', default='source')
    parser.add_argument('--interrupt-after', type=float,
                        help='Stop this execution after N seconds; requires incomplete tasks, never reports success')
    parser.add_argument('--original-workspace', type=Path)
    parser.add_argument('--source-host', default='publisher.test:5000')
    parser.add_argument('--harbor-host', default='harbor-source.test:8443')
    args = parser.parse_args()
    if args.phase == 'setup':
        setup(args.workspace)
    elif args.phase == 'setup-scoped':
        if not args.repository_prefix:
            parser.error('setup-scoped requires --namespace ALIAS and --repository-prefix PROJECT/SERVICE')
        setup_scoped(args.workspace, args.namespace, args.repository_prefix)
    elif args.phase == 'inspect':
        inspect_configuration(args.workspace)
    elif args.phase == 'replicate':
        replicate(args.workspace, args.namespace, args.label, args.interrupt_after)
    elif args.phase == 'transfer-probe':
        transfer_probe(args.workspace, args.harbor_host)
    elif args.phase == 'verify-probe':
        verify_probe(args.workspace, args.harbor_host)
    else:
        if args.original_workspace is None or args.label not in {'source', 'patched'}:
            parser.error('seed requires --original-workspace and --label source|patched')
        seed(args.workspace, args.original_workspace, args.label, args.source_host, args.harbor_host)


if __name__ == '__main__':
    main()
