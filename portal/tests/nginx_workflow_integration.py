"""Opt-in HTTP acceptance driver for a real nginx scan, patch and approval.

Run against an explicitly provisioned isolated stack; never seeds database rows
or substitutes scanner reports. Secrets and resumable state live in --workspace.
The companion nginx_replica_acceptance module verifies replicated OCI graphs.
"""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import parse_qs, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PAGE = 'application/vnd.cats.page+json'


class API:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.session = requests.Session()
        self.session.trust_env = False
        # Polls can race a server's idle keep-alive close. Retry reads only;
        # never replay a state-changing request after an ambiguous response.
        retries = Retry(total=2, connect=0, read=2, other=0,
                        allowed_methods={'GET'}, backoff_factor=0.3)
        for scheme in ('http://', 'https://'):
            self.session.mount(scheme, HTTPAdapter(max_retries=retries))
        self.csrf = None

    def request(self, method, path, **kwargs):
        response = self.session.request(method, self.base + path,
            timeout=kwargs.pop('timeout', 180), allow_redirects=False, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f'{method} {path}: {response.status_code}: {response.text[:2000]}')
        return response

    def page(self, path):
        return self.request('GET', path, headers={'Accept': PAGE}).json()['data']

    def login(self, username, password, new_password=None):
        response = self.request('POST', '/login', data={'username': username, 'password': password})
        location = response.headers.get('Location', '/')
        self.csrf = self.page('/account/password')['csrf_token']
        if location == '/account/password':
            if not new_password:
                raise RuntimeError('An initial password change is required')
            self.form('/account/password', current_password=password, new_password=new_password,
                      confirmation=new_password)
        return self

    def get(self, path):
        return self.request('GET', path).json()

    def post(self, path, data):
        return self.request('POST', path, json=data, headers={'X-CSRF-Token': self.csrf}).json()

    def form(self, path, files=None, **data):
        return self.request('POST', path, data={'csrf_token': self.csrf, **data}, files=files)


def wait_for(fetch, status, success, failure, label, timeout=3600):
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        value = fetch()
        current = status(value)
        if current != last:
            print(f'{label}: {current}', flush=True)
            last = current
        if current in success:
            return value
        if current in failure:
            raise RuntimeError(f'{label} failed: {json.dumps(value)[:5000]}')
        time.sleep(5)
    raise TimeoutError(f'{label} exceeded {timeout} seconds')


def save(root, name, value):
    # Resumable state contains one-time machine credentials. NamedTemporaryFile
    # creates mode 0600 on POSIX; replacement preserves that private mode.
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=root,
                                         prefix='.' + name + '-', delete=False) as output:
            pending = Path(output.name)
            json.dump(value, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, root / name)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


def load(root, name, default=None):
    path = root / name
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else default


def assign(admin, username, role, *, group_id=None, service_id=None):
    page = admin.page('/admin')
    user_id = next(item['id'] for item in page['users'] if item['username'] == username)
    role_id = next(item['id'] for item in page['roles'] if item['name'] == role)
    scope = {'group_id': group_id} if group_id is not None else {'service_id': service_id}
    if not any(value is not None for value in scope.values()):
        raise ValueError('Acceptance roles must have explicit scope')
    admin.form('/admin/assignments', user_id=user_id, role_id=role_id,
               assignment_mode='local', **scope)


def setup(api, root, stack, state):
    groups = api.page('/admin')['groups']
    group = next((item for item in groups if item['name'] == 'nginx acceptance'), None)
    if not group:
        api.form('/admin/groups', name='nginx acceptance', description='Isolated real workflow acceptance')
        group = next(item for item in api.page('/admin')['groups'] if item['name'] == 'nginx acceptance')
    state['group_id'] = group['id']
    assign(api, stack['admin_username'], 'Cybersecurity', group_id=group['id'])
    cert = (root / 'tls' / 'registry.crt').read_bytes()
    configuration = api.page('/admin/configuration')
    if not configuration['certificates']:
        api.form('/admin/configuration/trusted-certificates', files={'certificate': ('registry.crt', cert)})
    registry_id = 'nginx-acceptance'
    api.form('/admin/configuration/registries', registry_id=registry_id,
        display_name='Isolated nginx patch destination', endpoint='https://publisher.test:5000',
        namespace='patched', auth_mode='none', use_for_remediation='true')
    state['patch_registry_id'] = registry_id
    signer = stack.get('signer') or load(root, 'signer.json', {})
    if not configuration['signing'].get('configured'):
        api.form('/admin/configuration/signing', enabled='true', action='save',
            key_password=signer['password'], files={
                'private_key': ('cosign.key', (root / signer.get('host_key_path', signer.get('private_key', 'cosign.key'))).read_bytes()),
                'public_key': ('cosign.pub', (root / signer.get('host_public_key_path', signer.get('public_key', 'cosign.pub'))).read_bytes())})
    elif not configuration['signing'].get('enabled'):
        api.form('/admin/configuration/signing', enabled='true', action='save')
    state['trusted_fingerprint'] = api.page('/admin/configuration')['signing']['fingerprint']
    destinations = api.get('/api/approved-release-destinations')['items']
    destination = next((item for item in destinations if item['name'] == 'nginx acceptance'), None)
    if not destination:
        destination = api.post('/api/approved-release-destinations', {
            'name': 'nginx acceptance', 'endpoint': 'https://publisher.test:5000', 'namespace': 'approved',
            'ca_pem': cert.decode(), 'group_ids': [group['id']], 'is_default': True, 'enabled': True})
    state['destination_id'] = destination['id']
    state.setdefault('service_key', 'nginx-replica-acceptance')
    save(root, 'workflow-state.json', state)
    print('Normal administration and scoped workflow permissions configured.', flush=True)


def discover_scan(api, root, state, label, reference, retry_scan=False, replace_failed_publication=False):
    checkpoint = state.setdefault(label, {})
    if checkpoint.get('reference') and checkpoint['reference'] != reference:
        raise RuntimeError('The retained discovery belongs to a different input reference')
    def persist():
        save(root, 'workflow-state.json', state)
    if not checkpoint.get('discovery_id'):
        response = api.form('/api/discovery', group_id=state['group_id'], input_kind='reference',
                            reference=reference, options='{}')
        checkpoint['reference'] = reference
        checkpoint['discovery_id'] = response.json()['job_id']
        persist()
    result = wait_for(lambda: api.get('/api/discovery/' + checkpoint['discovery_id']),
        lambda item: item['job']['status'], {'completed'}, {'failed', 'cancelled'}, label + ' discovery')
    save(root, label + '-discovery.json', result)
    if not checkpoint.get('confirmation_id'):
        target = {'service_id': state['service_id']} if state.get('service_id') else {'new_service_key': state['service_key']}
        confirmation = api.post('/api/discovery/' + checkpoint['discovery_id'] + '/confirm',
            {**target, 'root_ids': [item['id'] for item in result['inventory']['roots']]})
        checkpoint['confirmation_id'] = confirmation['confirmed_inventory_id']
        services = api.get('/api/discovery')['services']
        state['service_id'] = next(item['id'] for item in services if item['service_key'] == state['service_key'])
        persist()
    path = '/api/services/' + state['service_key'] + '/distributions'
    if not checkpoint.get('distribution_id'):
        result = api.post(path, {'name': 'nginx ' + label, 'confirmation_id': checkpoint['confirmation_id'], 'enabled_chart_ids': []})
        checkpoint['distribution_id'] = result['distribution']['id']
        persist()
    if replace_failed_publication:
        if not checkpoint.get('approval_id'):
            raise RuntimeError('Replacing a failed publication requires a retained approval')
        prior = api.get('/api/cyber-approvals/' + str(checkpoint['approval_id']))
        publication = prior.get('publication') or {}
        if prior['publish_status'] != 'failed' or publication.get('release'):
            raise RuntimeError('Only an unpublished failed approval can be replaced by a fresh scan')
        save(root, label + '-failed-approval-' + str(prior['id']) + '.json', prior)
        checkpoint.setdefault('unsuccessful_approvals', []).append({
            'approval_id': prior['id'], 'scan_id': checkpoint['scan_id'],
            'source_execution_id': checkpoint.get('source_execution_id'),
            'diagnostic': prior.get('publication', {}).get('diagnostic')})
        for key in ('scan_id', 'source_execution_id', 'approval_id'):
            checkpoint.pop(key, None)
        persist()
    if retry_scan and checkpoint.get('scan_id'):
        prior = api.get('/api/public/jobs/' + checkpoint['scan_id'])
        if prior['status'] not in {'failed', 'error', 'incomplete', 'cancelled'} or checkpoint.get('approval_id'):
            raise RuntimeError('Only an unsuccessful, unapproved scan may be retried')
        checkpoint.setdefault('unsuccessful_scans', []).append(prior)
        save(root, label + '-failed-scan-' + checkpoint['scan_id'] + '.json', prior)
        checkpoint.pop('scan_id')
        persist()
    if not checkpoint.get('scan_id'):
        result = api.post(path + '/' + checkpoint['distribution_id'] + '/scan', {})
        checkpoint['scan_id'] = result['job_id']
        persist()
    result = wait_for(lambda: api.get('/api/public/jobs/' + checkpoint['scan_id']),
        lambda item: item['status'], {'complete'}, {'incomplete', 'error', 'failed', 'cancelled'}, label + ' scan')
    save(root, label + '-scan.json', result)
    readiness = api.get('/api/services/' + state['service_key'] + '/cyber-approval-readiness?distribution_id=' + checkpoint['distribution_id'])
    save(root, label + '-readiness.json', readiness)
    if not readiness['ready']:
        raise RuntimeError(f'{label} is not ready for approval: {readiness["blockers"]}')
    checkpoint['source_execution_id'] = readiness['source_execution_id']
    persist()
    return checkpoint


def approve(api, root, state, label):
    checkpoint = state[label]
    if not checkpoint.get('approval_id'):
        approval = api.post('/api/cyber-approvals', {
            'service_key': state['service_key'], 'variant': 'current_service',
            'distribution_id': checkpoint['distribution_id'],
            'expected_source_execution_id': checkpoint['source_execution_id'],
            'destination_id': state['destination_id'],
            'rationale': 'Isolated acceptance of real nginx scanner evidence and disconnected enforcement.'})
        checkpoint['approval_id'] = approval['id']
        save(root, 'workflow-state.json', state)
    path = '/api/cyber-approvals/' + str(checkpoint['approval_id'])
    approval = api.get(path)
    if approval['status'] == 'pending':
        api.post(path + '/decision', {'decision': 'approved',
            'rationale': 'Risk accepted for isolated workflow verification; this approval is not a production deployment.'})
    result = wait_for(lambda: api.get(path), lambda item: item['publish_status'],
        {'published'}, {'failed'}, label + ' signed publication')
    save(root, label + '-approval.json', result)
    receipt = result.get('publication') or {}
    save(root, label + '-receipt.json', receipt)
    if (receipt.get('status') != 'published'
            or receipt.get('verification_status') != 'verified'
            or receipt.get('signature_status') != 'verified'
            or not receipt.get('artifacts') or not receipt.get('release')
            or not (receipt.get('manifest') or {}).get('portable')):
        raise RuntimeError(f'{label} has no complete, verified portable publication receipt')
    for artifact in [*receipt['artifacts'], receipt['release']]:
        if (not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', artifact.get('reference', ''))
                or artifact['reference'].rsplit('@', 1)[1] != artifact.get('digest')
                or not artifact.get('tag')
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', (artifact.get('signature') or {}).get('digest', ''))):
            raise RuntimeError(f'{label} publication is missing immutable artifact or signature identities')
    if label == 'patched':
        immutable_patch = patched_reference(load(root, 'patch-result.json', {}))
        patch_digest = immutable_patch.rsplit('@', 1)[1]
        images = [item for item in receipt['artifacts'] if item.get('kind') == 'image']
        if (len(images) != 1 or not images[0].get('scan_identity_retained')
                or images[0].get('source_digest') != patch_digest
                or images[0].get('digest') != patch_digest):
            raise RuntimeError('Patched approval does not retain the actual immutable patch output')
    return result


def patched_reference(result):
    receipt = result.get('result') or {}
    reference = receipt.get('immutable_destination', '')
    if (result.get('status') != 'complete' or receipt.get('status') != 'complete'
            or receipt.get('output_mode') != 'push'
            or receipt.get('delivery_status') != 'delivered'
            or receipt.get('signature_status') != 'verified'
            or receipt.get('patch_status') not in {'PATCHED', 'PARTIALLY_PATCHED'}
            or not receipt.get('vulnerabilities_removed', 0)
            or not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', reference)):
        raise RuntimeError('Patch did not provide a signed, delivered, immutable image with actual vulnerability remediation; inspect patch-result.json')
    return reference


def patch(api, root, state, reference, retry_patch=False):
    if retry_patch:
        if not state.get('patch_id') or state.get('patched'):
            raise RuntimeError('Retry requires a retained unsuccessful patch without a successor discovery')
        prior = api.get('/api/public/patch-jobs/' + state['patch_id'])
        if prior['status'] not in {'failed', 'cancelled'}:
            raise RuntimeError('Only an unsuccessful patch may be retried')
        save(root, 'failed-patch-' + state['patch_id'] + '.json', prior)
        state.setdefault('unsuccessful_patches', []).append(prior)
        state.pop('patch_id')
        save(root, 'workflow-state.json', state)
    if not state.get('patch_id'):
        response = api.form('/patch', source_mode='oci', source_image=reference, output_mode='push',
            destination_image='nginx:patched', destination_registry_id=state['patch_registry_id'],
            service_id=state['service_key'])
        location = urlparse(response.headers.get('Location', ''))
        job_ids = parse_qs(location.query).get('job_id', [])
        if response.status_code != 303 or location.path != '/patch' or len(job_ids) != 1:
            raise RuntimeError(f'Patch was not accepted ({response.status_code}): {response.text[:2000]}')
        state['patch_id'] = job_ids[0]
        save(root, 'workflow-state.json', state)
    result = wait_for(lambda: api.get('/api/public/patch-jobs/' + state['patch_id']),
        lambda item: item['status'], {'complete'}, {'failed', 'cancelled'}, 'nginx package patch', timeout=7200)
    save(root, 'patch-result.json', result)
    if (result.get('result') or {}).get('source_image') != reference:
        raise RuntimeError('Patch output does not belong to the approved immutable source')
    state['patched_reference'] = patched_reference(result)
    save(root, 'workflow-state.json', state)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('setup', 'source', 'patch', 'patched'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--image', default='docker.io/library/nginx:1.28.0-alpine3.21')
    parser.add_argument('--retry-scan', action='store_true', help='Resubmit a retained unsuccessful scan after correcting its cause')
    parser.add_argument('--retry-patch', action='store_true', help='Resubmit a retained unsuccessful patch after correcting its cause')
    parser.add_argument('--replace-failed-publication', action='store_true',
        help='Keep an unpublished failed approval in history and scan again for a fresh approval')
    args = parser.parse_args()
    root = args.workspace.resolve()
    stack = load(root, 'stack.json')
    state = load(root, 'workflow-state.json', {})
    api = API(stack['full_url'])
    password = stack['admin_new_password'] if state.get('password_changed') else stack['admin_password']
    api.login(stack['admin_username'], password, stack['admin_new_password'])
    state['password_changed'] = True
    save(root, 'workflow-state.json', state)
    if args.phase == 'setup':
        setup(api, root, stack, state)
    elif args.phase == 'source':
        discover_scan(api, root, state, 'source', args.image, args.retry_scan, args.replace_failed_publication)
        approve(api, root, state, 'source')
    elif args.phase == 'patch':
        source = load(root, 'source-receipt.json', {})
        images = [item for item in source.get('artifacts', []) if item.get('kind') == 'image']
        if len(images) != 1 or not images[0].get('scan_identity_retained'):
            raise RuntimeError('Patch requires one approved nginx image with retained scan identity')
        artifact = images[0]
        reference = artifact['source_reference'].split('@', 1)[0] + '@' + artifact['source_digest']
        state['patch_source_reference'] = reference
        save(root, 'workflow-state.json', state)
        patch(api, root, state, reference, args.retry_patch)
    elif args.phase == 'patched':
        patch_result = load(root, 'patch-result.json', {})
        reference = patched_reference(patch_result)
        discover_scan(api, root, state, 'patched', reference, args.retry_scan, args.replace_failed_publication)
        approve(api, root, state, 'patched')


if __name__ == '__main__':
    main()
