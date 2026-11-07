"""Opt-in HTTPS, local authorization, restore and bounded-load qualification.

Run only against an explicitly isolated restored replica: the live phase creates
local qualification accounts/roles through the normal administration API. Private
credentials are read from a private stack file and are never included in reports.
This does not certify production DNS, enterprise PKI, external SSO or capacity.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import socket
import ssl
import statistics
import time
from urllib.parse import urlsplit

import requests

from nginx_workflow_integration import API


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def tls_probe(url, ca_bundle):
    """Require both chain verification and the URL's exact hostname."""
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Use an explicit credential-free HTTPS deployment origin')
    address = (parsed.hostname, parsed.port or 443)
    context = ssl.create_default_context(cafile=str(ca_bundle))
    with socket.create_connection(address, timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=parsed.hostname) as stream:
            cert = stream.getpeercert()
            result = dict(hostname=parsed.hostname, port=address[1], protocol=stream.version(),
                certificate_sha256=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest(),
                subject_alternative_names=cert.get('subjectAltName', []),
                not_after=cert.get('notAfter'), trusted_ca_and_hostname=True)
    for label, ctx, hostname in (
        ('wrong_hostname_rejected', context, 'wrong-name.invalid'),
        ('untrusted_ca_rejected', ssl.create_default_context(), parsed.hostname),
    ):
        try:
            with socket.create_connection(address, timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError:
            result[label] = True
        else:
            raise AssertionError(label + ' failed')
    return result


def compare_snapshots(before, after):
    """Compare every table, sequence and evidence file, never sample rows."""
    for category in ('tables', 'sequences', 'evidence'):
        require(category in before and category in after, 'Missing snapshot category: ' + category)
        require(before[category] == after[category], 'Restore differs: ' + category)
    require(before['tables'] and before['evidence'], 'Empty state is not a retained-evidence restore drill')
    return dict(equal=True, table_count=len(before['tables']),
        row_count=sum(item['rows'] for item in before['tables'].values()),
        sequence_count=len(before['sequences']), evidence_files=len(before['evidence']),
        evidence_bytes=sum(item['bytes'] for item in before['evidence'].values()))


def summarize_load(samples, elapsed, max_p95_ms):
    require(bool(samples), 'Load qualification must make requests')
    failures = sum(code != 200 for code, _ in samples)
    latency = sorted(ms for _, ms in samples)
    p95 = latency[max(0, (95 * len(latency) + 99) // 100 - 1)]
    result = dict(requests=len(samples), failures=failures, elapsed_seconds=round(elapsed, 3),
        requests_per_second=round(len(samples) / elapsed, 2),
        latency_ms=dict(min=round(latency[0], 2), median=round(statistics.median(latency), 2),
                        p95=round(p95, 2), max=round(latency[-1], 2)),
        max_p95_ms=max_p95_ms, passed=failures == 0 and p95 <= max_p95_ms)
    require(result['passed'], 'Bounded read load failed its declared status/latency limit: ' + json.dumps(result))
    return result


def qualify_password_change(client, username, initial_password, new_password):
    """Prove the challenge, mutation and authentication with replaced credentials."""
    challenge = client.request('POST', '/login',
        data={'username': username, 'password': initial_password})
    require(challenge.status_code == 303 and challenge.headers.get('Location') == '/account/password',
            'Initial credentials must explicitly require a password change')
    client.csrf = client.page('/account/password')['csrf_token']
    require(bool(client.csrf), 'Password change page must provide an authenticated CSRF token')
    changed = client.form('/account/password', current_password=initial_password,
                          new_password=new_password, confirmation=new_password)
    require(changed.status_code == 303 and changed.headers.get('Location') == '/',
            'Password change must complete successfully')

    # A still-authenticated session cannot prove that the new credentials work.
    client.session.cookies.clear()
    client.csrf = None
    rejected = client.session.post(client.base + '/login',
        data={'username': username, 'password': initial_password}, allow_redirects=False, timeout=30)
    require(rejected.status_code == 401, 'Replaced initial credentials must be rejected')
    client.session.cookies.clear()
    authenticated = client.request('POST', '/login',
        data={'username': username, 'password': new_password})
    require(authenticated.status_code == 303 and authenticated.headers.get('Location') == '/',
            'New credentials must authenticate without another password-change challenge')
    client.csrf = client.page('/account/password')['csrf_token']
    require(bool(client.csrf), 'New credentials must establish an authenticated session')
    return dict(challenge=dict(status=challenge.status_code, location=challenge.headers['Location']),
                change=dict(status=changed.status_code, location=changed.headers['Location']),
                initial_credentials_rejected_status=rejected.status_code,
                fresh_login=dict(status=authenticated.status_code,
                                 location=authenticated.headers['Location']),
                authenticated_password_page=True, passed=True)


def live(args):
    stack = json.loads(args.stack.read_text(encoding='utf-8-sig'))
    report = {'scope': 'Isolated restored local qualification deployment; not production acceptance',
              'tls': {key: tls_probe(stack[key], args.ca_bundle) for key in ('replica_url', 'proxy_url')}}
    api = API(stack['replica_url'])
    api.session.verify = str(args.ca_bundle)
    api.login(stack['replica_admin_username'], stack['replica_admin_new_password'])
    require(any(cookie.secure for cookie in api.session.cookies), 'Login cookie must be Secure')
    report['local_auth'] = dict(login=True, secure_cookie=True)
    anonymous = requests.Session()
    anonymous.trust_env = False
    anonymous.verify = str(args.ca_bundle)
    denied = anonymous.get(stack['replica_url'] + '/api/replica/releases', allow_redirects=False, timeout=20)
    require(denied.status_code in (401, 303), 'Anonymous release access was not denied')
    report['local_auth']['anonymous_denied_status'] = denied.status_code
    readiness = anonymous.get(stack['replica_url'] + '/readyz', allow_redirects=False, timeout=20)
    require(readiness.status_code == 200 and readiness.json() == {'status': 'ready'},
            'Anonymous deployment readiness must work through application middleware')
    report['anonymous_readiness'] = dict(status=readiness.status_code, body=readiness.json())
    releases = api.get('/api/replica/releases')['releases']
    require(releases, 'Restore must retain releases')
    evidence = []
    for release in releases:
        path = '/api/replica/releases/' + str(release['id'])
        context = api.get(path + '/context')
        raw = api.request('GET', path + '/evidence').content
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        require(digest == context['manifest']['evidence']['digest'], 'Restored signed evidence digest mismatch')
        evidence.append(dict(release_id=release['id'], service_id=release['service_id'],
            manifest_digest=release['manifest_digest'], evidence_digest=digest, evidence_bytes=len(raw)))
    report['restored_signed_evidence'] = evidence
    selected = releases[0]
    service_id = selected['service_id']
    release_path = '/api/replica/releases/' + str(selected['id']) + '/context'
    suffix = secrets.token_hex(5)
    username = 'deployment-viewer-' + suffix
    first_password, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    api.form('/admin/users', username=username, display_name='Isolated deployment viewer', password=first_password)
    viewer = API(stack['replica_url'])
    viewer.session.verify = str(args.ca_bundle)
    pending = viewer.request('POST', '/login', data={'username': username, 'password': first_password})
    require(pending.status_code == 303 and pending.headers.get('Location') == '/account/access',
            'Account without local grants must remain pending')
    page = api.page('/admin')
    user_id = next(row['id'] for row in page['users'] if row['username'] == username)
    auth = {}

    def status(client, path, expected):
        response = client.session.get(client.base + path, allow_redirects=False, timeout=30)
        require(response.status_code == expected, f'Authorization returned {response.status_code}; expected {expected}')
        return response.status_code

    auth['ungranted_evidence'] = status(viewer, release_path, 403)
    role_name = 'Deployment service viewer ' + suffix
    api.form('/admin/roles', name=role_name, permissions=['service.view'])
    role_id = next(row['id'] for row in api.page('/admin')['roles'] if row['name'] == role_name)
    api.form('/admin/assignments', user_id=user_id, role_id=role_id, service_id=service_id)
    auth['password_change'] = qualify_password_change(viewer, username, first_password, password)
    auth['service_view_without_evidence'] = status(viewer, release_path, 403)
    api.form('/admin/roles', name='Deployment evidence viewer ' + suffix,
             permissions=['service.view', 'evidence.view'])
    evidence_role = next(row['id'] for row in api.page('/admin')['roles']
                         if row['name'] == 'Deployment evidence viewer ' + suffix)
    api.form('/admin/assignments', user_id=user_id, role_id=evidence_role, service_id=service_id)
    auth['scoped_evidence_allowed'] = status(viewer, release_path, 200)
    other = next((row for row in releases if row['service_id'] != service_id), None)
    require(other is not None, 'Scope isolation qualification needs a second retained service')
    auth['other_service_evidence_denied'] = status(viewer,
        '/api/replica/releases/' + str(other['id']) + '/context', 404)
    auth['source_admin_api_denied'] = status(viewer, '/api/replica/sources', 403)
    missing_csrf = api.session.post(api.base + '/api/replica/sources', json={}, timeout=20)
    require(missing_csrf.status_code == 403, 'CSRF-less mutation was not rejected')
    auth['csrf_denied'] = missing_csrf.status_code
    assignments = next(row['assignments'] for row in api.page('/admin')['user_rows']
                       if row['user']['id'] == user_id)
    for row in assignments:
        if row['role'] == 'Deployment evidence viewer ' + suffix:
            api.form('/admin/assignments/' + str(row['id']) + '/delete')
    auth['same_session_role_removal_denied'] = status(viewer, release_path, 403)
    report['local_roles'] = auth
    cookies = api.session.cookies.get_dict()
    paths = ['/readyz', '/api/replica/releases', release_path]

    def worker(index):
        session = requests.Session()
        session.trust_env = False
        session.verify = str(args.ca_bundle)
        session.cookies.update(cookies)
        rows = []
        for offset in range(args.requests_per_worker):
            started = time.perf_counter()
            response = session.get(api.base + paths[(index + offset) % len(paths)], timeout=30,
                                   allow_redirects=False)
            rows.append((response.status_code, (time.perf_counter() - started) * 1000))
        session.close()
        return rows

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        samples = [row for group in pool.map(worker, range(args.concurrency)) for row in group]
    report['bounded_load'] = summarize_load(samples, time.perf_counter() - started, args.max_p95_ms)
    report['bounded_load'].update(concurrency=args.concurrency, paths=paths,
        scope='Authenticated read burst only; does not establish sustained production sizing or registry throughput')
    require(api.get('/health')['status'] == 'ok', 'Portal did not recover after bounded load')
    require(api.get('/readyz')['status'] == 'ready', 'Database readiness did not recover after bounded load')
    report['health_after_load'] = True
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': True, 'evidence_releases': len(evidence),
                      'requests': len(samples), 'report': str(args.output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack', type=Path, required=True)
    parser.add_argument('--ca-bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--concurrency', type=int, choices=range(1, 33), default=8)
    parser.add_argument('--requests-per-worker', type=int, choices=range(1, 1001), default=30)
    parser.add_argument('--max-p95-ms', type=float, default=5000)
    live(parser.parse_args())


if __name__ == '__main__':
    main()
