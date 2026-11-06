"""Opt-in, isolated TLS Harbor pair for real replication qualification.

Requires Docker Compose and Python requests, PyYAML and cryptography. The default
is plan-only. --provision uses locally pinned Harbor v2.15.4 images, downloading
only the checksum-verified official installer template when absent. No old Harbor
resources are reused. Credentials and generated configuration remain private in
--workspace; only endpoint metadata is printed. --cleanup stops this recorded
project; --remove-volumes additionally removes its own data, never other stacks.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tarfile
import time
import urllib.request

import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from nginx_acceptance_stack import Docker, private_write, write_json

VERSION = 'v2.15.4'
INSTALLER_SHA256 = 'eeb899cf7b626c925790adba87db9008dd1d73a693a72442651b5bdece9805c6'
OWNER = 'cats-real-harbor-pair-v1'


def private_bytes(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        if os.name == 'posix':
            os.fchmod(output.fileno(), 0o600)
        output.write(value)


def certificates(root):
    folder = root / 'tls'
    folder.mkdir(exist_ok=True)
    if (folder / 'ca.crt').exists():
        ca = x509.load_pem_x509_certificate((folder / 'ca.crt').read_bytes())
        if ca.not_valid_after_utc <= datetime.now(timezone.utc):
            raise ValueError('Harbor acceptance CA expired; use a fresh workspace.')
        return
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATS isolated Harbor acceptance CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
          .not_valid_after(now+timedelta(days=7)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))
    private_bytes(folder / 'ca.key', ca_key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (folder / 'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (folder / 'ca-bundle.crt').write_bytes(Path(requests.certs.where()).read_bytes() + b'\n' +
                                         ca.public_bytes(serialization.Encoding.PEM))
    for side in ('source', 'target'):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'harbor-{side}.test')])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
                .not_valid_after(now+timedelta(days=7)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(f'harbor-{side}.test'),
                     x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .sign(ca_key, hashes.SHA256()))
        (folder / f'{side}.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private_bytes(folder / f'{side}.key', key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def prepare_side(args, docker, side, passwords, lock):
    root = args.workspace
    side_root = root / side
    side_root.mkdir(exist_ok=True)
    archive = root / 'installer.tgz'
    if not archive.exists():
        urllib.request.urlretrieve(f'https://github.com/goharbor/harbor/releases/download/{VERSION}/'
                                   f'harbor-online-installer-{VERSION}.tgz', archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != INSTALLER_SHA256:
        raise ValueError('Official Harbor installer SHA-256 mismatch')
    with tarfile.open(archive) as bundle:
        member = bundle.getmember('harbor/harbor.yml.tmpl')
        template = yaml.safe_load(bundle.extractfile(member).read())
    host = f'harbor-{side}.test'
    template.update(hostname=host, external_url=f'https://{host}:8443', data_volume='/fixture/data',
                    harbor_admin_password=passwords['admin'])
    template.pop('http', None)
    template['https'] = {'port': 8443, 'certificate': f'/fixture/tls/{side}.crt',
                         'private_key': f'/fixture/tls/{side}.key'}
    template['database']['password'] = passwords['database']
    template['log']['local']['location'] = '/fixture/log'
    template['jobservice']['max_job_workers'] = 2
    template.setdefault('storage_service', {})['ca_bundle'] = '/fixture/tls/ca.crt'
    private_write(side_root / 'harbor.yml', yaml.safe_dump(template))
    for directory in ('data', 'common/config', 'log'):
        (side_root / directory).mkdir(parents=True, exist_ok=True)
    prepare_id = lock['cats-harbor-prepare:' + VERSION]['id']
    docker.run('prepare-' + side, ['run', '--rm', '--pull', 'never', '--network', 'none',
        '--mount', f'type=bind,src={side_root},dst=/input',
        '--mount', f'type=bind,src={side_root}/data,dst=/data',
        '--mount', f'type=bind,src={side_root},dst=/compose_location',
        '--mount', f'type=bind,src={side_root}/common/config,dst=/config',
        '--mount', f'type=bind,src={side_root},dst=/hostfs/fixture',
        '--mount', f'type=bind,src={root}/tls,dst=/hostfs/fixture/tls,readonly', prepare_id, 'prepare'])
    return yaml.safe_load((side_root / 'docker-compose.yml').read_text())


def composition(args, prepared, lock):
    result = {'name': args.project, 'services': {}, 'volumes': {}, 'networks': {
        name: {'name': args.project + '_' + name} for name in ('source', 'target', 'bridge')}}
    for side, supplied in prepared.items():
        side_root = args.workspace / side
        for name, service in supplied['services'].items():
            service['image'] = lock[service['image']]['id']
            service.pop('container_name', None)
            service['restart'] = 'no'
            service['logging'] = {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '2'}}
            service.pop('ports', None)
            if name == 'proxy':
                port = args.source_port if side == 'source' else args.target_port
                service['ports'] = [f'127.0.0.1:{port}:8443']
            service['networks'] = {side: {'aliases': [name]}}
            if name in ('proxy', 'jobservice', 'core'):
                service['networks']['bridge'] = {'aliases': [f'harbor-{side}.test']} if name == 'proxy' else {}
            dependencies = service.get('depends_on')
            if isinstance(dependencies, list):
                service['depends_on'] = [side + '-' + item for item in dependencies]
            elif isinstance(dependencies, dict):
                service['depends_on'] = {side + '-' + key: val for key, val in dependencies.items()}
            if name == 'jobservice':
                service['depends_on'] = {side + '-core': {'condition': 'service_healthy'}}
            if 'env_file' in service:
                service['env_file'] = [str(side_root / item.removeprefix('./')) for item in service['env_file']]
            mounts = []
            persistent = {'/storage': ('registry', 10000), '/var/lib/postgresql/data': ('database', 999),
                          '/var/lib/redis': ('redis', 999), '/var/log/jobs': ('jobs', 10000)}
            for entry in service.get('volumes', []):
                if isinstance(entry, str):
                    source, target, *mode = entry.split(':')
                    entry = {'type': 'bind', 'source': source, 'target': target,
                             'read_only': bool(mode and mode[0] == 'ro')}
                if entry['target'] in persistent:
                    logical = side + '-' + persistent[entry['target']][0]
                    result['volumes'][logical] = {'name': args.project + '_' + logical}
                    entry = {'type': 'volume', 'source': logical, 'target': entry['target']}
                else:
                    source = entry['source']
                    if source.startswith('/fixture/'):
                        entry['source'] = str(side_root / source[len('/fixture/'):])
                    elif source.startswith('./'):
                        entry['source'] = str(side_root / source[2:])
                mounts.append(entry)
            service['volumes'] = mounts
            result['services'][side + '-' + name] = service
    return result


def provision(args, owner):
    root = args.workspace
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    docker = Docker(root)
    if owner is None:
        if any((root / name).exists() for name in ('compose.json', 'credentials.json', 'harbor-stack.json')):
            raise ValueError('Unmanaged workspace; choose a fresh directory')
        for kind, command in (('containers', ['ps', '-aq', '--filter', f'label=com.docker.compose.project={args.project}']),
                              ('volumes', ['volume', 'ls', '-q', '--filter', f'name={args.project}_']),
                              ('networks', ['network', 'ls', '-q', '--filter', f'name={args.project}_'])):
            if docker.run('existing-' + kind, command).stdout.strip():
                raise ValueError('Project already owns resources; choose a fresh project')
        write_json(root / 'stack-owner.json', {'owner': OWNER, 'project': args.project,
                   'compose_file': str(root / 'compose.json')})
    lock = json.loads((args.repo / 'tests/harbor/images.lock.json').read_text())
    images = {value['id'] for value in lock.values()}
    inspected = json.loads(docker.run('images', ['image', 'inspect', *sorted(images)]).stdout)
    if {item['Id'] for item in inspected} != images:
        raise ValueError('Local Harbor image identity mismatch')
    certificates(root)
    credentials_path = root / 'credentials.json'
    if credentials_path.exists():
        passwords = json.loads(credentials_path.read_text())
    else:
        passwords = {side: {'admin': secrets.token_urlsafe(30), 'database': secrets.token_urlsafe(30)}
                     for side in ('source', 'target')}
        write_json(credentials_path, passwords)
    prepared = {side: prepare_side(args, docker, side, passwords[side], lock) for side in ('source', 'target')}
    config = composition(args, prepared, lock)
    compose_path = root / 'compose.json'
    write_json(compose_path, config)
    for logical, resource in config['volumes'].items():
        docker.run('volume-' + logical, ['volume', 'create', '--label', 'com.docker.compose.project=' + args.project,
                   '--label', 'com.docker.compose.volume=' + logical, resource['name']])
        uid = 999 if logical.endswith(('-database', '-redis')) else 10000
        docker.run('permissions-' + logical, ['run', '--rm', '--pull', 'never', '--network', 'none',
                   '--entrypoint', 'python3', '--mount', f'type=volume,src={resource["name"]},dst=/seed',
                   lock['cats-harbor-prepare:' + VERSION]['id'], '-c', f'import os; os.chown("/seed",{uid},{uid})'])
    stack = {'version': VERSION, 'project': args.project, 'network': args.project + '_bridge',
             'compose_file': str(compose_path), 'ca_file': str(root / 'tls/ca.crt'),
             'ca_bundle_file': str(root / 'tls/ca-bundle.crt'), 'image_ids': sorted(images)}
    for side, port in (('source', args.source_port), ('target', args.target_port)):
        stack[side] = {'url': f'https://127.0.0.1:{port}', 'endpoint': f'https://harbor-{side}.test:8443',
                       'registry': f'harbor-{side}.test:8443', 'username': 'admin',
                       'password': passwords[side]['admin'],
                       'services': [name for name in config['services'] if name.startswith(side + '-')]}
    write_json(root / 'harbor-stack.json', stack)
    docker.run('start', ['compose', '-p', args.project, '-f', str(compose_path), 'up', '-d', '--pull', 'never'])
    deadline = time.monotonic() + 360
    with requests.Session() as session:
        session.trust_env = False
        session.verify = stack['ca_file']
        for side in ('source', 'target'):
            while time.monotonic() < deadline:
                try:
                    endpoint = stack[side]
                    response = session.get(endpoint['url'] + '/api/v2.0/health', timeout=10)
                    user = session.get(endpoint['url'] + '/api/v2.0/users/current',
                                       auth=('admin', endpoint['password']), timeout=10)
                    if response.status_code == 200 and response.json().get('status') == 'healthy' and user.status_code == 200:
                        break
                except (requests.RequestException, ValueError):
                    pass
                time.sleep(3)
            else:
                raise RuntimeError(f'{side} Harbor was not healthy with authenticated TLS before timeout')
    print(json.dumps({'status': 'ready', 'version': VERSION, 'stack_file': str(root / 'harbor-stack.json'),
                      'network': stack['network'], 'source_url': stack['source']['url'], 'target_url': stack['target']['url']}))


def cleanup(args, owner):
    compose = args.workspace / 'compose.json'
    if not owner or Path(owner['compose_file']).resolve() != compose:
        raise ValueError('Cleanup requires this helper\'s ownership record and exact workspace compose path')
    config = json.loads(compose.read_text())
    if config.get('name') != args.project:
        raise ValueError('Compose project differs from ownership record')
    for collection in ('volumes', 'networks'):
        if any(item.get('external') or not item.get('name', '').startswith(args.project + '_')
               for item in config.get(collection, {}).values()):
            raise ValueError('Cleanup includes resources outside the recorded project')
    command = ['compose', '-p', args.project, '-f', str(compose), 'down']
    if args.remove_volumes:
        command.append('--volumes')
    Docker(args.workspace).run('cleanup', command)
    print(json.dumps({'status': 'stopped', 'project': args.project, 'removed_volumes': args.remove_volumes}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--project', default=None)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--provision', action='store_true')
    action.add_argument('--cleanup', action='store_true')
    parser.add_argument('--remove-volumes', action='store_true')
    parser.add_argument('--source-port', type=int, default=18443)
    parser.add_argument('--target-port', type=int, default=19443)
    args = parser.parse_args()
    args.repo, args.workspace = args.repo.resolve(), args.workspace.resolve()
    if args.remove_volumes and not args.cleanup:
        parser.error('--remove-volumes requires --cleanup')
    if not (1024 <= args.source_port <= 65535 and 1024 <= args.target_port <= 65535) or args.source_port == args.target_port:
        parser.error('Use two distinct unprivileged ports')
    if any(character in str(path) for path in (args.repo, args.workspace) for character in ',\n\r'):
        parser.error('Paths contain Docker mount delimiter characters')
    marker = args.workspace / 'stack-owner.json'
    owner = json.loads(marker.read_text()) if marker.exists() else None
    if owner and (owner.get('owner') != OWNER or (args.project and owner['project'] != args.project)):
        parser.error('Workspace ownership/project mismatch')
    args.project = (owner or {}).get('project') or args.project or ('cats-harbor-' + secrets.token_hex(5))
    if not re.fullmatch('[a-z0-9][a-z0-9_-]{2,62}', args.project):
        parser.error('Invalid Compose project name')
    if args.cleanup:
        cleanup(args, owner)
    elif args.provision:
        provision(args, owner)
    else:
        print(json.dumps({'action': 'plan-only', 'version': VERSION, 'project': args.project,
                          'workspace': str(args.workspace), 'ports': [args.source_port, args.target_port]}))


if __name__ == '__main__':
    main()
