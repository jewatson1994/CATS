"""Bounded temporary SSH bootstrap; only checked-in programs are executable."""
import base64
import hashlib
import io
import os
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import uuid
import time
from .validator_payload import validate_payload, SUPPORTED_UBUNTU

SCRIPTS = Path(os.getenv('CATS_VALIDATOR_BOOTSTRAP_SCRIPTS', str(Path(__file__).with_name('validator_bootstrap_assets'))))

def validate_target(host, ssh_port=22, username='ubuntu', api_port=8443):
    host = str(host).strip().lower()
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise ValueError('Unsafe target address')
    except ValueError as exc:
        if ':' in host or re.fullmatch(r'[0-9.]+', host):
            raise ValueError('Invalid target address') from exc
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('Invalid hostname') from exc
        if host.lower() == 'localhost':
            raise ValueError('Unsafe target hostname')
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError('Invalid hostname label')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', username):
        raise ValueError('Invalid bootstrap username')
    ports = [int(ssh_port), int(api_port)]
    if any(p < 1 or p > 65535 for p in ports):
        raise ValueError('Invalid port')
    return dict(host=host, ssh_port=ports[0], username=username, api_port=ports[1])

class SSHBootstrap:
    def __init__(self, target, credentials, expected_fingerprint=None):
        self.target = validate_target(**{k: target[k] for k in ('host','ssh_port','username','api_port') if k in target})
        self.target['minimum_resources'] = dict(target.get('minimum_resources', {}))
        self.credentials = dict(credentials)
        self._workspace_created = False
        self._remote_root = False
        self.expected_fingerprint = expected_fingerprint
        self.client = None
        self.workspace = '/tmp/cats-bootstrap-' + uuid.uuid4().hex

    def _transport(self):
        import paramiko
        addresses = socket.getaddrinfo(self.target['host'], self.target['ssh_port'], type=socket.SOCK_STREAM)
        for address in addresses:
            validate_target(address[4][0], self.target['ssh_port'], self.target['username'], self.target['api_port'])
        sock = socket.create_connection(addresses[0][4][:2], timeout=15)
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=15)
            return transport
        except Exception:
            transport.close()
            raise

    @staticmethod
    def _fingerprint(transport):
        return 'SHA256:' + base64.b64encode(hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()).decode().rstrip('=')

    def discover_fingerprint(self):
        transport = self._transport()
        try:
            return self._fingerprint(transport)
        finally:
            transport.close()

    def __enter__(self):
        import paramiko
        if not self.expected_fingerprint:
            raise ValueError('Explicit SSH host fingerprint confirmation required')
        transport = self._transport()
        try:
            if self._fingerprint(transport) != self.expected_fingerprint:
                raise ValueError('SSH host key changed or does not match')
            if self.credentials.get('private_key'):
                key = None
                for klass in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                    try:
                        key = klass.from_private_key(io.StringIO(self.credentials['private_key']), password=self.credentials.get('passphrase'))
                        break
                    except (paramiko.SSHException, ValueError):
                        continue
                if key is None:
                    raise ValueError('Unsupported private key')
                transport.auth_publickey(self.target['username'], key)
            else:
                transport.auth_password(self.target['username'], self.credentials.get('password', ''))
            if not transport.is_authenticated():
                raise ValueError('SSH authentication incomplete')
            self.client = paramiko.SSHClient()
            self.client._transport = transport
            return self
        except Exception:
            transport.close()
            raise

    def __exit__(self, *args):
        if self.client:
            self.client.close()
        self.credentials.clear()

    def _collect(self, stdout, timeout=1800):
        channel = stdout.channel
        deadline = time.monotonic() + timeout
        result = bytearray()
        total = 0
        while True:
            for ready, receive in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                while ready():
                    block = receive(32768)
                    total += len(block)
                    if total > 4 * 1024 * 1024:
                        channel.close()
                        raise RuntimeError('Remote output exceeded safety limit')
                    if receive == channel.recv:
                        result.extend(block)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() >= deadline:
                channel.close()
                raise TimeoutError('Remote operation timed out')
            time.sleep(0.02)
        status = channel.recv_exit_status()
        if status:
            raise RuntimeError('Remote operation failed (exit ' + str(status) + ')')
        output = result.decode('utf-8', errors='replace')
        for secret in self.credentials.values():
            if isinstance(secret, str) and secret:
                output = output.replace(secret, '[REDACTED]')
        return output

    def _ensure_workspace(self):
        if not self._workspace_created:
            self._run('workspace.sh')
            self._workspace_created = True

    def _sudo_available(self, passwordless=False):
        # Invalidate cached authentication; probe the actual supplied credential.
        password = '' if passwordless else self.credentials.get('sudo_password', self.credentials.get('password', ''))
        command = 'sudo -k -S -p "" -- true' if password else 'sudo -k -n -- true'
        stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
        if password:
            stdin.write(password + '\n')
        stdin.channel.shutdown_write()
        try:
            self._collect(stdout, 30)
            return True
        except RuntimeError:
            return False

    def _run(self, script, data=None, privileged=False):
        if script not in {'workspace.sh','preflight.sh','install.sh','identity.sh','certificates.sh','start.sh','cleanup.sh'}:
            raise ValueError('Unknown bootstrap operation')
        program = (SCRIPTS / script).read_text(encoding='utf-8-sig')
        if script in {'workspace.sh', 'preflight.sh'}:
            stdin, stdout, stderr = self.client.exec_command('sh -s -- ' + shlex.quote(self.workspace) + ' ' + str(self.target['api_port']) + ' ' + str(int(time.time())), timeout=60)
            stdin.write(program)
            stdin.channel.shutdown_write()
            return self._collect(stdout, 60)
        self._ensure_workspace()
        sftp = self.client.open_sftp()
        try:
            for name, content in [('operation.sh', program), ('input.json', json.dumps(data or {}))]:
                with sftp.file(self.workspace + '/' + name, 'w') as stream:
                    stream.write(content)
                sftp.chmod(self.workspace + '/' + name, 0o600)
            command = ('sudo -S -p "" -- ' if privileged and not self._remote_root else '') + 'sh ' + shlex.quote(self.workspace + '/operation.sh') + ' ' + shlex.quote(self.workspace)
            stdin, stdout, stderr = self.client.exec_command(command, timeout=1800)
            if privileged and not self._remote_root:
                stdin.write(self.credentials.get('sudo_password', self.credentials.get('password','')) + '\n')
            stdin.channel.shutdown_write()
            return self._collect(stdout)
        finally:
            sftp.close()

    def preflight(self):
        facts = json.loads(self._run('preflight.sh'))
        self._remote_root = bool(facts.get('root', False))
        passwordless = self._remote_root or self._sudo_available(passwordless=True)
        facts['sudo_password_required'] = not passwordless
        facts['sudo'] = passwordless or self._sudo_available()
        limits = self.target.get('minimum_resources', {})
        checks = {'platform': facts['os'] == 'ubuntu' and facts['os_version'] in SUPPORTED_UBUNTU, 'architecture': facts['architecture'] in ('amd64','arm64'), 'cpu': facts['cpus'] >= limits.get('cpus',2), 'memory': facts['memory_bytes'] >= limits.get('memory_bytes',4*1024**3), 'disk': facts['disk_bytes'] >= limits.get('disk_bytes',20*1024**3), 'sudo': facts['sudo'], 'systemd': facts['systemd'], 'cgroup_v2': facts.get('cgroup_v2', True), 'time': abs(facts.get('epoch', time.time()) - time.time()) < 300, 'api_port': facts.get('api_port_available', True) or facts.get('existing_service', False)}
        warnings = []
        if facts['cpus'] < 4 or facts['memory_bytes'] < 8*1024**3 or facts['disk_bytes'] < 40*1024**3:
            warnings.append('Resources meet hard minimum only; recommended 4 CPUs, 8 GiB memory, 40 GiB free disk')
        if not facts.get('api_port_available', True):
            warnings.append('API port is occupied by an existing validator service; provisioning replaces that service')
        warnings.append('Administrator must allow HQ to reach the mTLS API port; firewall rules are preserved')
        return {'status': 'supported_with_warnings' if all(checks.values()) and warnings else ('supported' if all(checks.values()) else 'unsupported'), 'checks': checks, 'facts': facts, 'warnings': warnings}

    def transfer_payload(self, path, manifest=None):
        # Catalog deployments pin the catalog globally; this release was already
        # selected and authenticated by HQ. Revalidate against that exact object.
        digest = hashlib.sha256((Path(path)/'manifest.json').read_bytes()).hexdigest() if manifest is not None else None
        verified = validate_payload(path, digest)
        if manifest is not None and verified != manifest:
            raise ValueError('Payload manifest changed')
        self._ensure_workspace()
        sftp = self.client.open_sftp()
        try:
            sftp.mkdir(self.workspace + '/payload', mode=0o700)
            # Upload the in-memory verified manifest, never reread a mutable file.
            with sftp.file(self.workspace + '/payload/manifest.json', 'w') as stream:
                stream.write(json.dumps(verified))
            sftp.chmod(self.workspace + '/payload/manifest.json', 0o600)
            for name in verified['files']:
                parts = name.split('/')
                current = self.workspace + '/payload'
                for part in parts[:-1]:
                    current += '/' + part
                    try: sftp.mkdir(current, mode=0o700)
                    except IOError: sftp.stat(current)
                sftp.put(str(Path(path)/name), self.workspace + '/payload/' + name)
                sftp.chmod(self.workspace + '/payload/' + name, 0o600)
        finally:
            sftp.close()
        return verified

    def install(self, config):
        return self._run('install.sh', config, True)

    def generate_csr(self, validator_id, host):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', validator_id): raise ValueError('Invalid validator identity')
        validate_target(host)
        return self._run('identity.sh', {'validator_id':validator_id, 'host':host}, True)

    def install_certificates(self, cert, ca, client_fingerprint, configuration):
        if not re.fullmatch(r'[a-fA-F0-9]{64}',client_fingerprint): raise ValueError('Invalid client fingerprint')
        return self._run('certificates.sh', {'cert':cert,'ca':ca,'client_fingerprint':client_fingerprint,'configuration':configuration}, True)

    def start_service(self):
        return self._run('start.sh', privileged=True)

    def cleanup(self):
        if self._workspace_created:
            return self._run('cleanup.sh')
