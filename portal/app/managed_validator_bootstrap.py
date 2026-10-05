"""Temporary pinned SSH deployment to an existing dedicated Docker-ready host.

No host package installation is permitted. Only two verified image archives,
private mTLS material and an owned validator container are transferred.
"""
from __future__ import annotations

import os
import base64
import errno
import hashlib
import hmac
import io
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import time
import uuid


class BootstrapError(RuntimeError):
    """Safe operator message; never carries SSH output or credential text."""


def preflight_failure(result):
    """Describe only structured host checks, never raw SSH output."""
    failed = [name for name, passed in result.get('checks', {}).items() if passed is not True]
    facts = result.get('facts', {})
    details = []
    for name, key, minimum in (('disk', 'disk_free_bytes', 20 * 1024**3),
                               ('memory', 'memory_bytes', 4 * 1024**3), ('cpu', 'cpus', 2)):
        if name in failed and isinstance(facts.get(key), (int, float)):
            details.append(f'{key}={facts[key]} (minimum {minimum})')
    error = BootstrapError('Validator host prerequisites failed: ' + (', '.join(failed) or 'inspection unavailable')
                           + ('. ' + '; '.join(details) if details else '')
                           + '. Review host readiness checks before retrying.')
    error.preflight = result
    return error


def validate_target(host, ssh_port=22, username='ubuntu', api_port=8443):
    host = str(host).strip().lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (not re.fullmatch(r'(?=.{1,253}$)[a-z0-9.-]+', host)
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.'))):
            raise ValueError('Invalid validator hostname') from None
    else:
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise ValueError('Validator must be a dedicated nonlocal host')
    if host == 'localhost' or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', str(username)):
        raise ValueError('Invalid validator bootstrap target')
    if any(isinstance(port, bool) or not str(port).isdigit() or not 1 <= int(port) <= 65535 for port in (ssh_port, api_port)):
        raise ValueError('Invalid validator port')
    return {'host': host, 'ssh_port': int(ssh_port), 'username': username, 'api_port': int(api_port)}


def _owner(value):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', str(value)):
        raise ValueError('Invalid managed validator ID')
    return str(value)


def _image(value):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,500}', str(value)):
        raise ValueError('Invalid release image reference')
    return str(value)


def validate_release(release):
    """Re-read the exact validated local release, preventing changed input rows."""
    from .managed_validator_release import load_release
    if not isinstance(release, dict) or not release.get('_directory'):
        raise ValueError('Validated managed validator release is required')
    verified = load_release(release['_directory'])
    if verified != release:
        raise ValueError('Managed validator release changed after validation')
    checked = {}
    for kind in ('cats', 'node'):
        row = verified[kind + '_image']
        checked[kind] = {'path': Path(verified['_directory']) / row['file'],
            'sha256': row['sha256'].removeprefix('sha256:'),
            'image_id': row['image_id'], 'reference': _image(row['reference'].split('@')[0])}
    return checked


class SSHBootstrap:
    def __init__(self, target, credentials, expected_fingerprint=None):
        self.target = validate_target(**{key: target[key] for key in ('host', 'ssh_port', 'username', 'api_port') if key in target})
        self.credentials = dict(credentials or {})
        self.expected_fingerprint = expected_fingerprint
        self.transport = None
        self.workspace = '/tmp/cats-validator-bootstrap-' + uuid.uuid4().hex
        self._staged = False

    @staticmethod
    def _fingerprint(transport):
        return 'SHA256:' + base64.b64encode(hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()).decode().rstrip('=')

    def _transport(self):
        import paramiko
        sock = None
        try:
            addresses = socket.getaddrinfo(self.target['host'], self.target['ssh_port'], type=socket.SOCK_STREAM)
            if not addresses:
                raise BootstrapError('Validator SSH address is unavailable')
            for address in addresses:
                validate_target(address[4][0], self.target['ssh_port'], self.target['username'], self.target['api_port'])
            sock = socket.create_connection(addresses[0][4][:2], timeout=15)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=15)
            return transport
        except Exception:
            if sock:
                sock.close()
            raise BootstrapError('Validator SSH connection failed') from None

    def discover_fingerprint(self):
        transport = None
        try:
            transport = self._transport()
            return self._fingerprint(transport)
        finally:
            if transport:
                transport.close()
            self.credentials.clear()

    def __enter__(self):
        import paramiko
        if not self.expected_fingerprint or not re.fullmatch(r'SHA256:[a-zA-Z0-9+/]{43}', self.expected_fingerprint):
            self.credentials.clear()
            raise BootstrapError('Explicit SSH fingerprint confirmation is required')
        transport = None
        try:
            transport = self._transport()
            if not hmac.compare_digest(self._fingerprint(transport), self.expected_fingerprint):
                raise BootstrapError('SSH fingerprint mismatch; confirm the host independently')
            if self.credentials.get('private_key'):
                key = None
                for kind in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                    try:
                        key = kind.from_private_key(io.StringIO(self.credentials['private_key']), password=self.credentials.get('passphrase'))
                        break
                    except (paramiko.SSHException, ValueError):
                        continue
                if key is None:
                    raise BootstrapError('Bootstrap SSH private key is invalid')
                transport.auth_publickey(self.target['username'], key)
            elif self.credentials.get('password'):
                transport.auth_password(self.target['username'], self.credentials['password'])
            else:
                raise BootstrapError('Temporary bootstrap SSH credentials are required')
            if not transport.is_authenticated():
                raise BootstrapError('Validator SSH authentication failed')
            self.transport = transport
            # Authentication material is retired immediately; sudo remains only
            # inside this bounded operation and is removed on exit.
            for name in ('private_key', 'passphrase', 'password'):
                self.credentials.pop(name, None)
            return self
        except Exception as exc:
            if transport:
                transport.close()
            self.credentials.clear()
            if isinstance(exc, BootstrapError):
                raise
            raise BootstrapError('Validator SSH authentication failed') from None

    def __exit__(self, *args):
        try:
            if self._staged and self.transport:
                self._run('rm -rf -- ' + shlex.quote(self.workspace), timeout=30)
        except BootstrapError:
            pass
        finally:
            if self.transport:
                self.transport.close()
            self.transport = None
            self.credentials.clear()

    def _run(self, script, *, sudo=False, timeout=60):
        if not self.transport:
            raise BootstrapError('Validator SSH session is not connected')
        password = self.credentials.get('sudo_password') if sudo else None
        command = ('sudo -S -p "" ' if password else 'sudo -n ') if sudo else ''
        command += 'bash -c ' + shlex.quote('set -euo pipefail\n' + script)
        channel = None
        try:
            channel = self.transport.open_session(timeout=15)
            channel.settimeout(timeout)
            channel.exec_command(command)
            if password:
                channel.sendall((password + '\n').encode())
            channel.shutdown_write()
            output = bytearray()
            deadline = time.monotonic() + timeout
            while True:
                if time.monotonic() >= deadline:
                    raise BootstrapError('Validator SSH operation timed out')
                for ready, receive in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                    if ready():
                        chunk = receive(32768)
                        output.extend(chunk)
                        if len(output) > 1024 * 1024:
                            raise BootstrapError('Validator SSH operation exceeded output limit')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                time.sleep(.01)
            if channel.recv_exit_status() != 0:
                raise BootstrapError('Validator host operation failed; verify Docker, sudo and host prerequisites')
            return output.decode('utf-8', errors='replace')
        except BootstrapError:
            raise
        except Exception:
            raise BootstrapError('Validator SSH operation failed') from None
        finally:
            if channel:
                channel.close()

    def preflight(self, owner_id=None):
        """Report individual read-only prerequisite checks without installing tools."""
        owner = _owner(owner_id) if owner_id else ''
        script = r'''
. /etc/os-release
os_name=$(printf '%s' "$ID" | tr -cd 'a-zA-Z0-9_-')
os_version=$(printf '%s' "$VERSION_ID" | tr -cd 'a-zA-Z0-9._-')
architecture=$(uname -m | tr -cd 'a-zA-Z0-9_-')
platform=false; [ "$ID" = ubuntu ] && { [ "$VERSION_ID" = 22.04 ] || [ "$VERSION_ID" = 24.04 ]; } && [ "$(uname -m)" = x86_64 ] && platform=true
docker_ok=false; daemon_ok=false; architecture_ok=false; cgroup_ok=false; runtime_ok=false; cgroup_driver_ok=false; socket_ok=false; version=0; disk=0; cgroup_version=unavailable; default_runtime=unavailable; cgroup_driver=unavailable
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  daemon_ok=true
  [ "$(docker info --format '{{.OSType}}/{{.Architecture}}')" = linux/x86_64 ] && architecture_ok=true
  cgroup_version=$(docker info --format '{{.CgroupVersion}}' | tr -cd '0-9')
  [ "$cgroup_version" = 2 ] && cgroup_ok=true
  cgroup_driver=$(docker info --format '{{.CgroupDriver}}' | tr -cd 'a-zA-Z0-9_-')
  [ "$cgroup_driver" = systemd ] && cgroup_driver_ok=true
  default_runtime=$(docker info --format '{{.DefaultRuntime}}' | tr -cd 'a-zA-Z0-9._-')
  # Docker's normal OCI runtime and containerd's runc runtime are compatible.
  case "$default_runtime" in runc|io.containerd.runc.v2) runtime_ok=true ;; esac
  version=$(docker version --format '{{.Server.Version}}' | tr -cd '0-9.a-zA-Z_-')
  if [ "${version%%.*}" -ge 28 ] && [ "$(docker info --format '{{.OSType}}/{{.Architecture}}')" = linux/x86_64 ]; then docker_ok=true; fi
  docker_root=$(docker info --format '{{.DockerRootDir}}')
  disk=$(df -PB1 "$docker_root" | awk 'NR==2 {print $4}')
fi
[ -S /var/run/docker.sock ] && socket_ok=true
memory=$(awk '/MemTotal:/ {printf "%.0f", $2 * 1024}' /proc/meminfo)
cpus=$(getconf _NPROCESSORS_ONLN)
memory_ok=false; [ "$memory" -ge 4294967296 ] && memory_ok=true
cpu_ok=false; [ "$cpus" -ge 2 ] && cpu_ok=true
disk_ok=false; [ "$disk" -ge 21474836480 ] && disk_ok=true
resources=false; [ "$memory_ok" = true ] && [ "$cpu_ok" = true ] && [ "$disk_ok" = true ] && resources=true
'''
        script += '\nowner=' + shlex.quote(owner) + '\nport=' + str(self.target['api_port']) + r'''
port_ok=false
if command -v ss >/dev/null; then
  port_ok=true
  if ss -H -ltn "sport = :$port" | grep -q .; then
    port_ok=false
    if [ -n "$owner" ] && [ "$(docker inspect --format '{{index .Config.Labels "cats.managed.owner"}}' "cats-validator-$owner" 2>/dev/null || true)" = "$owner" ]; then port_ok=true; fi
  fi
fi
printf '{"platform":%s,"docker":%s,"daemon":%s,"architecture_compatible":%s,"cgroup":%s,"cgroup_driver":%s,"runtime":%s,"socket":%s,"resources":%s,"port":%s,"cpu":%s,"memory":%s,"disk":%s,"memory_bytes":%s,"cpus":%s,"disk_free_bytes":%s,"os":"%s","os_version":"%s","architecture":"%s","docker_version":"%s","cgroup_version":"%s","default_runtime":"%s","cgroup_driver_name":"%s"}\n' "$platform" "$docker_ok" "$daemon_ok" "$architecture_ok" "$cgroup_ok" "$cgroup_driver_ok" "$runtime_ok" "$socket_ok" "$resources" "$port_ok" "$cpu_ok" "$memory_ok" "$disk_ok" "$memory" "$cpus" "$disk" "$os_name" "$os_version" "$architecture" "$version" "$cgroup_version" "$default_runtime" "$cgroup_driver"
'''
        try:
            facts = json.loads(self._run(script, sudo=True))
        except BootstrapError:
            return {'status': 'unsupported', 'checks': {'sudo': False}, 'facts': {}, 'warnings': ['SSH sudo execution or host inspection failed']}
        except (ValueError, TypeError):
            raise BootstrapError('Validator preflight returned invalid evidence') from None
        checks = {key: facts.pop(key) is True for key in ('platform', 'docker', 'daemon', 'architecture_compatible', 'cgroup', 'cgroup_driver', 'runtime', 'socket', 'resources', 'port', 'cpu', 'memory', 'disk')}
        checks['sudo'] = True
        warnings = [key + ' prerequisite is not satisfied' for key, value in checks.items() if not value]
        if not checks['docker'] or not checks['daemon']:
            warnings.append('Install or configure Docker 28+ externally before retrying; bootstrap does not install host tools')
        if all(checks.values()):
            for field, threshold, message in (
                    ('cpus', 4, 'Recommend at least 4 CPUs'),
                    ('memory_bytes', 8589934592, 'Recommend at least 8 GiB memory'),
                    ('disk_free_bytes', 42949672960, 'Recommend at least 40 GiB free Docker storage')):
                if facts[field] < threshold:
                    warnings.append(message)
        status = ('supported_with_warnings' if warnings else 'supported') if all(checks.values()) else 'unsupported'
        return {'status': status, 'checks': checks, 'facts': facts, 'warnings': warnings}

    def _stage(self):
        if not self._staged:
            self._run('umask 077; mkdir -- ' + shlex.quote(self.workspace))
            self._staged = True

    def _upload(self, name, *, path=None, content=None):
        import paramiko
        self._stage()
        sftp = None
        try:
            sftp = paramiko.SFTPClient.from_transport(self.transport)
            sftp.get_channel().settimeout(600)
            destination = self.workspace + '/' + name
            if path is not None:
                with Path(path).open('rb') as stream:
                    sftp.putfo(stream, destination, file_size=Path(path).stat().st_size, confirm=True)
            else:
                with sftp.open(destination, 'wx') as stream:
                    stream.write(content.encode())
            sftp.chmod(destination, 0o600)
        except Exception as exc:
            reason = {errno.ENOSPC: 'host staging storage is full',
                      errno.EACCES: 'host staging permission denied',
                      errno.EPERM: 'host staging permission denied',
                      errno.ENOENT: 'host staging directory is unavailable'}.get(getattr(exc, 'errno', None))
            if isinstance(exc, (TimeoutError, socket.timeout)):
                reason = 'SSH transfer timed out'
            label = 'image archive' if path is not None else 'validator configuration'
            detail = reason or 'SSH/SFTP transfer could not complete'
            raise BootstrapError('Validator secure transfer failed (' + label + '): ' + detail) from None
        finally:
            if sftp:
                sftp.close()

    def deploy(self, owner_id, release, identity):
        owner = _owner(owner_id)
        images = validate_release(release)
        preflight = self.preflight(owner)
        if preflight.get('status') not in ('supported', 'supported_with_warnings'):
            raise preflight_failure(preflight)
        for kind, image in images.items():
            self._upload(kind + '.tar', path=image['path'])
        for name, key in (('validator.crt', 'validator_certificate'), ('validator.key', 'validator_key'), ('client-ca.crt', 'client_ca')):
            if not isinstance(identity.get(key), str) or not identity[key]:
                raise ValueError('Managed validator identity is incomplete')
            self._upload(name, content=identity[key])
        fingerprint = identity.get('client_fingerprint', '')
        if not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
            raise ValueError('Invalid trusted HQ client fingerprint')
        root = '/var/lib/cats-managed-validator/' + owner
        name = 'cats-validator-' + owner
        env = {'CATS_ROLE': 'validator', 'CATS_VALIDATOR_ID': owner, 'CATS_MANAGED_VALIDATOR_ID': owner, 'CATS_VALIDATOR_PORT': str(self.target['api_port']),
            'CATS_VALIDATOR_STATE_DIR': root + '/state',
            'TMPDIR': root + '/state/workspaces', 'HOME': root + '/state',
            'HELM_CACHE_HOME': root + '/state/helm/cache', 'HELM_CONFIG_HOME': root + '/state/helm/config',
            'HELM_DATA_HOME': root + '/state/helm/data', 'CATS_VALIDATOR_SERVER_CERT': root + '/certs/validator.crt',
            'CATS_VALIDATOR_SERVER_KEY': root + '/certs/validator.key', 'CATS_VALIDATOR_CLIENT_CA': root + '/certs/client-ca.crt',
            'CATS_VALIDATOR_CLIENT_FINGERPRINTS': fingerprint, 'CATS_VALIDATOR_EXECUTION_MODE': 'permissive',
            'CATS_DEPLOYMENT_ENFORCE_RESOURCE_LIMITS': ('true' if os.getenv('CATS_DEPLOYMENT_ENFORCE_RESOURCE_LIMITS', 'false').strip().lower() in {'1', 'true', 'yes', 'on'} else 'false'),
            'CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS': 'true', 'CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES': 'false',
            'CATS_DEPLOYMENT_KIND_NODE_IMAGE': images['node']['reference']}
        self._upload('validator.env', content=''.join(key + '=' + value + '\n' for key, value in env.items()))
        q = shlex.quote
        script = 'workspace=' + q(self.workspace) + '\nroot=' + q(root) + '\nowner=' + q(owner) + '\nname=' + q(name) + r'''
umask 077
# Do not replace identity or container while strict validation resources remain.
if docker network ls --filter label=cats.deployment-validation=true --format '{{.ID}}' | grep -q .; then exit 1; fi
if docker ps -a --filter label=cats.deployment-validation=true --format '{{.ID}}' | grep -q .; then exit 1; fi
mkdir -p /var/lib/cats-managed-validator
[ ! -L /var/lib/cats-managed-validator ]
if [ -e "$root" ]; then
  [ ! -L "$root" ] && [ -f "$root/owner" ] && [ "$(cat "$root/owner")" = "$owner" ]
else
  mkdir -m 700 "$root"
  printf '%s' "$owner" > "$root/owner"
fi
if docker inspect "$name" >/dev/null 2>&1; then
  [ "$(docker inspect --format '{{index .Config.Labels "cats.managed.owner"}}' "$name")" = "$owner" ]
fi
'''
        for kind, image in images.items():
            script += '\n[ "$(sha256sum ' + q(self.workspace + '/' + kind + '.tar') + ' | cut -d " " -f1)" = ' + q(image['sha256']) + ' ]\n'
            script += 'docker load --input ' + q(self.workspace + '/' + kind + '.tar') + ' >/dev/null\n'
            script += '[ "$(docker image inspect --format \'{{.Id}}\' -- ' + q(image['reference']) + ')" = ' + q(image['image_id']) + ' ]\n'
        script += r'''
[ ! -L "$root/owner" ] && [ ! -L "$root/certs" ] && [ ! -L "$root/state" ] && [ ! -L "$root/validator.env" ]
mkdir -p "$root/certs" "$root/state"
[ ! -L "$root/state/workspaces" ] && [ ! -L "$root/state/helm" ]
mkdir -p "$root/state/workspaces" "$root/state/helm/cache" "$root/state/helm/config" "$root/state/helm/data"
chmod 700 "$root" "$root/certs" "$root/state"
for file in validator.crt validator.key client-ca.crt; do
  install -m 600 "$workspace/$file" "$root/certs/$file"
done
install -m 600 "$workspace/validator.env" "$root/validator.env"
if docker inspect "$name" >/dev/null 2>&1; then docker rm -f "$name" >/dev/null; fi
'''
        script += 'docker run -d --name ' + q(name) + ' --label ' + q('cats.managed.owner=' + owner) + ' --restart unless-stopped --network host --read-only --tmpfs /tmp:rw,nosuid,nodev,size=512m --env-file ' + q(root + '/validator.env') + ' --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock --mount ' + q('type=bind,src=' + root + '/certs,dst=' + root + '/certs,readonly') + ' --mount ' + q('type=bind,src=' + root + '/state,dst=' + root + '/state') + ' ' + q(images['cats']['image_id']) + ' >/dev/null\n'
        self._run(script, sudo=True, timeout=900)
        return {'validator_id': owner, 'container': name, 'version': str(release.get('version', '')),
                'images': {kind: {'reference': image['reference'], 'image_id': image['image_id'], 'archive_sha256': image['sha256']} for kind, image in images.items()},
                'socket_mounted': True, 'network': 'host'}

    def remove(self, owner_id):
        """Remove only this labeled container and marked private deployment."""
        owner = _owner(owner_id)
        q = shlex.quote
        script = 'owner=' + q(owner) + '\nname=' + q('cats-validator-' + owner) + '\nroot=' + q('/var/lib/cats-managed-validator/' + owner) + r'''
# A dedicated host must have no unfinished strict validation resources.
# Fail closed rather than deleting any cluster without per-validator ownership.
if docker network ls --filter label=cats.deployment-validation=true --format '{{.ID}}' | grep -q .; then exit 1; fi
if docker ps -a --filter label=cats.deployment-validation=true --format '{{.ID}}' | grep -q .; then exit 1; fi
if docker inspect "$name" >/dev/null 2>&1; then
  [ "$(docker inspect --format '{{index .Config.Labels "cats.managed.owner"}}' "$name")" = "$owner" ]
  docker rm -f "$name" >/dev/null
fi
if [ -e "$root" ]; then
  [ ! -L /var/lib/cats-managed-validator ] && [ ! -L "$root" ]
  [ ! -L "$root/owner" ] && [ -f "$root/owner" ] && [ "$(cat "$root/owner")" = "$owner" ]
  rm -rf -- "$root"
fi
'''
        self._run(script, sudo=True)
        return {'removed': True, 'validator_id': owner}
