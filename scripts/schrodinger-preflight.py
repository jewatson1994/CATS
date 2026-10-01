#!/usr/bin/env python3
"""Read-only host checks. Does not create clusters, files, networks, or requests."""
import argparse
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
from urllib.parse import urlsplit


def check_host(env=None, run=subprocess.run, which=shutil.which):
    env = dict(os.environ if env is None else env)
    checks = []
    def report(level, message):
        checks.append((level, message))
    def command(argv):
        try:
            return run(argv, capture_output=True, text=True, timeout=10, env=env)
        except (OSError, subprocess.TimeoutExpired):
            return None
    if os.name != 'posix':
        report('FAIL', 'Reference validation host requires Linux; run this on the VM')
    for name, arguments in [('docker', ['version', '--format', '{{.Server.Version}}']),
                            ('kind', ['version']), ('kubectl', ['version', '--client']),
                            ('helm', ['version', '--short']), ('openssl', ['version'])]:
        if not which(name):
            report('FAIL', f'{name} missing: install the approved binary')
            continue
        result = command([name, *arguments])
        version_match = re.search(r'\b\d+\.\d+\.\d+\b', result.stdout) if result and result.returncode == 0 else None
        report('PASS' if result and result.returncode == 0 else 'FAIL',
               f'{name} version check ' + ('succeeded' + (f' ({version_match.group(0)})' if version_match else '') if result and result.returncode == 0 else 'failed'))
    for variable in ('CATS_VALIDATOR_SERVER_CERT', 'CATS_VALIDATOR_SERVER_KEY', 'CATS_VALIDATOR_CLIENT_CA'):
        path = Path(env.get(variable, ''))
        if not env.get(variable) or not path.is_file() or path.is_symlink() or not os.access(path, os.R_OK):
            report('FAIL', f'{variable}: configure a readable regular file, without symlinks')
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o022 or (variable.endswith('_KEY') and mode & 0o077):
            report('FAIL', f'{variable}: remove unsafe group/other permissions')
        else:
            report('PASS', f'{variable}: readable and protected')
        if not variable.endswith('_KEY') and which('openssl'):
            result = command(['openssl', 'x509', '-in', str(path), '-noout', '-checkend', '0'])
            report('PASS' if result and result.returncode == 0 else 'FAIL',
                   f'{variable}: certificate expiration check')
            soon = command(['openssl', 'x509', '-in', str(path), '-noout', '-checkend', '2592000'])
            if soon and soon.returncode != 0:
                report('WARN', f'{variable}: renew within 30 days')
    if all(env.get(key) for key in ('CATS_VALIDATOR_SERVER_CERT', 'CATS_VALIDATOR_SERVER_KEY', 'CATS_VALIDATOR_CLIENT_CA')):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(env['CATS_VALIDATOR_SERVER_CERT'], env['CATS_VALIDATOR_SERVER_KEY'])
            context.load_verify_locations(cafile=env['CATS_VALIDATOR_CLIENT_CA'])
            report('PASS', 'TLS certificate/key match and client CA parse correctly')
        except (OSError, ssl.SSLError):
            report('FAIL', 'TLS material invalid or certificate/key mismatch; inspect PKI issuance')
    fingerprints = [value.strip().replace(':', '').lower() for value in env.get('CATS_VALIDATOR_CLIENT_FINGERPRINTS', '').split(',')]
    report('PASS' if fingerprints and all(re.fullmatch('[0-9a-f]{64}', value) for value in fingerprints) else 'FAIL',
           'Client authorization requires comma-separated SHA256 DER certificate fingerprints')
    state = Path(env.get('CATS_VALIDATOR_STATE_DIR', '/tmp/cats-validator'))
    if not state.is_absolute() or not state.is_dir() or state.is_symlink() or not os.access(state, os.W_OK | os.X_OK):
        report('FAIL', 'State directory must exist, be absolute, private, and writable by service user')
    else:
        if stat.S_IMODE(state.stat().st_mode) & 0o077:
            report('FAIL', 'State directory must have mode 0700')
        elif hasattr(os, 'getuid') and state.stat().st_uid != os.getuid():
            report('FAIL', 'Run as the owner of the state directory')
        else:
            report('PASS', 'State directory ownership, mode and access')
        try:
            minimum = int(env.get('CATS_VALIDATOR_MIN_DISK_BYTES', str(5 * 1024 ** 3)))
            if minimum <= 0:
                raise ValueError
            report('PASS' if shutil.disk_usage(state).free >= minimum else 'FAIL', 'State filesystem available disk space')
        except (OSError, ValueError):
            report('FAIL', 'Invalid disk threshold or inaccessible filesystem')
        workspace = state / 'workspaces'
        if workspace.exists() and (workspace.is_symlink() or not workspace.is_dir() or not os.access(workspace, os.W_OK | os.X_OK) or stat.S_IMODE(workspace.stat().st_mode) & 0o077):
            report('FAIL', 'Workspace directory must be private and writable')
        else:
            report('PASS', 'Workspace directory accessible or will be created by startup')
    for name, default, minimum, maximum in [('CATS_VALIDATOR_MAX_JOBS', 1, 1, 16), ('CATS_VALIDATOR_MAX_REQUEST_BYTES', 16777216, 1024, 104857600),
                                   ('CATS_VALIDATOR_MAX_OUTPUT_BYTES', 1048576, 4096, 8388608), ('CATS_VALIDATOR_MAX_TIMEOUT', 600, 30, 3600),
                                   ('CATS_VALIDATOR_MAX_RECORDS', 1000, 1, 10000)]:
        try:
            value = int(env.get(name, str(default)))
            if value < minimum or value > maximum:
                raise ValueError
            report('PASS', f'{name} within supported bounds')
        except ValueError:
            report('FAIL', f'{name}: use an integer from {minimum} to {maximum}')
    if env.get('CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS', 'false').lower() in ('true', '1', 'yes', 'on'):
        report('FAIL', 'Disable unrestricted network egress for hostile workloads')
    if env.get('CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES', 'true').lower() not in ('true', '1', 'yes', 'on'):
        report('FAIL', 'Enable local image requirement for offline validation')
    if which('docker'):
        version = command(['docker', 'version', '--format', '{{.Server.Version}}'])
        match = re.match(r'(\d+)\.', version.stdout.strip()) if version and version.returncode == 0 else None
        report('PASS' if match and int(match.group(1)) >= 28 else 'FAIL', 'Docker Engine 28+ required for isolated gateway networking')
        result = command(['docker', 'info', '--format', '{{json .SecurityOptions}}'])
        report('PASS' if result and result.returncode == 0 else 'FAIL', 'Docker daemon reachable as current service user')
        if result and result.returncode == 0 and 'rootless' not in result.stdout:
            report('WARN', 'Rootful Docker socket grants host-root authority; use a dedicated disposable VM')
        node = env.get('CATS_DEPLOYMENT_KIND_NODE_IMAGE', '')
        if not node or not re.search(r'@sha256:[0-9a-f]{64}$', node):
            report('FAIL', 'Explicitly configure an approved digest-pinned Kind node image')
        else:
            result = command(['docker', 'image', 'inspect', '--', node])
            report('PASS' if result and result.returncode == 0 else 'FAIL', 'Approved Kind node image preloaded locally')
    if which('kind'):
        result = command(['kind', 'get', 'clusters'])
        report('PASS' if result and result.returncode == 0 else 'FAIL', 'Kind read-only cluster inventory')
    try:
        port = int(env.get('CATS_VALIDATOR_PORT', '8443'))
        if not 1 <= port <= 65535:
            raise ValueError
        host = env.get('CATS_VALIDATOR_LISTEN', '0.0.0.0')
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        report('PASS', 'Listen address and port valid')
        with socket.socket() as probe:
            probe.settimeout(1)
            occupied = probe.connect_ex(('127.0.0.1' if host == '0.0.0.0' else host, port)) == 0
        report('WARN' if occupied else 'PASS', 'Port already listening; verify service ownership' if occupied else 'Port has no TCP listener (read-only probe)')
    except (ValueError, OSError):
        report('FAIL', 'Invalid/unresolvable listen address or port')
    endpoint = env.get('CATS_VALIDATOR_PREFLIGHT_ENDPOINT')
    if endpoint:
        try:
            parsed = urlsplit(endpoint)
            valid = parsed.scheme == 'https' and parsed.hostname and not (parsed.username or parsed.password or parsed.query or parsed.fragment) and (parsed.port is None or 1 <= parsed.port <= 65535)
            report('PASS' if valid else 'FAIL', 'Optional advertised endpoint must be credential-free HTTPS')
        except ValueError:
            report('FAIL', 'Invalid advertised endpoint')
    else:
        report('WARN', 'Set CATS_VALIDATOR_PREFLIGHT_ENDPOINT to check advertised HTTPS endpoint syntax')
    report('WARN', 'Read-only checks do not prove Kind lifecycle, SAN/chain authorization, firewall isolation, or image availability; run setup smoke tests')
    return checks


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    checks = check_host()
    for level, message in checks:
        print(f'{level}: {message}')
    ready = not any(level == 'FAIL' for level, _ in checks)
    print("CATSchrödinger's preflight: " + ('READY' if ready else 'NOT READY'))
    return 0 if ready else 1


if __name__ == '__main__':
    raise SystemExit(main())
