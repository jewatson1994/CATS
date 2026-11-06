"""Opt-in runtime verification of an explicitly built and published nginx derivative.

The source must be the immutable package-patched output. Build the adjacent
nginx-hardening Dockerfile with BASE_IMAGE set to that reference, then publish
normally and supply the resulting immutable reference. This verifier does not
build, publish, sign, approve, alter scanner policy, or claim zero findings.
It retains original filesystem layers and history, including historic findings.
For an internal registry unavailable to the runtime host, --offline-input accepts
raw source/hardened-manifest.json bytes and source/hardened.tar Docker exports.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import uuid


RECEIPT_FORMAT = 'cats-nginx-hardening-runtime-v1'
REQUIRED_CHECKS = ('immutable_identity', 'inherited_layers', 'inherited_history',
    'nonroot_uid', 'restricted_runtime', 'http_content', 'healthy',
    'unhealthy_on_outage', 'recovered')
RECIPE = Path(__file__).with_name('nginx-hardening')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
REFERENCE = re.compile(r'^[a-zA-Z0-9][^\s@]*@sha256:[0-9a-f]{64}$')
LAYER_MEDIA_TYPES = {
    'application/vnd.oci.image.layer.v1.tar': 'tar',
    'application/vnd.docker.image.rootfs.diff.tar': 'tar',
    'application/vnd.oci.image.layer.v1.tar+gzip': 'gzip',
    'application/vnd.docker.image.rootfs.diff.tar.gzip': 'gzip',
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(content):
    return 'sha256:' + hashlib.sha256(content).hexdigest()


def recipe_digest():
    payload = b''.join(name.encode() + b'\0' + (RECIPE / name).read_bytes() + b'\0'
        for name in ('Dockerfile', 'nginx.conf', 'default.conf'))
    return digest(payload)


def validate_references(source, hardened):
    require(bool(REFERENCE.fullmatch(source)) and bool(REFERENCE.fullmatch(hardened)),
            'Both source and hardened images must use immutable sha256 references')
    require(source.rsplit('@', 1)[1] != hardened.rsplit('@', 1)[1],
            'Hardening must produce a distinct immutable image')


def command(arguments, *, timeout=120, check=True):
    return subprocess.run(['docker', *arguments], capture_output=True, check=check,
                          timeout=timeout)


def docker_json(arguments):
    return json.loads(command(arguments).stdout)


def error_detail(error):
    """Keep bounded Docker diagnostics, including failures before a container starts."""
    details = {'message': str(error), 'type': type(error).__name__}
    for name in ('stdout', 'stderr'):
        value = getattr(error, name, None)
        if value:
            details[name] = (value.decode('utf-8', errors='replace')
                             if isinstance(value, bytes) else str(value))[-8192:]
    return details


def stream_digest(stream):
    checksum, size = hashlib.sha256(), 0
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        checksum.update(block)
        size += len(block)
    return 'sha256:' + checksum.hexdigest(), size


def archive_file(archive, name):
    member = archive.getmember(name)
    require(member.isfile(), 'Offline image archive references a non-file object')
    return archive.extractfile(member)


def offline_image_evidence(reference, folder, label):
    """Load exact exported content without contacting its internal registry."""
    require(label in {'source', 'hardened'}, 'Unknown offline image role')
    manifest_path = folder / (label + '-manifest.json')
    archive_path = folder / (label + '.tar')
    raw_manifest = manifest_path.read_bytes()
    manifest_digest = reference.rsplit('@', 1)[1]
    require(digest(raw_manifest) == manifest_digest,
            'Offline raw manifest differs from the supplied immutable reference')
    manifest = json.loads(raw_manifest)
    require(manifest.get('schemaVersion') == 2 and isinstance(manifest.get('config'), dict)
            and isinstance(manifest.get('layers'), list),
            'Offline input requires a concrete platform manifest')
    config_digest = manifest['config'].get('digest')
    require(bool(DIGEST.fullmatch(config_digest or '')), 'Offline configuration digest is missing')
    layer_proof = []
    with tarfile.open(archive_path) as archive:
        entries = json.load(archive_file(archive, 'manifest.json'))
        require(isinstance(entries, list) and len(entries) == 1,
                'Offline archive must contain exactly one image')
        raw_config = archive_file(archive, entries[0]['Config']).read()
        require(digest(raw_config) == config_digest
                and len(raw_config) == manifest['config'].get('size'),
                'Offline configuration differs from the immutable manifest')
        config = json.loads(raw_config)
        diff_ids = config.get('rootfs', {}).get('diff_ids', [])
        members = entries[0].get('Layers', [])
        require(bool(diff_ids) and len(diff_ids) == len(members) == len(manifest['layers']),
                'Offline archive layer inventory differs from the published image')
        for index, (member, expected, descriptor) in enumerate(zip(members, diff_ids, manifest['layers'])):
            require(bool(DIGEST.fullmatch(expected)), 'Offline image contains an invalid filesystem identity')
            require(isinstance(descriptor, dict)
                    and isinstance(descriptor.get('digest'), str)
                    and bool(DIGEST.fullmatch(descriptor['digest']))
                    and type(descriptor.get('size')) is int and descriptor['size'] > 0,
                    'Offline layer descriptor requires a valid digest and positive integer size')
            encoding = LAYER_MEDIA_TYPES.get(descriptor.get('mediaType'))
            require(encoding is not None, 'Offline image has an unsupported layer media type')
            require(encoding != 'gzip' or descriptor['digest'] != expected,
                    'Offline gzip layer descriptor identifies uncompressed content')
            with archive_file(archive, member) as stream:
                archived_digest, archived_size = stream_digest(stream)
                stream.seek(0)
                compressed = stream.read(2) == b'\x1f\x8b'
                stream.seek(0)
                if compressed:
                    with gzip.GzipFile(fileobj=stream) as expanded:
                        actual, _ = stream_digest(expanded)
                else:
                    actual, _ = stream_digest(stream)
            require(actual == expected, 'Offline filesystem layer differs from the published configuration')
            # Docker's classic exporter can decompress a published gzip layer.
            # Otherwise retain the exact original blob bytes and descriptor size.
            exact_blob = archived_digest == descriptor.get('digest') and archived_size == descriptor.get('size')
            require((exact_blob and compressed == (encoding == 'gzip'))
                    or (encoding == 'gzip' and not compressed and archived_digest == expected),
                    'Offline compressed layer differs from the published manifest')
            layer_proof.append({'index': index, 'archive_digest': archived_digest,
                'archive_size': archived_size, 'diff_id': actual, 'exact_published_blob': exact_blob})
    with archive_path.open('rb') as stream:
        archive_digest, archive_size = stream_digest(stream)
    command(['load', '--input', str(archive_path)], timeout=600)
    image = None
    for identity in (config_digest, manifest_digest):
        inspected = command(['image', 'inspect', identity], check=False)
        if inspected.returncode == 0:
            image = json.loads(inspected.stdout)[0]
            break
    require(isinstance(image, dict) and image.get('Id') in (config_digest, manifest_digest),
            'Loaded offline Docker identity differs from the immutable manifest/configuration')
    require(image.get('RootFS', {}).get('Layers') == diff_ids,
            'Loaded offline Docker filesystem differs from the verified archive')
    return {'reference': reference, 'manifest_digest': manifest_digest,
        'config_digest': config_digest, 'docker_image_id': image['Id'],
        'manifest': manifest, 'config': config, 'inspect': image,
        'offline_input': {'manifest_file': manifest_path.name, 'manifest_digest': manifest_digest,
            'archive_file': archive_path.name, 'archive_digest': archive_digest,
            'archive_size': archive_size, 'layers': layer_proof}}


def image_evidence(reference, folder):
    """Bind the exact registry manifest, saved image configuration and Docker ID."""
    command(['pull', reference], timeout=600)
    manifest = docker_json(['manifest', 'inspect', reference])
    require(isinstance(manifest, dict) and 'config' in manifest and 'layers' in manifest,
            'Use one concrete platform manifest, not a multi-platform index')
    config_digest = manifest['config'].get('digest')
    require(bool(DIGEST.fullmatch(config_digest or '')), 'Image configuration digest is missing')
    image = docker_json(['image', 'inspect', reference])[0]
    identity = image['Id']
    manifest_digest = reference.rsplit('@', 1)[1]
    require(identity in (manifest_digest, config_digest),
            'Loaded Docker identity differs from the immutable manifest/configuration')
    archive_path = folder / (manifest_digest[7:] + '.tar')
    command(['image', 'save', '--output', str(archive_path), identity], timeout=600)
    with tarfile.open(archive_path) as archive:
        entries = json.load(archive.extractfile('manifest.json'))
        require(len(entries) == 1, 'Saved archive contains an unexpected image inventory')
        stream = archive.extractfile(entries[0]['Config'])
        require(stream is not None, 'Saved archive lacks its image configuration')
        raw = stream.read()
    require(digest(raw) == config_digest,
            'Saved runtime configuration differs from the published configuration')
    return {'reference': reference, 'manifest_digest': manifest_digest,
        'config_digest': config_digest, 'docker_image_id': identity,
        'manifest': manifest, 'config': json.loads(raw), 'inspect': image}


def inherited_layer_mapping(before, after):
    """Allow only equivalent OCI/Docker media labels for unchanged layer bytes."""
    require(bool(before) and len(after) > len(before),
            'Hardening must retain every original layer descriptor in order')
    mapping = []
    for index, (original, candidate) in enumerate(zip(before, after)):
        source_type, hardened_type = original.get('mediaType'), candidate.get('mediaType')
        require(source_type in LAYER_MEDIA_TYPES and hardened_type in LAYER_MEDIA_TYPES,
                'Inherited layer uses an unsupported media type')
        normalized_source = {**original, 'mediaType': LAYER_MEDIA_TYPES[source_type]}
        normalized_candidate = {**candidate, 'mediaType': LAYER_MEDIA_TYPES[hardened_type]}
        require(json.dumps(normalized_source, sort_keys=True, allow_nan=False)
                == json.dumps(normalized_candidate, sort_keys=True, allow_nan=False),
                'Hardening must retain every original layer descriptor in order')
        mapping.append({'index': index, 'source': original, 'hardened': candidate})
    return mapping


def verify_ancestry(source, hardened):
    before, after = source['manifest']['layers'], hardened['manifest']['layers']
    descriptors = inherited_layer_mapping(before, after)
    original, candidate = source['config'], hardened['config']
    diff_ids = original.get('rootfs', {}).get('diff_ids', [])
    changed = candidate.get('rootfs', {}).get('diff_ids', [])
    require(bool(diff_ids) and len(changed) > len(diff_ids) and changed[:len(diff_ids)] == diff_ids,
            'Hardening must preserve every inherited filesystem layer')
    history = original.get('history', [])
    require(bool(history) and candidate.get('history', [])[:len(history)] == history,
            'Hardening must preserve the original image history')
    config = candidate.get('config') or {}
    labels = config.get('Labels') or {}
    require(labels.get('org.opencontainers.image.base.name') == source['reference']
            and labels.get('io.cats.nginx-hardening.recipe') == 'v1',
            'Hardening provenance does not identify the exact package-patched source')
    require(config.get('User') == '101:101', 'Hardened image must declare UID/GID 101')
    require(config.get('Entrypoint') == ['nginx'] and config.get('Cmd') == ['-g', 'daemon off;'],
            'Hardened image must start nginx directly without the root startup scripts')
    health = config.get('Healthcheck') or {}
    require(health.get('Test') == ['CMD-SHELL',
        'wget -q -T 2 -O /dev/null http://127.0.0.1:8080/ || exit 1'],
            'Hardened image must declare the real HTTP healthcheck')
    return {'inherited_layer_count': len(before), 'inherited_history_count': len(history),
            'inherited_layer_descriptors': descriptors, 'labels': labels}


def runtime_command(identity, name):
    require(bool(DIGEST.fullmatch(identity)), 'Runtime requires an immutable Docker image ID')
    return ['run', '--pull', 'never', '--detach', '--name', name, '--network', 'none',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777',
        '--memory', '128m', '--cpus', '1', '--pids-limit', '64', identity]


def wait_health(name, expected, *, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = docker_json(['inspect', '--format', '{{json .State}}', name])
        require(state.get('Running') is True, 'nginx exited during runtime verification')
        if (state.get('Health') or {}).get('Status') == expected:
            return state['Health']
        time.sleep(1)
    raise RuntimeError('nginx did not become ' + expected + ' before the deadline')


def signal_nginx(name, signal):
    require(signal in {'STOP', 'CONT'}, 'Only reversible nginx outage signals are supported')
    script = ('found=0; for p in /proc/[0-9]*; do '
        'if [ "$(cat "$p/comm" 2>/dev/null)" = nginx ]; then '
        f'kill -{signal} "${{p##*/}}" || exit 1; found=1; '
        'fi; done; test "$found" = 1')
    command(['exec', name, '/bin/sh', '-c', script])


def verify_runtime(source_reference, hardened_reference, workspace, *, offline_input=None):
    validate_references(source_reference, hardened_reference)
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    receipt_path = workspace / 'hardening-runtime.json'
    require(not receipt_path.exists(), 'Use a fresh runtime workspace; retained evidence is immutable')
    report = {'format': RECEIPT_FORMAT, 'complete': False, 'checks': {},
        'source_reference': source_reference, 'hardened_reference': hardened_reference,
        'recipe_sha256': recipe_digest(), 'started_at': datetime.now(timezone.utc).isoformat()}
    name = 'cats-nginx-hardening-' + uuid.uuid4().hex[:12]
    created, stopped = False, False
    try:
        if offline_input is not None:
            folder = Path(offline_input).resolve()
            source = offline_image_evidence(source_reference, folder, 'source')
            hardened = offline_image_evidence(hardened_reference, folder, 'hardened')
            report['offline_input'] = {'source': source['offline_input'], 'hardened': hardened['offline_input']}
        else:
            with tempfile.TemporaryDirectory(prefix='cats-nginx-hardening-') as directory:
                source = image_evidence(source_reference, Path(directory))
                hardened = image_evidence(hardened_reference, Path(directory))
        details = verify_ancestry(source, hardened)
        report.update(source_manifest_digest=source['manifest_digest'],
            source_config_digest=source['config_digest'],
            hardened_manifest_digest=hardened['manifest_digest'],
            hardened_config_digest=hardened['config_digest'],
            docker_image_id=hardened['docker_image_id'], execution_image=hardened['docker_image_id'],
            runtime_details=details, labels=details['labels'])
        report['checks'].update(immutable_identity=True, inherited_layers=True, inherited_history=True)
        created = True
        command(runtime_command(hardened['docker_image_id'], name))
        details['healthy'] = wait_health(name, 'healthy')
        report['checks']['healthy'] = True
        inspected = docker_json(['inspect', name])[0]
        host = inspected['HostConfig']
        require(inspected['Image'] == hardened['docker_image_id'], 'Running image identity changed')
        require(host.get('ReadonlyRootfs') is True and 'ALL' in host.get('CapDrop', [])
            and any(value in ('no-new-privileges', 'no-new-privileges:true')
                    for value in host.get('SecurityOpt', []))
            and host.get('NetworkMode') == 'none' and '/tmp' in host.get('Tmpfs', {}),
            'The actual container lacks the required runtime restrictions')
        details['host_config'] = {key: host.get(key) for key in
            ('ReadonlyRootfs', 'CapDrop', 'SecurityOpt', 'NetworkMode', 'Tmpfs', 'Memory', 'PidsLimit')}
        report['checks']['restricted_runtime'] = True
        uid = command(['exec', name, 'id', '-u']).stdout.decode().strip()
        status = command(['exec', name, 'cat', '/proc/1/status']).stdout.decode()
        require(uid == '101' and re.search(r'^Uid:\s+101\s+101\s+101\s+101\s*$', status, re.M),
                'The nginx master must run as nonroot UID 101')
        require(re.search(r'^CapEff:\s+0+\s*$', status, re.M)
                and re.search(r'^NoNewPrivs:\s+1\s*$', status, re.M),
                'nginx has effective capabilities or can gain privileges')
        details['uid'] = uid
        report['checks']['nonroot_uid'] = True
        details['recipe_files'] = {}
        for filename, target in (('nginx.conf', '/etc/nginx/nginx.conf'),
                                 ('default.conf', '/etc/nginx/conf.d/default.conf')):
            content = command(['exec', name, 'cat', target]).stdout
            require(content == (RECIPE / filename).read_bytes(),
                    'Running nginx configuration differs from the retained hardening recipe')
            details['recipe_files'][target] = digest(content)
        served = command(['exec', name, 'wget', '-q', '-T', '2', '-O', '-',
                          'http://127.0.0.1:8080/']).stdout
        static = command(['exec', name, 'cat', '/usr/share/nginx/html/index.html']).stdout
        require(bool(served) and served == static, 'HTTP must serve the inherited nginx static page exactly')
        details['http_content_sha256'] = digest(served)
        details['http_content_bytes'] = len(served)
        report['checks']['http_content'] = True
        stopped = True
        signal_nginx(name, 'STOP')
        details['unhealthy'] = wait_health(name, 'unhealthy')
        report['checks']['unhealthy_on_outage'] = True
        signal_nginx(name, 'CONT')
        stopped = False
        details['recovered'] = wait_health(name, 'healthy')
        report['checks']['recovered'] = True
        require(all(report['checks'].get(check) is True for check in REQUIRED_CHECKS),
                'Runtime verification is incomplete')
        report['complete'] = True
    except Exception as error:
        report['error'] = str(error)
        report['error_detail'] = error_detail(error)
        raise
    finally:
        if created:
            if stopped:
                try:
                    signal_nginx(name, 'CONT')
                except Exception:
                    pass
            try:
                cleanup = command(['rm', '--force', name], check=False)
                report['cleanup_complete'] = cleanup.returncode == 0
            except Exception as error:
                report['cleanup_complete'] = False
                report['cleanup_error'] = error_detail(error)
            if not report['cleanup_complete']:
                report['complete'] = False
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        receipt_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    require(report['complete'] is True, 'Runtime container cleanup failed')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-image', required=True)
    parser.add_argument('--hardened-image', required=True)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--offline-input', type=Path,
        help='Directory containing raw source/hardened-manifest.json and source/hardened.tar exports')
    args = parser.parse_args()
    report = verify_runtime(args.source_image, args.hardened_image, args.workspace,
                            offline_input=args.offline_input)
    print(json.dumps({'complete': report['complete'], 'hardened_reference': report['hardened_reference'],
                      'receipt': str(args.workspace.resolve() / 'hardening-runtime.json')}))


if __name__ == '__main__':
    main()
