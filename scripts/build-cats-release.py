#!/usr/bin/env python3
"""One connected entry point for a self-contained CATS release image."""
import argparse
import json
import hashlib
import pathlib
import shutil
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def commands(args, assets=None):
    common = ['docker', 'buildx', 'build', '--load', '--platform', 'linux/amd64']
    result = []
    if args.image == 'unified':
        if not args.scanner_base:
            result.append(common + ['--pull', '-f', str(ROOT / 'cats-scanner/Dockerfile'),
                                   '-t', 'catscan-base:local', str(ROOT / 'cats-scanner')])
        final = common + ['--build-arg', 'CATSCAN_BASE_IMAGE=' + (args.scanner_base or 'catscan-base:local'),
                          '-f', str(ROOT / 'cats-image/Dockerfile.all-in-one')]
        context = ROOT
    else:
        final = common + ['-f', str(ROOT / 'portal/Dockerfile')]
        context = ROOT / 'portal'
    final += ['--build-arg', 'CATS_VERSION=' + args.cats_version,
              '-t', args.tag or 'cats:' + args.cats_version, str(context)]
    result.append(final)
    return result


def discovery_tag(args):
    return args.tag or 'cats:' + args.cats_version


def export_discovery(output, reference):
    """Export the unified image and its exact approved sandbox policy.

    This is a companion bundle, not a complete CATS installation archive.
    No registry pull is performed and existing destinations are never replaced.
    """
    output = pathlib.Path(output)
    inspected = subprocess.run(['docker', 'image', 'inspect', reference], check=True,
                               capture_output=True, text=True)
    rows = json.loads(inspected.stdout)
    if len(rows) != 1 or rows[0].get('Os') != 'linux' or rows[0].get('Architecture') != 'amd64':
        raise ValueError('Discovery image must be local linux/amd64')
    row = rows[0]
    policy = ROOT / 'deploy/discovery-seccomp.json'
    json.loads(policy.read_text(encoding='utf-8'))
    output.mkdir(parents=True, exist_ok=False)
    (output / 'deploy').mkdir()
    shutil.copyfile(policy, output / 'deploy/discovery-seccomp.json')
    shutil.copyfile(ROOT / 'deploy/compose.discovery-mirror.yaml', output / 'deploy/compose.discovery-mirror.yaml')
    (output / 'deploy/discovery-mirror').mkdir()
    shutil.copyfile(ROOT / 'deploy/discovery-mirror/manifest.json', output / 'deploy/discovery-mirror/manifest.json')
    # Save the inspected identity under a content-specific tag, avoiding a mutable-tag race.
    saved_reference = 'cats:' + row['Id'].split(':', 1)[1]
    subprocess.run(['docker', 'tag', row['Id'], saved_reference], check=True)
    subprocess.run(['docker', 'save', '--output', str(output / 'discovery-image.tar'), saved_reference], check=True)
    files = {}
    for name in ('discovery-image.tar', 'deploy/discovery-seccomp.json', 'deploy/compose.discovery-mirror.yaml', 'deploy/discovery-mirror/manifest.json'):
        with (output / name).open('rb') as handle:
            files[name] = hashlib.file_digest(handle, 'sha256').hexdigest()
    manifest = {'schema_version': 1, 'kind': 'cats-unified-runtime',
                'image_reference': saved_reference, 'image_id': row['Id'], 'files': files}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (output / 'IMPORT.txt').write_text(
        'Verify manifest.json file SHA-256 digests before import.\n'
        'docker load --input discovery-image.tar\n'
        'Set CATS_IMAGE=' + saved_reference + ' in the CATS deployment environment.\n'
        'Copy deploy/discovery-seccomp.json and deploy/discovery-mirror/manifest.json into the matching CATS deployment paths.\n'
        'Optionally copy deploy/compose.discovery-mirror.yaml and set CATS_DISCOVERY_MIRROR_DIR to your verified local mirror.\n'
        'Add -f deploy/compose.discovery-mirror.yaml after -f compose.yaml to enable that read-only mirror.\n'
        'Start the matching CATS Compose release with --no-build --pull never.\n', encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cats-version', default='1.3')
    parser.add_argument('--tag')
    parser.add_argument('--discovery-tag', help='Deprecated compatibility option; Discovery uses --tag')
    parser.add_argument('--discovery-offline-output', type=pathlib.Path, help='Export Discovery image and approved seccomp policy into a new companion directory')
    parser.add_argument('--image', choices=['unified', 'portal'], default='unified')
    parser.add_argument('--profile', choices=['release', 'development', 'runtime'], default='release')
    parser.add_argument('--scanner-base', help='Use an already built, offline-capable scanner base')
    parser.add_argument('--prepare-validator-release', action='store_true', help='Optional legacy staged validator export; Provision prepares its own payload by default')
    parser.add_argument('--cache-dir', type=pathlib.Path, default=ROOT / '.release-cache/managed-validator')
    args = parser.parse_args()
    if args.discovery_offline_output and args.image != 'unified':
        parser.error('Discovery companion export requires a unified release')
    if not shutil.which('docker'):
        parser.exit(1, 'Docker CLI is unavailable. Install/start a Linux-container Docker engine to build the release.\n')
    subprocess.run(['docker', 'info'], check=True, stdout=subprocess.DEVNULL)
    if args.prepare_validator_release and args.image != 'unified':
        parser.error('Docker-host releases require the unified CATS runtime image')
    for command in commands(args, None):
        subprocess.run(command, check=True, cwd=ROOT)
    if args.discovery_offline_output:
        export_discovery(args.discovery_offline_output, discovery_tag(args))
    if args.prepare_validator_release:
        sys.path.insert(0, str(ROOT / 'portal'))
        from app.managed_validator_release import configured_node_pin
        node = configured_node_pin()
        if subprocess.run(['docker', 'image', 'inspect', node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            subprocess.run(['docker', 'pull', node], check=True)
        output = args.cache_dir.resolve() / uuid.uuid4().hex
        subprocess.run([sys.executable, str(ROOT / 'scripts/prepare-docker-validator-release.py'),
                        '--output', str(output), '--cats-image', args.tag or 'cats:' + args.cats_version,
                        '--activate-env', str(ROOT / '.env')], check=True)
        print('Set CATS_MANAGED_VALIDATOR_RELEASE_SOURCE=' + str(output))
    subprocess.run(['docker', 'image', 'inspect', args.tag or 'cats:' + args.cats_version,
                    '--format', '{{.Id}} {{.Size}}'], check=True)


if __name__ == '__main__':
    main()
