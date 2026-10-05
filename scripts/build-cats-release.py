#!/usr/bin/env python3
"""One connected entry point for a self-contained CATS release image."""
import argparse
import json
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
    return result + [final]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cats-version', default='1.3')
    parser.add_argument('--tag')
    parser.add_argument('--image', choices=['unified', 'portal'], default='unified')
    parser.add_argument('--profile', choices=['release', 'development', 'runtime'], default='release')
    parser.add_argument('--scanner-base', help='Use an already built, offline-capable scanner base')
    parser.add_argument('--cache-dir', type=pathlib.Path, default=ROOT / '.release-cache/managed-validator')
    args = parser.parse_args()
    if not shutil.which('docker'):
        parser.exit(1, 'Docker CLI is unavailable. Install/start a Linux-container Docker engine to build the release.\n')
    subprocess.run(['docker', 'info'], check=True, stdout=subprocess.DEVNULL)
    if args.profile == 'release' and args.image != 'unified':
        parser.error('Docker-host releases require the unified CATS runtime image')
    for command in commands(args, None):
        subprocess.run(command, check=True, cwd=ROOT)
    if args.profile == 'release':
        sys.path.insert(0, str(ROOT / 'portal'))
        from app.deployment_validation import ValidationConfig
        node = ValidationConfig.kind_node_image
        if subprocess.run(['docker', 'image', 'inspect', node], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            subprocess.run(['docker', 'pull', node], check=True)
        output = args.cache_dir.resolve() / uuid.uuid4().hex
        subprocess.run([sys.executable, str(ROOT / 'scripts/prepare-docker-validator-release.py'),
                        '--output', str(output), '--cats-image', args.tag or 'cats:' + args.cats_version], check=True)
        print('Set CATS_MANAGED_VALIDATOR_RELEASE_SOURCE=' + str(output))
    subprocess.run(['docker', 'image', 'inspect', args.tag or 'cats:' + args.cats_version,
                    '--format', '{{.Id}} {{.Size}}'], check=True)


if __name__ == '__main__':
    main()
