"""Opt in to the public GitLab example using ordinary CATS deployment settings.

Run with --apply after reviewing deploy/discovery-gitlab-public.json.
Use --artifact-cache PATH for disconnected installation of the pinned charts.
Existing credentials and unrelated .env entries are preserved. No containers start.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--artifact-cache', type=Path)
    args = parser.parse_args()
    profile = json.loads((ROOT / 'deploy/discovery-gitlab-public.json').read_text())
    if not args.apply:
        print(json.dumps(profile, indent=2))
        return
    env_path = ROOT / '.env'
    text = env_path.read_text(encoding='utf-8-sig') if env_path.exists() else ''
    configured = re.search(r'^CATS_DISCOVERY_MIRROR_DIR=(.*)$', text, re.M)
    if configured and configured[1].strip().strip("\"'") not in ('', './deploy/discovery-mirror', './deploy/discovery-mirror-local'):
        raise ValueError('An existing mirror is configured; merge the reviewed profile manually to preserve it.')
    # This fixed, reviewed profile contains public artifact URLs and pinned hashes.
    artifacts = []
    for row in profile['artifacts']:
        if args.artifact_cache:
            content = (args.artifact_cache / row['path']).read_bytes()
        else:
            with urllib.request.urlopen(row['download_url'], timeout=30) as response:
                if not response.url.startswith('https://'):
                    raise ValueError('Artifact download must retain TLS')
                content = response.read(32 * 1024 * 1024 + 1)
        if len(content) > 32 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != row['sha256']:
            raise ValueError('Pinned artifact verification failed: ' + row['path'])
        artifacts.append((row, content))
    settings = {'HELM_ALLOW_NETWORK': 'true',
                'CATS_DISCOVERY_MIRROR_DIR': './deploy/discovery-mirror-local'}
    for key, field in [('CATS_DISCOVERY_HELM_SOURCES', 'sources'),
                       ('CATS_DISCOVERY_HELM_ORIGINS', 'redirect_origins'),
                       ('CATS_DISCOVERY_HELM_TOKEN_ORIGINS', 'token_origins')]:
        match = re.search(r'^' + key + r'=(.*)$', text, re.M)
        previous = json.loads(match[1].strip().strip("'")) if match else []
        if not isinstance(previous, list):
            raise ValueError('Expected JSON array for ' + key)
        settings[key] = "'" + json.dumps(list(dict.fromkeys(previous + profile[field])), separators=(',', ':')) + "'"
    for key, value in settings.items():
        pattern = r'^' + key + r'=[^\r\n]*'
        if re.search(pattern, text, re.M):
            text = re.sub(pattern, lambda _: key + '=' + value, text, flags=re.M)
        else:
            text = text.rstrip() + '\n' + key + '=' + value + '\n'
    mirror = ROOT / 'deploy/discovery-mirror-local'
    mirror.mkdir(exist_ok=True)
    for row, content in artifacts:
        (mirror / row['path']).write_bytes(content)
    manifest_path = mirror / 'manifest.json'
    previous_manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {'artifacts': []}
    manifest = {'version': 1, 'artifacts': [{k: v for k, v in row.items() if k != 'download_url'} for row, _ in artifacts]}
    identities = {(r['reference'], r['version']) for r in manifest['artifacts']}
    manifest['artifacts'] += [r for r in previous_manifest['artifacts'] if (r['reference'], r['version']) not in identities]
    (mirror / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    env_path.write_text(text, encoding='utf-8')
    print('Configured .env and deploy/discovery-mirror-local. Recreate discovery-worker with normal Compose.')
    print('For this example, select these values files in Discovery, in order:')
    print('\n'.join(profile['discovery_options']['values_files']))


if __name__ == '__main__':
    main()
