"""Connected release preparation; qualification runs in a disposable offline Docker harness.

Never invoked by runtime payload building or target provisioning. No qualification
flags or seal are published until the clean native harness completes successfully.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT / 'scripts/managed-validator-release'
PLATFORM = 'ubuntu-22.04-amd64'


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(*argv, capture=False, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, text=True,
                          stdout=subprocess.PIPE if capture else None, **kwargs)


def copy_pinned_image(source, destination, reference):
    # Ubuntu 22.04's Skopeo lacks --preserve-digests. Require the same
    # manifest digest explicitly after copying, failing before publication.
    if source.startswith('docker://') and '@sha256:' in source:
        repository, digest = source.removeprefix('docker://').split('@', 1)
        # Remove only a tag on the final path component; retain registry ports.
        prefix, separator, image = repository.rpartition('/')
        image = image.split(':', 1)[0]
        source = 'docker://' + prefix + separator + image + '@' + digest
    # The pinned node digest identifies a multi-platform index. Copy the index
    # and its children rather than replacing it with the amd64 child manifest.
    options = ['--all'] if source.startswith('docker://') else []
    run('skopeo', 'copy', *options, '--override-arch', 'amd64', '--override-os', 'linux',
        source, destination)
    expected = reference.rsplit('@sha256:', 1)[1]
    archive_path = destination.removeprefix('oci-archive:').removesuffix(':' + reference)
    with tarfile.open(archive_path) as archive:
        index = json.load(archive.extractfile('index.json'))
        if not any(item['digest'] == 'sha256:' + expected for item in index['manifests']):
            raise ValueError('Copied image manifest digest mismatch: ' + reference)
        manifest = archive.extractfile('blobs/sha256/' + expected).read()
        if hashlib.sha256(manifest).hexdigest() != expected:
            raise ValueError('Copied image manifest content mismatch: ' + reference)


def validate_pins(pins):
    for name in ('kind', 'kubectl', 'helm'):
        item = pins[name]
        if not re.fullmatch(r'v?\d+\.\d+\.\d+', item['version']):
            raise ValueError('An exact version is required: ' + name)
        if not re.fullmatch(r'[a-f0-9]{64}', item['sha256']):
            raise ValueError('Independent SHA256 is required: ' + name)
        if not item['url'].startswith('https://') or 'latest' in item['url']:
            raise ValueError('Pinned HTTPS vendor URL required')
    for name in ('ubuntu_image', 'node_image'):
        if 'latest' in pins[name]['reference'] or not re.fullmatch(r'[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}', pins[name]['reference']):
            raise ValueError('Immutable image digest required: ' + name)
    if int(pins['docker']['engine_version'].split('.')[0]) < 28:
        raise ValueError('Docker Engine 28+ required')
    required = {'docker-ce','docker-ce-cli','containerd.io','docker-buildx-plugin','docker-compose-plugin'}
    if set(pins['docker']['packages']) != required:
        raise ValueError('Complete pinned Docker package selection required')
    if not re.fullmatch(r'[a-f0-9]{64}', pins['docker']['key_sha256']) or not re.fullmatch(r'[A-F0-9]{40}', pins['docker']['key_fingerprint']):
        raise ValueError('Docker signing key requires SHA256 and fingerprint')
    for name, version in pins['docker']['packages'].items():
        if not version or 'latest' in version or '*' in version:
            raise ValueError('Exact Docker package version required: ' + name)
    node_minor = int(pins['node_image']['kubernetes_version'].lstrip('v').split('.')[1])
    client_minor = int(pins['kubectl']['version'].lstrip('v').split('.')[1])
    if abs(node_minor - client_minor) > 1:
        raise ValueError('kubectl must be within one Kubernetes minor version')
    return pins


def verified_download(url, expected, cache, destination):
    if not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Download requires independent SHA256')
    cache, destination = Path(cache), Path(destination)
    cache.mkdir(parents=True, exist_ok=True)
    item = cache / expected
    if item.exists() and (item.is_symlink() or sha256(item) != expected):
        raise ValueError('Corrupted cached vendor artifact rejected')
    if not item.exists():
        temporary = cache / (expected + '.' + uuid.uuid4().hex + '.part')
        try:
            with urllib.request.urlopen(url, timeout=120) as response, temporary.open('wb') as output:
                shutil.copyfileobj(response, output)
            if sha256(temporary) != expected:
                raise ValueError('Vendor artifact SHA256 mismatch: ' + url)
            temporary.replace(item)
        finally:
            temporary.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(item, destination)
    if sha256(destination) != expected:
        raise ValueError('Copied artifact SHA256 mismatch')


def validate_inventory(root, inventory):
    for name, entry in inventory.items():
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', name) or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('Unsafe release closure path')
        path = Path(root) / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != entry['size'] or sha256(path) != entry['sha256']:
            raise ValueError('Incomplete or mutated release closure: ' + name)
    if not any(n.startswith('packages/') and n.endswith('.deb') for n in inventory):
        raise ValueError('Missing Docker package closure')
    if not any(n.startswith('wheels/') and n.endswith('.whl') for n in inventory):
        raise ValueError('Missing native wheel closure')


def validate_chart(chart):
    import yaml
    metadata = yaml.safe_load((Path(chart) / 'Chart.yaml').read_text())
    if metadata.get('dependencies'):
        raise ValueError('Self-test chart cannot have dependencies')
    for path in Path(chart).rglob('*'):
        if path.is_symlink():
            raise ValueError('Self-test chart symlink forbidden')
        if path.is_file() and any(word in path.read_text() for word in ('https://', 'http://', 'oci://')):
            raise ValueError('Self-test chart remote reference forbidden')


def json_write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def inventory(root, sources):
    return {name: {'sha256': sha256(Path(root) / name),
                   'size': (Path(root) / name).stat().st_size, 'source': source}
            for name, source in sorted(sources.items())}


def write_manifest(root, cats_version, pins, evidence):
    root = Path(root)
    base = root / PLATFORM
    files = json.loads((base / 'inventory.json').read_text())
    validate_inventory(base, files)
    qualifications = ('runtime_packages', 'python_wheels', 'image_digests', 'self_test')
    if any(evidence.get(key) is not True for key in qualifications):
        raise ValueError('Completed offline qualification is mandatory')
    packages = sorted(n for n in files if n.startswith('packages/'))
    wheels = sorted(n for n in files if n.startswith('wheels/'))
    manifest = dict(format=1, os='ubuntu', os_version='22.04', architecture='amd64',
        payload_version=cats_version + '-ubuntu-22.04-amd64', python_version='3.10',
        versions={**{k: pins[k]['version'] for k in ('kind', 'kubectl', 'helm')},
            'runtime': pins['docker']['engine_version'], 'node_image': pins['node_image']['kubernetes_version'],
            'self_test_image': '1.0.0', 'self_test_chart': '1.0.0'},
        node_image_reference=pins['node_image']['reference'],
        self_test_image_reference=evidence['self_test_image_reference'],
        assets={'kind':'bin/kind', 'kubectl':'bin/kubectl', 'helm':'bin/helm',
                'node_image':'images/node.tar', 'self_test_image':'images/self-test.tar',
                'self_test_chart':'self-test-chart.tar.gz'},
        packages=packages, wheels=wheels, files=files,
        runtime={'engine_version':pins['docker']['engine_version'], 'packages':packages},
        qualification={key: True for key in qualifications}, provenance={
            'pins':pins, 'built_at':datetime.now(timezone.utc).isoformat(),
            'target_platform':PLATFORM, 'requirements_sha256':sha256(ROOT / 'portal/requirements.txt'),
            'native_packages':json.loads((base / 'package-provenance.json').read_text()) if (base / 'package-provenance.json').exists() else [],
            'self_test_result':json.loads((base / 'self-test-qualification.json').read_text()) if (base / 'self-test-qualification.json').exists() else {}},
        qualification_evidence=evidence)
    json_write(base / 'validator-assets.json', manifest)
    json_write(root / 'release.json', {'format':1, 'cats_version':cats_version,
        'platforms':[{'os':'ubuntu', 'os_version':'22.04', 'architecture':'amd64',
                      'path':PLATFORM, 'sha256':sha256(base / 'validator-assets.json')}]})


def native_acquire(args, pins):
    base = Path(args.output) / PLATFORM
    for name in ('bin', 'packages', 'wheels', 'images'):
        (base / name).mkdir(parents=True, exist_ok=True)
    sources = {}
    for name in ('kind', 'kubectl', 'helm'):
        pin = pins[name]
        downloaded = base / ('helm.tar.gz' if name == 'helm' else 'bin/' + name)
        verified_download(pin['url'], pin['sha256'], args.cache, downloaded)
        if name == 'helm':
            with tarfile.open(downloaded) as archive:
                member = archive.getmember('linux-amd64/helm')
                if not member.isfile(): raise ValueError('Invalid official Helm archive')
                with archive.extractfile(member) as src, (base / 'bin/helm').open('wb') as dst:
                    shutil.copyfileobj(src, dst)
            downloaded.unlink()
        (base / 'bin' / name).chmod(0o755)
        sources['bin/' + name] = pin['url'] + '#sha256=' + pin['sha256']
    # Signed APT metadata is the authoritative independent package checksum source.
    run('apt-get', 'update')
    empty = base / 'empty-dpkg-status'; empty.write_text('')
    requested = [name + '=' + version for name, version in pins['docker']['packages'].items()]
    requested += ['python3', 'python3-venv', 'ca-certificates', 'iptables', 'iproute2', 'kmod']
    uri_output = run('apt-get', '-o', 'Dir::State::status=' + str(empty),
        '--print-uris', '--yes', '--download-only', '--no-install-recommends', 'install',
        *requested, capture=True).stdout
    # --print-uris may print MD5 even though signed Packages contains SHA256.
    # Read SHA256 from the authenticated APT package index, never trust MD5.
    package_details = []
    for line in uri_output.splitlines():
        match = re.match(r"'([^']+)'\s+(\S+)\s+(\d+)\s+\S+$", line)
        if not match: continue
        url, original_filename, size = match.groups()
        url_path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
        # Ask for the exact solver-selected version; dumpavail can choose a
        # newer candidate and omit our explicitly pinned Docker release.
        fields = urllib.parse.unquote(original_filename).split('_')
        if len(fields) != 3: raise ValueError('Invalid APT package filename')
        metadata = run('apt-cache','show',fields[0] + '=' + fields[1],capture=True).stdout
        records = []
        for paragraph in metadata.split('\n\n'):
            record = dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line.startswith(' '))
            if all(key in record for key in ('Filename','SHA256','Package','Version')) and url_path.endswith('/' + urllib.parse.unquote(record['Filename'])):
                if record not in records: records.append(record)
        if len(records) != 1: raise ValueError('APT URI missing authenticated SHA256 metadata: ' + original_filename)
        record = records[0]; digest = record['SHA256']
        filename = digest + '.deb'
        verified_download(url, digest, args.cache, base / 'packages' / filename)
        if (base / 'packages' / filename).stat().st_size != int(size): raise ValueError('APT package size mismatch')
        details = run('dpkg-deb', '-f', base / 'packages' / filename, 'Package', 'Version', capture=True).stdout
        package_details.append({'file':filename, 'original_filename':original_filename,
            'package':record['Package'], 'version':record['Version'],
            'metadata':details.strip(), 'url':url, 'sha256':digest})
        sources['packages/' + filename] = url
    empty.unlink()
    if not package_details: raise ValueError('APT did not return a SHA256 verified closure')
    json_write(base / 'package-provenance.json', package_details)
    run('python3', '-m', 'pip', 'download', '--only-binary=:all:', '--dest', base / 'wheels',
        '-r', ROOT / 'portal/requirements.txt')
    # Verify every downloaded wheel against PyPI's independently fetched release metadata.
    for wheel in (base / 'wheels').glob('*.whl'):
        distribution, version = wheel.name.split('-')[:2]
        url = 'https://pypi.org/pypi/' + distribution + '/' + version + '/json'
        with urllib.request.urlopen(url, timeout=120) as response:
            release = json.load(response)
        records = [r for r in release['urls'] if r['filename'] == wheel.name]
        if len(records) != 1 or records[0]['digests']['sha256'] != sha256(wheel):
            raise ValueError('Wheel does not match independent PyPI SHA256: ' + wheel.name)
        sources['wheels/' + wheel.name] = records[0]['url'] + '#sha256=' + records[0]['digests']['sha256']
    copy_pinned_image('docker://' + pins['node_image']['reference'],
        'oci-archive:' + str(base / 'images/node.tar') + ':' + pins['node_image']['reference'],
        pins['node_image']['reference'])
    sources['images/node.tar'] = 'docker://' + pins['node_image']['reference']
    # Static scratch binary is built locally. No base image or registry is involved.
    run('gcc', '-static', '-Os', '-s', '-o', base / 'self-test-server', SUPPORT / 'self-test-server.c',
        '-Wl,--build-id=none')
    layout = base / 'self-test-oci'
    run('python3', SUPPORT / 'make-self-test-oci.py', base / 'self-test-server', layout)
    image_ref = (layout / 'reference.txt').read_text().strip()
    (layout / 'reference.txt').unlink()
    copy_pinned_image('oci:' + str(layout) + ':1.0.0',
        'oci-archive:' + str(base / 'images/self-test.tar') + ':' + image_ref, image_ref)
    sources['images/self-test.tar'] = 'cats-local-build:scratch-http-server-1.0.0'
    chart = base / 'chart'; shutil.copytree(SUPPORT / 'chart', chart)
    deployment = chart / 'templates/deployment.yaml'
    deployment.write_text(deployment.read_text().replace('SELF_TEST_IMAGE', image_ref))
    validate_chart(chart)
    run(base / 'bin/helm', 'lint', chart)
    # Contract places Chart.yaml at the archive root. Normalize metadata and gzip mtime.
    import gzip
    with (base / 'self-test-chart.tar.gz').open('wb') as output, gzip.GzipFile(fileobj=output, mode='wb', mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w') as archive:
        for path in sorted(chart.rglob('*')):
            if not path.is_file(): continue
            info = archive.gettarinfo(str(path), arcname=path.relative_to(chart).as_posix())
            info.mtime=0; info.uid=info.gid=0; info.uname=info.gname=''; info.mode=0o644
            with path.open('rb') as stream: archive.addfile(info, stream)
    sources['self-test-chart.tar.gz'] = 'cats-local-build:dependency-free-self-test-chart-1.0.0'
    json_write(base / 'inventory.json', inventory(base, sources))
    json_write(base / 'acquisition.json', {'self_test_image_reference':image_ref})
    shutil.rmtree(layout); (base / 'self-test-server').unlink()


def native_qualify(args, pins):
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise ValueError('Qualification must start in the disposable --network none harness')
    base = Path(args.output) / PLATFORM
    files = json.loads((base / 'inventory.json').read_text())
    validate_inventory(base, files)
    # Qualification image has only Ubuntu's baseline Python; no Docker/wheel package preinstallation.
    run('apt-get', '--no-download', '--yes', 'install', *sorted((base / 'packages').glob('*.deb')))
    run('python3', '-m', 'venv', '/tmp/qualification-venv')
    python = '/tmp/qualification-venv/bin/python'
    run(python, '-m', 'pip', 'install', '--no-index', '--find-links', base / 'wheels',
        '-r', ROOT / 'portal/requirements.txt')
    run(python, '-m', 'pip', 'check')
    for tool, command in [('kind', ['version']), ('kubectl', ['version','--client','-o','json']), ('helm', ['version','--short'])]:
        version = run(base / 'bin' / tool, *command, capture=True).stdout
        if pins[tool]['version'].lstrip('v') not in version: raise ValueError('Wrong vendor executable version: ' + tool)
    # The daemon exists only inside this --privileged --network none disposable container.
    daemon = subprocess.Popen(['dockerd', '--host=unix:///var/run/docker.sock', '--feature=containerd-snapshotter=true'],
                              stdout=open('/tmp/dockerd.log','w'), stderr=subprocess.STDOUT)
    try:
        for _ in range(90):
            if subprocess.run(['docker','info'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
            if daemon.poll() is not None: raise ValueError('Disposable Docker daemon could not start')
            time.sleep(1)
        else: raise ValueError('Disposable Docker daemon startup timed out')
        version = run('docker','version','--format','{{.Server.Version}}',capture=True).stdout.strip()
        if version != pins['docker']['engine_version']: raise ValueError('Unexpected offline Docker Engine version')
        driver = run('docker','info','--format','{{json .DriverStatus}}',capture=True).stdout
        if 'io.containerd.snapshotter.v1' not in driver: raise ValueError('OCI digest qualification requires the containerd image store')
        acquisition = json.loads((base / 'acquisition.json').read_text())
        for archive, ref in [('node.tar',pins['node_image']['reference']), ('self-test.tar',acquisition['self_test_image_reference'])]:
            run('docker','load','--input',base / 'images' / archive)
            run('docker','image','inspect',ref)
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'portal'), PATH=str(base / 'bin') + ':' + os.environ['PATH'])
        run(python, SUPPORT / 'qualify-self-test.py', base, args.pins, env=env)
        evidence = {key:True for key in ('runtime_packages','python_wheels','image_digests','self_test')}
        evidence.update(acquisition, network='docker --network none', python_version='3.10', engine_version=version)
        json_write(base / 'qualification.json', evidence)
    finally:
        daemon.terminate()
        try: daemon.wait(timeout=30)
        except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()


def prepare(args, pins):
    output = Path(args.output).resolve()
    if output.is_symlink(): raise ValueError('Release output cannot be a symlink')
    output.parent.mkdir(parents=True, exist_ok=True)
    run('docker','info',capture=True)
    cache = Path(args.cache).resolve(); cache.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.validator-release-', dir=output.parent))
    connected = 'cats-validator-acquisition:' + sha256(args.pins)[:16]
    clean = 'cats-validator-qualification:' + sha256(args.pins)[:16]
    try:
        build = ['docker','build','--platform','linux/amd64','--build-arg','UBUNTU_IMAGE=' + pins['ubuntu_image']['reference']]
        run(*build, '--build-arg','DOCKER_KEY_SHA256=' + pins['docker']['key_sha256'],
            '--build-arg','DOCKER_KEY_FINGERPRINT=' + pins['docker']['key_fingerprint'],
            '-t',connected,'-f',SUPPORT / 'Dockerfile.connected',ROOT)
        run(*build,'-t',clean,'-f',SUPPORT / 'Dockerfile.qualification',ROOT)
        common = ['--rm','--platform','linux/amd64','--mount','type=bind,src=' + str(ROOT) + ',dst=/src,readonly',
                  '--mount','type=bind,src=' + str(stage) + ',dst=/release']
        internal = ['python3','/src/scripts/prepare-managed-validator-release.py', '--output','/release',
                    '--cats-version',args.cats_version, '--pins','/src/' + Path(args.pins).resolve().relative_to(ROOT).as_posix()]
        run('docker','run',*common,'--mount','type=bind,src=' + str(cache) + ',dst=/cache',connected,
            *internal,'--cache','/cache','--native-phase','acquire')
        run('docker','run',*common,'--privileged','--network','none',clean,*internal,'--native-phase','qualify')
        if hasattr(os, 'getuid'):
            run('docker','run',*common,'--network','none',connected,
                'chown','-R',str(os.getuid()) + ':' + str(os.getgid()),'/release')
        evidence = json.loads((stage / PLATFORM / 'qualification.json').read_text())
        write_manifest(stage,args.cats_version,pins,evidence)
        # Existing verifier/sealer is the sole authority for release format acceptance.
        run('docker','run',*common,'--network','none',connected,'python3','/src/scripts/seal-managed-validator-release.py',
            '/release','/release/validator-assets.sha256','--cats-version',args.cats_version)
        previous = output.with_name(output.name + '.previous-' + uuid.uuid4().hex)
        if output.exists(): output.replace(previous)
        try: stage.replace(output)
        except Exception:
            if previous.exists(): previous.replace(output)
            raise
        if previous.exists(): shutil.rmtree(previous, ignore_errors=True)
        print('Qualified, sealed managed-validator release: ' + str(output))
    except Exception:
        # Preserve diagnosis without publishing release.json or a trusted seal.
        # An older qualified output remains intact until a replacement succeeds.
        (stage / 'validator-assets.sha256').unlink(missing_ok=True)
        (stage / 'release.json').unlink(missing_ok=True)
        failed = stage.with_name(stage.name + '.failed')
        stage.replace(failed)
        print('Unsealed failed preparation retained for diagnosis: ' + str(failed), file=sys.stderr)
        raise
    finally:
        if stage.exists(): shutil.rmtree(stage)


if __name__ == '__main__':
    raise SystemExit('This native Ubuntu package preparation pipeline is retired. Use scripts/build-cats-release.py to build CATS and export the Docker validator release.')
