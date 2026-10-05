set -eu
umask 077
python3 - "$1" <<'PY'
import hashlib, json, os, pathlib, shlex, subprocess, sys, tarfile
root = pathlib.Path(sys.argv[1]) / 'payload'
m = json.loads((root/'manifest.json').read_text())
if m['os'] != 'ubuntu' or m['os_version'] not in {'22.04', '24.04'}: raise RuntimeError('Unsupported payload')
release = {}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    line = line.strip()
    if not line or line.startswith('#'): continue
    key, separator, value = line.partition('=')
    if not separator or not key.isidentifier() or key in release: raise RuntimeError('Invalid host release metadata')
    words = shlex.split(value, comments=False, posix=True)
    if len(words) > 1: raise RuntimeError('Invalid host release metadata')
    release[key] = words[0] if words else ''
if (release.get('ID'), release.get('VERSION_ID')) != (m['os'], m['os_version']): raise RuntimeError('Payload does not match host OS/version')
if subprocess.check_output(['dpkg','--print-architecture'],text=True).strip() != m['architecture']: raise RuntimeError('Wrong architecture')
for name, expected in m['files'].items():
    p = pathlib.PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or any(part.is_symlink() for part in [root/name, *(root/name).parents]): raise RuntimeError('Unsafe payload')
    file = root/name
    if file.stat().st_size != expected['size']: raise RuntimeError('Payload size')
    h = hashlib.sha256()
    with file.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): h.update(block)
    if h.hexdigest() != expected['sha256']: raise RuntimeError('Payload integrity')
def run(args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
def safe_extract(archive, destination):
    # Python 3.10 (Ubuntu 22.04) has no extractall filter argument.
    # Validate every member before writing; extract only ordinary files/directories.
    destination = destination.resolve()
    members = archive.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (not member.name or '\\' in member.name or path.is_absolute()
                or '..' in path.parts or ':' in member.name
                or not (member.isfile() or member.isdir())
                or member.issym() or member.islnk() or member.isdev()
                or (not path.parts and not member.isdir())):
            raise RuntimeError('Unsafe archive member')
    for member in members:
        target = destination.joinpath(*pathlib.PurePosixPath(member.name).parts)
        # Also reject any links already present or introduced at a destination.
        current = target
        while True:
            if current.is_symlink(): raise RuntimeError('Unsafe extraction destination')
            if current == destination: break
            current = current.parent
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None: raise RuntimeError('Invalid archive file')
            with source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
# Existing worker cannot import a partially replaced application.
import shutil
reuse_runtime = False
if shutil.which('docker'):
    version = subprocess.check_output(['docker','version','--format','{{.Client.Version}}'],text=True).strip()
    if int(version.split('.')[0]) < 28: raise RuntimeError('Existing Docker is unsupported; administrator must upgrade to Docker 28+ before retry')
    reuse_runtime = True
runtime_packages = {'docker-ce','docker-ce-cli','containerd.io','docker-buildx-plugin','docker-compose-plugin','docker.io','containerd','runc'}
packages = []
for name in m['packages']:
    archive = str((root/name).resolve())
    package = subprocess.check_output(['dpkg-deb','-f',archive,'Package'],text=True).strip()
    if not reuse_runtime or package not in runtime_packages: packages.append(archive)
if pathlib.Path('/etc/systemd/system/cats-validator.service').exists(): run(['systemctl','stop','cats-validator.service'])
# Never update repositories or download missing dependencies.
if packages: run(['apt-get','--no-download','-y','install',*packages])
# OCI archives retain the immutable manifest identity in the containerd store.
# Do not migrate an administrator's existing image store during bootstrap.
if not reuse_runtime:
    daemon_config = pathlib.Path('/etc/docker/daemon.json')
    if daemon_config.is_symlink(): raise RuntimeError('Unsafe Docker configuration')
    config = json.loads(daemon_config.read_text()) if daemon_config.exists() else {}
    features = config.setdefault('features', {})
    if not isinstance(features, dict): raise RuntimeError('Invalid Docker features configuration')
    features['containerd-snapshotter'] = True
    daemon_config.parent.mkdir(parents=True, exist_ok=True)
    daemon_config.write_text(json.dumps(config) + '\n')
run(['systemctl','enable','--now','docker'])
if not reuse_runtime: run(['systemctl','restart','docker'])
run(['docker','info'])
driver_status = subprocess.check_output(['docker','info','--format','{{json .DriverStatus}}'],text=True)
if 'io.containerd.snapshotter.v1' not in driver_status:
    raise RuntimeError('Docker containerd image store required for offline digest archives; administrator must enable it before retry')
version = subprocess.check_output(['docker','version','--format','{{.Server.Version}}'],text=True).strip()
if int(version.split('.')[0]) < 28: raise RuntimeError('Docker Engine 28+ required')
if subprocess.run(['id','cats-validator'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
    run(['useradd','--system','--create-home','--home-dir','/var/lib/cats-validator','--shell','/usr/sbin/nologin','cats-validator'])
run(['usermod','-aG','docker','cats-validator'])
for directory in ['/opt/cats-validator','/etc/cats-validator','/var/lib/cats-validator']:
    pathlib.Path(directory).mkdir(parents=True,exist_ok=True)
    os.chmod(directory,0o755 if directory == '/opt/cats-validator' else 0o700)
for tool in ['kind','kubectl','helm']:
    import shutil
    shutil.copyfile(root/m['assets'][tool],'/usr/local/bin/'+tool)
    os.chmod('/usr/local/bin/'+tool,0o755)
app = pathlib.Path('/opt/cats-validator/app')
if app.is_symlink(): raise RuntimeError('Application directory cannot be a symlink')
if app.exists(): shutil.rmtree(app)
app.mkdir()
with tarfile.open(root/m['assets']['validator']) as archive:
    # The application contains wheels, requirements.txt, app/, validator_server.py.
    safe_extract(archive, app)
run(['python3','-m','venv','/opt/cats-validator/venv'])
run(['/opt/cats-validator/venv/bin/pip','install','--no-index','--find-links',str(app/'wheels'),'-r',str(app/'requirements.txt')])
for asset in ['node_image','self_test_image']: run(['docker','load','-i',str(root/m['assets'][asset])])
selftest = pathlib.Path('/opt/cats-validator/self-test')
selftest.mkdir(exist_ok=True)
chart = selftest/'chart'
if chart.exists():
    import shutil
    shutil.rmtree(chart)
chart.mkdir()
with tarfile.open(root/m['assets']['self_test_chart']) as archive:
    safe_extract(archive, chart)
# Builder packages chart contents at archive root, not a containing directory.
if not (chart/'Chart.yaml').is_file(): raise RuntimeError('Self-test chart layout invalid')
import shutil
shutil.copyfile(root/m['assets']['self_test_image'], selftest/'image.tar')
hashes = {}
for file in selftest.rglob('*'):
    if file.is_symlink(): raise RuntimeError('Self-test symlinks forbidden')
    if file.is_file() and file.name != 'manifest.json':
        digest = hashlib.sha256()
        with file.open('rb') as stream:
            for block in iter(lambda: stream.read(1024*1024), b''): digest.update(block)
        hashes[file.relative_to(selftest).as_posix()] = digest.hexdigest()
(selftest/'manifest.json').write_text(json.dumps({'chart':'chart','archive':'image.tar','image':m['self_test_image_reference'],'sha256':hashes}))
# Fail before enrollment when saved archives do not provide the pinned images.
for image in ['node_image_reference','self_test_image_reference']: run(['docker','image','inspect',m[image]])
pathlib.Path('/var/lib/cats-validator/tmp').mkdir(exist_ok=True)
# Application is immutable to the service but must be traversable/readable.
run(['chmod','-R','a+rX','/opt/cats-validator'])
run(['chown','-R','cats-validator:cats-validator','/var/lib/cats-validator','/etc/cats-validator'])
unit = '''[Unit]
Description=CATS managed validator
After=docker.service network-online.target
Requires=docker.service
[Service]
User=cats-validator
Group=cats-validator
SupplementaryGroups=docker
WorkingDirectory=/opt/cats-validator/app
EnvironmentFile=/etc/cats-validator/runtime.env
ExecStart=/opt/cats-validator/venv/bin/python -m validator_server
Restart=on-failure
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/cats-validator
Environment=HOME=/var/lib/cats-validator
Environment=TMPDIR=/var/lib/cats-validator/tmp
[Install]
WantedBy=multi-user.target
'''
pathlib.Path('/etc/systemd/system/cats-validator.service').write_text(unit)
run(['systemctl','daemon-reload'])
PY
