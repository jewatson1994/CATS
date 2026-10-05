import base64
import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch, call

import pytest
from app.validator_bootstrap import SSHBootstrap, validate_target
from app.validator_payload import REQUIRED, validate_payload, select_payload


def payload(tmp_path, version='24.04', architecture='amd64'):
    assets = {name: name + '.asset' for name in REQUIRED}
    manifest = {'format': 1, 'payload_version': 'test-1', 'os': 'ubuntu', 'os_version': version, 'architecture': architecture, 'assets': assets, 'versions': {name:'1' for name in REQUIRED}, 'packages':['runtime.deb'], 'node_image_reference':'kindest/node@sha256:'+'a'*64, 'self_test_image_reference':'test/image@sha256:'+'b'*64, 'files':{}}
    for name in [*assets.values(), 'runtime.deb']:
        data = name.encode()
        (tmp_path/name).write_bytes(data)
        manifest['files'][name] = {'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    return manifest


def test_payload_integrity_and_external_trust(tmp_path):
    expected = payload(tmp_path)
    digest = hashlib.sha256((tmp_path/'manifest.json').read_bytes()).hexdigest()
    assert validate_payload(tmp_path, digest) == expected
    with pytest.raises(ValueError, match='trusted'):
        validate_payload(tmp_path, '0'*64)
    (tmp_path/'runtime.deb').write_bytes(b'corrupt')
    with pytest.raises(ValueError):
        validate_payload(tmp_path, digest)


def test_payload_unmanifested_file_rejected(tmp_path):
    payload(tmp_path)
    (tmp_path/'surprise').write_text('untrusted')
    with pytest.raises(ValueError, match='Unmanifested'):
        validate_payload(tmp_path)


@pytest.mark.parametrize('version', ['22.04', '24.04'])
@pytest.mark.parametrize('architecture', ['amd64', 'arm64'])
def test_supported_platform_preflight_and_payload(tmp_path, version, architecture):
    expected = payload(tmp_path, version, architecture)
    digest = hashlib.sha256((tmp_path/'manifest.json').read_bytes()).hexdigest()
    facts = {'os':'ubuntu', 'os_version':version, 'architecture':architecture,
             'cpus':4, 'memory_bytes':8*1024**3, 'disk_bytes':40*1024**3,
             'root':True, 'systemd':True, 'cgroup_v2':True}
    bootstrap = SSHBootstrap({'host':'192.168.1.4'}, {})
    with patch.object(bootstrap, '_run', return_value=json.dumps(facts)):
        assert bootstrap.preflight()['checks']['platform'] is True
    assert select_payload(tmp_path, digest, facts)[1] == expected
    with pytest.raises(ValueError, match='matching'):
        select_payload(tmp_path, digest, dict(facts, os_version='20.04'))


def test_catalog_selects_exact_platform_and_rejects_tampering(tmp_path):
    entries=[]
    for version in ('22.04', '24.04'):
        path=tmp_path/version; path.mkdir(); payload(path, version)
        entries.append({'os':'ubuntu', 'os_version':version, 'architecture':'amd64',
                        'path':version, 'sha256':hashlib.sha256((path/'manifest.json').read_bytes()).hexdigest()})
    catalog=tmp_path/'catalog.json'
    catalog.write_text(json.dumps({'format':1, 'payloads':entries}))
    trusted=hashlib.sha256(catalog.read_bytes()).hexdigest()
    for version in ('22.04', '24.04'):
        facts={'os':'ubuntu', 'os_version':version, 'architecture':'amd64'}
        assert select_payload(tmp_path, trusted, facts)[0] == tmp_path/version
    with pytest.raises(ValueError, match='matching'):
        select_payload(tmp_path, trusted, dict(facts, architecture='arm64'))
    (tmp_path/'22.04'/'runtime.deb').write_bytes(b'tampered')
    with pytest.raises(ValueError):
        select_payload(tmp_path, trusted, dict(facts, os_version='22.04'))
    catalog.write_text(catalog.read_text()+' ')
    with pytest.raises(ValueError, match='trusted'):
        select_payload(tmp_path, trusted, facts)


def test_catalog_transfer_revalidates_selected_manifest_not_catalog_digest(tmp_path, monkeypatch):
    expected=payload(tmp_path, '22.04')
    monkeypatch.setenv('CATS_VALIDATOR_PAYLOAD_SHA256', 'f'*64)
    bootstrap=SSHBootstrap({'host':'192.168.1.4'}, {})
    bootstrap.client=Mock()
    bootstrap.client.open_sftp.return_value.file.return_value.__enter__=Mock(return_value=Mock())
    bootstrap.client.open_sftp.return_value.file.return_value.__exit__=Mock(return_value=False)
    with patch.object(bootstrap, '_ensure_workspace'):
        assert bootstrap.transfer_payload(tmp_path, expected) == expected


@pytest.mark.parametrize('name,kind', [('app/file','file'),('../escape','file'),('/absolute','file'),
                                      ('app\\escape','file'),('link','symlink'),('hard','hardlink'),('dev','device')])
def test_python310_archive_extraction(tmp_path, name, kind):
    import ast
    import io
    import pathlib
    import shutil
    import tarfile
    script=Path(__file__).parents[1]/'app'/'validator_bootstrap_assets'/'install.sh'
    program=script.read_text().split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
    ast.parse(program, feature_version=(3,10))
    node=next(n for n in ast.parse(program).body if isinstance(n,ast.FunctionDef) and n.name=='safe_extract')
    namespace={'pathlib':pathlib,'shutil':shutil}
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(script),'exec'),namespace)
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w') as archive:
        member=tarfile.TarInfo(name)
        if kind=='file': member.size=2
        elif kind=='symlink': member.type=tarfile.SYMTYPE;member.linkname='file'
        elif kind=='hardlink': member.type=tarfile.LNKTYPE;member.linkname='file'
        else: member.type=tarfile.CHRTYPE
        archive.addfile(member,io.BytesIO(b'ok') if kind=='file' else None)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as archive:
        if name=='app/file':
            namespace['safe_extract'](archive,tmp_path)
            assert (tmp_path/name).read_bytes()==b'ok'
        else:
            with pytest.raises(RuntimeError,match='Unsafe'):
                namespace['safe_extract'](archive,tmp_path)


def test_resource_overrides_retained_and_preflight_read_only():
    bootstrap = SSHBootstrap({'host':'192.168.1.4','minimum_resources':{'cpus':8}}, {'sudo_password':'secret'})
    facts = {'os':'ubuntu','os_version':'24.04','architecture':'amd64','cpus':4,'memory_bytes':8*1024**3,'disk_bytes':40*1024**3,'sudo':False,'systemd':True}
    with patch.object(bootstrap, '_run', return_value=json.dumps(facts)) as run, patch.object(bootstrap, '_sudo_available', return_value=True):
        result = bootstrap.preflight()
    assert result['status'] == 'unsupported'
    assert result['checks']['sudo'] is True
    run.assert_called_once_with('preflight.sh')
    assert not bootstrap._workspace_created


def test_changed_host_key_never_authenticates():
    bootstrap = SSHBootstrap({'host':'192.168.1.4'}, {'password':'secret'}, 'SHA256:wrong')
    transport = Mock()
    transport.get_remote_server_key.return_value.asbytes.return_value = b'key'
    with patch.dict(sys.modules, {'paramiko':Mock()}), patch.object(bootstrap, '_transport', return_value=transport), pytest.raises(ValueError, match='host key'):
        bootstrap.__enter__()
    transport.auth_password.assert_not_called()
    transport.close.assert_called_once()


def test_enter_creates_no_workspace():
    transport = Mock()
    transport.get_remote_server_key.return_value.asbytes.return_value = b'key'
    fp = 'SHA256:' + base64.b64encode(hashlib.sha256(b'key').digest()).decode().rstrip('=')
    bootstrap = SSHBootstrap({'host':'192.168.1.4'}, {'password':'secret'}, fp)
    with patch.dict(sys.modules, {'paramiko':Mock()}), patch.object(bootstrap, '_transport', return_value=transport), patch.object(bootstrap, '_run') as run:
        with bootstrap:
            pass
    run.assert_not_called()
    assert not bootstrap.credentials


@pytest.mark.parametrize('host', ['127.0.0.1','0.0.0.0','169.254.2.4','::1','localhost','bad;command'])
def test_unsafe_targets(host):
    with pytest.raises(ValueError):
        validate_target(host)


def test_preflight_rejects_cgroup_port_and_time_skew():
    bootstrap = SSHBootstrap({'host':'192.168.1.4'}, {})
    facts = {'os':'ubuntu','os_version':'24.04','architecture':'amd64','cpus':4,'memory_bytes':8*1024**3,'disk_bytes':40*1024**3,'root':True,'systemd':True,'cgroup_v2':False,'api_port_available':False,'epoch':0}
    with patch.object(bootstrap, '_run', return_value=json.dumps(facts)):
        result = bootstrap.preflight()
    assert result['status'] == 'unsupported'
    assert not result['checks']['cgroup_v2']
    assert not result['checks']['api_port']
    assert not result['checks']['time']


def test_bounded_reader_drains_stderr_and_redacts_secrets():
    bootstrap = SSHBootstrap({'host':'192.168.1.4'}, {'password':'sensitive'})
    class Channel:
        def __init__(self):
            self.out = [b'result sensitive']
            self.err = [b'sensitive stderr']
        def recv_ready(self): return bool(self.out)
        def recv_stderr_ready(self): return bool(self.err)
        def recv(self, count): return self.out.pop(0)
        def recv_stderr(self, count): return self.err.pop(0)
        def exit_status_ready(self): return True
        def recv_exit_status(self): return 0
    assert bootstrap._collect(Mock(channel=Channel())) == 'result [REDACTED]'



def rotation_invalidator():
    import ast
    import stat
    from pathlib import PurePosixPath
    from types import SimpleNamespace
    script = Path(__file__).parents[1] / 'app' / 'validator_bootstrap_assets' / 'certificates.sh'
    program = script.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    node = next(n for n in ast.parse(program).body if isinstance(n, ast.FunctionDef) and n.name == 'invalidate_rotation_state')
    fake_os = Mock(O_RDONLY=0, O_DIRECTORY=1, O_NOFOLLOW=2)
    fake_os.open.side_effect = [10, 11, 12, 13, 14]
    namespace = {'os':fake_os, 'stat':stat, 'pathlib':SimpleNamespace(Path=PurePosixPath)}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(script), 'exec'), namespace)
    return namespace['invalidate_rotation_state'], fake_os


def test_reenrollment_invalidates_only_rotation_pointers():
    import stat
    from types import SimpleNamespace
    invalidate, remote_os = rotation_invalidator()
    remote_os.stat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
    invalidate('/var/lib/cats-validator')
    assert remote_os.unlink.call_args_list == [call('current.json', dir_fd=14), call('pending.json', dir_fd=14)]
    assert remote_os.open.call_args_list[-1].kwargs == {'dir_fd':13}
    assert remote_os.open.call_args_list[-1].args == ('identity', 3)


def test_reenrollment_rejects_symlink_rotation_pointer():
    import stat
    from types import SimpleNamespace
    invalidate, remote_os = rotation_invalidator()
    remote_os.stat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
    with pytest.raises(RuntimeError, match='Unsafe persisted'):
        invalidate('/var/lib/cats-validator')
    remote_os.unlink.assert_not_called()


def test_reenrollment_rejects_symlink_identity_directory():
    invalidate, remote_os = rotation_invalidator()
    remote_os.open.side_effect = [10, 11, 12, 13, OSError('symlink refused')]
    with pytest.raises(OSError, match='symlink refused'):
        invalidate('/var/lib/cats-validator')
    remote_os.unlink.assert_not_called()
