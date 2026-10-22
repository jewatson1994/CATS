import json
import pytest
from app import patch_inputs


def fixture_binding(tmp_path, monkeypatch):
    scanner = tmp_path / 'db'
    scanner.mkdir()
    (scanner / 'vulnerability.db').write_bytes(b'retained database')
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'package.apk').write_bytes(b'package')
    registry = tmp_path / 'registry'
    registry.mkdir()
    (registry / 'blob').write_bytes(b'helper image')
    spec = {'schema': 'cats-isolated-copa-v1', 'network': 'isolated', 'services': ['mirror'],
            'scanner_root': str(scanner), 'repository_root': str(repo), 'registry_root': str(registry),
            'buildkit_image': 'engine', 'buildkit_config': str(tmp_path / 'buildkit.toml'),
            'repository_policies': {}, 'staging_registry': {'container': 'stage', 'upload_url': 'http://stage:5000', 'pull_prefix': 'stage:5000'}}
    (tmp_path / 'spec.json').write_text(json.dumps(spec))
    monkeypatch.setenv('CATS_PATCH_BINDING_SPEC', str(tmp_path / 'spec.json'))
    monkeypatch.setattr(patch_inputs, '_runtime', lambda spec: {'buildkit_image': 'sha256:engine'})
    commands = []
    monkeypatch.setattr(patch_inputs, '_docker', lambda *args: commands.append(args) or '')
    monkeypatch.setattr(patch_inputs, '_inspect', lambda *args: {
        'Id': 'daemon-id', 'State': {'Running': True}, 'HostConfig': {'Privileged': False},
        'NetworkSettings': {'Networks': {'isolated': {'IPAddress': '172.20.0.2'}}}})
    config = {'job_id': 'job1', 'source_mode': 'oci', 'source_image': 'image@sha256:' + 'a'*64,
              'repository_policies': {}, 'destination_scope': {'host': 'registry'}}
    prepared = patch_inputs.prepare_binding(config, tmp_path / 'bindings')
    return config, prepared, tmp_path / 'bindings', repo, commands


def test_binding_uses_retained_bytes_and_fresh_isolated_daemon(tmp_path, monkeypatch):
    config, prepared, root, repo, commands = fixture_binding(tmp_path, monkeypatch)
    assert commands[0][0] == 'create'
    assert commands[1][0] == 'cp'
    assert commands[2][0] == 'start'
    assert '--mount' not in commands[0]
    assert '--privileged' not in commands[0]
    assert '--network' in commands[0] and 'isolated' in commands[0]
    config['execution_binding'] = prepared['binding_id']
    binding = patch_inputs.consume_binding(config, root)
    assert binding.identity == prepared['identity']
    assert binding.buildkit_addr == 'tcp://172.20.0.2:1234'
    receipt = binding.receipt(config, 'output@sha256:' + 'b'*64)
    assert 'execution_binding' not in receipt['config']
    with pytest.raises(FileExistsError):
        patch_inputs.consume_binding(config, root)
    (repo / 'package.apk').write_bytes(b'different package')
    with pytest.raises(RuntimeError, match='inputs changed'):
        binding.verify()


def test_prepared_config_cannot_be_changed(tmp_path, monkeypatch):
    config, prepared, root, _, _ = fixture_binding(tmp_path, monkeypatch)
    config.update(execution_binding=prepared['binding_id'], job_id='another')
    with pytest.raises(ValueError, match='configuration differs'):
        patch_inputs.consume_binding(config, root)


def test_unconfigured_worker_does_not_offer_identity(monkeypatch, tmp_path):
    monkeypatch.delenv('CATS_PATCH_BINDING_SPEC', raising=False)
    assert patch_inputs.prepare_binding({}, tmp_path) is None
    assert patch_inputs.consume_binding({}, tmp_path) is None
    with pytest.raises(ValueError, match='Invalid execution binding'):
        patch_inputs.consume_binding({'execution_binding': '../outside'}, tmp_path)


def test_external_network_rejected(monkeypatch):
    monkeypatch.setattr(patch_inputs, '_inspect', lambda *args: {'Internal': False, 'Driver': 'bridge'})
    with pytest.raises(ValueError, match='internal Docker bridge'):
        patch_inputs._runtime({'network': 'external'})


def test_release_fences_consumption(tmp_path, monkeypatch):
    config, prepared, root, _, _ = fixture_binding(tmp_path, monkeypatch)
    patch_inputs.release_binding(prepared['binding_id'], root)
    config['execution_binding'] = prepared['binding_id']
    with pytest.raises(ValueError, match='released'):
        patch_inputs.consume_binding(config, root)


def test_consumed_binding_cannot_be_released(tmp_path, monkeypatch):
    config, prepared, root, _, _ = fixture_binding(tmp_path, monkeypatch)
    config['execution_binding'] = prepared['binding_id']
    patch_inputs.consume_binding(config, root)
    with pytest.raises(ValueError, match='already been consumed'):
        patch_inputs.release_binding(prepared['binding_id'], root)


def test_prepare_endpoint_requires_worker_authentication(monkeypatch):
    from fastapi import HTTPException
    from app import patch_service
    monkeypatch.setattr(patch_service, 'TOKEN', '')
    with pytest.raises(HTTPException) as exc:
        patch_service.prepare_patch_binding({'config': {}}, None)
    assert exc.value.status_code == 503
    monkeypatch.setattr(patch_service, 'TOKEN', 'shared-secret')
    with pytest.raises(HTTPException) as exc:
        patch_service.prepare_patch_binding({'config': {}}, 'wrong')
    assert exc.value.status_code == 403


def test_prepare_endpoint_issues_only_worker_binding(monkeypatch):
    from app import patch_service
    monkeypatch.setattr(patch_service, 'TOKEN', 'shared-secret')
    monkeypatch.setattr(patch_inputs, 'prepare_binding', lambda config, root: {'binding_id': 'a'*32, 'identity': {'worker': True}})
    result = patch_service.prepare_patch_binding({'config': {'job_id': 'one'}}, 'shared-secret')
    assert result['prepared']['identity'] == {'worker': True}


@pytest.mark.parametrize("value", [0, -1, 8761, True, "720"])
def test_scanner_age_policy_rejects_unbounded_or_invalid_values(value):
    with pytest.raises(ValueError, match="between 1 and 8760"):
        patch_inputs._scanner_max_age({"scanner_max_age_hours": value})


def test_scanner_age_policy_has_strict_default_and_changes_identity():
    assert patch_inputs._scanner_max_age({}) == 120
    first = {"scanner_max_age_hours": patch_inputs._scanner_max_age({})}
    second = {"scanner_max_age_hours": patch_inputs._scanner_max_age({"scanner_max_age_hours": 720})}
    assert patch_inputs._digest(first) != patch_inputs._digest(second)


def test_python_identity_hashes_installed_bytes_and_standard_library(tmp_path, monkeypatch):
    library = tmp_path / 'stdlib'
    library.mkdir()
    standard = library / 'ssl.py'
    standard.write_text('standard library one')
    dependency = tmp_path / 'dependency.py'
    dependency.write_text('dependency one')

    class Distribution:
        files = ['dependency.py']
        metadata = {'Name': 'same-name'}
        version = '1.0'
        def read_text(self, name):
            return None
        def locate_file(self, relative):
            return tmp_path / relative

    monkeypatch.setattr(patch_inputs.importlib.metadata, 'distributions', lambda: [Distribution()])
    monkeypatch.setattr(patch_inputs.sysconfig, 'get_path', lambda name: str(library))
    original = patch_inputs._python_runtime_identity()
    dependency.write_text('changed contents, unchanged version')
    changed = patch_inputs._python_runtime_identity()
    assert changed != original
    standard.write_text('standard library two')
    assert patch_inputs._python_runtime_identity() != changed


def test_python_identity_rejects_editable_or_uninventoried_install(monkeypatch):
    class Distribution:
        files = None
        def read_text(self, name):
            return None
    dist = Distribution()
    monkeypatch.setattr(patch_inputs.importlib.metadata, 'distributions', lambda: [dist])
    with pytest.raises(ValueError, match='file inventory'):
        patch_inputs._python_runtime_identity()
    dist.read_text = lambda name: '{"dir_info":{"editable":true}}'
    with pytest.raises(ValueError, match='editable'):
        patch_inputs._python_runtime_identity()


def test_engine_identity_changes_with_effective_system_trust(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_inputs, '_inspect', lambda kind, name:
                        {'Internal': True, 'Driver': 'bridge'} if kind == 'network' else {'Id': 'buildkit'})
    monkeypatch.setattr(patch_inputs.shutil, 'which', lambda name: 'executable')
    monkeypatch.setattr(patch_inputs, '_file_digest', lambda path: 'fixed-bytes')
    monkeypatch.setattr(patch_inputs, '_python_runtime_identity', lambda: 'fixed-python')
    monkeypatch.setattr(patch_inputs, 'system_ca_bundle', lambda: 'first certificate')
    spec = {'network': 'isolated', 'services': [], 'buildkit_image': 'buildkit', 'buildkit_config': 'config'}
    first = patch_inputs._runtime(spec)
    monkeypatch.setattr(patch_inputs, 'system_ca_bundle', lambda: 'second certificate')
    second = patch_inputs._runtime(spec)
    assert first['system_ca_bundle'] != second['system_ca_bundle']
    assert patch_inputs._digest(first) != patch_inputs._digest(second)
    assert 'certificate' not in json.dumps(second)
