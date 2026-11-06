"""Bounded verifier regressions; actual Docker/nginx qualification is opt-in."""
from copy import deepcopy
import gzip
import io
import json
import subprocess
from types import SimpleNamespace
import tarfile

import pytest

import nginx_hardening_qualification as hardening


def image_pair():
    layer = {'digest': 'sha256:' + 'a' * 64, 'size': 12,
             'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}
    source = {'reference': 'registry.example/patched/nginx@sha256:' + 'b' * 64,
        'manifest_digest': 'sha256:' + 'b' * 64, 'config_digest': 'sha256:' + 'c' * 64,
        'docker_image_id': 'sha256:' + 'c' * 64,
        'manifest': {'layers': [layer]},
        'config': {'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'd' * 64]},
                   'history': [{'created_by': 'original source including retained findings'}]}}
    candidate = deepcopy(source)
    candidate.update(reference='registry.example/hardened/nginx@sha256:' + 'e' * 64,
        manifest_digest='sha256:' + 'e' * 64, config_digest='sha256:' + 'f' * 64,
        docker_image_id='sha256:' + 'f' * 64)
    candidate['manifest']['layers'].append({**layer, 'digest': 'sha256:' + '1' * 64})
    candidate['config']['rootfs']['diff_ids'].append('sha256:' + '2' * 64)
    candidate['config']['history'].append({'created_by': 'explicit nginx recipe'})
    candidate['config']['config'] = {'User': '101:101', 'Entrypoint': ['nginx'],
        'Cmd': ['-g', 'daemon off;'], 'Labels': {
            'org.opencontainers.image.base.name': source['reference'],
            'io.cats.nginx-hardening.recipe': 'v1'},
        'Healthcheck': {'Test': ['CMD-SHELL',
            'wget -q -T 2 -O /dev/null http://127.0.0.1:8080/ || exit 1']}}
    return source, candidate


def test_recipe_preserves_source_history_instead_of_manufacturing_clean_evidence():
    source, candidate = image_pair()
    details = hardening.verify_ancestry(source, candidate)
    assert details['inherited_layer_count'] == details['inherited_history_count'] == 1
    assert hardening.DIGEST.fullmatch(hardening.recipe_digest())


@pytest.mark.parametrize('source_type,hardened_type', [
    ('application/vnd.oci.image.layer.v1.tar', 'application/vnd.docker.image.rootfs.diff.tar'),
    ('application/vnd.docker.image.rootfs.diff.tar', 'application/vnd.oci.image.layer.v1.tar'),
    ('application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'),
    ('application/vnd.docker.image.rootfs.diff.tar.gzip', 'application/vnd.oci.image.layer.v1.tar+gzip'),
])
def test_equivalent_media_labels_preserve_original_descriptors_in_receipt(source_type, hardened_type):
    source, candidate = image_pair()
    source['manifest']['layers'][0]['mediaType'] = source_type
    candidate['manifest']['layers'][0]['mediaType'] = hardened_type
    before, after = deepcopy(source), deepcopy(candidate)
    details = hardening.verify_ancestry(source, candidate)
    assert details['inherited_layer_descriptors'] == [{'index': 0,
        'source': source['manifest']['layers'][0], 'hardened': candidate['manifest']['layers'][0]}]
    assert details['inherited_layer_descriptors'][0]['source']['mediaType'] == source_type
    assert details['inherited_layer_descriptors'][0]['hardened']['mediaType'] == hardened_type
    assert (source, candidate) == (before, after)


@pytest.mark.parametrize('replacement', [
    {'digest': 'sha256:' + '9' * 64}, {'size': 13}, {'size': '12'},
    {'mediaType': 'application/vnd.docker.image.rootfs.diff.tar'},
    {'mediaType': 'application/vnd.oci.image.layer.v1.tar+zstd'},
    {'mediaType': 'application/vnd.example.unknown'},
    {'annotations': {'example': 'changed'}},
])
def test_media_aliases_never_allow_changed_layer_identity_or_compression(replacement):
    source, candidate = image_pair()
    candidate['manifest']['layers'][0].update(replacement)
    with pytest.raises(RuntimeError):
        hardening.verify_ancestry(source, candidate)


def test_matching_unknown_media_types_are_rejected():
    source, candidate = image_pair()
    for image in (source, candidate):
        image['manifest']['layers'][0]['mediaType'] = 'application/vnd.example.unknown'
    with pytest.raises(RuntimeError, match='unsupported media type'):
        hardening.verify_ancestry(source, candidate)


@pytest.mark.parametrize('change, message', [
    (lambda c: c['manifest']['layers'].pop(0), 'original layer'),
    (lambda c: c['manifest']['layers'].reverse(), 'original layer'),
    (lambda c: c['config']['rootfs']['diff_ids'].pop(0), 'filesystem layer'),
    (lambda c: c['config']['history'].pop(0), 'original image history'),
    (lambda c: c['config']['history'][0].update(created_by='sanitized'), 'original image history'),
    (lambda c: c['config']['config']['Labels'].update({'org.opencontainers.image.base.name': 'different'}), 'provenance'),
    (lambda c: c['config']['config'].update(User='0'), 'UID/GID'),
    (lambda c: c['config']['config'].update(Entrypoint=['/docker-entrypoint.sh']), 'root startup'),
    (lambda c: c['config']['config'].update(Healthcheck={'Test': ['CMD', 'true']}), 'HTTP healthcheck'),
])
def test_unsafe_or_unbound_derivative_fails_closed(change, message):
    source, candidate = image_pair()
    change(candidate)
    with pytest.raises(RuntimeError, match=message):
        hardening.verify_ancestry(source, candidate)


@pytest.mark.parametrize('source, candidate', [
    ('nginx:latest', 'host/nginx@sha256:' + 'a' * 64),
    ('host/nginx@sha256:' + 'a' * 64, 'nginx:hardened'),
    ('host/nginx@sha256:' + 'a' * 64, 'other/nginx@sha256:' + 'a' * 64),
])
def test_bad_identity_is_rejected_before_any_docker_command(tmp_path, monkeypatch, source, candidate):
    monkeypatch.setattr(hardening, 'command', lambda *a, **k: pytest.fail('No Docker command permitted'))
    with pytest.raises(RuntimeError):
        hardening.verify_runtime(source, candidate, tmp_path)
    assert not (tmp_path / 'hardening-runtime.json').exists()


@pytest.fixture
def runtime(monkeypatch):
    source, candidate = image_pair()
    state = SimpleNamespace(source=source, candidate=candidate, calls=[], health='healthy',
        mismatch=False, root=False, recipe_mismatch=False, cleanup_failure=False)
    monkeypatch.setattr(hardening, 'image_evidence', lambda ref, folder:
        deepcopy(source if ref == source['reference'] else candidate))

    def command(arguments, **kwargs):
        state.calls.append(arguments)
        result = b''
        if arguments[:1] == ['exec']:
            if arguments[2:4] == ['id', '-u']:
                result = b'101\n'
            elif arguments[2:4] == ['cat', '/proc/1/status']:
                result = (b'Uid:\t0\t0\t0\t0\n' if state.root else b'Uid:\t101\t101\t101\t101\n')
                result += b'CapEff:\t0000000000000000\nNoNewPrivs:\t1\n'
            elif arguments[2:4] == ['cat', '/etc/nginx/nginx.conf']:
                result = b'incorrect' if state.recipe_mismatch else (hardening.RECIPE / 'nginx.conf').read_bytes()
            elif arguments[2:4] == ['cat', '/etc/nginx/conf.d/default.conf']:
                result = (hardening.RECIPE / 'default.conf').read_bytes()
            elif arguments[2:4] == ['cat', '/usr/share/nginx/html/index.html']:
                result = b'inherited static page\n'
            elif arguments[2] == 'wget':
                result = b'wrong body' if state.mismatch else b'inherited static page\n'
            elif arguments[2:4] == ['/bin/sh', '-c']:
                assert 'comm' in arguments[4] and '= nginx' in arguments[4]
                state.health = 'unhealthy' if 'kill -STOP' in arguments[4] else 'healthy'
        return SimpleNamespace(stdout=result, returncode=int(state.cleanup_failure and arguments[0] == 'rm'))

    def docker_json(arguments):
        if arguments[:3] == ['inspect', '--format', '{{json .State}}']:
            return {'Running': True, 'Health': {'Status': state.health}}
        assert arguments[0] == 'inspect'
        return [{'Image': candidate['docker_image_id'], 'HostConfig': {
            'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
            'NetworkMode': 'none', 'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=16777216,mode=1777'}}}]

    monkeypatch.setattr(hardening, 'command', command)
    monkeypatch.setattr(hardening, 'docker_json', docker_json)
    return state


@pytest.mark.parametrize('identity', ['config_digest', 'manifest_digest'])
def test_runtime_uses_verified_id_checks_actual_health_transition_and_cleans(tmp_path, runtime, identity):
    runtime.candidate['docker_image_id'] = runtime.candidate[identity]
    report = hardening.verify_runtime(runtime.source['reference'], runtime.candidate['reference'], tmp_path)
    assert report['complete'] and report['cleanup_complete']
    assert all(report['checks'][name] is True for name in hardening.REQUIRED_CHECKS)
    run = next(call for call in runtime.calls if call[0] == 'run')
    assert run[-1] == runtime.candidate[identity] == report['execution_image']
    assert run[-1] not in (runtime.source['reference'], runtime.candidate['reference'])
    assert run[run.index('--network') + 1] == 'none'
    assert '--read-only' in run and run[run.index('--cap-drop') + 1] == 'ALL'
    assert run[run.index('--security-opt') + 1] == 'no-new-privileges'
    assert report['runtime_details']['unhealthy']['Status'] == 'unhealthy'
    assert report['runtime_details']['recovered']['Status'] == 'healthy'
    assert runtime.calls[-1][:2] == ['rm', '--force']
    assert json.loads((tmp_path / 'hardening-runtime.json').read_text()) == report


@pytest.mark.parametrize('failure', ['mismatch', 'root', 'recipe_mismatch', 'cleanup_failure'])
def test_failed_runtime_cannot_produce_success_receipt_and_always_cleans(tmp_path, runtime, failure):
    setattr(runtime, failure, True)
    with pytest.raises(RuntimeError):
        hardening.verify_runtime(runtime.source['reference'], runtime.candidate['reference'], tmp_path)
    report = json.loads((tmp_path / 'hardening-runtime.json').read_text())
    assert report['complete'] is False
    assert runtime.calls[-1][:2] == ['rm', '--force']


def test_outage_failure_resumes_server_before_cleanup(tmp_path, runtime, monkeypatch):
    def wait(name, expected, **kwargs):
        if expected == 'unhealthy':
            raise RuntimeError('Healthcheck incorrectly continued reporting healthy')
        return {'Status': expected}
    monkeypatch.setattr(hardening, 'wait_health', wait)
    with pytest.raises(RuntimeError, match='continued reporting healthy'):
        hardening.verify_runtime(runtime.source['reference'], runtime.candidate['reference'], tmp_path)
    assert 'kill -CONT' in runtime.calls[-2][-1]
    assert runtime.calls[-1][:2] == ['rm', '--force']
    assert json.loads((tmp_path / 'hardening-runtime.json').read_text())['complete'] is False


def test_existing_runtime_evidence_is_never_replaced(tmp_path, runtime):
    evidence = tmp_path / 'hardening-runtime.json'
    evidence.write_text('retained')
    with pytest.raises(RuntimeError, match='fresh runtime workspace'):
        hardening.verify_runtime(runtime.source['reference'], runtime.candidate['reference'], tmp_path)
    assert evidence.read_text() == 'retained' and not runtime.calls


def test_saved_config_must_match_published_identity(tmp_path, monkeypatch):
    raw = json.dumps({'config': {'User': '101:101'}}).encode()
    source = 'registry.example/nginx@sha256:' + 'a' * 64
    config_digest = hardening.digest(raw)

    def docker_json(arguments):
        if arguments[:2] == ['manifest', 'inspect']:
            return {'config': {'digest': config_digest}, 'layers': []}
        return [{'Id': config_digest}]

    def command(arguments, **kwargs):
        if arguments[:2] == ['image', 'save']:
            with tarfile.open(arguments[3], 'w') as archive:
                for name, value in [('manifest.json', b'[{"Config":"config.json"}]'),
                                    ('config.json', raw + b' ' )]:
                    info = tarfile.TarInfo(name)
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
        return SimpleNamespace(stdout=b'', returncode=0)

    monkeypatch.setattr(hardening, 'command', command)
    monkeypatch.setattr(hardening, 'docker_json', docker_json)
    with pytest.raises(RuntimeError, match='differs from the published configuration'):
        hardening.image_evidence(source, tmp_path)


def offline_bundle(folder, *, compressed=False, decompressed_export=False, change=None,
                   blob_paths=False, descriptor_change=None):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w') as archive:
        info = tarfile.TarInfo('example')
        info.size = 5
        archive.addfile(info, io.BytesIO(b'hello'))
    layer = content.getvalue()
    blob = gzip.compress(layer, mtime=0) if compressed else layer
    config = {'architecture': 'amd64', 'os': 'linux', 'config': {'User': '101:101'},
              'rootfs': {'type': 'layers', 'diff_ids': [hardening.digest(layer)]}}
    config_bytes = json.dumps(config, sort_keys=True).encode()
    manifest = {'schemaVersion': 2,
        'config': {'digest': hardening.digest(config_bytes), 'size': len(config_bytes)},
        'layers': [{'digest': hardening.digest(blob), 'size': len(blob),
            'mediaType': 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if compressed else '')}]}
    if descriptor_change:
        manifest['layers'][0].update(descriptor_change)
    raw = json.dumps(manifest, sort_keys=True).encode()
    reference = 'internal.registry.invalid/nginx@' + hardening.digest(raw)
    (folder / 'source-manifest.json').write_bytes(raw + (b'\n' if change == 'manifest' else b''))
    exported = layer if decompressed_export else blob
    if change == 'layer':
        exported += b'tampering'
    elif change == 'compressed':
        exported = gzip.compress(layer, mtime=1)
    if change == 'config':
        config_bytes += b'\n'
    config_path = 'blobs/sha256/' + hardening.digest(config_bytes)[7:] if blob_paths else 'config.json'
    layer_path = 'blobs/sha256/' + hardening.digest(exported)[7:] if blob_paths else 'layer.tar'
    entries = [{'Config': config_path, 'Layers': [layer_path],
                'RepoTags': None if blob_paths else ['untrusted:tag']}]
    with tarfile.open(folder / 'source.tar', 'w') as archive:
        for name, value in [('manifest.json', json.dumps(entries).encode()),
                            (config_path, config_bytes), (layer_path, exported)]:
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return reference, manifest, config


@pytest.mark.parametrize('compressed,decompressed_export,manifest_id,blob_paths', [
    (False, False, False, False), (True, False, True, False),
    (True, True, False, False), (True, False, True, True),
])
def test_offline_bundle_binds_original_bytes_and_runs_no_registry_requests(
        tmp_path, monkeypatch, compressed, decompressed_export, manifest_id, blob_paths):
    reference, manifest, config = offline_bundle(tmp_path,
        compressed=compressed, decompressed_export=decompressed_export, blob_paths=blob_paths)
    config_id, root_id = manifest['config']['digest'], reference.rsplit('@', 1)[1]
    calls = []

    def command(arguments, **kwargs):
        calls.append(arguments)
        if arguments[:1] == ['load']:
            return SimpleNamespace(returncode=0, stdout=b'Loaded image: untrusted:tag')
        assert arguments[:2] == ['image', 'inspect']
        assert arguments[2] in (config_id, root_id)
        if manifest_id and arguments[2] == config_id:
            return SimpleNamespace(returncode=1, stdout=b'')
        return SimpleNamespace(returncode=0, stdout=json.dumps([{
            'Id': root_id if manifest_id else config_id, 'RootFS': {'Layers': config['rootfs']['diff_ids']}}]).encode())

    monkeypatch.setattr(hardening, 'command', command)
    evidence = hardening.offline_image_evidence(reference, tmp_path, 'source')
    assert evidence['manifest'] == manifest and evidence['config'] == config
    assert evidence['docker_image_id'] == (root_id if manifest_id else config_id)
    assert evidence['offline_input']['manifest_digest'] == root_id
    assert evidence['offline_input']['archive_digest'] == hardening.digest((tmp_path / 'source.tar').read_bytes())
    assert evidence['offline_input']['layers'][0]['exact_published_blob'] is not decompressed_export
    assert calls[0] == ['load', '--input', str(tmp_path / 'source.tar')]


@pytest.mark.parametrize('change,message', [
    ('manifest', 'raw manifest'), ('config', 'Offline configuration'),
    ('layer', 'Offline filesystem layer'), ('compressed', 'Offline compressed layer'),
])
def test_tampered_offline_bundle_is_rejected_before_loading(tmp_path, monkeypatch, change, message):
    reference, _, _ = offline_bundle(tmp_path, compressed=change == 'compressed', change=change)
    monkeypatch.setattr(hardening, 'command', lambda *a, **k: pytest.fail('Tampered bundle must never load'))
    with pytest.raises(RuntimeError, match=message):
        hardening.offline_image_evidence(reference, tmp_path, 'source')


@pytest.mark.parametrize('compressed,descriptor_change', [
    (False, {'digest': 'sha256:' + 'f' * 64}),
    (False, {'size': 1}),
    (True, {'mediaType': 'application/vnd.oci.image.layer.v1.tar'}),
    (False, {'mediaType': 'unknown'}),
])
def test_offline_layers_must_match_published_descriptors(tmp_path, monkeypatch, compressed, descriptor_change):
    reference, _, _ = offline_bundle(tmp_path, compressed=compressed,
                                     descriptor_change=descriptor_change)
    monkeypatch.setattr(hardening, 'command', lambda *a, **k: pytest.fail('Invalid layer must never load'))
    with pytest.raises(RuntimeError, match='Offline .*layer'):
        hardening.offline_image_evidence(reference, tmp_path, 'source')


@pytest.mark.parametrize('descriptor_change', [
    {'digest': None}, {'digest': 'sha256:invalid'}, {'digest': 1},
    {'size': -1}, {'size': 0}, {'size': '123'}, {'size': 123.0}, {'size': True},
])
def test_decompressed_offline_export_rejects_invalid_published_descriptors(
        tmp_path, monkeypatch, descriptor_change):
    reference, _, _ = offline_bundle(tmp_path, compressed=True, decompressed_export=True,
                                     descriptor_change=descriptor_change)
    monkeypatch.setattr(hardening, 'command', lambda *a, **k: pytest.fail('Invalid descriptor must never load'))
    with pytest.raises(RuntimeError, match='valid digest and positive integer size'):
        hardening.offline_image_evidence(reference, tmp_path, 'source')


def test_decompressed_offline_export_rejects_gzip_descriptor_for_uncompressed_content(tmp_path, monkeypatch):
    _, _, config = offline_bundle(tmp_path, compressed=True, decompressed_export=True)
    reference, _, _ = offline_bundle(tmp_path, compressed=True, decompressed_export=True,
        descriptor_change={'digest': config['rootfs']['diff_ids'][0]})
    monkeypatch.setattr(hardening, 'command', lambda *a, **k: pytest.fail('Invalid encoding must never load'))
    with pytest.raises(RuntimeError, match='gzip layer descriptor identifies uncompressed content'):
        hardening.offline_image_evidence(reference, tmp_path, 'source')


@pytest.mark.parametrize('change,message', [('identity', 'Docker identity'), ('layers', 'Docker filesystem')])
def test_stale_loaded_identity_or_filesystem_cannot_be_accepted(tmp_path, monkeypatch, change, message):
    reference, manifest, config = offline_bundle(tmp_path)
    image = {'Id': manifest['config']['digest'], 'RootFS': {'Layers': config['rootfs']['diff_ids']}}
    if change == 'identity':
        image['Id'] = 'sha256:' + 'f' * 64
    else:
        image['RootFS']['Layers'] = ['sha256:' + 'f' * 64]
    monkeypatch.setattr(hardening, 'command', lambda arguments, **kwargs:
        SimpleNamespace(returncode=0, stdout=json.dumps([image]).encode()))
    with pytest.raises(RuntimeError, match=message):
        hardening.offline_image_evidence(reference, tmp_path, 'source')


def test_offline_runtime_uses_the_same_restrictions_and_receipt_checks(tmp_path, runtime, monkeypatch):
    roles = []

    def offline(reference, folder, role):
        roles.append(role)
        evidence = deepcopy(runtime.source if role == 'source' else runtime.candidate)
        evidence['offline_input'] = {'manifest_digest': evidence['manifest_digest']}
        return evidence

    monkeypatch.setattr(hardening, 'offline_image_evidence', offline)
    monkeypatch.setattr(hardening, 'image_evidence', lambda *a: pytest.fail('Offline mode must not pull'))
    report = hardening.verify_runtime(runtime.source['reference'], runtime.candidate['reference'],
                                     tmp_path, offline_input=tmp_path / 'inputs')
    assert roles == ['source', 'hardened']
    assert report['complete'] and report['offline_input']['source']['manifest_digest'] == runtime.source['manifest_digest']
    run = next(call for call in runtime.calls if call[0] == 'run')
    assert '--memory' in run and '--cpus' in run and '--read-only' in run and '--cap-drop' in run


def test_failed_container_start_keeps_diagnostics_and_attempts_cleanup(tmp_path, runtime, monkeypatch):
    original = hardening.command

    def command(arguments, **kwargs):
        if arguments[0] == 'run':
            raise subprocess.CalledProcessError(125, ['docker', *arguments],
                output=b'starting', stderr=b'cannot enter cgroupv2: domain controllers in threaded mode')
        return original(arguments, **kwargs)

    monkeypatch.setattr(hardening, 'command', command)
    with pytest.raises(subprocess.CalledProcessError):
        hardening.verify_runtime(runtime.source['reference'], runtime.candidate['reference'], tmp_path)
    report = json.loads((tmp_path / 'hardening-runtime.json').read_text())
    assert report['complete'] is False and report['cleanup_complete'] is True
    assert 'domain controllers' in report['error_detail']['stderr']
    assert report['error_detail']['stdout'] == 'starting'
    assert runtime.calls[-1][:2] == ['rm', '--force']


def test_docker_error_diagnostics_are_bounded():
    error = subprocess.TimeoutExpired(['docker', 'inspect'], 1, stderr=b'x' * 20000)
    assert len(hardening.error_detail(error)['stderr']) == 8192
