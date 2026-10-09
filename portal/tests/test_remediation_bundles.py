import io
import json
import hashlib
import tarfile
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from app import remediation_bundles as producer
from app.deployment_bundle import file_digest, validate_bundle
from test_deployment_bundle import docker_archive


def test_missing_dependencies_require_configured_trust(tmp_path):
    chart = tmp_path / 'app'
    chart.mkdir()
    (chart / 'Chart.yaml').write_text('name: app\nversion: 1.0.0\ndependencies:\n- name: child\n  version: 1.2.3\n  repository: https://private.test/charts\n')
    with pytest.raises(ValueError, match='not uniquely configured'):
        producer._dependencies(chart, tmp_path, 'helm', {})


def test_recursive_dependency_retrieval_exact_versions_and_tls(tmp_path, monkeypatch):
    chart = tmp_path / 'app'
    chart.mkdir()
    (chart / 'Chart.yaml').write_text('name: app\nversion: 1.0.0\ndependencies:\n- name: child\n  version: 1.2.3\n  repository: https://private.test/charts\n')
    ca = tmp_path / 'ca.pem'
    ca.write_text('configured test trust')
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        name = command[2]
        version = command[command.index('--version') + 1]
        destination = Path(command[command.index('--destination') + 1])
        text = f'name: {name}\nversion: {version}\n'
        if name == 'child':
            text += 'dependencies:\n- name: grandchild\n  version: 2.0.0\n  repository: https://private.test/charts\n'
        with tarfile.open(destination / f'{name}.tgz', 'w:gz') as archive:
            data = text.encode()
            member = tarfile.TarInfo(f'{name}/Chart.yaml')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        return SimpleNamespace(returncode=0, stdout='')
    monkeypatch.setattr(producer, '_run', run)
    inventory, evidence = producer._dependencies(chart, tmp_path, 'helm', {'helm_repositories': [{'url': 'https://private.test/charts', 'ca_file': str(ca)}]})
    assert {row['name'] for row in inventory} == {'child', 'grandchild'}
    assert len(evidence) == 2
    assert all('--ca-file' in command and '--insecure-skip-tls-verify' not in command for command in calls)
    assert [command[command.index('--version') + 1] for command in calls] == ['1.2.3', '2.0.0']


def test_skopeo_archive_streams_using_configured_trust_and_auth(tmp_path, monkeypatch):
    ca = tmp_path / 'ca.pem'
    ca.write_text('test trust')
    target = tmp_path / 'image.tar'
    calls = []
    monkeypatch.setattr(producer.shutil, 'which', lambda name: name)
    def run(command, **kwargs):
        calls.append(command)
        if command[1] == 'inspect':
            return SimpleNamespace(stdout=b'{"schemaVersion":2,"config":{}}')
        docker_archive(target, 'private.test/app:1')
    monkeypatch.setattr(producer, '_run', run)
    evidence = producer._acquire_image('private.test/app:1', target, tmp_path, {'image_registries': [{'endpoint': 'https://private.test', 'ca_file': str(ca), 'username': 'user', 'password': 'secret'}]})
    assert evidence['identityType'] == 'docker_config'
    assert evidence['archiveDigest'] == file_digest(target)
    assert '--tls-verify=true' in calls[0]
    assert '--src-tls-verify=true' in calls[1]
    assert 'secret' not in ' '.join(calls[1])
    assert calls[1][-1].startswith('docker-archive:')
    assert '@sha256:' in calls[1][-2]
    assert evidence['registryManifestDigest'].startswith('sha256:')
    assert json.loads((tmp_path / 'image-auth-image.json').read_text())['auths']['private.test']


def test_assembly_includes_unchanged_rendered_image_and_ordered_values(tmp_path, monkeypatch):
    job = tmp_path / 'job'
    job.mkdir()
    candidate = job / 'candidate.zip'
    with ZipFile(candidate, 'w') as archive:
        archive.writestr('candidate/helm/app/Chart.yaml', 'name: app\nversion: 1.0.0\n')
        archive.writestr('candidate/first.yaml', 'x: 1')
        archive.writestr('candidate/second.yaml', 'x: 2')
        archive.writestr('documentation/remediation/summary-of-changes.md', 'Auditable retained changes')
        archive.writestr('manifest.json', json.dumps({'values_files': ['first.yaml', 'second.yaml'], 'images': []}))
    record = SimpleNamespace(job_key='job', artifact_path=str(candidate), artifact_digest=file_digest(candidate),
                             service=SimpleNamespace(service_key='app'), source_execution_id=1, source_version_id=1)
    monkeypatch.setattr(producer.shutil, 'which', lambda name: name)
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: unchanged\n    image: private.test/unchanged:1\n')
    monkeypatch.setattr(producer, '_run', run)
    def acquire(reference, target, workspace, configuration):
        assert reference == 'private.test/unchanged:1'
        docker_archive(target, reference)
        return {'reference': reference, 'identityType': 'docker_config'}
    monkeypatch.setattr(producer, '_acquire_image', acquire)
    result, path = producer.assemble(record, tmp_path, 'attempt', 'offline-bundle', '2')
    manifest = validate_bundle(path)
    with ZipFile(path) as archive:
        assert archive.read('documentation/remediation/summary-of-changes.md') == b'Auditable retained changes'
    assert 'documentation/remediation/summary-of-changes.md' in manifest['files']
    assert manifest['requiredImages'] == ['private.test/unchanged:1']
    assert manifest['deployment']['valuesFiles'] == ['first.yaml', 'second.yaml']
    assert manifest['images'][0]['identityType'] == 'docker_config'
    assert result['materialized_digest'] == file_digest(path)
    assert commands[0][-3].endswith('first.yaml')
    assert commands[0][-1].endswith('second.yaml')
    assert result['artifact_identities'][0]['identity_type'] == 'bundle_sha256'
    assert result['artifact_identities'][1]['identity_type'] == 'source_tree_sha256'


def test_existing_configuration_auth_material_is_ephemeral_and_admin_only(tmp_path, monkeypatch):
    import app.secrets
    monkeypatch.setattr(app.secrets, 'decrypt_secret', lambda value: 'decoded-secret')
    settings = {'trusted_ca_certificates': json.dumps([{'pem': '-----BEGIN CERTIFICATE-----\nADMIN\n-----END CERTIFICATE-----'}]),
                'oci_registries': json.dumps([{'endpoint': 'https://private.test', 'namespace': 'charts',
                                               'username': 'saved-user', 'password': 'encrypted'}])}
    with producer.configured_material(settings, ['https://repository.test/charts']) as configuration:
        ca = Path(configuration['helm_ca_file'])
        auth = Path(configuration['image_auth_file'])
        assert 'ADMIN' in ca.read_text()
        assert 'certifi' not in ca.read_text()
        assert {row['url'] for row in configuration['helm_repositories']} == {'https://repository.test/charts', 'oci://private.test/charts'}
        assert json.loads(auth.read_text())['auths']['private.test']
        assert configuration['image_registries'][0]['password'] == 'decoded-secret'
    assert not auth.exists()
    assert not ca.exists()


@pytest.fixture
def release_candidate(tmp_path, monkeypatch):
    directory = tmp_path / 'job'
    directory.mkdir()
    candidate = directory / 'candidate.zip'
    with ZipFile(candidate, 'w') as archive:
        archive.writestr('candidate/helm/app/Chart.yaml', 'apiVersion: v2\nname: app\nversion: 1.0.0\n')
        archive.writestr('manifest.json', json.dumps({'values_files': [], 'images': []}))
    record = SimpleNamespace(job_key='job', artifact_path=str(candidate), artifact_digest=file_digest(candidate),
                             service=SimpleNamespace(service_key='app'), source_execution_id=1, source_version_id=1)
    reference = 'private.test/app@sha256:' + 'a' * 64
    rendered = 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    image: ' + reference + '\n'
    monkeypatch.setattr(producer.shutil, 'which', lambda name: name)
    monkeypatch.setattr(producer, '_run', lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=rendered))
    monkeypatch.setattr(producer, '_acquire_image', lambda ref, target, *args: {'identity': docker_archive(target, ref)})
    return record, reference, rendered


@pytest.mark.parametrize('bundle_type', ['standard-bundle', 'offline-bundle'])
def test_release_builder_receives_materialized_identities_and_files_are_inventory_bound(tmp_path, release_candidate, bundle_type):
    record, reference, rendered = release_candidate
    docs = tmp_path / 'documentation.zip'
    with ZipFile(docs, 'w') as archive:
        archive.writestr('Assets.csv', 'Name\napp\n')
    captured = []
    documentation = {'status': 'ready', 'sha256': file_digest(docs), 'signing': {'status': 'unsigned'}}

    def builder(artifacts):
        captured.extend(artifacts)
        release_manifest = tmp_path / 'release-manifest.json'
        release_manifest.write_text(json.dumps({'artifacts': artifacts, 'documentation': {'sha256': file_digest(docs)}}))
        return {'documentation.zip': docs, 'release-manifest.json': release_manifest}, documentation

    result, path = producer.assemble(record, tmp_path, 'release', bundle_type, '2', documentation_builder=builder)
    manifest = validate_bundle(path, expected_type=bundle_type, expected_digest=result['materialized_digest'])
    assert result['documentation'] == documentation
    assert captured[0] == result['artifact_identities'][1]
    assert captured[0]['digest'] == manifest['provenance']['embeddedDeployment']['digest']
    assert captured[1] == {'kind': 'rendered-manifests', 'reference': 'rendered.yaml',
                           'digest': 'sha256:' + hashlib.sha256(rendered.encode()).hexdigest(), 'identity_type': 'file_sha256'}
    assert captured[1]['digest'] == manifest['files']['rendered.yaml']['sha256']
    assert captured[-1] == {'kind': 'image', 'reference': reference, 'digest': 'sha256:' + 'a' * 64,
                            'identity_type': 'oci_manifest_digest'}
    embedded_images = [item for item in captured if item['kind'] == 'image-archive']
    assert len(embedded_images) == (1 if bundle_type == 'offline-bundle' else 0)
    for image in embedded_images:
        assert image['digest'] == manifest['files'][image['reference']]['sha256']
    assert manifest['files']['release/documentation.zip']['sha256'] == file_digest(docs)
    with ZipFile(path) as archive:
        assert archive.read('release/documentation.zip') == docs.read_bytes()
        assert json.loads(archive.read('release/release-manifest.json'))['artifacts'] == captured
        tampered = tmp_path / 'tampered.zip'
        with ZipFile(tampered, 'w') as altered:
            for name in archive.namelist():
                altered.writestr(name, b'changed documentation' if name == 'release/documentation.zip' else archive.read(name))
    with pytest.raises(ValueError, match='artifact integrity mismatch'):
        validate_bundle(tampered, expected_digest=result['materialized_digest'])
    with pytest.raises(ValueError, match='file integrity mismatch'):
        validate_bundle(tampered)


@pytest.mark.parametrize('name', ['../escape', '/escape', 'documentation.zip/../escape'])
def test_release_builder_rejects_unsafe_filenames(tmp_path, release_candidate, name):
    record, _, _ = release_candidate
    document = tmp_path / 'documentation.zip'
    document.write_bytes(b'documentation')
    with pytest.raises(ValueError, match='Unsafe bundle path'):
        producer.assemble(record, tmp_path, 'release', 'standard-bundle', '2',
                          documentation_builder=lambda artifacts: ({name: document}, {'status': 'ready'}))
    assert not (tmp_path / 'job' / 'delivery-release.zip').exists()


def test_release_builder_rejects_collision_with_candidate_sources(tmp_path, release_candidate):
    record, _, _ = release_candidate
    with ZipFile(record.artifact_path, 'a') as archive:
        archive.writestr('candidate/release/documentation.zip', 'preexisting')
    record.artifact_digest = file_digest(record.artifact_path)
    document = tmp_path / 'documentation.zip'
    document.write_bytes(b'documentation')
    with pytest.raises(ValueError, match='conflicts with bundle sources'):
        producer.assemble(record, tmp_path, 'release', 'standard-bundle', '2',
                          documentation_builder=lambda artifacts: ({'documentation.zip': document}, {'status': 'ready'}))
    assert not (tmp_path / 'job' / 'delivery-release.zip').exists()


def test_failed_release_builder_never_produces_final_bundle(tmp_path, release_candidate):
    record, _, _ = release_candidate
    def builder(artifacts):
        raise ValueError('Release signature verification failed')
    with pytest.raises(ValueError, match='signature verification failed'):
        producer.assemble(record, tmp_path, 'release', 'offline-bundle', '2', documentation_builder=builder)
    assert not (tmp_path / 'job' / 'delivery-release.zip').exists()
