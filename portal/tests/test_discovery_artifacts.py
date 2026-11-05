import hashlib
from io import BytesIO
import json
from pathlib import Path
import socket
import zipfile

import pytest

from app import discovery_artifacts as artifacts
from app.helm_archives import extract_chart


def mirror(tmp_path, member='chart/Chart.yaml', content=b'name: example', **changes):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr(member, content)
    data = buffer.getvalue()
    (tmp_path / 'source.zip').write_bytes(data)
    entry = dict(kind='helm', reference='oci://registry.example/chart', version='1.0',
                 path='source.zip', sha256=hashlib.sha256(data).hexdigest())
    entry.update(changes)
    manifest = tmp_path / 'mirror.json'
    manifest.write_text(json.dumps({'version': 1, 'artifacts': [entry]}))
    return manifest, entry


@pytest.mark.parametrize('kind', ['helm', 'oci', 'git'])
def test_exact_offline_resolution_and_safe_stage(tmp_path, monkeypatch, kind):
    def deny(*args, **kwargs):
        pytest.fail('Offline resolution attempted network access')
    monkeypatch.setattr(socket, 'socket', deny)
    manifest, entry = mirror(tmp_path, kind=kind)
    original = manifest.read_bytes()
    resolver = artifacts.LocalArtifactResolver(manifest)
    result = resolver.resolve(kind, entry['reference'], entry['version'])
    staged = result.stage(tmp_path / 'scratch')
    assert (staged['root'] / 'chart/Chart.yaml').read_text() == 'name: example'
    assert staged['provenance']['sha256'] == entry['sha256']
    assert 'registry.example' not in str(staged['provenance'])
    assert str(tmp_path) not in repr(result)
    assert manifest.read_bytes() == original
    with pytest.raises(artifacts.ArtifactResolutionError, match='Exact artifact version'):
        resolver.resolve(kind, entry['reference'], 'latest')


@pytest.mark.parametrize('filename', ['demo.tgz', 'demo.tar.gz'])
@pytest.mark.parametrize('payload_type', [bytes, BytesIO])
def test_helm_packaged_chart_matches_scan_extraction(tmp_path, filename, payload_type):
    chart = Path(__file__).resolve().parents[2] / 'scanning-main/examples/helm-diagram-demo-1.0.0.tgz'
    data = chart.read_bytes()
    assert data[:2] == b'\x1f\x8b'
    assert data[3] & 0x04, 'The regression chart must retain its gzip FEXTRA header'

    scan_root = tmp_path / 'scan'
    extract_chart(data, filename, scan_root)
    scan_package = next(scan_root.iterdir())
    expected = {path.relative_to(scan_package).as_posix(): path.read_bytes()
                for path in scan_package.rglob('*') if path.is_file()}
    assert 'helm-diagram-demo/Chart.yaml' in expected

    digest = hashlib.sha256(data).hexdigest()
    artifact = artifacts.ResolvedArtifact(payload_type(data), filename, digest, 'helm', 'test')
    staged = artifact.stage(tmp_path / 'discovery')
    actual = {name: (staged['root'] / name).read_bytes() for name in staged['files']}
    assert actual == expected
    assert staged['provenance']['sha256'] == digest


@pytest.mark.parametrize('path', ['../source.zip', '/source.zip', 'C:/source.zip', r'..\source.zip'])
def test_mirror_path_traversal_rejected(tmp_path, path):
    manifest, _ = mirror(tmp_path, path=path)
    with pytest.raises(artifacts.ArtifactResolutionError, match='Unsafe'):
        artifacts.LocalArtifactResolver(manifest)


def test_checksum_mismatch_has_fixed_error(tmp_path):
    manifest, entry = mirror(tmp_path, sha256='0' * 64)
    with pytest.raises(artifacts.ArtifactResolutionError, match='^Artifact checksum verification failed.$'):
        artifacts.LocalArtifactResolver(manifest).resolve('helm', entry['reference'], '1.0')


@pytest.mark.parametrize('member', ['../escape', '/escape', r'..\escape'])
def test_archive_traversal_rejected_before_write(tmp_path, member):
    manifest, entry = mirror(tmp_path, member=member)
    result = artifacts.LocalArtifactResolver(manifest).resolve('helm', entry['reference'], '1.0')
    with pytest.raises(artifacts.ArtifactResolutionError, match='safely staged'):
        result.stage(tmp_path / 'scratch')
    assert not (tmp_path / 'escape').exists()


def test_manifest_and_artifact_bounds(tmp_path, monkeypatch):
    manifest, entry = mirror(tmp_path)
    monkeypatch.setattr(artifacts, 'MAX_MANIFEST', 10)
    with pytest.raises(artifacts.ArtifactResolutionError):
        artifacts.LocalArtifactResolver(manifest)
    monkeypatch.setattr(artifacts, 'MAX_MANIFEST', 1024 * 1024)
    resolver = artifacts.LocalArtifactResolver(manifest)
    monkeypatch.setenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', '10')
    with pytest.raises(artifacts.ArtifactResolutionError, match='size limits'):
        resolver.resolve('helm', entry['reference'], '1.0')


def test_decompressed_member_bound(tmp_path, monkeypatch):
    manifest, entry = mirror(tmp_path, content=b'x' * 100)
    result = artifacts.LocalArtifactResolver(manifest).resolve('helm', entry['reference'], '1.0')
    monkeypatch.setenv('CATS_DISCOVERY_MAX_FILE_BYTES', '10')
    with pytest.raises(artifacts.ArtifactResolutionError):
        result.stage(tmp_path / 'scratch')


@pytest.mark.parametrize('reference', ['https://user:password@example.com/chart', 'https://example.com/chart?token=secret'])
def test_credentials_not_supported(tmp_path, reference):
    manifest, _ = mirror(tmp_path, reference=reference)
    with pytest.raises(artifacts.ArtifactResolutionError) as error:
        artifacts.LocalArtifactResolver(manifest)
    assert 'password' not in str(error.value)
    assert 'secret' not in str(error.value)


def test_duplicate_identity_rejected(tmp_path):
    manifest, entry = mirror(tmp_path)
    manifest.write_text(json.dumps({'version': 1, 'artifacts': [entry, entry]}))
    with pytest.raises(artifacts.ArtifactResolutionError, match='Duplicate'):
        artifacts.LocalArtifactResolver(manifest)


def test_symlink_archive_rejected(tmp_path):
    manifest, _ = mirror(tmp_path)
    target = tmp_path / 'target.zip'
    (tmp_path / 'source.zip').rename(target)
    try:
        (tmp_path / 'source.zip').symlink_to(target)
    except OSError:
        pytest.skip('Symlink creation unavailable')
    with pytest.raises(artifacts.ArtifactResolutionError, match='Unsafe'):
        artifacts.LocalArtifactResolver(manifest)


def test_worker_mirror_requires_absolute_admin_path(tmp_path, monkeypatch):
    from app.discovery_worker import configured_artifact_resolver
    from app.durable_jobs import JobError
    monkeypatch.delenv('CATS_DISCOVERY_ARTIFACT_MANIFEST', raising=False)
    assert configured_artifact_resolver() is None
    monkeypatch.setenv('CATS_DISCOVERY_ARTIFACT_MANIFEST', 'uploaded/mirror.json')
    with pytest.raises(JobError):
        configured_artifact_resolver()
    manifest, _ = mirror(tmp_path)
    monkeypatch.setenv('CATS_DISCOVERY_ARTIFACT_MANIFEST', str(manifest))
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path))
    with pytest.raises(JobError):
        configured_artifact_resolver()
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path / 'uploads'))
    assert isinstance(configured_artifact_resolver(), artifacts.LocalArtifactResolver)


def test_artifact_ignores_legacy_compose_budgets(tmp_path, monkeypatch):
    manifest, entry = mirror(tmp_path, content=b'x' * 100)
    monkeypatch.setattr(artifacts.compose, 'MAX_TOTAL', 10)
    monkeypatch.setattr(artifacts.compose, 'MAX_FILE', 10)
    result = artifacts.LocalArtifactResolver(manifest).resolve('helm', entry['reference'], '1.0')
    assert not isinstance(result.payload, bytes)
    staged = result.stage(tmp_path / 'scratch')
    assert (staged['root'] / 'chart/Chart.yaml').stat().st_size == 100
