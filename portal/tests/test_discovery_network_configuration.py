"""Network configuration reaches retrieval only, never uploaded job options."""
import hashlib
import json
import sys
from types import SimpleNamespace
import pytest
from app.discovery_artifacts import ArtifactResolutionError
from app.discovery_helm_network import HelmNetworkResolver
from app.discovery_worker import configured_artifact_resolver
from app.durable_jobs import JobError

@pytest.fixture
def clean_configuration(monkeypatch):
    for name in ('CATS_DISCOVERY_ARTIFACT_MANIFEST', 'CATS_DISCOVERY_HTTPS_ARTIFACT_MANIFEST',
                 'CATS_DISCOVERY_ARTIFACT_CA_FILE', 'CATS_DISCOVERY_HELM_SOURCES',
                 'CATS_DISCOVERY_HELM_ORIGINS', 'CATS_DISCOVERY_HELM_TOKEN_ORIGINS',
                 'HELM_ALLOW_NETWORK'):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def configuration(clean_configuration, monkeypatch):
    seen = {}
    class Network:
        def __init__(self, **kwargs):
            seen.update(kwargs)
        def resolve(self, *args):
            return args
    monkeypatch.setitem(sys.modules, 'app.discovery_helm_network', SimpleNamespace(HelmNetworkResolver=Network))
    return seen

def test_network_disabled_by_default(configuration, monkeypatch):
    monkeypatch.delenv('HELM_ALLOW_NETWORK', raising=False)
    assert configured_artifact_resolver() is None
    assert not configuration

def test_network_uses_current_saved_trust_and_auth(configuration, monkeypatch):
    monkeypatch.setenv('HELM_ALLOW_NETWORK', 'true')
    monkeypatch.setenv('CATS_DISCOVERY_HELM_SOURCES', '["https://charts.example"]')
    registries = [{'endpoint': 'https://registry.example', 'namespace': 'charts', 'password': 'encrypted'}]
    certificates = [{'pem': 'test'}]
    resolver = configured_artifact_resolver({'oci_registries': json.dumps(registries), 'trusted_ca_certificates': json.dumps(certificates)})
    assert configuration['oci_registries'] == registries
    assert configuration['trusted_ca_certificates'] == certificates
    assert configuration['allowed_sources'] == ['https://charts.example']
    assert resolver.resolve('helm', 'https://charts.example/a', '1.0') == ('helm', 'https://charts.example/a', '1.0')

def test_invalid_admin_sources_fail_closed(configuration, monkeypatch):
    monkeypatch.setenv('HELM_ALLOW_NETWORK', 'true')
    monkeypatch.setenv('CATS_DISCOVERY_HELM_SOURCES', '{bad')
    with pytest.raises(JobError, match='configuration is invalid'):
        configured_artifact_resolver()


@pytest.mark.parametrize('network_enabled', [None, 'false'])
def test_wildcard_sources_do_not_enable_network(clean_configuration, monkeypatch, network_enabled):
    monkeypatch.setenv('CATS_DISCOVERY_HELM_SOURCES', '["*"]')
    if network_enabled is not None:
        monkeypatch.setenv('HELM_ALLOW_NETWORK', network_enabled)

    def deny_initialization(*args, **kwargs):
        pytest.fail('Disabled Helm networking constructed its transport')

    monkeypatch.setattr(HelmNetworkResolver, '__init__', deny_initialization)
    assert configured_artifact_resolver() is None


def test_worker_wildcard_configuration_resolves_unlisted_source(clean_configuration, monkeypatch):
    monkeypatch.setenv('HELM_ALLOW_NETWORK', 'true')
    monkeypatch.setenv('CATS_DISCOVERY_HELM_SOURCES', '["*"]')
    archive = b'chart archive'
    digest = hashlib.sha256(archive).hexdigest()
    index = json.dumps({'entries': {'demo': [{'version': '1.2.3', 'digest': digest,
                                            'urls': ['demo.tgz']}]}}).encode()
    responses = {'https://unlisted.example/charts/index.yaml': index,
                 'https://unlisted.example/charts/demo.tgz': archive}
    calls = []

    def get(self, url, **kwargs):
        calls.append(url)
        return responses[url], {}

    monkeypatch.setattr(HelmNetworkResolver, '_get', get)
    resolver = configured_artifact_resolver()
    result = resolver.resolve('helm', 'https://unlisted.example/charts/demo', '1.2.3')
    assert result.data == archive
    assert result.sha256 == digest
    assert calls == list(responses)


def test_wildcard_network_never_retries_exact_mirror_checksum_failure(clean_configuration, monkeypatch, tmp_path):
    monkeypatch.setenv('HELM_ALLOW_NETWORK', 'true')
    monkeypatch.setenv('CATS_DISCOVERY_HELM_SOURCES', '["*"]')
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path / 'uploads'))
    reference = 'oci://unlisted.example/charts/demo'
    (tmp_path / 'chart.tgz').write_bytes(b'corrupt mirror archive')
    manifest = tmp_path / 'mirror.json'
    manifest.write_text(json.dumps({'version': 1, 'artifacts': [{
        'kind': 'helm', 'reference': reference, 'version': '1.2.3',
        'path': 'chart.tgz', 'sha256': '0' * 64}]}))
    monkeypatch.setenv('CATS_DISCOVERY_ARTIFACT_MANIFEST', str(manifest))

    def deny_network(*args, **kwargs):
        pytest.fail('Exact mirror checksum failure fell back to Helm networking')

    monkeypatch.setattr(HelmNetworkResolver, 'resolve', deny_network)
    resolver = configured_artifact_resolver()
    with pytest.raises(ArtifactResolutionError, match='^Artifact checksum verification failed\\.$'):
        resolver.resolve('helm', reference, '1.2.3')
