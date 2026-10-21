"""Network configuration reaches retrieval only, never uploaded job options."""
import json
import sys
from types import SimpleNamespace
import pytest
from app.discovery_worker import configured_artifact_resolver
from app.durable_jobs import JobError

@pytest.fixture
def configuration(monkeypatch):
    for name in ('CATS_DISCOVERY_ARTIFACT_MANIFEST', 'CATS_DISCOVERY_HTTPS_ARTIFACT_MANIFEST',
                 'CATS_DISCOVERY_ARTIFACT_CA_FILE', 'CATS_DISCOVERY_HELM_SOURCES',
                 'CATS_DISCOVERY_HELM_ORIGINS', 'CATS_DISCOVERY_HELM_TOKEN_ORIGINS'):
        monkeypatch.delenv(name, raising=False)
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
