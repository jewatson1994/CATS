"""Configured trust reaches replica discovery, proxy pulls and connection checks."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import sessionmaker

from app import oci_proxy, oci_transport, replica_sync, service_oci
from app.models import PortalSetting
from app.oci_models import OCIRepository, OCIUpstream
from test_oci_admin import context, post
from test_registry_ca_inheritance import authorities
from test_replica_import import replica_import


@pytest.mark.parametrize('custom', [False, True])
def test_replica_sync_inherits_current_global_ca_and_keeps_registry_additions(
        replica_import, authorities, monkeypatch, custom):
    f = replica_import
    global_ca, custom_ca = authorities['configured'][0], authorities['custom'][0]
    setting = PortalSetting(key='trusted_ca_certificates', value=json.dumps([{'pem': global_ca}]))
    f.db.add(setting)
    upstream = f.db.get(OCIUpstream, f.source.upstream_id)
    upstream.ca_pem = custom_ca if custom else ''
    f.db.commit()
    sessions = sessionmaker(f.db.get_bind(), expire_on_commit=False)
    ctx = SimpleNamespace(session_factory=sessions, job=SimpleNamespace(correlation_id='ca-test'),
                          checkpoint=lambda *args: None, stage=lambda *args: None,
                          _owned=lambda db: None)
    bundles, contents = [], []
    def discover(host, repository, env):
        bundle = Path(env['SSL_CERT_FILE'])
        bundles.append(bundle)
        contents.append(bundle.read_text())
        return iter(())
    monkeypatch.setattr(replica_sync.portable_release, 'discover_release_references', discover)
    environment_before = dict(os.environ)
    replica_sync.sync(ctx, {'source_id': f.source.id})
    assert global_ca in contents[0]
    assert (custom_ca in contents[0]) is custom
    assert dict(os.environ) == environment_before
    assert not bundles[0].exists()

    # Changes are picked up on the next sync, not retained in a process cache.
    setting.value = json.dumps([{'pem': authorities['system'][0]}])
    f.db.commit()
    replica_sync.sync(ctx, {'source_id': f.source.id})
    assert authorities['system'][0] in contents[1] and global_ca not in contents[1]
    assert (custom_ca in contents[1]) is custom
    assert not bundles[1].exists()


def test_proxy_uses_global_trust_from_its_current_session(replica_import, authorities, monkeypatch):
    f = replica_import
    configured = [{'pem': authorities['configured'][0]}]
    f.db.add(PortalSetting(key='trusted_ca_certificates', value=json.dumps(configured)))
    upstream = f.db.get(OCIUpstream, f.source.upstream_id)
    upstream.ca_pem = authorities['custom'][0]
    mapping = OCIRepository(public_repository='approved/image', upstream_repository='team/image',
                            service_id=51, upstream_id=upstream.id)
    f.db.add(mapping)
    f.db.commit()
    monkeypatch.setattr(oci_proxy, 'RegistryClient', lambda config: config)
    result = oci_proxy.client(mapping)
    assert result['trusted_ca_certificates'] == configured
    assert result['ca_pem'] == authorities['custom'][0]
    assert upstream.ca_pem == authorities['custom'][0]


def test_registry_connection_check_inherits_trust(context, authorities, monkeypatch):
    client, db, _ = context
    configured = [{'pem': authorities['configured'][0]}]
    db.add(PortalSetting(key='trusted_ca_certificates', value=json.dumps(configured)))
    db.commit()
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example',
                                             ca_pem=authorities['custom'][0])).json()
    mapping = post(client, 'repositories', dict(public_repository='project/image', service_id=1,
        upstream_id=upstream['id'], upstream_repository='team/image')).json()
    configurations = []
    class Client:
        def __init__(self, configuration):
            configurations.append(configuration)
        def fetch_manifest(self, repository, reference):
            return b'{}', 'application/json', 'sha256:' + 'a' * 64
    monkeypatch.setattr(oci_transport, 'RegistryClient', Client)
    assert post(client, f"repositories/{mapping['id']}/test", {}).json()['ok']
    assert configurations[0]['trusted_ca_certificates'] == configured
    assert configurations[0]['ca_pem'] == authorities['custom'][0]


def test_service_connection_check_inherits_trust(replica_import, authorities, monkeypatch):
    f = replica_import
    configured = [{'pem': authorities['configured'][0]}]
    f.db.add(PortalSetting(key='trusted_ca_certificates', value=json.dumps(configured)))
    destination = service_oci.ServiceOCIDestination(service_id=51, name='Registry',
        endpoint='https://registry.example', ca_pem=authorities['custom'][0])
    f.db.add(destination)
    f.db.commit()
    calls = []
    def check(value, certificates):
        calls.append((value, certificates))
        return {'tls': 'PASSED'}
    monkeypatch.setattr(service_oci, 'test_connection', check)
    monkeypatch.setattr(service_oci, '_csrf', lambda *args: None)
    monkeypatch.setattr(service_oci, 'record_audit', lambda *args, **kwargs: None)
    assert service_oci.connection(None, 'unrelated', destination.id, f.db, None)['tls'] == 'PASSED'
    assert calls[0][1] == configured
    assert calls[0][0]['ca_pem'] == authorities['custom'][0]
