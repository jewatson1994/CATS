import json
from contextlib import contextmanager
import pytest
from app import artifact_image_validation as module
from app import cyber_release_publication as publication, release_oci


@pytest.fixture
def binding(monkeypatch, tmp_path):
    path = tmp_path / 'bundle.zip'; path.write_bytes(b'actual-test-bundle')
    config = 'sha256:' + 'b' * 64
    raw = json.dumps({'config': {'digest': config}}).encode()
    digest = release_oci._digest(raw)
    manifest = {'service': {'id': 'one', 'version': '1'}, 'images': [{'digest': config, 'reference': 'runtime:one'}]}
    monkeypatch.setattr(module.deployment_bundle, 'validate_bundle', lambda *a, **kw: manifest)
    @contextmanager
    def environments(settings):
        yield {}, {}
    monkeypatch.setattr(publication, '_source_environments', environments)
    class Client:
        api = '/v2/image'
        def __init__(self, *a): pass
        def request(self, *a, **kw): return 200, {}, raw
    monkeypatch.setattr(release_oci, '_Client', Client)
    kwargs = dict(service={'id': 'one', 'version': '1'}, reference='registry.test/image@' + digest, digest=digest, settings={})
    return path, kwargs, manifest


def test_registry_manifest_binds_runtime_config_not_bundle_digest(binding):
    path, kwargs, manifest = binding
    result = module.bind_bundle(path, **kwargs)
    assert result['manifest_digest'] == kwargs['digest']
    assert result['config_digest'] == manifest['images'][0]['digest']
    assert result['bundle_digest'] != result['manifest_digest']


@pytest.mark.parametrize('change', ['service', 'version', 'config', 'extra_image', 'manifest', 'mutable'])
def test_wrong_runtime_or_identity_rejected(binding, change):
    path, kwargs, manifest = binding
    if change == 'service': manifest['service']['id'] = 'other'
    if change == 'version': manifest['service']['version'] = '2'
    if change == 'config': manifest['images'][0]['digest'] = 'sha256:' + 'c' * 64
    if change == 'extra_image': manifest['images'].append(dict(manifest['images'][0]))
    if change == 'manifest':
        kwargs['digest'] = 'sha256:' + 'd' * 64
        kwargs['reference'] = 'registry.test/image@' + kwargs['digest']
    if change == 'mutable': kwargs['reference'] = 'registry.test/image:latest'
    with pytest.raises(ValueError): module.bind_bundle(path, **kwargs)


@pytest.mark.parametrize('case,code', [('csrf',403), ('hidden',404), ('permission',403), ('inactive',403)])
def test_route_requires_scoped_authorization(monkeypatch, case, code):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from app import artifact_catalog_routes as routes
    service = SimpleNamespace(id=42, lifecycle_status='retired' if case == 'inactive' else 'active')
    db = SimpleNamespace(scalar=lambda query: service)
    auth = SimpleNamespace(csrf_token='expected', has=lambda permission, identity:
        identity == 42 and not (case == 'hidden' or case == 'permission' and permission == 'remediation.execute'))
    request = SimpleNamespace(headers={'X-CSRF-Token': 'wrong' if case == 'csrf' else 'expected'})
    with pytest.raises(HTTPException) as error:
        routes.image_validation('one',1,request,1,'registry/image@sha256:'+'a'*64,None,db,auth)
    assert error.value.status_code == code
