"""All-source Discovery retrieves charts without broadening credential scope."""
import hashlib
import json
from io import BytesIO
from urllib.error import HTTPError

import pytest

from app import discovery_helm_network as network
from app.discovery_artifacts import ArtifactResolutionError


ARCHIVE = b'chart archive'
DIGEST = hashlib.sha256(ARCHIVE).hexdigest()


class Response(BytesIO):
    headers = {}


class Opener:
    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def open(self, req, **kwargs):
        self.calls.append(req)
        return Response(self.respond(req))


def index(download):
    return json.dumps({'entries': {'demo': [{
        'version': '1.2.3', 'digest': DIGEST, 'urls': [download],
    }]}}).encode()


@pytest.mark.parametrize('repository', [
    'https://charts.jetstack.io',
    'https://atlassian.github.io/data-center-helm-charts',
])
def test_wildcard_resolves_unlisted_repository_archive_and_signed_redirect(repository):
    resolver = network.HelmNetworkResolver(allowed_sources=['*'])

    def respond(req):
        if req.full_url == repository + '/index.yaml':
            return index('https://downloads.example/demo.tgz')
        if req.full_url == 'https://downloads.example/demo.tgz':
            raise HTTPError(req.full_url, 307, '', {
                'Location': 'https://storage.example/demo.tgz?signature=example',
            }, None)
        assert req.full_url == 'https://storage.example/demo.tgz?signature=example'
        return ARCHIVE

    resolver.opener = Opener(respond)
    artifact = resolver.resolve('helm', repository + '/demo', '1.2.3')
    assert artifact.data == ARCHIVE
    assert artifact.sha256 == DIGEST
    assert len(resolver.opener.calls) == 3


@pytest.mark.parametrize(('kind', 'reference', 'version'), [
    ('helm', 'http://charts.example/demo', '1.2.3'),
    ('helm', 'https://user:secret@charts.example/demo', '1.2.3'),
    ('helm', 'https://charts.example/repo/%2e%2e/demo', '1.2.3'),
    ('helm', 'https://charts.example/demo', '*'),
    ('helm', 'https://charts.example/demo', 'latest'),
    ('kustomize', 'https://charts.example/demo', '1.2.3'),
])
def test_wildcard_keeps_input_validation(kind, reference, version):
    resolver = network.HelmNetworkResolver(allowed_sources=['*'])
    resolver.opener = Opener(lambda req: pytest.fail('Invalid input reached the network'))
    with pytest.raises(ArtifactResolutionError):
        resolver.resolve(kind, reference, version)


@pytest.mark.parametrize('redirect', [False, True])
def test_wildcard_rejects_http_archives_and_redirects(redirect):
    resolver = network.HelmNetworkResolver(allowed_sources=['*'])

    def respond(req):
        if req.full_url.endswith('/index.yaml'):
            return index('https://cdn.example/demo.tgz' if redirect else 'http://cdn.example/demo.tgz')
        assert req.full_url == 'https://cdn.example/demo.tgz'
        raise HTTPError(req.full_url, 302, '', {'Location': 'http://cdn.example/demo.tgz'}, None)

    resolver.opener = Opener(respond)
    with pytest.raises(ArtifactResolutionError):
        resolver.resolve('helm', 'https://charts.example/demo', '1.2.3')
    assert all(req.full_url.startswith('https://') for req in resolver.opener.calls)


def test_wildcard_keeps_checksum_verification():
    resolver = network.HelmNetworkResolver(allowed_sources=['*'])
    resolver.opener = Opener(lambda req: index('demo.tgz') if req.full_url.endswith('/index.yaml') else b'tampered')
    with pytest.raises(ArtifactResolutionError, match='checksum verification failed'):
        resolver.resolve('helm', 'https://charts.example/demo', '1.2.3')


@pytest.mark.parametrize(('reference', 'realm', 'allow_token', 'registry_basic', 'token_basic'), [
    ('oci://registry.example/private/demo', 'https://registry.example/token', False, True, True),
    ('oci://registry.example/private/demo', 'https://auth.example/token', True, True, True),
    ('oci://registry.example/private/demo', 'https://auth.example/token', False, True, False),
    ('oci://registry.example/private-other/demo', 'https://registry.example/token', False, False, False),
    ('oci://other.example/private/demo', 'https://auth.example/token', False, False, False),
])
def test_wildcard_oci_tokens_and_registry_credentials_keep_scope(reference, realm, allow_token, registry_basic, token_basic):
    resolver = network.HelmNetworkResolver(allowed_sources=['*'],
        allowed_token_origins=[realm] if allow_token else [])
    resolver.credentials = [('oci://registry.example/private', 'Basic private-secret')]
    manifest = json.dumps({'layers': [{'mediaType': network.CHART_LAYER,
        'digest': 'sha256:' + DIGEST, 'size': len(ARCHIVE)}]}).encode()

    def respond(req):
        if req.full_url.startswith(realm + '?'):
            assert req.get_header('Authorization') == ('Basic private-secret' if token_basic else None)
            return b'{"token":"chart-token"}'
        if req.get_header('Authorization') != 'Bearer chart-token':
            assert req.get_header('Authorization') == ('Basic private-secret' if registry_basic else None)
            raise HTTPError(req.full_url, 401, '', {
                'WWW-Authenticate': f'Bearer realm="{realm}",service="registry"',
            }, None)
        return manifest if '/manifests/' in req.full_url else ARCHIVE

    resolver.opener = Opener(respond)
    assert resolver.resolve('helm', reference, '1.2.3').data == ARCHIVE
    assert len(resolver.opener.calls) == 4


@pytest.mark.parametrize('authorization', ['Basic private-secret', 'Bearer chart-token'])
def test_wildcard_cross_origin_redirect_strips_credentials(authorization):
    resolver = network.HelmNetworkResolver(allowed_sources=['*'])

    def respond(req):
        if req.full_url == 'https://registry.example/resource':
            assert req.get_header('Authorization') == authorization
            raise HTTPError(req.full_url, 302, '', {'Location': 'https://unlisted.example/resource'}, None)
        assert req.full_url == 'https://unlisted.example/resource'
        assert req.get_header('Authorization') is None
        return b'content'

    resolver.opener = Opener(respond)
    data, _ = resolver._get('https://registry.example/resource', headers={'Authorization': authorization})
    assert data == b'content'


def test_wildcard_redirects_remain_bounded():
    resolver = network.HelmNetworkResolver(allowed_sources=['*'])

    def respond(req):
        raise HTTPError(req.full_url, 302, '', {'Location': 'https://next.example/resource'}, None)

    resolver.opener = Opener(respond)
    with pytest.raises(ArtifactResolutionError, match='limits'):
        resolver._get('https://registry.example/resource')
    assert len(resolver.opener.calls) == 6
