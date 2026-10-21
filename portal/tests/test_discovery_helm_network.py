import hashlib
import json
from io import BytesIO
from urllib.error import HTTPError

import pytest

from app import discovery_helm_network as network
from app.discovery_artifacts import ArtifactResolutionError


def test_https_index_exact_version_checksum(monkeypatch):
    resolver = network.HelmNetworkResolver(allowed_sources=['https://charts.example/repo'])
    archive = b'chart archive'
    digest = hashlib.sha256(archive).hexdigest()
    index = json.dumps({'entries': {'demo': [{'version': '1.2.3', 'digest': digest, 'urls': ['demo.tgz']}]}}).encode()
    calls = []
    def get(url, **kwargs):
        calls.append(url)
        return (index if url.endswith('index.yaml') else archive), {}
    monkeypatch.setattr(resolver, '_get', get)
    result = resolver.resolve('helm', 'https://charts.example/repo/demo', '1.2.3')
    assert result.data == archive
    assert result.sha256 == digest
    assert calls == ['https://charts.example/repo/index.yaml', 'https://charts.example/repo/demo.tgz']


@pytest.mark.parametrize('reference,version', [
    ('https://charts.example/repository/demo', '1.2.3'),
    ('https://charts.example/repo/../evil', '1.2.3'),
    ('https://charts.example/repo/demo', '*'),
    ('https://charts.example/repo/demo', '1.2.3?secret')])
def test_rejects_unapproved_or_nonexact_inputs(reference, version):
    resolver = network.HelmNetworkResolver(allowed_sources=['https://charts.example/repo'])
    with pytest.raises(ArtifactResolutionError):
        resolver.resolve('helm', reference, version)


def test_oci_layer_integrity(monkeypatch):
    resolver = network.HelmNetworkResolver(allowed_sources=['oci://registry.example/team'])
    archive = b'chart'
    manifest = json.dumps({'layers': [{'mediaType': network.CHART_LAYER,
        'digest': 'sha256:' + hashlib.sha256(archive).hexdigest(), 'size': len(archive)}]}).encode()
    def get(url, **kwargs):
        return (manifest if '/manifests/' in url else archive), {}
    monkeypatch.setattr(resolver, '_get', get)
    assert resolver.resolve('helm', 'oci://registry.example/team/demo', '1.2.3').data == archive
    archive = b'wrong'
    with pytest.raises(ArtifactResolutionError, match='checksum'):
        resolver.resolve('helm', 'oci://registry.example/team/demo', '1.2.3')


class Response(BytesIO):
    headers = {}


def test_redirect_strips_credentials_and_requires_approved_origin():
    resolver = network.HelmNetworkResolver()
    calls = []
    class Opener:
        def open(self, req, **kwargs):
            calls.append(req)
            if len(calls) == 1:
                raise HTTPError(req.full_url, 302, '', {'Location': 'https://cdn.example/chart'}, None)
            return Response(b'chart')
    resolver.opener = Opener()
    origins = {network._origin('https://registry.example'), network._origin('https://cdn.example')}
    data, _ = resolver._get('https://registry.example/chart', headers={'Authorization': 'secret'}, origins=origins)
    assert data == b'chart'
    assert calls[0].get_header('Authorization') == 'secret'
    assert calls[1].get_header('Authorization') is None
    calls.clear()
    with pytest.raises(ArtifactResolutionError, match='redirect'):
        resolver._get('https://registry.example/chart', origins={network._origin('https://registry.example')})


def test_bounded_transport():
    resolver = network.HelmNetworkResolver()
    class Opener:
        def open(self, *args, **kwargs):
            return Response(b'1234')
    resolver.opener = Opener()
    with pytest.raises(ArtifactResolutionError, match='size limit'):
        resolver._get('https://charts.example/archive', limit=3, origins={network._origin('https://charts.example')})


def test_unapproved_token_realm_never_requested(monkeypatch):
    resolver = network.HelmNetworkResolver(allowed_sources=['oci://registry.example/team'])
    calls = []
    def get(url, **kwargs):
        calls.append(url)
        raise HTTPError(url, 401, '', {'WWW-Authenticate': 'Bearer realm="https://evil.example/token"'}, None)
    monkeypatch.setattr(resolver, '_get', get)
    with pytest.raises(ArtifactResolutionError, match='token service origin'):
        resolver.resolve('helm', 'oci://registry.example/team/chart', '1.2.3')
    assert len(calls) == 1


def test_registry_auth_requires_credentials_mode_and_namespace(monkeypatch):
    from app import secrets
    decrypted = []
    def decrypt(value):
        decrypted.append(value)
        return 'password'
    monkeypatch.setattr(secrets, 'decrypt_secret', decrypt)
    resolver = network.HelmNetworkResolver(oci_registries=[
        {'endpoint': 'https://registry.example', 'namespace': 'team',
         'auth_mode': 'none', 'username': 'stale', 'password': 'stale'},
        {'endpoint': 'https://registry.example', 'namespace': 'private',
         'auth_mode': 'credentials', 'username': 'user', 'password': 'encrypted'}])
    assert decrypted == ['encrypted']
    assert len(resolver.credentials) == 1
    assert resolver.credentials[0][0] == 'oci://registry.example/private'
    with pytest.raises(ArtifactResolutionError, match='administrator-approved'):
        resolver.resolve('helm', 'oci://registry.example/private-other/chart', '1.2.3')


def test_proxy_disabled_and_custom_trust_is_additive(monkeypatch):
    loaded = []
    class Context:
        def load_verify_locations(self, **kwargs):
            loaded.append(kwargs)
    monkeypatch.setattr(network.ssl, 'create_default_context', lambda: Context())
    monkeypatch.setattr(network.request, 'HTTPSHandler', lambda **kwargs: network.request.BaseHandler())
    handlers = []
    monkeypatch.setattr(network.request, 'build_opener', lambda *args: handlers.extend(args))
    network.HelmNetworkResolver(ca_file='custom.pem', trusted_ca_certificates=[{'pem': '-----BEGIN CERTIFICATE-----\nexample'}])
    assert loaded[0] == {'cafile': 'custom.pem'}
    assert 'BEGIN CERTIFICATE' in loaded[1]['cadata']
    assert handlers[0].proxies == {}


def test_encoded_gitlab_project_identifier_keeps_scope(monkeypatch):
    source = 'https://gitlab.com/api/v4/projects/gitlab-org%2fcharts%2fai-gateway-helm-chart/packages/helm/devel'
    resolver = network.HelmNetworkResolver(allowed_sources=[source])
    archive = b'chart'
    index = json.dumps({'entries': {'demo': [{'version': '1.2.3',
        'digest': hashlib.sha256(archive).hexdigest(), 'urls': ['demo.tgz']}]}}).encode()
    calls = []
    def get(url, **kwargs):
        calls.append(url)
        return (index if url.endswith('index.yaml') else archive), {}
    monkeypatch.setattr(resolver, '_get', get)
    assert resolver.resolve('helm', source.replace('%2f', '%2F') + '/demo', '1.2.3').data == archive
    assert '%2F' in calls[0]
    assert not network._under(source.replace('%2f', '/') + '/demo', source)
    assert not network._under('https://registry.example/team%2fchart', 'https://registry.example/team')


@pytest.mark.parametrize('suffix', ['/%2e%2e/evil', '/safe%2f..%2fevil', '/%252e%252e/evil',
    '/%2e/chart', '/%5c..%5cevil', '/%00evil', '/%0aevil', '/%7fevil', '/%GG', '/%2', '/%3fquery'])
def test_encoded_traversal_and_ambiguous_paths_rejected(suffix):
    with pytest.raises(ArtifactResolutionError, match='Invalid Helm source'):
        network._url('https://charts.example/repo' + suffix)


def test_real_tls_requires_ca_and_checks_hostname(tmp_path):
    import datetime
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(pem)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'verified')
        def log_message(self, *args):
            pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f'https://localhost:{server.server_port}/chart'
        origins = {network._origin(url)}
        untrusted = network.HelmNetworkResolver(timeout=10)
        with pytest.raises(network.error.URLError):
            untrusted._get(url, origins=origins)
        trusted = network.HelmNetworkResolver(trusted_ca_certificates=[{'pem': pem.decode()}], timeout=10)
        assert trusted._get(url, origins=origins)[0] == b'verified'
        wrong_host = f'https://127.0.0.1:{server.server_port}/chart'
        with pytest.raises(network.error.URLError):
            trusted._get(wrong_host, origins={network._origin(wrong_host)})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
