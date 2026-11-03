import hashlib
from io import BytesIO
import json
import ssl
from urllib import error, request

import pytest

from app import discovery_gitlab as gitlab


HOST = 'https://gitlab.example:8443'
PROJECT = HOST + '/group/subgroup/repo'
SHA = '0123456789abcdef' * 2 + '01234567'
ZIP = b'PK\x03\x04' + b'x' * 100_000


class Response(BytesIO):
    status = 200

    def __init__(self, data, **headers):
        super().__init__(data)
        self.headers = headers


@pytest.fixture
def network(monkeypatch):
    monkeypatch.setenv('CATS_DISCOVERY_GITLAB_SOURCES', PROJECT)
    monkeypatch.delenv('CATS_DISCOVERY_GITLAB_CA_FILE', raising=False)
    monkeypatch.delenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', raising=False)
    calls, handlers, replies = [], [], []

    class Opener:
        def open(self, req, timeout):
            calls.append(req)
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

    def build(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr(request, 'build_opener', build)
    return calls, handlers, replies


@pytest.mark.parametrize(('ref', 'commit_path'), [
    ('release/1.0', '/commits/release%2F1.0?stats=false'),
    ('v2.0', '/commits/v2.0?stats=false'),
    (SHA, '/commits/' + SHA + '?stats=false'),
    ('', '/commits?per_page=1'),
])
def test_streams_zip_pinned_to_commit(network, ref, commit_path):
    calls, handlers, replies = network
    metadata = {'id': SHA}
    replies.extend([Response(json.dumps(metadata if ref else [metadata]).encode()), Response(ZIP)])
    output = BytesIO()
    assert gitlab.fetch_gitlab_archive(PROJECT + '.git/', ref, output, token='private') == (
        SHA, hashlib.sha256(ZIP).hexdigest())
    assert output.getvalue() == ZIP
    base = HOST + '/api/v4/projects/group%2Fsubgroup%2Frepo/repository'
    assert [req.full_url for req in calls] == [base + commit_path, base + '/archive.zip?sha=' + SHA]
    assert all(req.get_header('Private-token') == 'private' and 'Private-token' not in req.headers
               and req.get_header('Accept-encoding') == 'identity' for req in calls)
    tls = next(h._context for h in handlers if isinstance(h, request.HTTPSHandler))
    assert tls.verify_mode == ssl.CERT_REQUIRED and tls.check_hostname
    assert next(h.proxies for h in handlers if isinstance(h, request.ProxyHandler)) == {}
    redirect = next(h for h in handlers if isinstance(h, request.HTTPRedirectHandler))
    assert redirect.redirect_request(calls[-1], None, 302, '', {}, 'https://untrusted.example') is None


def test_explicit_approved_scope(monkeypatch):
    monkeypatch.delenv('CATS_DISCOVERY_GITLAB_SOURCES', raising=False)
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.validate_gitlab_project(PROJECT)
    assert exc.value.status_code == 403
    monkeypatch.setenv('CATS_DISCOVERY_GITLAB_SOURCES', json.dumps([PROJECT + '.git', 'https://GITLAB.COM:443/']))
    assert gitlab.validate_gitlab_project(PROJECT + '/') == PROJECT
    assert gitlab.validate_gitlab_project('https://gitlab.com/another/team/project.git') == 'https://gitlab.com/another/team/project'
    for url in (PROJECT + '2', PROJECT + '/child', PROJECT.replace(':8443', ''), 'https://gitlab.com.attacker.test/group/project'):
        with pytest.raises(gitlab.GitLabSourceError) as exc:
            gitlab.validate_gitlab_project(url)
        assert exc.value.status_code == 403
    monkeypatch.setenv('CATS_DISCOVERY_GITLAB_SOURCES', PROJECT + ',https://*.example')
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.validate_gitlab_project(PROJECT)
    assert exc.value.status_code == 503


@pytest.mark.parametrize('url', [
    'http://gitlab.com/org/proj', 'https://user:token@gitlab.com/org/proj',
    'https://gitlab.com/org/proj?token=x', 'https://gitlab.com/org/proj#', 'https://gitlab.com:70000/org/proj',
    'https://gitlab.com/org/proj%2Fother', 'https://gitlab.com/org/../proj', 'https://gitlab.com/org//proj',
    'https://gitlab.com/only-group', 'https://gitlab.com/org/proj/-/tree/master',
    'https://gitlab.com/org/proj.git.git', 'https://bad.test\\@gitlab.com/org/proj',
    'https://gitlab.com/org/\rproj',
])
def test_invalid_project_rejected_before_network(network, url):
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(url, '', BytesIO(), token='private')
    assert exc.value.status_code == 422 and not network[1]


@pytest.mark.parametrize('ref', ['a..b', '.', 'feature//one', 'x\r\nsecret', 'thing@{one}', '/main', 'tag.lock', '-foo'])
def test_invalid_revision_rejected_before_network(network, ref):
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(PROJECT, ref, BytesIO())
    assert exc.value.status_code == 422 and not network[1]


@pytest.mark.parametrize(('code', 'status'), [(302, 502), (404, 404), (401, 403), (429, 503), (500, 502)])
def test_upstream_failure_sanitized(network, code, status):
    calls, _, replies = network
    replies.append(error.HTTPError('https://secret', code, 'private error', {'Location': 'https://secrets'}, BytesIO(b'secret')))
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(PROJECT, '', BytesIO())
    assert len(calls) == 1 and calls[0].get_header('Private-token') is None
    assert exc.value.status_code == status and 'secret' not in str(exc.value)


@pytest.mark.parametrize('headers', [{}, {'Content-Length': str(len(ZIP))}])
def test_archive_budget(network, monkeypatch, headers):
    monkeypatch.setenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', '64')
    network[2].extend([Response(json.dumps({'id': SHA}).encode()), Response(ZIP, **headers)])
    out = BytesIO()
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(PROJECT, 'main', out)
    assert exc.value.status_code == 413 and not out.getvalue()


@pytest.mark.parametrize(('metadata', 'ref', 'status'), [
    (b'[]', '', 404), (b'{}', 'main', 502), (b'bad', 'main', 502),
    (b'{"id":"123"}', 'main', 502), (json.dumps({'id': '0' * 40}).encode(), SHA, 502),
    (b'x' * (1024 * 1024 + 1), 'main', 502),
], ids=['empty-default', 'no-id', 'invalid-json', 'short-id', 'wrong-id', 'oversized'])
def test_invalid_metadata_cannot_select_an_archive(network, metadata, ref, status):
    network[2].append(Response(metadata))
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(PROJECT, ref, BytesIO())
    assert len(network[0]) == 1 and exc.value.status_code == status


@pytest.mark.parametrize(('data', 'headers'), [
    (b'<html>', {}), (b'PK', {}), (ZIP, {'Content-Length': str(len(ZIP) + 1)}),
    (ZIP, {'Content-Length': 'invalid'}), (ZIP, {'Content-Encoding': 'gzip'}),
], ids=['html', 'truncated-signature', 'truncated-response', 'invalid-length', 'encoded-content'])
def test_rejects_unusable_archive_response(network, data, headers):
    network[2].extend([Response(json.dumps({'id': SHA}).encode()), Response(data, **headers)])
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(PROJECT, 'main', BytesIO())
    assert exc.value.status_code == 502


def test_additive_system_and_operator_ca_trust(network, monkeypatch):
    loaded = []

    class Context:
        def load_verify_locations(self, **kwargs):
            loaded.append(kwargs)

    monkeypatch.setenv('CATS_DISCOVERY_GITLAB_CA_FILE', '/certs/gitlab.pem')
    monkeypatch.setattr(ssl, 'create_default_context', Context)
    monkeypatch.setattr(request, 'HTTPSHandler', lambda **kwargs: request.BaseHandler())
    pem = '-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----'
    network[2].extend([Response(json.dumps({'id': SHA}).encode()), Response(ZIP)])
    gitlab.fetch_gitlab_archive(PROJECT, 'main', BytesIO(), trusted_ca_certificates=[{'pem': pem}])
    assert loaded == [{'cafile': '/certs/gitlab.pem'}, {'cadata': pem + '\n'}]


def test_lists_filtered_branches_and_tags_without_following_next_page(network):
    calls, _, replies = network
    branches = ['release/' + str(i) for i in range(51)]
    replies.extend([Response(json.dumps([{'name': name, 'commit': {'id': SHA}} for name in branches]).encode()),
                    Response(b'[{"name":"release/v1"}]')])
    assert gitlab.list_gitlab_refs(PROJECT, token='private', search='^release/') == {
        'branches': branches[:50], 'tags': ['release/v1'], 'truncated': True}
    api = HOST + '/api/v4/projects/group%2Fsubgroup%2Frepo/repository'
    assert [req.full_url for req in calls] == [
        api + '/' + kind + '?per_page=51&search=%5Erelease%2F' for kind in ('branches', 'tags')]
    assert all(req.get_header('Private-token') == 'private' for req in calls)


def test_lists_empty_refs_and_rejects_invalid_metadata(network):
    calls, _, replies = network
    replies.extend([Response(b'[]'), Response(b'[]'), Response(b'[{"name":"in\\nvalid"}]')])
    assert gitlab.list_gitlab_refs(PROJECT) == {'branches': [], 'tags': [], 'truncated': False}
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.list_gitlab_refs(PROJECT)
    assert len(calls) == 3 and exc.value.status_code == 502


@pytest.mark.parametrize('search', [None, 'invalid\nsearch', 'x' * 129])
def test_invalid_ref_search_cannot_make_a_request(network, search):
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.list_gitlab_refs(PROJECT, search=search)
    assert not network[0] and exc.value.status_code == 422


def test_same_named_branch_and_annotated_tag_pin_different_commits(network):
    calls, _, replies = network
    for kind, collection, sha in [('branch', 'branches', SHA), ('tag', 'tags', 'f' * 40)]:
        replies.extend([Response(json.dumps({'name': 'release/latest', 'commit': {'id': sha},
                                             'target': 'a' * 40}).encode()), Response(ZIP)])
        assert gitlab.fetch_gitlab_archive(PROJECT, 'release/latest', BytesIO(), ref_kind=kind)[0] == sha
        assert calls[-2].full_url.endswith('/' + collection + '/release%2Flatest')
        assert calls[-1].full_url.endswith('/archive.zip?sha=' + sha)


@pytest.mark.parametrize(('ref', 'kind'), [('', 'branch'), ('main', 'invalid')])
def test_invalid_ref_kind_rejected_before_network(network, ref, kind):
    with pytest.raises(gitlab.GitLabSourceError) as exc:
        gitlab.fetch_gitlab_archive(PROJECT, ref, BytesIO(), ref_kind=kind)
    assert not network[0] and exc.value.status_code == 422


def test_private_gitlab_tag_over_tls(tmp_path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    from zipfile import ZipFile
    from cryptography.fernet import Fernet
    from app.managed_validator_pki import create_identity

    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.delenv('CATS_DISCOVERY_GITLAB_CA_FILE', raising=False)
    monkeypatch.delenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', raising=False)
    identity = create_identity('test-gitlab', '127.0.0.1', 'https://127.0.0.1')['deployment']
    cert, key = tmp_path / 'server.crt', tmp_path / 'server.key'
    cert.write_text(identity['validator_certificate'])
    key.write_text(identity['validator_key'])
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    expected = BytesIO()
    with ZipFile(expected, 'w') as archive:
        archive.writestr('release/compose.yaml', 'services: {}')
    api = '/api/v4/projects/team%2Fprivate/repository'
    commit_path = api + '/tags/v1.2.3'
    archive_path = api + '/archive.zip?sha=' + SHA
    responses = {commit_path: json.dumps({'name': 'v1.2.3', 'commit': {'id': SHA}}).encode(),
                 archive_path: expected.getvalue()}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.headers.get('PRIVATE-TOKEN') != 'test-project-token':
                return self.send_error(401)
            if self.path not in responses:
                return self.send_error(404)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(responses[self.path])

        def log_message(self, *args):
            pass

    with HTTPServer(('127.0.0.1', 0), Handler) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        project = f'https://127.0.0.1:{server.server_port}/team/private'
        monkeypatch.setenv('CATS_DISCOVERY_GITLAB_SOURCES', project)
        trusted = [{'pem': identity['client_ca']}]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = BytesIO()
            with pytest.raises(gitlab.GitLabSourceError) as untrusted:
                gitlab.fetch_gitlab_archive(project, 'v1.2.3', result, token='test-project-token', ref_kind='tag')
            assert untrusted.value.status_code == 502 and not requests
            with pytest.raises(gitlab.GitLabSourceError) as unauthenticated:
                gitlab.fetch_gitlab_archive(project, 'v1.2.3', result, ref_kind='tag', trusted_ca_certificates=trusted)
            assert unauthenticated.value.status_code == 403, repr(unauthenticated.value.__context__)
            assert not result.getvalue()
            assert gitlab.fetch_gitlab_archive(project, 'v1.2.3', result, token='test-project-token', ref_kind='tag',
                trusted_ca_certificates=trusted) == (SHA, hashlib.sha256(expected.getvalue()).hexdigest())
            assert requests == [commit_path, commit_path, archive_path]
            assert result.getvalue() == expected.getvalue()
        finally:
            server.shutdown()
            thread.join(timeout=3)
