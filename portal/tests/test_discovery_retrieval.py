import hashlib
from io import BytesIO
import json
import ssl
from urllib import request

import pytest

from app import discovery_artifacts as a


def manifest(tmp_path, **changes):
    entry = dict(kind='helm', reference='oci://registry.example/chart', version='1.2.3',
                 url='https://mirror.example/chart.tgz', sha256=hashlib.sha256(b'archive').hexdigest())
    entry.update(changes)
    path = tmp_path / 'https.json'
    path.write_text(json.dumps(dict(version=2, allowed_origins=['https://mirror.example'], artifacts=[entry])))
    return path


class Response(BytesIO):
    status = 200
    headers = {}


class Opener:
    def __init__(self, data=b'archive'):
        self.data, self.calls = data, []
    def open(self, req, timeout):
        self.calls.append((req.full_url, timeout))
        return Response(self.data)


def test_exact_resolution_verified_cached_and_tls(tmp_path, monkeypatch):
    calls = []
    original = request.build_opener
    def capture(*handlers):
        calls.extend(handlers)
        return original(*handlers)
    monkeypatch.setattr(request, 'build_opener', capture)
    resolver = a.ApprovedHTTPSArtifactResolver(manifest(tmp_path))
    tls = next(h for h in calls if isinstance(h, request.HTTPSHandler))._context
    assert tls.verify_mode == ssl.CERT_REQUIRED and tls.check_hostname
    assert next(h for h in calls if isinstance(h, request.ProxyHandler)).proxies == {}
    resolver._opener = opener = Opener()
    result = resolver.resolve('helm', 'oci://registry.example/chart', '1.2.3')
    assert result.data == b'archive'
    assert result.provenance['source'] == 'admin-approved-https-mirror'
    assert resolver.resolve('helm', 'oci://registry.example/chart', '1.2.3') is result
    assert opener.calls == [('https://mirror.example/chart.tgz', 10)]
    with pytest.raises(a.ArtifactResolutionError, match='Exact artifact version'):
        resolver.resolve('helm', 'https://evil.example/chart', '1.2.3')
    assert len(opener.calls) == 1


@pytest.mark.parametrize('url', ['http://mirror.example/chart.tgz', 'https://evil.example/chart.tgz',
    'https://mirror.example.evil/chart.tgz', 'https://u:p@mirror.example/chart.tgz',
    'https://mirror.example/chart.tgz?token=secret', 'https://mirror.example/chart.tgz#fragment',
    'https://mirror.example:444/chart.tgz', 'https://mirror.example/chart.txt'])
def test_disallowed_urls(tmp_path, url):
    with pytest.raises(a.ArtifactResolutionError):
        a.ApprovedHTTPSArtifactResolver(manifest(tmp_path, url=url))


def test_bounds_checksum_and_deadline(tmp_path, monkeypatch):
    resolver = a.ApprovedHTTPSArtifactResolver(manifest(tmp_path))
    resolver._opener = Opener(b'wrong')
    with pytest.raises(a.ArtifactResolutionError, match='checksum'):
        resolver.resolve('helm', 'oci://registry.example/chart', '1.2.3')
    assert not resolver._cache
    monkeypatch.setenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', '3')
    with pytest.raises(a.ArtifactResolutionError, match='size limits'):
        resolver.resolve('helm', 'oci://registry.example/chart', '1.2.3')
    monkeypatch.delenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES')
    ticks = iter([0, 31])
    monkeypatch.setattr(a.time, 'monotonic', lambda: next(ticks))
    with pytest.raises(a.ArtifactResolutionError, match='time limit'):
        resolver.resolve('helm', 'oci://registry.example/chart', '1.2.3')


def test_redirect_denied():
    with pytest.raises(a.ArtifactResolutionError, match='redirects'):
        a._NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example')


def test_offline_worker_default_and_explicit_opt_in(tmp_path, monkeypatch):
    from app.discovery_worker import configured_artifact_resolver
    from app.durable_jobs import JobError
    monkeypatch.delenv('CATS_DISCOVERY_ARTIFACT_MANIFEST', raising=False)
    monkeypatch.delenv('CATS_DISCOVERY_HTTPS_ARTIFACT_MANIFEST', raising=False)
    monkeypatch.delenv('CATS_DISCOVERY_ARTIFACT_CA_FILE', raising=False)
    assert configured_artifact_resolver() is None
    path = manifest(tmp_path)
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path / 'uploads'))
    monkeypatch.setenv('CATS_DISCOVERY_HTTPS_ARTIFACT_MANIFEST', str(path))
    assert isinstance(configured_artifact_resolver(), a.ApprovedHTTPSArtifactResolver)
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path))
    with pytest.raises(JobError):
        configured_artifact_resolver()


def test_no_network_fallback_after_local_failure():
    class Local:
        _entries = {('helm', 'chart', '1'): True}
        def resolve(self, *args):
            raise a.ArtifactResolutionError('Artifact checksum verification failed.')
    class Remote:
        def resolve(self, *args):
            pytest.fail('Integrity failure must not trigger network fallback')
    with pytest.raises(a.ArtifactResolutionError, match='checksum'):
        a.ArtifactResolverChain(Local(), Remote()).resolve('helm', 'chart', '1')

def test_persistent_cache_reauthorizes_and_checks_integrity(tmp_path, monkeypatch):
    import base64
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x'*32).decode())
    path = manifest(tmp_path)
    cache = tmp_path / 'cache'
    first = a.ApprovedHTTPSArtifactResolver(path, cache_directory=cache)
    first._opener = Opener()
    first.resolve('helm', 'oci://registry.example/chart', '1.2.3')
    second = a.ApprovedHTTPSArtifactResolver(path, cache_directory=cache)
    second._opener = Opener(b'wrong')
    assert second.resolve('helm', 'oci://registry.example/chart', '1.2.3').data == b'archive'
    assert second.cache_hits == 1 and not second._opener.calls
    stored = next(cache.glob('*.artifact'))
    assert b'archive' not in stored.read_bytes()
    stored.write_bytes(b'corrupt')
    with pytest.raises(a.ArtifactResolutionError, match='checksum'):
        second.resolve('helm', 'oci://registry.example/chart', '1.2.3')
    path.write_text(json.dumps(dict(version=2, allowed_origins=['https://mirror.example'], artifacts=[])))
    revoked = a.ApprovedHTTPSArtifactResolver(path, cache_directory=cache)
    with pytest.raises(a.ArtifactResolutionError, match='Exact artifact'):
        revoked.resolve('helm', 'oci://registry.example/chart', '1.2.3')


def test_https_payload_is_file_backed_without_legacy_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(a.compose, 'MAX_TOTAL', 3)
    resolver = a.ApprovedHTTPSArtifactResolver(manifest(tmp_path))
    resolver._opener = Opener()
    result = resolver.resolve('helm', 'oci://registry.example/chart', '1.2.3')
    assert not isinstance(result.payload, bytes)
    assert result.data == b'archive'
