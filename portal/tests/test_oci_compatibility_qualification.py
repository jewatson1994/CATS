"""A registry error cannot stand in for a disconnected source."""
import errno
import json
import socket
import ssl
from urllib.error import HTTPError, URLError

import pytest

from app.release_oci import _RegistryError
from oci_compatibility_qualification import require_source_transport_unavailable


class Source:
    base = 'https://publisher.test:5000'

    def __init__(self, failure=None):
        self.failure = failure

    def request(self, method, url):
        assert (method, url) == ('GET', self.base + '/v2/')
        if self.failure is not None:
            raise self.failure
        return 200, {}, b'{}'


@pytest.mark.parametrize(('code', 'label'), [
    (errno.ECONNREFUSED, 'connection_refused'),
    (errno.EHOSTUNREACH, 'host_unreachable'),
    (errno.ENETUNREACH, 'network_unreachable'),
])
@pytest.mark.parametrize('wrapped', [False, True])
def test_offline_probe_records_only_observed_transport_failure(code, label, wrapped):
    error = OSError(code, 'private connection details')
    result = require_source_transport_unavailable(Source(URLError(error) if wrapped else error))
    assert result == dict(transport_unavailable=True, reason=label)
    assert 'private' not in json.dumps(result)
    assert 'stopped' not in json.dumps(result)


@pytest.mark.parametrize('failure', [
    *[_RegistryError(status) for status in (401, 403, 500)],
    HTTPError(Source.base, 401, 'Unauthorized', {}, None),
    ssl.SSLCertVerificationError(1, 'certificate verify failed'),
    URLError(ssl.SSLCertVerificationError(1, 'certificate verify failed')),
    URLError(ssl.SSLError(1, 'TLS handshake failure')),
    URLError(ssl.SSLError(errno.ECONNREFUSED, 'TLS error with a network-like code')),
    URLError(socket.gaierror(socket.EAI_NONAME, 'unknown hostname')),
    URLError(TimeoutError('timed out')),
    URLError('unknown transport error'),
    ValueError('invalid source configuration'),
    RuntimeError('unexpected implementation failure'),
])
def test_offline_probe_rejects_http_auth_tls_dns_and_unrelated_errors(failure):
    with pytest.raises((AssertionError, ValueError, RuntimeError)):
        require_source_transport_unavailable(Source(failure))


def test_offline_probe_rejects_a_reachable_publisher():
    with pytest.raises(AssertionError, match='Publisher responded'):
        require_source_transport_unavailable(Source())
