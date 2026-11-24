"""Publisher outage probes must not resolve another Compose project's portal."""
import pytest

from harbor_nginx_qualification import publisher_portal_url
from nginx_acceptance_stack import replica_polling_service


def test_replica_polling_has_registry_trust_and_writable_evidence_without_a_listener():
    environment = {'DATABASE_URL': 'postgresql://cats@replica-db/cats', 'PGPASSWORD': 'test',
                   'CATS_MODE': 'replica', 'CATS_CONFIG_ENCRYPTION_KEY': 'test-key',
                   'REQUESTS_CA_BUNDLE': '/run/acceptance-tls/ca-bundle.crt'}
    portal = {'image': 'cats:test', 'entrypoint': [], 'ports': ['127.0.0.1:18897:8000'],
              'environment': {**environment, 'CATS_BOOTSTRAP_PASSWORD': 'portal-only'},
              'volumes': ['replica_evidence:/var/lib/cats', '/test/bundle:/run/acceptance-tls/ca-bundle.crt:ro'],
              'networks': {'default': {}, 'harbor': {}}, 'cap_drop': ['ALL'],
              'security_opt': ['no-new-privileges:true'], 'restart': 'no'}
    worker = replica_polling_service(portal)
    assert worker['command'] == ['python', '-m', 'app.polling_worker']
    assert worker['environment'] == {**environment, 'CATS_POLLING_VERIFY_DIR': '/var/cache/cats-polling/verify'}
    assert worker['volumes'] == [*portal['volumes'], '/var/cache/cats-polling']
    assert worker['read_only'] and worker['tmpfs'] == ['/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777']
    assert worker['depends_on'] == {'replica-portal': {'condition': 'service_healthy'}}
    assert 'ports' not in worker
    assert worker['healthcheck'] == {'disable': True}
    for key in ('image', 'entrypoint', 'networks', 'cap_drop', 'security_opt'):
        assert worker[key] == portal[key]
    assert 'CATS_BOOTSTRAP_PASSWORD' in portal['environment']


def test_publisher_probe_uses_project_container_identity():
    template = {'services': {'portal': {}}}
    assert publisher_portal_url({'project': 'cats-nginx-qualification'}, template) == (
        'http://cats-nginx-qualification-portal-1:8000/login')
    assert publisher_portal_url({'project': 'cats-inventory-qualification'}, template) != (
        publisher_portal_url({'project': 'cats-nginx-qualification'}, template))


def test_publisher_probe_honors_explicit_container_identity():
    template = {'services': {'portal': {'container_name': 'nginx-publisher-specific'}}}
    assert publisher_portal_url({'project': 'other'}, template) == (
        'http://nginx-publisher-specific:8000/login')


def test_publisher_probe_rejects_non_hostname_identity():
    with pytest.raises(AssertionError, match='unique valid container identity'):
        publisher_portal_url({'project': 'unused'}, {'services': {'portal': {'container_name': 'other/path'}}})
