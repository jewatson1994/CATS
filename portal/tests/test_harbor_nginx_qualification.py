"""Publisher outage probes must not resolve another Compose project's portal."""
import pytest

from harbor_nginx_qualification import publisher_portal_url


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
