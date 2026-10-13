"""Directory discovery requires global administration and never grants access."""
import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app import main
from app.auth import AuthContext
from app.secrets import encrypt_secret


@pytest.fixture
def client(monkeypatch):
    role = SimpleNamespace(permissions=['config.manage'], name='Administrator')
    user = SimpleNamespace(id=1, role_assignments=[SimpleNamespace(role=role, service_id=None, group_id=None)])
    context = AuthContext(user=user, session=SimpleNamespace(csrf_token='csrf'))
    main.app.dependency_overrides[main.require_user] = lambda: context
    main.app.dependency_overrides[main.get_db] = lambda: None
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setattr(main, 'get_global_configuration', lambda db: {'oidc_configuration': json.dumps({
        'issuer': 'https://identity.example/realms/company', 'client_id': 'cats',
        'client_secret': encrypt_secret('private-client-secret'),
    })})
    test_client = TestClient(main.app)
    try:
        yield test_client, context
    finally:
        test_client.close()
        main.app.dependency_overrides.clear()


def test_directory_uses_saved_decrypted_connection_without_returning_secrets(client, monkeypatch):
    from app import oidc_directory
    calls = []
    def discover(connection, ca_bundle):
        calls.append(connection)
        return {'provider': 'keycloak', 'candidates': [{'kind': 'group', 'label': '/Existing',
            'claim_path': 'groups', 'expected_value': '/Existing'}], 'warnings': []}
    monkeypatch.setattr(oidc_directory, 'discover_oidc_directory', discover)
    response = client[0].post('/admin/configuration/oidc-mappings/discover', data={'csrf_token': 'csrf'})
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert calls[0]['client_secret'] == 'private-client-secret'
    assert 'private-client-secret' not in response.text
    assert response.json()['candidates'][0]['expected_value'] == '/Existing'


@pytest.mark.parametrize('restriction', ['csrf', 'scoped', 'unprivileged'])
def test_directory_rejects_unauthorized_requests_before_contacting_provider(client, monkeypatch, restriction):
    from app import oidc_directory
    def unexpected(*args):
        pytest.fail('Unauthorized discovery contacted the provider')
    monkeypatch.setattr(oidc_directory, 'discover_oidc_directory', unexpected)
    if restriction == 'scoped':
        client[1].user.role_assignments[0].group_id = 3
    elif restriction == 'unprivileged':
        client[1].user.role_assignments.clear()
    response = client[0].post('/admin/configuration/oidc-mappings/discover', data={
        'csrf_token': 'invalid' if restriction == 'csrf' else 'csrf'})
    assert response.status_code == 403


def test_directory_setup_failure_is_actionable_and_not_cached(client, monkeypatch):
    from app import oidc_directory
    def denied(*args):
        raise oidc_directory.OidcDirectoryError('Enable service accounts in Keycloak.')
    monkeypatch.setattr(oidc_directory, 'discover_oidc_directory', denied)
    response = client[0].post('/admin/configuration/oidc-mappings/discover', data={'csrf_token': 'csrf'})
    assert response.status_code == 422
    assert response.json()['detail'] == 'Enable service accounts in Keycloak.'
    assert response.headers['cache-control'] == 'no-store'
