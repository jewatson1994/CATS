import base64
import hashlib
import sys
import types
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.managed_validator_bootstrap import BootstrapError, SSHBootstrap, validate_target
from app.managed_validator_pki import create_identity, deployment_identity
from app.secrets import decrypt_secret


def test_dedicated_pki_encryption_chain_and_roles(monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    identity = create_identity('host-1', 'validator.example', 'https://validator.example:8443')
    config, saved, deployment = identity['configuration'], identity['persistence'], identity['deployment']
    assert config['client_key'].startswith('enc:v1:')
    assert saved['ca_key'].startswith('enc:v1:') and saved['server_key'].startswith('enc:v1:')
    assert deployment_identity(config, saved) == deployment
    assert 'PRIVATE KEY' not in str(identity['public'])
    ca = x509.load_pem_x509_certificate(config['ca_certificate'].encode())
    server = x509.load_pem_x509_certificate(deployment['validator_certificate'].encode())
    client = x509.load_pem_x509_certificate(config['client_certificate'].encode())
    for certificate in (server, client):
        ca.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(certificate.signature_hash_algorithm))
    assert server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ['validator.example']
    assert server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    assert client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    client_key = serialization.load_pem_private_key(decrypt_secret(config['client_key']).encode(), None)
    assert client_key.public_key().public_numbers() == client.public_key().public_numbers()
    second = create_identity('host-2', 'validator.example', 'https://validator.example:8443')
    assert second['configuration']['ca_certificate'] != config['ca_certificate']
    assert second['public']['client_fingerprint'] != identity['public']['client_fingerprint']


@pytest.mark.parametrize('endpoint', ['http://validator.example', 'https://other.example', 'https://user:secret@validator.example', 'https://validator.example/path'])
def test_pki_rejects_endpoint_mismatch(endpoint):
    with pytest.raises(ValueError):
        create_identity('host-1', 'validator.example', endpoint)


@pytest.mark.parametrize('host', ['127.0.0.1', '::1', '0.0.0.0', '169.254.1.1', 'localhost', 'host;bad', '-bad.example'])
def test_rejects_nonremote_or_injected_target(host):
    with pytest.raises(ValueError):
        validate_target(host)


class Transport:
    def __init__(self):
        self.closed = False
        self.authenticated = False
    def get_remote_server_key(self):
        return types.SimpleNamespace(asbytes=lambda: b'host key')
    def auth_password(self, user, password):
        self.authenticated = True
    def is_authenticated(self):
        return self.authenticated
    def close(self):
        self.closed = True


def fake_paramiko(monkeypatch):
    monkeypatch.setitem(sys.modules, 'paramiko', types.SimpleNamespace())


def test_pin_mismatch_never_authenticates_and_forgets_credentials(monkeypatch):
    fake_paramiko(monkeypatch)
    transport = Transport()
    bootstrap = SSHBootstrap({'host':'192.0.2.5'}, {'password':'sensitive'}, 'SHA256:' + 'a'*43)
    monkeypatch.setattr(bootstrap, '_transport', lambda: transport)
    with pytest.raises(BootstrapError, match='fingerprint mismatch'):
        bootstrap.__enter__()
    assert not transport.authenticated and transport.closed and not bootstrap.credentials


def test_confirmed_pin_authentication_retires_temporary_secret(monkeypatch):
    fake_paramiko(monkeypatch)
    transport = Transport()
    pin = SSHBootstrap._fingerprint(transport)
    bootstrap = SSHBootstrap({'host':'192.0.2.5'}, {'password':'sensitive','sudo_password':'sudo-sensitive'}, pin)
    monkeypatch.setattr(bootstrap, '_transport', lambda: transport)
    with bootstrap:
        assert bootstrap.credentials == {'sudo_password':'sudo-sensitive'}
    assert transport.closed and not bootstrap.credentials


def test_connection_failure_retires_credentials(monkeypatch):
    fake_paramiko(monkeypatch)
    bootstrap = SSHBootstrap({'host':'192.0.2.5'}, {'password':'sensitive'}, 'SHA256:'+'a'*43)
    def fail():
        raise BootstrapError('Validator SSH connection failed')
    monkeypatch.setattr(bootstrap, '_transport', fail)
    with pytest.raises(BootstrapError):
        bootstrap.__enter__()
    assert not bootstrap.credentials


def test_deployment_preserves_failed_preflight_details(monkeypatch):
    import app.managed_validator_bootstrap as module
    monkeypatch.setattr(module, 'validate_release', lambda release: {})
    bootstrap = SSHBootstrap({'host': '192.0.2.5'}, {})
    result = {'status': 'unsupported', 'checks': {'disk': False, 'port': False},
              'facts': {'disk_free_bytes': 123}}
    monkeypatch.setattr(bootstrap, 'preflight', lambda owner: result)
    with pytest.raises(BootstrapError) as caught:
        bootstrap.deploy('owned-1', {}, {})
    assert caught.value.preflight == result
    assert 'disk, port' in str(caught.value)
    assert 'disk_free_bytes=123' in str(caught.value)


def test_deployment_is_exact_offline_and_owned(monkeypatch):
    import app.managed_validator_bootstrap as module
    images = {kind: {'path':Path(kind+'.tar'), 'sha256':'a'*64, 'image_id':'sha256:'+'b'*64, 'reference':kind+':pinned'} for kind in ('cats','node')}
    monkeypatch.setattr(module,'validate_release',lambda release:images)
    bootstrap = SSHBootstrap({'host':'192.0.2.5'}, {})
    uploads, commands = {}, []
    monkeypatch.setattr(bootstrap,'preflight',lambda owner: {'status':'supported'})
    monkeypatch.setattr(bootstrap,'_upload',lambda name,**args: uploads.update({name:args}))
    monkeypatch.setattr(bootstrap,'_run',lambda script,**args: commands.append(script))
    monkeypatch.delenv('CATS_DEPLOYMENT_ENFORCE_RESOURCE_LIMITS', raising=False)
    bootstrap.deploy('owned-1',{}, {'validator_certificate':'cert','validator_key':'key','client_ca':'ca','client_fingerprint':'c'*64})
    assert 'CATS_DEPLOYMENT_ENFORCE_RESOURCE_LIMITS=false\n' in uploads['validator.env']['content']
    assert 'CATS_VALIDATOR_EXECUTION_MODE=permissive\n' in uploads['validator.env']['content']
    assert 'CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS=true\n' in uploads['validator.env']['content']
    assert 'CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES=false\n' in uploads['validator.env']['content']
    command = commands[0]
    assert set(uploads) == {'cats.tar','node.tar','validator.crt','validator.key','client-ca.crt','validator.env'}
    assert '--network host' in command and '--read-only' in command
    assert command.count('docker load --input') == 2
    assert 'cats.managed.owner' in command and 'sha256sum' in command
    assert command.index('docker network ls --filter label=cats.deployment-validation=true') < command.index('install -m 600')
    assert 'docker pull' not in command and 'apt' not in command
    assert 'CATS_DEPLOYMENT_KIND_NODE_IMAGE=node:pinned' in uploads['validator.env']['content']
    assert 'TMPDIR=/var/lib/cats-managed-validator/owned-1/state/workspaces' in uploads['validator.env']['content']
    assert 'HELM_CACHE_HOME=' in uploads['validator.env']['content']
    assert 'sensitive' not in command


@pytest.mark.parametrize('failed', ['platform','docker','daemon','architecture_compatible','cgroup','cgroup_driver','runtime','socket','resources','port'])
def test_preflight_reports_individual_failure(monkeypatch, failed):
    import json
    bootstrap = SSHBootstrap({'host':'192.0.2.5'}, {})
    facts = dict.fromkeys(('platform','docker','daemon','architecture_compatible','cgroup','cgroup_driver','runtime','socket','resources','port','cpu','memory','disk'), True)
    facts.update(memory_bytes=4294967296, cpus=2, disk_free_bytes=21474836480)
    facts[failed] = False
    monkeypatch.setattr(bootstrap,'_run',lambda *args,**kwargs:json.dumps(facts))
    result = bootstrap.preflight()
    assert result['status'] == 'unsupported' and result['checks'][failed] is False
    assert result['warnings'][0] == failed+' prerequisite is not satisfied'
    if failed == 'docker':
        assert 'externally' in result['warnings'][1]


def test_removal_blocks_unfinished_kind_before_container_delete(monkeypatch):
    bootstrap = SSHBootstrap({'host':'192.0.2.5'}, {})
    commands=[]
    monkeypatch.setattr(bootstrap, '_run',lambda script,**kwargs:commands.append(script))
    bootstrap.remove('owned-1')
    script=commands[0]
    assert script.index('docker network ls --filter label=cats.deployment-validation=true') < script.index('docker rm -f')
    assert 'cats.managed.owner' in script and '[ ! -L "$root/owner" ]' in script


def test_preflight_recommended_resources_warn_without_rejecting(monkeypatch):
    import json
    bootstrap=SSHBootstrap({'host':'192.0.2.5'}, {})
    facts=dict.fromkeys(('platform','docker','daemon','architecture_compatible','cgroup','cgroup_driver','runtime','socket','resources','port','cpu','memory','disk'), True)
    facts.update(memory_bytes=4294967296,cpus=2,disk_free_bytes=21474836480,os='ubuntu',os_version='24.04',architecture='x86_64',docker_version='28.1.1')
    monkeypatch.setattr(bootstrap,'_run',lambda *args,**kwargs:json.dumps(facts))
    result=bootstrap.preflight()
    assert result['status']=='supported_with_warnings' and len(result['warnings'])==3
    assert result['facts']['os_version']=='24.04' and result['facts']['docker_version']=='28.1.1'


def test_configuration_transfer_opens_writable_exclusive_file(monkeypatch):
    import sys
    from types import SimpleNamespace
    paramiko = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=None))
    monkeypatch.setitem(sys.modules, 'paramiko', paramiko)
    from app.managed_validator_bootstrap import SSHBootstrap
    bootstrap = SSHBootstrap({'host': '192.0.2.10'}, {})
    bootstrap._staged = True
    calls = []
    class Stream:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def write(self, content): calls.append(content)
    class SFTP:
        def get_channel(self): return self
        def settimeout(self, timeout): pass
        def open(self, destination, mode):
            assert 'w' in mode and 'x' in mode
            return Stream()
        def chmod(self, destination, mode): assert mode == 0o600
        def close(self): calls.append('closed')
    monkeypatch.setattr(paramiko.SFTPClient, 'from_transport', lambda transport: SFTP())
    bootstrap._upload('validator.key', content='private material')
    assert calls == [b'private material', 'closed']


def test_transfer_error_reports_safe_storage_reason(monkeypatch):
    import errno
    import sys
    from types import SimpleNamespace
    paramiko = SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=None))
    monkeypatch.setitem(sys.modules, 'paramiko', paramiko)
    import pytest
    from app.managed_validator_bootstrap import SSHBootstrap, BootstrapError
    bootstrap = SSHBootstrap({'host': '192.0.2.10'}, {})
    bootstrap._staged = True
    def fail(transport): raise OSError(errno.ENOSPC, 'sensitive detail')
    monkeypatch.setattr(paramiko.SFTPClient, 'from_transport', fail)
    with pytest.raises(BootstrapError, match='host staging storage is full') as error:
        bootstrap._upload('validator.key', content='private material')
    assert 'sensitive detail' not in str(error.value)
    assert 'private material' not in str(error.value)
