"""Synthetic queue/restart and offline-input tests; no VM or Docker required."""
from datetime import timedelta
import json
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import managed_validators as managed, provisioning_worker as worker, validator_on_demand as demand
from app.models import Base, ManagedValidator, ManagedValidatorOperation, ValidatorProvisioningAttempt
from app.secrets import decrypt_secret


@pytest.fixture
def sessions(monkeypatch):
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(managed, 'SessionLocal', factory)
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    with factory() as db:
        db.add(ManagedValidator(id='host1', name='VM', host='192.0.2.5', fingerprint='trusted', fingerprint_confirmed=True))
        db.commit()
    yield factory
    engine.dispose()


def enqueue(sessions, action='test'):
    with sessions() as db:
        return managed.claim_operation(db, db.get(ManagedValidator, 'host1'), action,
            credentials={'password': 'DO_NOT_LEAK'}, acknowledgments={}).id


def test_submission_is_durable_encrypted_and_portal_restart_does_not_fail_it(sessions):
    operation = enqueue(sessions)
    with sessions() as db:
        attempt = db.get(ValidatorProvisioningAttempt, operation)
        assert 'DO_NOT_LEAK' not in attempt.encrypted_credentials
        assert json.loads(decrypt_secret(attempt.encrypted_credentials))['password'] == 'DO_NOT_LEAK'
        assert db.get(ManagedValidatorOperation, operation).status == 'QUEUED'
    assert worker.claim(sessions)[0] == operation
    managed.recover_operations()
    with sessions() as db:
        assert db.get(ManagedValidatorOperation, operation).status == 'RUNNING'
        assert db.get(ManagedValidator, 'host1').active_operation_id == operation


def test_live_lease_excludes_duplicate_and_expiry_fences_old_worker(sessions):
    operation = enqueue(sessions)
    _, first = worker.claim(sessions)
    assert worker.claim(sessions) is None
    with sessions() as db:
        db.get(ValidatorProvisioningAttempt, operation).lease_until = worker.now() - timedelta(seconds=1)
        db.commit()
    _, second = worker.claim(sessions)
    with sessions() as db:
        assert second != first and not worker.owns(db, operation, first)
        assert worker.owns(db, operation, second)
        db.info['provisioning_lease_owner'] = first
        with pytest.raises(managed.BootstrapError, match='lease'):
            managed.phase(db, db.get(ManagedValidatorOperation, operation), 'DEPLOYING')


def test_completion_purges_credentials(sessions, monkeypatch):
    operation = enqueue(sessions)
    monkeypatch.setattr(managed, 'health_checked', lambda *args: {'ready': True})
    assert worker.run_once(sessions)
    with sessions() as db:
        attempt = db.get(ValidatorProvisioningAttempt, operation)
        assert attempt.status == 'SUCCEEDED' and attempt.encrypted_credentials is None
        assert attempt.completed_at and attempt.heartbeat_at
        assert db.get(ManagedValidator, 'host1').active_operation_id is None


def test_failure_retries_with_backoff_then_purges(sessions, monkeypatch):
    operation = enqueue(sessions)
    def failure(*args):
        raise RuntimeError('DO_NOT_LEAK')
    monkeypatch.setattr(managed, 'health_checked', failure)
    for iteration in range(3):
        assert worker.run_once(sessions)
        with sessions() as db:
            attempt = db.get(ValidatorProvisioningAttempt, operation)
            assert attempt.attempts == iteration + 1
            assert 'DO_NOT_LEAK' not in attempt.failure
            if iteration < 2:
                assert attempt.status == 'QUEUED' and attempt.available_at
                assert db.get(ManagedValidator, 'host1').active_operation_id == operation
                attempt.available_at = worker.now() - timedelta(seconds=1)
                db.commit()
            else:
                assert attempt.status == 'FAILED' and attempt.encrypted_credentials is None
                assert db.get(ManagedValidator, 'host1').active_operation_id is None


def test_queued_cancellation_never_contacts_target(sessions, monkeypatch):
    operation = enqueue(sessions, 'provision')
    with sessions() as db:
        db.get(ManagedValidatorOperation, operation).cancel_requested = True
        db.commit()
    monkeypatch.setattr(managed, 'SSHBootstrap', lambda *args, **kwargs: pytest.fail('must not connect'))
    worker.run_once(sessions)
    with sessions() as db:
        assert db.get(ValidatorProvisioningAttempt, operation).status == 'CANCELLED'
        assert db.get(ValidatorProvisioningAttempt, operation).encrypted_credentials is None


def test_public_registry_and_mutable_sources_are_rejected(monkeypatch):
    monkeypatch.setenv('CATS_PROVISIONING_INTERNAL_REGISTRIES', 'harbor.internal,docker.io')
    for ref in ('docker.io/cats@sha256:' + 'a'*64, 'harbor.internal/cats:latest'):
        with pytest.raises(managed.BootstrapError, match='approved internal'):
            demand.approved_reference(ref)
    assert demand.approved_reference('harbor.internal/cats@sha256:' + 'a'*64)


def test_missing_input_does_not_pull_without_approved_source(monkeypatch):
    calls = []
    def missing(*args):
        calls.append(args)
        raise managed.BootstrapError('absent')
    monkeypatch.setattr(demand, 'docker', missing)
    with pytest.raises(managed.BootstrapError, match='Missing dependency'):
        demand.resolve_image('sha256:' + 'a'*64)
    assert calls == [('image', 'inspect', 'sha256:' + 'a'*64)]


def test_on_demand_reuses_only_matching_verified_inputs(tmp_path, monkeypatch):
    monkeypatch.delenv('CATS_MANAGED_VALIDATOR_RELEASE_DIR', raising=False)
    monkeypatch.delenv('CATS_DEPLOYMENT_KIND_NODE_IMAGE', raising=False)
    monkeypatch.setenv('CATS_PROVISIONING_CATS_IMAGE', 'sha256:' + 'a'*64)
    monkeypatch.setenv('CATS_PROVISIONING_CACHE', str(tmp_path))
    resolved = []
    def resolve(ref, source=None):
        resolved.append(ref)
        return {'Id': 'sha256:' + ('a' if ref.startswith('sha256:') else 'b')*64, 'Size': 1}
    monkeypatch.setattr(demand, 'resolve_image', resolve)
    built, verified = [], []
    def prepare(path, image, **kwargs):
        path.mkdir()
        built.append((image, kwargs))
    monkeypatch.setattr(demand.recipe, 'prepare', prepare)
    monkeypatch.setattr(demand, 'load_release', lambda path: verified.append(Path(path)) or {'_directory': str(path)})
    first = demand.prepare_release()
    assert demand.prepare_release() == first and len(built) == 1
    assert len(verified) == 3  # verify before publication, after publication and reuse
    provenance = json.loads((Path(first['_directory']) / 'provenance.json').read_text())
    assert provenance['cats_image_id'] == 'sha256:' + 'a'*64 and provenance['recipe_sha256']
    from app.deployment_validation import ValidationConfig
    assert provenance['node_pin'] == ValidationConfig.kind_node_image
    assert resolved[-1] == ValidationConfig.kind_node_image
    assert built[0][1] == {'node_image': 'sha256:' + 'b'*64, 'node_pin': ValidationConfig.kind_node_image}
    # Even when two pins inspect to the same image ID, their cache keys differ.
    previous = first
    for pin in ('harbor.internal/node:v1.35.0@sha256:' + 'c'*64,
                'harbor.internal/node:v1.35.0@sha256:' + 'd'*64,
                'harbor.internal/node:v1.35.1@sha256:' + 'd'*64):
        monkeypatch.setenv('CATS_DEPLOYMENT_KIND_NODE_IMAGE', pin)
        current = demand.prepare_release()
        assert current != previous
        count = len(built)
        assert demand.prepare_release() == current and len(built) == count
        assert built[-1][1]['node_pin'] == pin
        assert resolved[-1] == pin
        assert json.loads((Path(current['_directory']) / 'provenance.json').read_text())['node_pin'] == pin
        previous = current
    assert len(built) == 4


def test_missing_runtime_package_catalog_has_actionable_failure(monkeypatch, tmp_path):
    monkeypatch.setenv('CATS_PROVISIONING_CACHE', str(tmp_path))
    from app.validator_runtime_packages import packages_for
    monkeypatch.delenv('CATS_PROVISIONING_DOCKER_PACKAGES', raising=False)
    with pytest.raises(managed.BootstrapError, match='Docker 28.*dependency closure'):
        packages_for({'os_version': '24.04'})


def test_repeated_process_death_is_bounded_at_claim(sessions):
    operation = enqueue(sessions)
    for _ in range(worker.MAX_ATTEMPTS):
        assert worker.claim(sessions)[0] == operation
        with sessions() as db:
            db.get(ValidatorProvisioningAttempt, operation).lease_until = worker.now() - timedelta(seconds=1)
            db.commit()
    assert worker.claim(sessions) is None
    with sessions() as db:
        attempt = db.get(ValidatorProvisioningAttempt, operation)
        assert attempt.status == 'FAILED' and attempt.attempts == worker.MAX_ATTEMPTS
        assert attempt.encrypted_credentials is None
        assert db.get(ManagedValidator, 'host1').active_operation_id is None


def test_heartbeat_does_not_resurrect_expired_lease(sessions):
    operation = enqueue(sessions)
    _, token = worker.claim(sessions)
    with sessions() as db:
        db.get(ValidatorProvisioningAttempt, operation).lease_until = worker.now() - timedelta(seconds=1)
        db.commit()
    class Once:
        def wait(self, seconds):
            return False
    worker.heartbeat(operation, token, Once(), sessions)
    with sessions() as db:
        assert not worker.owns(db, operation, token)


def test_cache_removes_abandoned_owned_artifacts_and_enforces_budget(tmp_path, monkeypatch):
    import os, time
    monkeypatch.setenv('CATS_PROVISIONING_CACHE_MAX_BYTES', '100')
    stale = tmp_path / '.prepare-stale'
    stale.mkdir()
    os.utime(stale, (time.time()-8000,)*2)
    release = tmp_path / ('a'*64)
    release.mkdir()
    (release/'asset').write_bytes(b'x'*90)
    os.utime(release, (time.time()-8000,)*2)
    unrelated = tmp_path/'operator-files'
    unrelated.mkdir()
    demand.prune_cache(tmp_path, reserve=50)
    assert not stale.exists() and not release.exists() and unrelated.exists()
    with pytest.raises(managed.BootstrapError, match='budget'):
        demand.prune_cache(tmp_path, reserve=101)


def test_missing_images_fail_before_runtime_install(sessions, monkeypatch):
    from app import validator_runtime_packages as packages
    operation = enqueue(sessions, 'provision')
    class SSH:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def preflight(self, **kwargs):
            return {'status': 'unsupported', 'facts': {'os_version': '24.04'},
                    'checks': dict.fromkeys(('platform', 'sudo', 'cpu', 'memory', 'disk', 'port'), True)}
    monkeypatch.setattr(managed, 'SSHBootstrap', SSH)
    monkeypatch.setattr(packages, 'packages_for', lambda facts: [('verified.deb', 'a'*64)])
    monkeypatch.setattr(packages, 'install', lambda *args: pytest.fail('target must remain unchanged'))
    def missing(**kwargs):
        raise managed.BootstrapError('Missing dependency: pinned Kind')
    monkeypatch.setattr(demand, 'prepare_release', missing)
    worker.run_once(sessions)
    with sessions() as db:
        attempt = db.get(ValidatorProvisioningAttempt, operation)
        assert attempt.status == 'QUEUED' and 'Missing dependency' in attempt.failure


def test_retry_resumes_remote_selftest_without_replacing_enrollment(sessions, monkeypatch):
    operation = enqueue(sessions, 'provision')
    remote = 'b'*32
    image_id = 'sha256:' + 'a'*64
    with sessions() as db:
        row = db.get(ManagedValidator, 'host1')
        row.configuration = {'endpoint': 'https://example.test'}
        row.image = {'image_id': image_id}
        attempt = db.get(ValidatorProvisioningAttempt, operation)
        attempt.request = {'validation_id': remote, 'image_id': image_id, 'identity_created': True}
        db.commit()
    monkeypatch.setattr(managed, 'SSHBootstrap', lambda *args, **kwargs: pytest.fail('must not redeploy'))
    monkeypatch.setattr(managed, 'create_identity', lambda *args: pytest.fail('must not rotate trust'))
    monkeypatch.setattr(managed, 'health_checked', lambda *args: {'ready': True})
    def release(**kwargs):
        assert kwargs['expected'] == image_id
        return {}
    monkeypatch.setattr(demand, 'prepare_release', release)
    monkeypatch.setattr(managed, 'selftest_request', lambda release: ({}, Path('fixture.zip')))
    def validate(config, request, **kwargs):
        assert request['request_id'] == operation
        assert kwargs['resume_validation_id'] == remote
        return {'status': 'VERIFIED', 'cleanup_status': 'COMPLETE',
                'helm_result': {'install': 'PASS', 'release_status': 'DEPLOYED'},
                'resource_summary': {'pods': {'expected': 1, 'ready': 1}}}
    monkeypatch.setattr(managed.validator_client, 'validate', validate)
    worker.run_once(sessions)
    with sessions() as db:
        assert db.get(ValidatorProvisioningAttempt, operation).status == 'SUCCEEDED'
        assert db.get(ManagedValidator, 'host1').status == 'HEALTHY'


def test_cached_packages_are_verified_before_use(tmp_path, monkeypatch):
    import hashlib
    from app.validator_runtime_packages import packages_for
    data = b'verified package fixture'
    digest = hashlib.sha256(data).hexdigest()
    root = tmp_path/'packages'
    root.mkdir()
    (root/(digest+'.deb')).write_bytes(data)
    monkeypatch.setenv('CATS_PROVISIONING_CACHE', str(tmp_path))
    monkeypatch.setenv('CATS_PROVISIONING_DOCKER_PACKAGES', json.dumps({'ubuntu-24.04-amd64': [{'sha256': digest}]}))
    assert packages_for({'os_version': '24.04'}) == [(root/(digest+'.deb'), digest)]
    (root/(digest+'.deb')).write_bytes(b'corrupted')
    with pytest.raises(managed.BootstrapError, match='SHA256'):
        packages_for({'os_version': '24.04'})
