"""Actionable, secret-free diagnostics belong to the current unresolved request."""
import hashlib
import json
import ssl
import urllib.error
from types import SimpleNamespace

from sqlalchemy import create_engine, inspect

from app import oci_proxy
from app.oci_transport import RegistryClient, RegistryError
from app.runtime_candidates import RuntimeReleaseCandidate, assessment_for_review, reconcile
from app.runtime_models import upgrade_connection
from app.runtime_registry_resolution import DIAGNOSTIC_LIMIT, FAILURES, resolve_requests
from test_runtime_candidates import REPO, application, runtime


REQUEST = REPO + ':latest'
SECRET = 'sensitive-registry-response-must-never-be-stored'
MEDIA = 'application/vnd.oci.image.manifest.v1+json'
RAW = json.dumps({'mediaType': MEDIA, 'schemaVersion': 2, 'layers': [], 'config': {
    'mediaType': 'application/vnd.oci.image.config.v1+json', 'size': 32, 'digest': 'sha256:' + 'e' * 64}}).encode()
DIGEST = 'sha256:' + hashlib.sha256(RAW).hexdigest()


def failing(error):
    def fetch(*args, **kwargs):
        raise error
    return fetch


def client_for(monkeypatch, fetch):
    monkeypatch.setattr(oci_proxy, 'client', lambda mapping: SimpleNamespace(fetch_manifest=fetch, timeout=4))


def test_actionable_scoped_failures_and_successful_retry(runtime, monkeypatch):
    db, sessions, service, env, mapping = runtime
    app = application('', '')
    sibling = 'unmapped.internal/sidecar:stable'
    app.components[1]['image_ref'] = sibling
    row = reconcile(db, env, service, [app], 'default')
    original_hash = row.fingerprint
    db.commit()

    # Exercise the same exception wrapping used by the real urllib HTTPS transport without external I/O.
    tls = RegistryClient({'endpoint': mapping.upstream.endpoint})
    monkeypatch.setattr(tls.opener, 'open', failing(urllib.error.URLError(ssl.SSLError(SECRET))))
    for reason, fetch in [
            ('authentication', failing(RegistryError(SECRET, 403))),
            ('not_found', failing(RegistryError(SECRET, 404))),
            ('tls', tls.fetch_manifest),
            ('transport', failing(OSError(SECRET))),
            ('integrity', lambda *args: (RAW, MEDIA, 'sha256:' + '0' * 64))]:
        client_for(monkeypatch, fetch)
        assert resolve_requests(sessions, row.id, [1]) == row.id
        review = assessment_for_review(db, row, service)
        assert row.fingerprint == original_hash and 'resolution_diagnostics' not in row.inventory
        assert {key: item['reason'] for key, item in row.resolution_diagnostics.items()} == {
            REQUEST: reason, sibling: 'unmapped'}
        assert f'{REQUEST}: {FAILURES[reason]}' in review['blockers']
        assert f'{sibling}: {FAILURES["unmapped"]}' in review['runtime_evidence']['blockers']
        assert SECRET not in json.dumps(row.resolution_diagnostics) and SECRET not in str(review)
        db.rollback()

    client_for(monkeypatch, lambda *args: (RAW, MEDIA, DIGEST))
    current = db.get(RuntimeReleaseCandidate, resolve_requests(sessions, row.id, [1]))
    assert current.id != row.id and current.fingerprint != original_hash
    assert set(current.resolution_diagnostics) == {sibling}
    assert current.inventory['registry_resolutions'][REQUEST]['digest'] == DIGEST
    review = assessment_for_review(db, current, service)
    assert not any(FAILURES['integrity'] in item for item in review['blockers'])
    assert f'{sibling}: {FAILURES["unmapped"]}' in review['blockers']
    db.refresh(row)
    assert not row.current and row.resolution_diagnostics[REQUEST]['reason'] == 'integrity'


def test_slow_response_cannot_overwrite_newer_attempt_or_changed_mapping(runtime, monkeypatch):
    db, sessions, service, env, mapping = runtime
    row = reconcile(db, env, service, [application('')], 'default')
    db.commit()

    def older_result(*args):
        client_for(monkeypatch, failing(RegistryError(SECRET, 404)))
        resolve_requests(sessions, row.id, [1])
        return RAW, MEDIA, DIGEST

    client_for(monkeypatch, older_result)
    assert resolve_requests(sessions, row.id, [1]) == row.id
    db.refresh(row)
    diagnostic = row.resolution_diagnostics[REQUEST]
    assert diagnostic['reason'] == 'not_found'

    def credentials_changed(*args):
        mapping.upstream.username = 'new-credential-setting'
        db.commit()
        raise RegistryError(SECRET, 403)

    client_for(monkeypatch, credentials_changed)
    resolve_requests(sessions, row.id, [1])
    db.refresh(row)
    assert row.resolution_diagnostics[REQUEST] == diagnostic

    def replacement_revision(*args):
        new_app = application('')
        new_app.components[0]['app_version'] = '2.0'
        reconcile(db, env, service, [new_app], 'default')
        db.commit()
        raise RegistryError(SECRET, 403)

    client_for(monkeypatch, replacement_revision)
    resolve_requests(sessions, row.id, [1])
    db.refresh(row)
    assert not row.current and row.resolution_diagnostics[REQUEST] == diagnostic
    current = db.query(RuntimeReleaseCandidate).filter_by(current=True).one()
    assert current.resolution_diagnostics == {}

    def submit_during_request(*args):
        current.status = 'submitted'
        db.commit()
        return RAW, MEDIA, DIGEST

    client_for(monkeypatch, submit_during_request)
    assert resolve_requests(sessions, current.id, [1]) == current.id
    db.refresh(current)
    assert current.status == 'submitted' and current.resolution_diagnostics == {}


def test_only_recent_unresolved_diagnostics_are_retained(runtime):
    db, sessions, service, env, _ = runtime
    app = application(*([''] * (DIAGNOSTIC_LIMIT + 5)))
    for index, component in enumerate(app.components):
        component['image_ref'] = f'unmapped.internal/project/image-{index}:latest'
    row = reconcile(db, env, service, [app], 'default')
    all_requests = row.inventory['unresolved_image_requests']
    row.resolution_diagnostics = {ref: {'reason': 'transport', 'started_at': '2000-01-01T00:00:00+00:00'}
                                  for ref in all_requests}
    db.commit()
    resolve_requests(sessions, row.id, [0])
    db.refresh(row)
    assert len(row.resolution_diagnostics) == DIAGNOSTIC_LIMIT
    assert sum(item['reason'] == 'unmapped' for item in row.resolution_diagnostics.values()) == 8
    assert row.inventory['unresolved_image_requests'] == all_requests


def test_diagnostics_schema_upgrade_is_additive_and_repeatable():
    engine = create_engine('sqlite://')
    with engine.begin() as conn:
        conn.exec_driver_sql('CREATE TABLE runtime_environments (id INTEGER PRIMARY KEY)')
        conn.exec_driver_sql('CREATE TABLE runtime_release_candidates (id INTEGER PRIMARY KEY)')
        conn.exec_driver_sql('INSERT INTO runtime_release_candidates (id) VALUES (1)')
        upgrade_connection(conn)
        upgrade_connection(conn)
        assert 'resolution_diagnostics' in {item['name'] for item in inspect(conn).get_columns('runtime_release_candidates')}
        assert conn.exec_driver_sql('SELECT resolution_diagnostics FROM runtime_release_candidates').scalar_one() is None
