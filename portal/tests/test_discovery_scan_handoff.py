"""Discovery hands reviewed evidence to the real durable scanner admission path."""
import pytest
from sqlalchemy.orm import sessionmaker
from test_discovery_routes import api, job, post, stub_packaged_intelligence_startup
from app import main, scan_coordination
from app.discovery_models import DiscoveryScan, DiscoveryConfirmation


@pytest.mark.parametrize('stage_new', [False, True])
def test_confirmed_discovery_creates_real_durable_scan(api, monkeypatch, tmp_path, stage_new):
    client, db, current = api
    if stage_new:
        current['auth'].user.role_assignments[0].role.name = 'Cybersecurity'
        current['auth'].user.role_assignments[0].role.system = True
    sessions = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    monkeypatch.setattr(main, 'SessionLocal', sessions)
    monkeypatch.setattr(scan_coordination, 'SessionLocal', sessions)
    monkeypatch.setattr(main, 'PUBLIC_JOB_ROOT', tmp_path / 'scan-jobs')
    _, inventory = job(db)
    selection = {'new_service_key': 'discovered-scan-service'} if stage_new else {'service_id': 1}
    response = post(client, '/own/confirm', {**selection, 'root_ids': ['root']})
    assert response.status_code == 200, response.text
    confirmation_id = response.json()['confirmed_inventory_id']
    response = post(client, '/own/scan', {'confirmation_id': confirmation_id})
    assert response.status_code == 200, response.text
    scan_id = response.json()['job_id']
    queued = main.PUBLIC_JOBS[scan_id]
    assert queued['status'] == 'queued'
    assert queued['image_list'] == 'nginx:1.2'
    assert queued['ingest_service_db_id'] == db.get(DiscoveryConfirmation, confirmation_id).service_id
    assert queued['ingest_scope'] == 'service'
    assert queued['owner_user_id'] == 7
    assert queued['definition_context']['discovery_inventory_id'] == inventory.id
    assert queued['definition_context']['discovery_confirmation_id'] == confirmation_id
    assert queued['definition_context']['discovery_completeness'] == 'complete'
    assert queued['definition_context']['discovery_images'] == inventory.inventory['images']
    assert (main.PUBLIC_JOB_ROOT / scan_id / 'input.tar.gz').is_file()
    assert db.get(DiscoveryScan, confirmation_id).scan_job_id == scan_id
    assert post(client, '/own/scan').json()['job_id'] == scan_id

    # Simulate loss of the final association commit after durable admission.
    db.delete(db.get(DiscoveryScan, confirmation_id))
    db.commit()
    assert post(client, '/own/scan').json()['job_id'] == scan_id
    assert db.get(DiscoveryScan, confirmation_id).scan_job_id == scan_id


def test_discovery_completion_preserves_inventory_without_legacy_update(monkeypatch):
    from app import definition_routes
    def unexpected_update(*args, **kwargs):
        raise AssertionError("Discovery must not update a legacy definition run")
    monkeypatch.setattr(definition_routes, '_status', unexpected_update)
    for status in ('complete', 'incomplete', 'error', 'cancelled'):
        definition_routes.complete_scan('scan-1', {
            'status': status,
            'definition_context': {'discovery_inventory_id': 'inventory-1'},
        })
