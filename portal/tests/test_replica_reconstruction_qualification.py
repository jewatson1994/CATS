"""Independent semantic qualification of rich source evidence and native views."""
from copy import deepcopy
from io import BytesIO
from types import SimpleNamespace
from zipfile import ZipFile

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import exchange_routes, main, models as m, portable_release_capture, replica_routes, risk_routes
from app.auth import require_user
from app.database import get_db
from app.operating_mode import ReplicaModeMiddleware
from app.replica_import import reconcile
from app.service_bundle import encode
from replica_reconstruction_qualification import (archive_content, canonical, checksum,
    compare_evidence, normalize_state, verify_native_views)
from test_replica_evidence_api import seed_rich_evidence
from test_replica_import import replica_import, verified


def archive(state):
    output = BytesIO()
    with ZipFile(output, 'w') as bundle:
        bundle.writestr('replica-service.json', encode(state))
        bundle.writestr('boe/ppsm.csv', 'protocol,port\nTCP,443\n')
        bundle.writestr('boe/approval.json', '{"approved":true}')
    return output.getvalue()


def context_and_receipt(state, raw):
    manifest = {'signing_fingerprint': 'publisher', 'approval': {'approved_at': '2026-11-01T00:00:00Z',
        'expires_at': '2026-12-01T00:00:00Z'},
        'portable': {'release_uuid': 'release-1'}, 'evidence': {'digest': checksum(raw)}}
    reference = 'registry.test/approved/service@sha256:' + 'a' * 64
    return {'read_only': True, 'manifest': manifest, 'original_evidence': state,
        'release': {'id': 1, 'publisher': 'publisher', 'source_release_id': 'release-1',
            'manifest_digest': checksum(canonical(manifest)), 'source_reference': reference,
            'approved_at': '2026-11-01T00:00:00+00:00', 'expires_at': '2026-12-01T00:00:00+00:00'}}, {
        'manifest': manifest, 'release': {'reference': reference, 'digest': 'sha256:' + 'a' * 64}}


def test_comparison_ignores_row_order_but_retains_nested_semantics():
    state = {'records': {'services': [{'id': 2}, {'id': 1}]},
             'extension': {'risk': [{'id': 5, 'details': ['first', 'second']}]}, 'activity': []}
    reordered = deepcopy(state)
    reordered['records']['services'].reverse()
    assert normalize_state(reordered) == normalize_state(state)
    reordered['extension']['risk'][0]['details'].reverse()
    assert normalize_state(reordered) != normalize_state(state)


@pytest.mark.parametrize('field', ['mission_impact', 'sbom', 'vex', 'lineage', 'risk', 'expiration'])
def test_comparison_rejects_changed_source_or_imported_domains(field):
    state = {'records': {'services': [{'id': 1, 'name': 'Mission'}]}, 'extension': {
        key: {'value': 'original'} for key in ('mission_impact', 'sbom', 'vex', 'lineage', 'risk')}}
    raw = archive(state)
    context, receipt = context_and_receipt(state, raw)
    assert compare_evidence(raw, raw, context, receipt)['equal']
    context = deepcopy(context)
    if field == 'expiration':
        context['release']['expires_at'] = '2027-01-01T00:00:00+00:00'
    else:
        context['original_evidence']['extension'][field]['value'] = 'altered'
    with pytest.raises(AssertionError):
        compare_evidence(raw, raw, context, receipt)
    with pytest.raises(AssertionError, match='System A BOE'):
        compare_evidence(archive({'different': True}), raw, context, receipt)


def test_archive_duplicate_members_are_rejected():
    output = BytesIO()
    with ZipFile(output, 'w') as bundle:
        bundle.writestr('replica-service.json', '{}')
        with pytest.warns(UserWarning):
            bundle.writestr('replica-service.json', '{"other":true}')
    with pytest.raises(AssertionError, match='Duplicate'):
        archive_content(output.getvalue())


def test_rich_source_semantics_survive_native_http_reconstruction(replica_import, monkeypatch):
    f = replica_import
    monkeypatch.setenv('CATS_MODE', 'full')
    seed_rich_evidence(f)
    f.origin.add(m.ServiceImage(service_id=f.service.id, image_reference='mirror/app:1',
        image_digest='sha256:' + 'a' * 64, scan_status='completed'))
    # Use real exchange catalog keys so native PPSM/assets views exercise the
    # configured records as well as their exact retained BOE representations.
    for row in f.origin.scalars(select(m.InventoryRecord)):
        if row.dataset == 'asset_list':
            row.dataset = 'assets'
            row.values = {'asset.name': 'mission-api', 'asset.type': 'Container'}
        else:
            row.values = {'network.protocol': 'TCP', 'network.port': '443', 'network.purpose': 'Mission API'}
    metadata = f.origin.get(m.ServiceMetadata, f.service.id)
    metadata.values = {**metadata.values, 'system.owner': 'Fleet Systems'}
    f.origin.flush()
    state = portable_release_capture.capture(f.origin, f.service, {'source_execution_id': f.execution.id})
    raw = archive(state)
    context, receipt = context_and_receipt(state, raw)
    comparison = compare_evidence(raw, raw, context, receipt)
    assert all(item['equal'] for item in comparison['domains'].values())
    assert comparison['domains']['records.inventory_records']['count'] == 2
    incoming = verified(f)
    incoming.update(state=state, evidence=raw)
    incoming['manifest']['evidence'] = {'digest': checksum(raw)}
    monkeypatch.setenv('CATS_MODE', 'replica')
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    application = FastAPI()
    for router in (replica_routes.router, risk_routes.router, exchange_routes.router):
        application.include_router(router)
    application.add_api_route('/services/{service_key}', main.service_detail, methods=['GET'])
    application.add_api_route('/poam/entries/{poam_id}', main.poam_entry_page, methods=['GET'])
    application.add_api_route('/api/services/{service_key}/artifacts/images/status', main.artifact_image_status, methods=['GET'])
    application.add_middleware(ReplicaModeMiddleware)
    auth = SimpleNamespace(user=f.user, csrf_token='csrf', can_manage_group=lambda _: False,
        has=lambda permission, service_id=None: True, accessible_service_ids=lambda permission: {result['service_id']},
        effective_assignments=[], session=SimpleNamespace(id=1))
    monkeypatch.setattr(main, 'SessionLocal', lambda: Session(f.db.get_bind()))
    application.dependency_overrides[require_user] = lambda: auth
    application.dependency_overrides[get_db] = lambda: f.db
    with TestClient(application) as client:
        class ReadAPI:
            def get(self, path):
                response = client.get(path)
                assert response.status_code == 200, (path, response.text[:1000])
                return response.json()

            def page(self, path):
                response = client.get(path, headers={'Accept': 'application/vnd.cats.page+json'})
                assert response.status_code == 200, (path, response.text[:1000])
                return response.json()['data']

        report = verify_native_views(ReadAPI(), state)
        assert report['service_images']['count'] == 2
        assert report['findings']['count'] == 1
        assert report['executions']['count'] == 2
        assert report['risk_decisions']['count'] == 1
        assert report['poam_history']['count'] == 1
        assert report['vex_observation_dispositions']['count'] == 1
        assert report['vex_documents']['count'] == 1
        # The signed context can remain correct while the relational projection
        # is damaged; native checks must catch that independent failure mode.
        image = f.db.scalar(select(m.ServiceImage))
        image.scan_error = 'local corruption'
        f.db.flush()
        with pytest.raises(AssertionError, match='Native image inventory differs'):
            verify_native_views(ReadAPI(), state)
