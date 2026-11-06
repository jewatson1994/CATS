"""Synthetic rich source evidence through production capture/import and HTTP APIs.

The OCI verification boundary is supplied by a verified-format fixture here;
these tests do not claim a real registry transfer or a scanner run.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import gzip
import hashlib
from io import BytesIO
import json
from types import SimpleNamespace
from zipfile import ZipFile

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import main, models as m, portable_release_capture, replica_routes, risk_routes
from app.artifact_catalog import (ArtifactLocation, ArtifactPatchLineage, GlobalArtifact,
    ServiceArtifactAssignment)
from app.auth import require_user
from app.cyber_approvals import CyberApproval
from app.database import get_db
from app.native_vex import ALGORITHM
from app.native_vex_models import (VexDispositionEvaluation, VexDispositionPolicy,
    VexDispositionService, VexFindingDisposition, VexObservationDisposition)
from app.operating_mode import ReplicaModeMiddleware
from app.replica_import import reconcile
from app.replica_models import ReplicaRecordMap, ReplicaRelease
from app.risk_models import RiskAssessment, RiskDecision, RiskPolicyVersion
from app.service_bundle import encode
from app.vex_models import VexDocument, VexSource, VexStatement
from test_replica_import import replica_import, verified


def seed_rich_evidence(f):
    """Reusable source data; every assertion below checks retained values."""
    f.service.description = 'Mission application with a frozen approval'
    observer = m.User(username='audit-only-reviewer', display_name='Evidence Reviewer', password_hash='!')
    f.origin.add(observer)
    f.origin.flush()
    f.origin.add(m.AuditEvent(actor_user_id=observer.id, action='evidence.reviewed',
        target_type='service', target_id=str(f.service.id), detail={'note': 'Original source review'}))
    scanner = b'{"scanner":"original"}'
    f.execution.raw_payload = {**f.execution.raw_payload,
        'sbom_components': [{'name': 'openssl', 'version': '3.0.15', 'image': 'registry/app:1'}],
        'helm_source_files': {'app/Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n'},
        'service_overview': {'images': [{'image': 'registry/app:1', 'digest': 'sha256:' + 'a' * 64}],
            'charts': [{'name': 'app', 'version': '1.0.0'}]},
        'evidence_documents': [{'name': 'scanner.json', 'category': 'scanner', 'format': 'grype-json',
            'content': base64.b64encode(gzip.compress(scanner)).decode(), 'bytes': len(scanner),
            'sha256': hashlib.sha256(scanner).hexdigest()}]}
    old_time = f.now - timedelta(days=2)
    f.origin.add(m.Execution(service_id=f.service.id, service_version_id=f.service.current_version_id,
        execution_key='previous-scan', scanned_at=old_time, complete=True,
        raw_payload={**f.execution.raw_payload, 'execution_id': 'previous-scan', 'scanned_at': old_time.isoformat()}))
    finding = m.Finding(service_id=f.service.id, cve='CVE-2026-4242', severity='High',
        first_seen=f.now, episode_started=f.now, last_seen=f.now, active=True)
    f.origin.add(finding)
    f.origin.flush()
    observation = m.FindingObservation(finding_id=finding.id, execution_id=f.execution.id,
        image='registry/app:1', package='openssl', installed_version='3.0.15', fixed_version='3.0.16',
        evidence={'remediation': 'Retained publisher remediation'})
    f.origin.add(observation)
    f.origin.add(m.ServiceImage(service_id=f.service.id, image_reference='registry/app:1',
        image_digest='sha256:' + 'a' * 64, scan_status='completed'))
    chart = m.ServiceArtifact(service_id=f.service.id, artifact_type='helm', artifact_name='app',
        chart_name='app', chart_version='1.0.0', source_execution_id=f.execution.id)
    f.origin.add(chart)
    f.origin.flush()
    f.origin.add(m.ServiceArtifactRevision(artifact_id=chart.id, revision_number=1, checksum='c' * 64,
        files={'Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n'}, created_by_id=f.author.id))
    poam = m.PoamEntry(service_id=f.service.id, service_version='1.0', finding_id=finding.id,
        item_type='vulnerability', title='Patch OpenSSL', description='Publisher weakness description',
        remediation='Apply approved vendor update', status='approved', created_by_id=f.author.id,
        approved_by_id=f.author.id, approved_at=f.now, due_date=f.now + timedelta(days=20))
    f.origin.add(poam)
    f.origin.flush()
    f.origin.add(m.PoamHistory(poam_id=poam.id, actor_user_id=f.author.id,
        action='approved', note='Retain milestone and original approval', detail={'milestone': 'Vendor patch'}))
    f.origin.add(m.ServiceMetadata(service_id=f.service.id,
        values={'mission_impact': 'Provides fleet communications', 'system_owner': 'Fleet Systems'}))
    for dataset, values in [('ppsm', {'protocol': 'TCP', 'port': '443', 'purpose': 'Mission API'}),
                            ('asset_list', {'hostname': 'mission-api', 'asset_type': 'Container'})]:
        f.origin.add(m.InventoryRecord(service_id=f.service.id, version='1.0', dataset=dataset,
            record_key=dataset, values=values, updated_by_id=f.author.id))
    policy = RiskPolicyVersion(name='Publisher risk policy', version=1, configuration={'basis': 'mission'},
        digest='d' * 64, created_by=f.author.username)
    f.origin.add(policy)
    f.origin.flush()
    assessment = RiskAssessment(service_id=f.service.id, policy_id=policy.id,
        source_execution_id=f.execution.id, as_of=f.now, valid_until=f.now + timedelta(days=30),
        provenance={'assignment': 'Fleet'}, summary={'rating': 'Moderate', 'total': 1},
        details=[{'cve': finding.cve, 'rating': 'Moderate'}])
    f.origin.add(assessment)
    f.origin.flush()
    f.origin.add(RiskDecision(service_id=f.service.id, assessment_id=assessment.id, kind='ao_decision',
        decision='accepted', payload={'rationale': 'Mission continuity'}, created_by=f.author.username,
        expires_at=f.now + timedelta(days=30)))
    f.origin.add(CyberApproval(service_id=f.service.id, source_execution_id=f.execution.id,
        requested_by_id=f.author.id, decided_by_id=f.author.id, variant='original', status='approved',
        snapshot={'service': {'name': f.service.name}}, snapshot_digest='sha256:' + 'c' * 64,
        rationale='Mission approval request', decision_rationale='Approved after evidence review',
        decided_at=f.now))
    artifacts = []
    for i in range(3):
        artifact = GlobalArtifact(digest='sha256:' + f'{100+i:064x}',
            media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
        f.origin.add(artifact)
        f.origin.flush()
        f.origin.add(ArtifactLocation(artifact_id=artifact.id, reference=f'registry/app:{i}',
            provenance={'source': 'publisher'}))
        artifacts.append(artifact)
    for i in range(2):
        patch = m.PatchExecution(service_id=f.service.id, requested_by_id=f.author.id,
            job_key=f'patch-{i}', source_mode='registry', output_mode='registry', status='completed')
        f.origin.add(patch)
        f.origin.flush()
        f.origin.add(ArtifactPatchLineage(patch_execution_id=patch.id,
            source_artifact_id=artifacts[i].id, output_artifact_id=artifacts[i+1].id,
            evidence={'patch': f'publisher-patch-{i}'}))
    f.origin.add(ServiceArtifactAssignment(service_id=f.service.id, artifact_id=artifacts[-1].id, role='approved'))
    # Native-only VEX references must retain the original document even without
    # a VEX reference anywhere in the informational risk assessment above.
    source = VexSource(name='Publisher advisory', trusted=True)
    f.origin.add(source)
    f.origin.flush()
    document = VexDocument(source_id=source.id, sha256='e' * 64, raw_text='{"original":"native VEX"}',
        format='openvex', document_key='advisory-1', version='1', issued_at=f.now, verification='verified')
    f.origin.add(document)
    f.origin.flush()
    f.origin.add(VexStatement(document_id=document.id, cve=finding.cve, product_id='pkg:generic/openssl@3.0.15',
        identity={'name': 'openssl'}, status='not_affected', justification='vulnerable_code_not_present'))
    f.origin.flush()
    policy = f.origin.get(VexDispositionPolicy, 1)
    policy.enabled = True
    f.origin.flush()
    state = f.origin.get(VexDispositionService, f.service.id)
    f.origin.refresh(state)
    f.origin.refresh(policy)
    evaluation = VexDispositionEvaluation(service_id=f.service.id, execution_id=f.execution.id,
        service_generation=state.generation, intelligence_generation=policy.generation,
        policy_version=policy.policy_version, algorithm=ALGORITHM, evaluated_at=f.now,
        valid_until=f.now + timedelta(days=10), summary={'total': 1})
    f.origin.add(evaluation)
    f.origin.flush()
    state.evaluation_id = evaluation.id
    f.origin.add_all([VexObservationDisposition(evaluation_id=evaluation.id, observation_id=observation.id,
        finding_id=finding.id, excluded=True, evidence={'statements': [{'document_id': document.id}]}),
        VexFindingDisposition(evaluation_id=evaluation.id, finding_id=finding.id, observations=1, excluded_observations=1)])
    f.origin.flush()
    return SimpleNamespace(finding=finding, observation=observation, document=document,
        artifacts=artifacts, observer=observer)


def test_rich_capture_reconstructs_original_domains_through_replica_http(replica_import, monkeypatch):
    f = replica_import
    monkeypatch.setenv('CATS_MODE', 'full')
    seeded = seed_rich_evidence(f)
    state = portable_release_capture.capture(f.origin, f.service, {'source_execution_id': f.execution.id})
    extension = state['extension']
    assert {row['id'] for row in extension['global_artifacts']} == {row.id for row in seeded.artifacts}
    assert len(extension['artifact_patch_lineage']) == 2
    assert extension['vex_documents'][0]['raw_text'] == seeded.document.raw_text
    assert extension['native_vex_context']['current'] is True
    output = BytesIO()
    with ZipFile(output, 'w') as archive:
        archive.writestr('replica-service.json', encode(state))
        archive.writestr('boe/approval.json', json.dumps({'decision': 'approved', 'reviewer': f.author.username}))
        archive.writestr('boe/ppsm.csv', 'protocol,port\nTCP,443\n')
        archive.writestr('boe/asset_list.csv', 'hostname\nmission-api\n')
    raw = output.getvalue()
    incoming = verified(f)
    incoming.update(state=state, evidence=raw)
    incoming['manifest']['evidence'] = {'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}
    monkeypatch.setenv('CATS_MODE', 'replica')
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    maps = {(row.table_name, row.source_id): row.local_id for row in f.db.scalars(select(ReplicaRecordMap))}
    # Use genuine routers and middleware; no endpoint response is mocked.
    application = FastAPI()
    application.include_router(replica_routes.router)
    application.include_router(risk_routes.router)
    application.add_api_route('/services/{service_key}', main.service_detail, methods=['GET'])
    application.add_api_route('/poam/entries/{poam_id}', main.poam_entry_page, methods=['GET'])
    application.add_middleware(ReplicaModeMiddleware)
    auth = SimpleNamespace(user=f.user, csrf_token='csrf', can_manage_group=lambda _: False,
        has=lambda permission, service_id=None: True, accessible_service_ids=lambda permission: {result['service_id']},
        effective_assignments=[], session=SimpleNamespace(id=1))
    monkeypatch.setattr(main, 'SessionLocal', lambda: Session(f.db.get_bind()))
    application.dependency_overrides[require_user] = lambda: auth
    application.dependency_overrides[get_db] = lambda: f.db
    path = f'/api/replica/releases/{result["release_id"]}'
    with TestClient(application) as client:
        response = client.get(path + '/context')
        assert response.status_code == 200
        body = response.json()
        assert body['read_only'] is True
        records, imported = body['original_evidence']['records'], body['original_evidence']['extension']
        assert records['services'][0]['service_key'] == f.service.service_key
        assert body['release']['source_release_id'] == 'release-1' and body['release']['sequence'] == 1
        assert datetime.fromisoformat(body['release']['approved_at']).replace(tzinfo=timezone.utc) == datetime.fromisoformat(incoming['manifest']['approved_at'])
        assert len(records['executions']) == 2
        approved = next(row for row in records['executions'] if row['id'] == f.execution.id)
        assert approved['raw_payload']['sbom_components'][0]['name'] == 'openssl'
        assert approved['raw_payload']['evidence_documents'][0]['name'] == 'scanner.json'
        assert records['findings'][0]['cve'] == 'CVE-2026-4242'
        assert records['service_images'][0]['image_digest'] == 'sha256:' + 'a' * 64
        assert records['service_artifacts'][0]['chart_version'] == '1.0.0'
        assert records['service_artifact_revisions'][0]['files']['Chart.yaml'].startswith('apiVersion: v2')
        assert records['poam_entries'][0]['title'] == 'Patch OpenSSL'
        assert records['poam_history'][0]['detail']['milestone'] == 'Vendor patch'
        assert {row['dataset'] for row in records['inventory_records']} == {'ppsm', 'asset_list'}
        assert records['service_metadata'][0]['values']['mission_impact'] == 'Provides fleet communications'
        assert imported['cyber_approvals'][0]['decision_rationale'] == 'Approved after evidence review'
        assert len(imported['artifact_patch_lineage']) == 2 and len(imported['global_artifacts']) == 3
        assert body['original_evidence']['actors'][str(f.author.id)] == 'upstream-author'
        assert body['original_evidence']['actors'][str(seeded.observer.id)] == 'audit-only-reviewer'
        assert body['original_evidence']['activity'][0]['detail']['note'] == 'Original source review'
        page_headers = {'Accept': 'application/vnd.cats.page+json'}
        poams = client.get(f'/services/{f.service.service_key}?poam=true', headers=page_headers)
        assert poams.status_code == 200
        original_poam = next(row for row in poams.json()['data']['entries'] if row['title'] == 'Patch OpenSSL')
        assert original_poam['created_by'] == original_poam['approved_by'] == 'upstream-author'
        detail = client.get(f'/poam/entries/{original_poam["id"]}', headers=page_headers)
        assert detail.status_code == 200
        assert detail.json()['data']['history'][0]['actor'] == 'upstream-author'
        # Neither source authors nor their permissions become local users.
        assert set(f.db.scalars(select(m.User.username))) == {'local-importer'}
        assert f.db.get(m.PoamEntry, original_poam['id']).created_by_id == f.user.id
        activity = client.get(f'/services/{f.service.service_key}?activity=true', headers=page_headers)
        assert activity.status_code == 200
        assert activity.json()['data']['total_items'] == 1
        assert activity.json()['data']['events'][0]['action'] == 'evidence.reviewed'
        assert activity.json()['data']['events'][0]['actor_name'] == 'audit-only-reviewer'
        # A missing historical mapping must not relabel the importer as author.
        poam_map = f.db.scalar(select(ReplicaRecordMap).where(
            ReplicaRecordMap.table_name == 'poam_entries', ReplicaRecordMap.local_id == original_poam['id']))
        captured_id = poam_map.source_id
        poam_map.source_id = captured_id + 1000000
        f.db.commit()
        missing_actor = client.get(f'/poam/entries/{original_poam["id"]}', headers=page_headers)
        assert missing_actor.json()['data']['entry']['created_by'] == 'Unavailable original identity'
        poam_map.source_id = captured_id
        f.db.commit()
        risk = client.get(f'/api/risk/services/{f.service.service_key}').json()
        assert risk['assessment']['summary']['rating'] == 'Moderate'
        assert risk['decisions'][0]['payload']['rationale'] == 'Mission continuity'
        assert risk['can_assess'] is False
        native = client.get(f'/api/risk/services/{f.service.service_key}/native-vex',
            params={'finding_id': maps['findings', seeded.finding.id]}).json()
        assert native['current'] and native['enabled'] and not native['pending']
        assert native['finding_disposition'] == 'vex_not_affected'
        assert native['items'][0]['observation_id'] == maps['finding_observations', seeded.observation.id]
        assert native['items'][0]['effective_disposition'] == 'vex_not_affected'
        assert native['items'][0]['source_observation_id'] == seeded.observation.id
        downloaded = client.get(path + '/evidence')
        assert downloaded.status_code == 200 and downloaded.content == raw
        assert 'boe/approval.json' in ZipFile(BytesIO(downloaded.content)).namelist()
        assert client.post(path + '/context', json={}, headers={'X-CSRF-Token': 'csrf'}).status_code == 403
        # Revision 2 preserves the original HTTP-addressable evidence unchanged.
        second = deepcopy(incoming)
        second['manifest']['portable'].update(release_uuid='release-2', release_sequence=2,
            supersedes_release_uuid='release-1')
        second['state']['records']['services'][0]['description'] = 'Updated mission metadata'
        # Legacy captures retain malformed/missing timestamps as evidence; the
        # display must remain readable without manufacturing a timestamp.
        for index, timestamp in enumerate(('not-a-date', None, 42), start=1):
            event = deepcopy(state['activity'][0])
            event.update(id=event['id'] + index, created_at=timestamp)
            second['state']['activity'].append(event)
        next_archive = BytesIO()
        with ZipFile(next_archive, 'w') as archive:
            archive.writestr('replica-service.json', encode(second['state']))
            archive.writestr('boe/approval.json', json.dumps({'decision': 'approved', 'revision': 2}))
        second['evidence'] = next_archive.getvalue()
        second['manifest']['evidence']['digest'] = 'sha256:' + hashlib.sha256(second['evidence']).hexdigest()
        result2 = reconcile(f.db, f.source, second, now=f.now)
        f.db.commit()
        assert result2['service_id'] == result['service_id']
        old = client.get(path + '/context').json()
        assert old['release']['status'] == 'superseded'
        assert old['original_evidence'] == state
        current = client.get(f'/api/replica/releases/{result2["release_id"]}/context').json()
        assert current['original_evidence']['records']['services'][0]['description'] == 'Updated mission metadata'
        activity = client.get(f'/services/{f.service.service_key}?activity=true', headers=page_headers)
        assert activity.status_code == 200
        displayed = activity.json()['data']['events']
        assert len(displayed) == 4 and displayed[0]['created_at']
        assert all(row['created_at'] is None for row in displayed[1:])
        assert current['original_evidence']['activity'] == second['state']['activity']


def test_historical_native_vex_does_not_claim_effective_exclusion(replica_import, monkeypatch):
    from app.replica_views import native_vex
    f = replica_import
    monkeypatch.setenv('CATS_MODE', 'full')
    seeded = seed_rich_evidence(f)
    policy = f.origin.get(VexDispositionPolicy, 1)
    policy.enabled = False
    policy.generation += 1  # Retained evaluation is stale as well as disabled.
    state = portable_release_capture.capture(f.origin, f.service, {'source_execution_id': f.execution.id})
    assert state['extension']['native_vex_context'] == {
        'evaluation_id': 1, 'current': False, 'enabled': False, 'pending': True}
    incoming = verified(f)
    incoming['state'] = state
    monkeypatch.setenv('CATS_MODE', 'replica')
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    finding_id = f.db.scalar(select(ReplicaRecordMap.local_id).where(
        ReplicaRecordMap.table_name == 'findings', ReplicaRecordMap.source_id == seeded.finding.id))
    view = native_vex(f.db, result['service_id'], finding_id=finding_id)
    assert not view['current'] and not view['enabled'] and view['pending']
    assert view['finding_disposition'] == 'active'
    assert view['items'][0]['effective_disposition'] == 'actionable'
    assert not view['items'][0]['verified_not_affected']
    # A v1 capture without the new context never upgrades historic evidence.
    incoming = deepcopy(incoming)
    del incoming['state']['extension']['native_vex_context']
    incoming['manifest']['portable'].update(release_uuid='release-2', release_sequence=2,
        supersedes_release_uuid='release-1')
    reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    legacy = native_vex(f.db, result['service_id'], finding_id=finding_id)
    assert not legacy['current'] and not legacy['enabled'] and legacy['pending']
