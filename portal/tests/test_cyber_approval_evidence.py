from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile
import json
import pytest
from sqlalchemy import select
from app import cyber_approval_evidence as evidence
from app.models import Service, Execution
from app.execution_summaries import payload_digest
from test_cyber_release_publication import environment as publication_environment
from test_portal import setup_function, new_client, csrf, payload, pipeline_headers, SessionLocal
from test_retained_evidence_exports import document

D = 'sha256:' + 'a' * 64

SELECTED = 'source.example/app:1'
EXCLUDED = 'source.example/optional:1'


def retained_reports(images):
    reports = []
    for index, image in enumerate(images):
        reports.append(document(image=image, name=f'grype-{index}.json'))
        reports.append(document(b'{"artifacts":[]}', image=image, category='sbom',
                                format='syft-json', name=f'syft-{index}.json'))
    return reports


@pytest.fixture
def distribution_case(tmp_path, monkeypatch):
    from app import cyber_approvals, main
    from app.discovery_models import DiscoveryConfirmation, DiscoveryInventory
    from app.durable_jobs import DurableJob
    from app.models import Role, User, UserRoleAssignment

    seeded()
    client = new_client()
    token = csrf(client)
    monkeypatch.setattr(main, 'PUBLIC_JOB_ROOT', tmp_path / 'scans')
    monkeypatch.setattr(cyber_approvals, 'root', lambda: tmp_path / 'approvals')
    inventory = {'completeness': 'complete', 'roots': [{'id': 'product', 'technology': 'kubernetes'}],
                 'nodes': [], 'edges': [], 'images': []}
    # Invert the Discovery defaults to prove that the release uses the saved selection.
    for name, reference, default, checksum in [('api', SELECTED, False, 'a'), ('optional', EXCLUDED, True, 'b')]:
        inventory['nodes'].append({'id': name, 'name': name, 'root_id': 'product', 'kind': 'ChartReference',
            'state': 'rendered', 'provenance': [{'enabled': default, 'version': '1.2.3', 'path': 'values.yaml',
                'reference': 'oci://charts.example/' + name, 'chart_sha256': checksum * 64, 'chart_digest_kind': 'archive'}]})
        inventory['edges'].append({'kind': 'declares', 'source': 'product', 'target': name})
        inventory['images'].append({'root_id': 'product', 'component_id': name, 'reference': reference})
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        group_id = service.groups[0].id
        baseline_version = service.current_version_id
        baseline_execution = db.scalar(select(Execution.id))
        admin_id = db.scalar(select(User.id).where(User.username == 'admin'))
        db.add(UserRoleAssignment(user_id=admin_id, service_id=service.id,
                                  role_id=db.scalar(select(Role.id).where(Role.name == 'Service Manager'))))
        db.add(DurableJob(id='discovery', kind='discovery', status='completed'))
        db.flush()
        db.add(DiscoveryInventory(id='inventory', job_id='discovery', group_id=group_id, source_hash='d' * 64,
                                  content_hash='e' * 64, inventory=inventory))
        db.flush()
        db.add(DiscoveryConfirmation(id='confirmed', inventory_id='inventory', service_id=service.id,
                                     confirmed_by=admin_id, root_ids=['product']))
        db.add(cyber_approvals.ApprovedReleaseDestination(name='Approved', endpoint='https://approved.example',
                                                         namespace='team', group_ids=[group_id]))
        db.commit()
    base = '/api/services/payments-service'
    created = client.post(base + '/distributions', json={'csrf_token': token, 'name': 'Core',
                          'confirmation_id': 'confirmed', 'enabled_chart_ids': ['api']})
    assert created.status_code == 200, created.text
    selected = created.json()['distribution']

    def scan(images, extra_report_image=None):
        admitted = client.post(f"{base}/distributions/{selected['id']}/scan", json={'csrf_token': token})
        assert admitted.status_code == 200, admitted.text
        job_id = admitted.json()['job_id']
        assert main.PUBLIC_JOBS[job_id]['image_list'].splitlines() == [SELECTED]
        body = payload('worker', datetime.now(timezone.utc), [])
        body['service_overview'] = {'images': [{'image': ref, 'digest': pin} for ref, pin in images]}
        body['sbom_components'] = [{'image': ref, 'image_digest': pin, 'name': 'openssl', 'version': '1'}
                                   for ref, pin in images]
        report_images = [ref for ref, _ in images]
        if extra_report_image:
            report_images.append(extra_report_image)
        body['evidence_documents'] = retained_reports(report_images)
        output = main.PUBLIC_JOB_ROOT / job_id / 'output' / 'portal-result.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(body), encoding='utf-8')
        main.PUBLIC_JOBS.update_job(job_id, {'status': 'complete'})
        ingested = client.post(f'/api/public/jobs/{job_id}/ingest', params={'service_id': 'payments-service'})
        assert ingested.status_code == 200, ingested.text
        return job_id

    return SimpleNamespace(client=client, headers={'X-CSRF-Token': token}, selected=selected, scan=scan,
        ready=base + '/cyber-approval-readiness', baseline_version=baseline_version, baseline_execution=baseline_execution)


@pytest.mark.parametrize('governed_revision', [False, True], ids=['normal-publication', 'governed-revision'])
def test_distribution_scan_through_signed_publication(distribution_case, publication_environment, tmp_path,
                                                      monkeypatch, governed_revision):
    from app import artifact_catalog, cyber_approvals, cyber_release_publication, release_revisions, signing
    from app.models import Finding

    case, registry = distribution_case, publication_environment
    pin = registry.approval.snapshot['artifacts'][0]['digest']
    params = {'distribution_id': case.selected['id']}
    request = {'service_key': 'payments-service', **params}
    material = signing.job_material({}, 'push')
    config, _ = material
    monkeypatch.setattr(signing, 'configuration', lambda _: {'fingerprint': registry.fingerprint,
                        'public_key': config['signing_public_key'], 'enabled': True, 'private_key': 'fixture'})
    if governed_revision:
        monkeypatch.setattr(release_revisions, 'root', lambda: tmp_path / 'approvals')
        with SessionLocal() as db:
            artifact = artifact_catalog.register_artifact(db, digest=pin, media_type='application/vnd.oci.image.manifest.v1+json')
            artifact_catalog.assign_artifact(db, service_id=db.scalar(select(Service.id)), artifact_id=artifact.id)
            request['release_revision'] = {'artifact_ids': [artifact.id], 'base_revision_id': None}
            db.commit()
    case.scan([(SELECTED, pin)])
    first = case.client.get(case.ready, params=params).json()
    assert first['ready'], first['blockers']
    job_id = case.scan([(SELECTED, pin)])
    ready = case.client.get(case.ready, params=params).json()
    assert ready['ready'], ready['blockers']
    assert ready['source_execution_id'] != first['source_execution_id']
    stale = case.client.post('/api/cyber-approvals', headers=case.headers,
        json={**request, 'expected_source_execution_id': first['source_execution_id']})
    assert stale.status_code == 409 and 'scan changed' in stale.text
    assert case.client.get(case.ready).json()['source_execution_id'] == case.baseline_execution
    created = case.client.post('/api/cyber-approvals', headers=case.headers,
        json={**request, 'expected_source_execution_id': ready['source_execution_id']})
    assert created.status_code == 200, created.text
    assert all(chart['source_path'] == 'values.yaml' for chart in created.json()['snapshot']['distribution']['charts'])
    approval_id = created.json()['id']
    decided = case.client.post(f'/api/cyber-approvals/{approval_id}/decision', headers=case.headers,
        json={'decision': 'approved', 'rationale': 'Reviewed the Core distribution.'})
    assert decided.status_code == 200, decided.text
    with SessionLocal() as db:
        assert db.scalar(select(Service)).current_version_id == case.baseline_version
        assert db.scalar(select(Finding).where(Finding.cve == 'CVE-1')).active
        row = db.get(cyber_approvals.CyberApproval, approval_id)
        execution = db.get(Execution, row.source_execution_id)
        assert execution.execution_key == 'public:' + job_id and execution.scan_scope == 'distribution'
        assert row.snapshot['source_payload_digest'] == execution.payload_digest
        frozen = row.snapshot['distribution']
        assert frozen == ready['distribution']
        assert frozen['selection_digest'] == case.selected['selection_digest']
        assert frozen['content_hash'] == 'e' * 64 and frozen['images'] == [SELECTED]
        assert frozen['enabled_chart_ids'] == ['api'] and frozen['disabled_chart_ids'] == ['optional']
        assert [(c['id'], c['default_enabled'], c['content_digest']) for c in frozen['charts']] == [
            ('api', False, 'a' * 64), ('optional', True, 'b' * 64)]
        assert row.snapshot['findings']['vulnerabilities'] == []
        with ZipFile(row.snapshot['evidence']['path']) as archive:
            assert json.loads(archive.read('distribution.json')) == frozen
            assert {item['image'] for item in json.loads(archive.read('sbom-components.json'))} == {SELECTED}
            for name in ('raw-scanner-outputs.zip', 'sboms.zip'):
                with ZipFile(BytesIO(archive.read(name))) as reports:
                    manifest = json.loads(reports.read('manifest.json'))
                    assert manifest['execution_id'] == 'public:' + job_id
                    assert [entry['image'] for entry in manifest['entries']] == [SELECTED]
                    assert reports.read(manifest['entries'][0]['archive_name']) == (
                        b'{"matches":[]}\r\n' if name == 'raw-scanner-outputs.zip' else b'{"artifacts":[]}')
        receipt = cyber_release_publication.publish(db, row, row.destination, lambda _: None)
        if governed_revision:
            signed = release_revisions.publish_manifest(db, row, material)
            assert signed['signature_status'] == 'verified' and signed['key_fingerprint'] == registry.fingerprint
            revision = db.scalar(select(release_revisions.ReleaseRevision).where(
                release_revisions.ReleaseRevision.approval_id == approval_id))
            signed_revision = json.loads((release_revisions.manifest_directory(revision) / 'release-manifest.json').read_bytes())
            assert signed_revision['distribution'] == frozen
            assert [a['digest'] for a in signed_revision['artifacts']] == [pin]
    assert receipt['status'] == 'published', receipt
    output = tmp_path / 'offline'
    with ZipFile(receipt['bundle_path']) as bundle:
        bundle.extractall(output)
    cyber_release_publication.verify_local(output, registry.fingerprint)
    manifest = json.loads((output / 'release-manifest.json').read_bytes())
    assert manifest['snapshot']['distribution'] == frozen
    assert [item['source_reference'] for item in manifest['artifacts']] == ['source.example/app@' + pin]


@pytest.mark.parametrize('images,extra_report_image', [
    ([], None), ([(SELECTED, D), (EXCLUDED, 'sha256:' + 'b' * 64)], None), ([(SELECTED, D)], EXCLUDED),
], ids=['missing-selected-image', 'unexpected-disabled-image', 'off-scope-original-reports'])
def test_distribution_refuses_different_scanned_images(distribution_case, images, extra_report_image):
    case = distribution_case
    case.scan(images, extra_report_image)
    params = {'distribution_id': case.selected['id']}
    ready = case.client.get(case.ready, params=params).json()
    assert not ready['ready']
    assert any('distribution' in blocker.lower() and 'image' in blocker.lower() for blocker in ready['blockers'])
    denied = case.client.post('/api/cyber-approvals', headers=case.headers,
        json={'service_key': 'payments-service', **params, 'expected_source_execution_id': ready['source_execution_id']})
    assert denied.status_code == 409
    assert denied.json()['detail']['blockers'] == ready['blockers']


def seeded(scan_scope='service'):
    client = new_client()
    body = payload('approval-source', datetime.now(timezone.utc), ['CVE-1'])
    body['helm_source_files'] = {'app/Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n',
        'app/values.yaml': 'replicaCount: 2\n', 'app/templates/deployment.yaml': 'retained template bytes'}
    for finding in body['findings']:
        finding['image'] = 'registry.example/app:1'
    body['sbom_components'] = [{'name': 'pkg', 'version': '1', 'image': 'registry.example/app:1'}]
    body['evidence_documents'] = retained_reports(['registry.example/app:1'])
    body['helm_values_files'] = ['app/values.yaml']
    body['service_overview'] = {'images': [{'image': 'registry.example/app:1', 'digest': D}],
        'charts': [{'name': 'app', 'version': '1.0.0'}],
        'rendered_resources': [{'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'app'},
            'spec': {'containers': [{'name': 'app', 'image': 'registry.example/app:1'}]}}]}
    body['scan_scope'] = scan_scope
    if scan_scope == 'image':
        body['scope_image'] = 'registry.example/app:1'
    assert client.post('/api/v1/pipeline-results', json=body, headers=pipeline_headers).status_code == 201


def fake_export(output, service, db, auth):
    with ZipFile(output, 'w') as archive:
        archive.writestr('findings.xlsx', b'workbook fixture')
        archive.writestr('mitigations.xlsx', b'mitigation fixture')
    return {'entries': [{'name': 'findings.xlsx', 'status': 'included'}]}


def test_portable_capture_freezes_canonical_decisions_without_local_secrets():
    from app import portable_release_capture as capture
    from app.models import Finding, FindingClassification, PortalSetting
    seeded()
    with SessionLocal() as db:
        service, execution = db.scalar(select(Service)), db.scalar(select(Execution))
        # No classification cache is needed to produce authoritative evidence.
        for row in db.scalars(select(FindingClassification)):
            db.delete(row)
        db.add(PortalSetting(key='oidc_configuration', value='{"client_secret":"private-source-only"}'))
        db.add(PortalSetting(key='compliance_mode', value='raw'))
        db.flush()
        state = capture.capture(db, service, {'source_execution_id': execution.id,
            'evidence': {'path': 'C:\\private-publisher\\evidence.zip', 'digest': 'sha256:retained'}})
        extension = state['extension']
        ids = set(db.scalars(select(Finding.id).where(Finding.service_id == service.id)))
        assert {row['finding_id'] for row in extension['finding_classifications']} == ids
        assert {row['finding_id'] for row in extension['finding_decisions']} == ids
        assert all(row['eligible'] is True for row in extension['finding_decisions'])
        assert extension['display']['configuration']['compliance_mode'] == 'raw'
        assert 'oidc_configuration' not in extension['display']['configuration']
        assert 'private-source-only' not in json.dumps(state)
        assert 'private-publisher' not in json.dumps(state)
        assert extension['approval_context']['evidence']['digest'] == 'sha256:retained'
        assert extension['observation_decisions'] == []
        assert db.scalar(select(FindingClassification)) is None


def test_ready_uses_exact_scan_and_preserves_chart_values_and_inventory(tmp_path, monkeypatch):
    seeded()
    monkeypatch.setattr('app.service_exports.write_all', fake_export)
    intelligence = {'basis': 'approval-request', 'captured_at': 'request-time',
        'kev': {'state': 'LOADED', 'metadata': {'catalog_version': 'test-version'}},
        'findings': {'CVE-1': {'kev': True, 'epss': .5}}}
    def capture(identifiers, captured_at):
        assert set(identifiers) == {'CVE-1'}
        assert datetime.fromisoformat(captured_at).tzinfo is not None
        return intelligence
    monkeypatch.setattr(evidence, 'review_intelligence_snapshot', capture)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        service.description = 'Internal reporting service'
        service.owner = 'Platform team'
        db.flush()
        ready = evidence.readiness(db, service)
        assert ready['ready'], ready['blockers']
        assert not any('Image identity was not retained' in note for note in ready['review_notes'])
        snapshot = evidence.freeze(db, service, SimpleNamespace(), ready, tmp_path)
        assert snapshot['service_context']['description'] == 'Internal reporting service'
        assert snapshot['service_context']['owner'] == 'Platform team'
        assert snapshot['service_context']['deployment_types'] == ['Helm']
        assert snapshot['service_context']['architecture']['components']['Pod'] == 1
        service.description = 'Changed after submission'
        assert snapshot['service_context']['description'] == 'Internal reporting service'
        assert snapshot['artifacts'][0]['reference'] == 'registry.example/app@' + D
        assert snapshot['evidence']['digest'] == evidence.file_digest(snapshot['evidence']['path'])
        with ZipFile(snapshot['evidence']['path']) as archive:
            assert archive.read('findings.xlsx') == b'workbook fixture'
            assert archive.read('chart-sources/app/values.yaml') == b'replicaCount: 2\n'
            assert json.loads(archive.read('scan-values-files.json')) == ['app/values.yaml']
            assert json.loads(archive.read('frozen-snapshot.json'))['risk_intelligence'] == intelligence
            assert json.loads(archive.read('frozen-snapshot.json'))['service_context'] == snapshot['service_context']
        import tarfile
        with tarfile.open(snapshot['artifacts'][1]['path']) as archive:
            assert archive.extractfile('app/values.yaml').read() == b'replicaCount: 2\n'
        assert snapshot['findings']['vulnerabilities'][0]['cve'] == 'CVE-1'
        assert snapshot['risk_intelligence'] == intelligence


@pytest.mark.parametrize('candidate', [False, True])
def test_service_context_uses_only_selected_variant_architecture(candidate):
    retained = {'service_overview': {'compose': {'services': [
        {'name': 'api', 'image': 'harbor.test/api:1', 'configuration': {
            'depends_on': ['db'], 'environment': {'PASSWORD': 'never-retain-this'}}},
        {'name': 'db', 'image': 'postgres:16', 'configuration': {}},
    ]}}}
    ready = {'remediation': object() if candidate else None, 'payload': retained,
             'overview': {}, 'rendered': '', 'artifacts': [{'kind': 'image'}]}
    context = evidence._service_context(SimpleNamespace(description=None, owner=None), ready)
    assert 'never-retain-this' not in json.dumps(context)
    if candidate:
        assert context['deployment_types'] == ['Container images']
        assert context['architecture'] is None
    else:
        assert context['deployment_types'] == ['Docker Compose']
        assert context['architecture']['components']['ComposeService'] == 2
        assert context['architecture']['relationships'] > 0


def test_review_identifiers_include_candidate_grype_and_trivy_findings():
    findings = {'vulnerability_scans': {'app': {'matches': [{'vulnerability': {'id': 'CVE-G'}}]},
        'db': {'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'CVE-T'}]}]}}}
    assert set(evidence._finding_identifiers(findings)) == {'CVE-G', 'CVE-T'}


@pytest.mark.parametrize('mutation,expected', [
    ('digest', 'digest'), ('skip', 'Missing'),
    ('dependency', 'dependency'), ('chart', 'matched'),
])
def test_missing_or_mismatched_evidence_blocks(mutation, expected):
    seeded()
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        if mutation == 'skip': body['skipped_charts'] = [{'chart': 'lost', 'reason': 'download failed'}]
        if mutation == 'dependency': body['helm_source_files']['app/Chart.yaml'] += 'dependencies:\n- name: lost\n  version: 1.0.0\n  repository: https://example.test\n'
        if mutation == 'chart': body['service_overview']['charts'].append({'name': 'missing', 'version': '2'})
        execution.raw_payload = body
        db.flush()
        if mutation == 'digest':
            from sqlalchemy import text
            db.execute(text("UPDATE executions SET payload_digest = :digest WHERE id = :id"), {'digest': '0' * 64, 'id': execution.id})
        db.flush()
        result = evidence.readiness(db, service)
        assert not result['ready']
        assert expected.lower() in ' '.join(result['blockers']).lower(), result['blockers']


@pytest.mark.parametrize('scan_scope', ['service', 'image'])
def test_newer_incomplete_scan_does_not_fall_back_to_older_complete(scan_scope):
    seeded(scan_scope)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        first = db.scalar(select(Execution))
        db.add(Execution(execution_key='incomplete', service_id=service.id, service_version_id=service.current_version_id,
            scanned_at=datetime(2099, 1, 1, tzinfo=timezone.utc), complete=False, scan_scope=scan_scope, raw_payload=dict(first.raw_payload)))
        db.commit()
        result = evidence.readiness(db, service)
        assert not result['ready'] and result['execution'].execution_key == 'incomplete'


def test_unavailable_export_all_is_not_silently_approved(tmp_path, monkeypatch):
    seeded()
    monkeypatch.setattr('app.service_exports.write_all', lambda *args: {'entries': [{'name': 'sbom', 'status': 'unavailable'}]})
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        with pytest.raises(ValueError, match='Export All evidence unavailable'):
            evidence.freeze(db, service, SimpleNamespace(), evidence.readiness(db, service), tmp_path)


def test_candidate_requires_matching_retained_verified_evidence():
    seeded()
    with SessionLocal() as db:
        result = evidence.readiness(db, db.scalar(select(Service)), 'cats_remediated', 999999)
        assert not result['ready']
        assert any('Candidate must belong' in item for item in result['blockers'])


@pytest.mark.parametrize('corrupt', [False, True])
@pytest.mark.parametrize('unverified', [False, True])
def test_candidate_freeze_binds_verified_sources_and_labels_baseline(tmp_path, monkeypatch, corrupt, unverified):
    from app import main
    from app.models import RemediationExecution
    import hashlib
    import yaml
    seeded()
    monkeypatch.setattr(main, 'REMEDIATION_JOB_ROOT', tmp_path)
    monkeypatch.setattr('app.service_exports.write_all', fake_export)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        source = json.loads(json.dumps(execution.raw_payload))
        files = {'candidate/' + name: content.encode() for name, content in source['helm_source_files'].items()}
        files['scans/rendered-after.yaml'] = yaml.safe_dump_all(source['service_overview']['rendered_resources']).encode()
        if not unverified:
            files['scans/trivy-config-after.json'] = b'{"Results": []}'
        manifest = {'source_execution_id': execution.id, 'source_version_id': service.current_version_id,
            'values_files': ['app/values.yaml'], 'images': [],
            'deployment_manifest': {'deployment': {'chartPath': 'candidate/app'},
            'files': {name: {'bytes': len(content), 'sha256': 'sha256:' + hashlib.sha256(content).hexdigest()} for name, content in files.items()}}}
        if corrupt:
            manifest['deployment_manifest']['files']['candidate/app/values.yaml']['sha256'] = 'sha256:' + '0' * 64
        candidate_dir = tmp_path / 'candidatejob'
        candidate_dir.mkdir()
        candidate = candidate_dir / 'candidate.zip'
        with ZipFile(candidate, 'w') as archive:
            for name, content in files.items(): archive.writestr(name, content)
            archive.writestr('manifest.json', json.dumps(manifest))
        record = RemediationExecution(job_key='candidatejob', service_id=service.id, requested_by_id=1,
            source_execution_id=execution.id, source_version_id=service.current_version_id,
            status='validated', remediation_status='complete', verification_status='failed' if unverified else 'verified',
            artifact_path=str(candidate), artifact_digest=evidence.file_digest(candidate),
            scan_results={'configuration': {'status': 'SKIP' if unverified else 'PASS'}, 'vulnerabilities': {'status': 'FAIL' if unverified else 'PASS'}},
            after_snapshot={'findings': [{'cve': 'CVE-CANDIDATE', 'status': 'remaining'}]})
        db.add(record); db.commit()
        ready = evidence.readiness(db, service, 'cats_remediated', record.id)
        if corrupt:
            assert not ready['ready'] and any('digest mismatch' in item for item in ready['blockers'])
            return
        assert ready['ready'], ready['blockers']
        snapshot = evidence.freeze(db, service, SimpleNamespace(), ready, tmp_path / 'frozen')
        assert snapshot['evidence_scope'] == 'remediation-candidate'
        assert snapshot['overview']['source'] == 'CATS Remediated candidate'
        assert snapshot['findings']['summary'] == record.after_snapshot
        assert snapshot['findings']['configuration'] == (None if unverified else {'Results': []})
        if unverified:
            assert any('verification: failed' in note for note in snapshot['review_notes'])
        with ZipFile(snapshot['evidence']['path']) as archive:
            assert 'current-service-baseline/all.zip' in archive.namelist()
            assert 'candidate/evidence.xlsx' in archive.namelist()
            assert archive.read('candidate/candidate.zip') == candidate.read_bytes()


def test_freeze_detects_new_scan_arriving_during_export(tmp_path, monkeypatch):
    seeded()
    def changing_export(output, service, db, auth):
        result = fake_export(output, service, db, auth)
        first = db.scalar(select(Execution))
        db.add(Execution(execution_key='arrived-during-freeze', service_id=service.id, service_version_id=service.current_version_id,
            scanned_at=datetime(2099, 1, 1, tzinfo=timezone.utc), complete=True, scan_scope='service', raw_payload=dict(first.raw_payload)))
        db.flush()
        return result
    monkeypatch.setattr('app.service_exports.write_all', changing_export)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        with pytest.raises(ValueError, match='changed while freezing'):
            evidence.freeze(db, service, SimpleNamespace(), evidence.readiness(db, service), tmp_path)


@pytest.mark.parametrize('scan_scope', ['service', 'image'])
def test_image_only_freezes_actual_export_all(tmp_path, scan_scope):
    seeded(scan_scope)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        body.pop('helm_source_files')
        body.pop('helm_values_files')
        body['service_overview'].pop('charts')
        body['service_overview'].pop('rendered_resources')
        execution.raw_payload = body
        db.flush()
        ready = evidence.readiness(db, service)
        assert ready['ready'], ready['blockers']
        assert ready['scan_date'] == execution.scanned_at.isoformat()
        if scan_scope == 'image':
            assert any('selected image scan only' in note for note in ready['review_notes'])
        assert [item['kind'] for item in ready['artifacts']] == ['image']
        auth = SimpleNamespace(has=lambda permission, service_id: permission == 'service.export')
        snapshot = evidence.freeze(db, service, auth, ready, tmp_path)
        assert snapshot['evidence_scope'] == f'current-{scan_scope}-scan'
        with ZipFile(snapshot['evidence']['path']) as archive:
            assert json.loads(archive.read('sbom-components.json'))['execution_id'] == execution.execution_key
            assert {'ppsm.xlsx', 'poam.xlsx', 'asset_list.xlsx', 'mitigations.xlsx', 'findings.xlsx',
                    'diagrams.zip', 'sbom-components.json', 'raw-scanner-outputs.zip', 'sboms.zip',
                    'frozen-snapshot.json'}.issubset(archive.namelist())
            from openpyxl import load_workbook
            with archive.open('findings.xlsx') as stream:
                book = load_workbook(stream)
                assert book.active.max_row >= 2
                book.close()


def test_image_rescan_does_not_replace_whole_service_evidence():
    seeded()
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        first = db.scalar(select(Execution))
        db.add(Execution(execution_key='image-rescan', service_id=service.id,
            service_version_id=service.current_version_id, scan_scope='image', complete=True,
            scanned_at=datetime(2099, 1, 1, tzinfo=timezone.utc), raw_payload=dict(first.raw_payload)))
        db.commit()
        assert evidence.readiness(db, service)['execution'].id == first.id


def test_image_scan_can_be_submitted_through_approval_api(tmp_path, monkeypatch):
    from app import cyber_approvals
    from test_portal import csrf
    seeded('image')
    monkeypatch.setattr(cyber_approvals, 'root', lambda: tmp_path)
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        for key in ('helm_source_files', 'helm_values_files'):
            body.pop(key)
        for key in ('charts', 'rendered_resources'):
            body['service_overview'].pop(key)
        execution.raw_payload = body
        db.commit()
        execution_id = execution.id
    client = new_client()
    ready = client.get('/api/services/payments-service/cyber-approval-readiness')
    assert ready.status_code == 200, ready.text
    assert ready.json()['ready'] and ready.json()['scan_date']
    submitted = client.post('/api/cyber-approvals', json={
        'service_key': 'payments-service', 'variant': 'current_service'},
        headers={'x-csrf-token': csrf(client)})
    assert submitted.status_code == 200, submitted.text
    with SessionLocal() as db:
        approval = db.get(cyber_approvals.CyberApproval, submitted.json()['id'])
        assert approval.status == 'pending'
        assert approval.source_execution_id == execution_id
        assert approval.snapshot['evidence_scope'] == 'current-image-scan'
        assert any('selected image scan only' in note for note in approval.snapshot['review_notes'])
        assert Path(approval.snapshot['evidence']['path']).is_file()


def test_image_evidence_never_falls_back_to_another_version():
    from app.models import ServiceVersion
    seeded('image')
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        version = ServiceVersion(service_id=service.id, version='unscanned')
        db.add(version)
        db.flush()
        service.current_version_id = version.id
        db.commit()
        ready = evidence.readiness(db, service)
        assert not ready['ready']
        assert ready['execution'] is None
        assert ready['scan_date'] is None
        assert 'exact current service version' in ready['blockers'][0]
        from app.service_exports import _service_sbom_components
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _service_sbom_components(service.service_key, db)
        assert exc.value.status_code == 422


def test_chart_root_under_charts_directory_is_retained():
    charts = evidence._charts({'charts/package-123/app/Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n',
                              'charts/package-123/app/values.yaml': 'replicas: 1\n'})
    assert len(charts) == 1
    assert charts[0]['source_root'] == 'charts/package-123/app'


def test_candidate_without_selection_returns_blockers():
    seeded()
    with SessionLocal() as db:
        result = evidence.readiness(db, db.scalar(select(Service)), 'cats_remediated')
        assert not result['ready']
        assert any('Candidate must belong' in item for item in result['blockers'])


def test_large_vendored_chart_inventory_is_complete_and_packaged(tmp_path, monkeypatch):
    import tarfile
    seeded()
    monkeypatch.setattr('app.service_exports.write_all', fake_export)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        declarations = []
        for index in range(90):
            name = f'component-{index}'
            declarations.append(f'- name: {name}\n  version: 1.0.0\n')
            body['helm_source_files'][f'app/charts/{name}/Chart.yaml'] = f'apiVersion: v2\nname: {name}\nversion: 1.0.0\n'
            body['service_overview']['charts'].append({'name': name, 'version': '1.0.0'})
        body['helm_source_files']['app/Chart.yaml'] += 'dependencies:\n' + ''.join(declarations)
        execution.raw_payload = body
        db.flush()
        ready = evidence.readiness(db, service)
        assert ready['ready'], ready['blockers']
        snapshot = evidence.freeze(db, service, SimpleNamespace(), ready, tmp_path)
        charts = [item for item in snapshot['artifacts'] if item['kind'] == 'chart']
        assert len(charts) == 1
        assert len(charts[0]['dependencies']) == 90
        with tarfile.open(charts[0]['path']) as archive:
            assert len([name for name in archive.getnames() if name.endswith('/Chart.yaml')]) == 91


@pytest.mark.parametrize('retained_digest', [D, 'registry.example/app@' + D])
def test_repeated_finding_image_digests_produce_one_artifact(retained_digest):
    seeded()
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        body['service_overview']['images'][0]['digest'] = retained_digest
        body['findings'] = [dict(body['findings'][0], image='registry.example/app:1',
            image_digest=retained_digest, cve=f'CVE-{i}') for i in range(250)]
        execution.raw_payload = body
        db.flush()
        result = evidence.readiness(db, db.scalar(select(Service)))
        assert result['ready'], result['blockers']
        images = [item for item in result['artifacts'] if item['kind'] == 'image']
        assert len(images) == 1
        assert images[0]['reference'] == 'registry.example/app@' + D


@pytest.mark.parametrize('digest,message', [
    ('bad-digest', 'Invalid retained image digest'),
    ('sha256:' + 'b' * 64, 'Conflicting retained image digests'),
    ('other.example/app@' + D, 'Retained image digest repository does not match'),
])
def test_repeated_image_errors_are_unique_and_still_block_approval(digest, message):
    seeded()
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        body['findings'] = [dict(body['findings'][0], image='registry.example/app:1',
            image_digest=digest, cve=f'CVE-{i}') for i in range(250)]
        # A separate affected image must retain its own diagnostic.
        body['findings'].append(dict(body['findings'][0], image='registry.example/other:1',
            image_digest='bad-digest'))
        execution.raw_payload = body
        db.flush()
        result = evidence.readiness(db, db.scalar(select(Service)))
        assert not result['ready']
        assert result['blockers'].count(message + ': registry.example/app:1') == 1
        assert 'Invalid retained image digest: registry.example/other:1' in result['blockers']
        assert len(result['blockers']) == len(set(result['blockers']))


@pytest.mark.parametrize('reference,retained', [
    ('tsuru/nginx-operator:0.17.0', 'docker.io/tsuru/nginx-operator'),
    ('nginx:1', 'docker.io/library/nginx'),
    ('docker.io/nginx:1', 'index.docker.io/library/nginx'),
    ('localhost:5000/team/app:1', 'localhost:5000/team/app'),
])
def test_repository_digest_accepts_same_image_and_docker_hub_aliases(reference, retained):
    pinned, digest = evidence._identity(reference, retained + '@' + D)
    assert digest == D
    assert pinned.endswith('@' + D)


@pytest.mark.parametrize('retained', [
    'registry.example/app@sha256:short',
    'registry.example/app@sha256:' + 'b' * 64,
    'registry.example/other@' + D,
    'other.example/app@' + D,
    'registry.example/app@@' + D,
])
def test_repository_digest_rejects_invalid_or_inconsistent_identity(retained):
    with pytest.raises(ValueError):
        evidence._identity('registry.example/app@' + D, retained)


@pytest.mark.parametrize('legacy_digest', [False, True])
def test_tag_only_vulnerable_image_can_be_submitted_without_helm_or_config(tmp_path, monkeypatch, legacy_digest):
    seeded()
    monkeypatch.setattr('app.service_exports.write_all', fake_export)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        body.pop('helm_source_files')
        body.pop('helm_values_files')
        reference = 'tsuru/nginx-operator:0.17.0'
        body['service_overview'] = {'images': [{'image': reference}]}
        body['findings'] = [dict(body['findings'][0], image=reference,
            image_digest=reference if legacy_digest else None, cve=f'CVE-{i}') for i in range(250)]
        execution.raw_payload = body
        db.flush()
        ready = evidence.readiness(db, service)
        assert ready['ready'], ready['blockers']
        assert len(ready['artifacts']) == 1
        assert ready['artifacts'][0]['resolve_at_publication']
        assert sum('Image identity' in note for note in ready['review_notes']) == 1
        assert any('No Helm charts' in note for note in ready['review_notes'])
        assert any('Configuration coverage' in note for note in ready['review_notes'])
        snapshot = evidence.freeze(db, service, SimpleNamespace(), ready, tmp_path)
        assert len(snapshot['findings']['vulnerabilities']) == 250
        assert snapshot['review_notes'] == ready['review_notes']


@pytest.mark.parametrize('missing', [None, 'sbom/image1.json', 'scans/image1-grype-after.json', 'images/image1.tar'])
def test_image_only_candidate_retains_archive_and_findings_without_runtime_pass(tmp_path, monkeypatch, missing):
    from app import main
    from app.models import RemediationExecution
    import hashlib
    seeded()
    monkeypatch.setattr(main, 'REMEDIATION_JOB_ROOT', tmp_path)
    monkeypatch.setattr('app.service_exports.write_all', fake_export)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        archive_bytes = b'retained candidate image'
        files = {'images/image1.tar': archive_bytes, 'sbom/image1.json': b'{"artifacts": []}',
            'scans/image1-grype-after.json': b'{"matches": [{"vulnerability": {"id": "CVE-REMAINING"}}]}'}
        manifest = {'source_execution_id': execution.id, 'source_version_id': service.current_version_id,
            'images': [{'original': 'registry.example/app:1', 'remediated': 'local/candidate:patched',
                'archive_path': 'images/image1.tar', 'artifact_sha256': hashlib.sha256(archive_bytes).hexdigest(),
                'evidence': {'grype': 'complete', 'sbom': 'complete'}}]}
        folder = tmp_path / 'imagecandidate'
        folder.mkdir()
        candidate = folder / 'candidate.zip'
        with ZipFile(candidate, 'w') as archive:
            archive.writestr('manifest.json', json.dumps(manifest))
            for name, content in files.items():
                if name != missing:
                    archive.writestr(name, content)
        record = RemediationExecution(job_key='imagecandidate', service_id=service.id, requested_by_id=1,
            source_execution_id=execution.id, source_version_id=service.current_version_id,
            status='failed', remediation_status='complete', verification_status='failed',
            artifact_path=str(candidate), artifact_digest=evidence.file_digest(candidate),
            scan_results={'images': {'image1': {}}, 'vulnerabilities': {'status': 'FAIL'}},
            after_snapshot={'findings': [{'cve': 'CVE-REMAINING'}]})
        db.add(record); db.commit()
        ready = evidence.readiness(db, service, 'cats_remediated', record.id)
        if missing:
            assert not ready['ready']
            return
        assert ready['ready'], ready['blockers']
        snapshot = evidence.freeze(db, service, SimpleNamespace(), ready, tmp_path / 'frozen')
        item = next(item for item in snapshot['artifacts'] if item.get('format') == 'docker-archive')
        assert Path(item['path']).read_bytes() == archive_bytes
        assert snapshot['findings']['vulnerability_scans']['image1']['matches'][0]['vulnerability']['id'] == 'CVE-REMAINING'
        assert any('No Helm charts' in note for note in snapshot['review_notes'])


def test_absent_rendered_output_is_review_note_when_chart_sources_are_retained():
    seeded()
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        body = json.loads(json.dumps(execution.raw_payload))
        body['service_overview']['rendered_resources'] = []
        execution.raw_payload = body
        db.commit()
        ready = evidence.readiness(db, db.scalar(select(Service)))
        assert ready['ready'], ready['blockers']
        assert 'Rendered deployment evidence is unavailable.' in ready['review_notes']
        assert any(item['kind'] == 'chart' for item in ready['artifacts'])
