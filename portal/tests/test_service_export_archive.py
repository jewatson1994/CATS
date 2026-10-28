"""The All download contains the same permission-scoped, configured exports."""
from export_job_helpers import completed_export
import json
from io import BytesIO
from zipfile import ZipFile

from openpyxl import load_workbook
from sqlalchemy import select

from app.models import AuditEvent, Execution, Service, ServiceMetadata, utcnow
from app.purpose_exports import CATALOG, default_template
from test_portal import SessionLocal, add_user, csrf, new_client, pipeline_headers, setup_function
from test_purpose_exports import _service
from test_retained_evidence_exports import collected, pipeline_payload


def _archive(client):
    response = completed_export(client, '/services/export-test/exports/all.zip')
    assert response.status_code == 200, response.text
    assert response.headers['content-type'] == 'application/zip'
    assert 'export-test-exports.zip' in response.headers['content-disposition']
    return ZipFile(BytesIO(response.content))


def _cells(data):
    book = load_workbook(BytesIO(data))
    return {sheet.title: list(sheet.values) for sheet in book}


def test_all_matches_individual_downloads_and_configured_templates():
    _service()
    client = new_client()
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == 'export-test'))
        db.add(Execution(service_id=service.id, execution_key='export-evidence', scanned_at=utcnow(),
            complete=True, raw_payload={
                'rendered_resources': [{'apiVersion': 'v1', 'kind': 'Service',
                    'metadata': {'name': 'web'}, 'spec': {'ports': [{'port': 443}]}}],
                'sbom_components': [{'name': 'openssl', 'version': '3.0'}],
            }))
        db.commit()
    for kind in CATALOG:
        columns = list(reversed(default_template(kind)))
        columns[0].update(heading=f'Configured {kind}', enabled=True)
        columns[-1]['enabled'] = False
        response = client.post(f'/admin/configuration/export-templates/{kind}', data={
            'csrf_token': csrf(client), 'field': [c['field'] for c in columns],
            'heading': [c['heading'] for c in columns],
            'enabled': [c['field'] for c in columns if c['enabled']],
        }, follow_redirects=False)
        assert response.status_code == 303
    with _archive(client) as archive:
        assert set(archive.namelist()) == {'diagrams.zip', 'ppsm.xlsx', 'poam.xlsx',
            'mitigations.xlsx', 'asset_list.xlsx', 'findings.xlsx', 'sbom-components.json', 'cats-service.zip',
            'raw-scanner-outputs.zip.unavailable.txt', 'sboms.zip.unavailable.txt'}
        for kind in (*CATALOG, 'mitigations', 'findings'):
            individual = completed_export(client, f'/services/export-test/exports/{kind}.xlsx')
            assert individual.status_code == 200
            cells = _cells(archive.read(f'{kind}.xlsx'))
            assert cells == _cells(individual.content)
            if kind in CATALOG:
                assert next(iter(cells.values()))[0][0] == f'Configured {kind}'
                assert 'Service' not in next(iter(cells.values()))[0]
        assert json.loads(archive.read('sbom-components.json')) == completed_export(client,
            '/services/export-test/exports/sbom.json').json()
        with ZipFile(BytesIO(archive.read('diagrams.zip'))) as diagrams, ZipFile(BytesIO(
                completed_export(client, '/services/export-test/exports/diagrams.zip').content)) as individual:
            assert diagrams.namelist() == individual.namelist()
            for name in diagrams.namelist():
                assert diagrams.read(name) == individual.read(name)
        with ZipFile(BytesIO(archive.read('cats-service.zip'))) as bundle:
            assert bundle.testzip() is None
            assert bundle.namelist()
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == 'bundle.export'))


def test_missing_evidence_is_explained_and_bundle_permission_is_respected():
    _service()
    add_user('archive-assessor', 'Assessor')
    with _archive(new_client('archive-assessor')) as archive:
        assert 'cats-service.zip' not in archive.namelist()
        assert len(archive.namelist()) == 9
        assert b'No architecture evidence' in archive.read('diagrams.zip.unavailable.txt')
        assert b'No retained SBOM' in archive.read('sbom-components.json.unavailable.txt')
        assert b'No retained original Grype/Trivy' in archive.read('raw-scanner-outputs.zip.unavailable.txt')
        assert b'No retained SBOM documents' in archive.read('sboms.zip.unavailable.txt')
        assert 'asset_list.xlsx' in archive.namelist()


def test_all_download_accepts_portable_manifest_over_64k():
    _service()
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == 'export-test'))
        db.add(ServiceMetadata(service_id=service.id, values={
            f"api_key_{index:04d}_{'x' * 80}": "sensitive" for index in range(1000)}))
        db.commit()
    with _archive(new_client()) as archive:
        with ZipFile(BytesIO(archive.read('cats-service.zip'))) as bundle:
            assert bundle.getinfo('manifest.json').file_size > 65536
            assert bundle.testzip() is None


def test_all_obeys_service_scope():
    _service()
    with SessionLocal() as db:
        other = Service(service_key='other', name='Other')
        db.add(other)
        db.commit()
        other_id = other.id
    add_user('scoped-export', 'Assessor', service_id=other_id)
    client = new_client('scoped-export')
    for filename in ('all.zip', 'raw-scanner-outputs.zip', 'sboms.zip'):
        response = client.get(f'/services/export-test/exports/{filename}')
        assert response.status_code in (403, 404)


def test_retained_documents_reach_individual_and_all_queued_exports(collected):
    retained, grype, trivy, syft = collected
    client = new_client()
    payload = pipeline_payload(**retained)
    payload['service']['groups'] = ['Test group']
    response = client.post('/api/v1/pipeline-results', json=payload, headers=pipeline_headers)
    assert response.status_code == 201, response.text
    # Idempotent delivery includes the same retained documents.
    assert client.post('/api/v1/pipeline-results', json=payload, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        assert len(db.scalars(select(Execution).where(Execution.execution_key == payload['execution_id'])).all()) == 1
    with _archive(client) as all_exports:
        for filename in ('raw-scanner-outputs.zip', 'sboms.zip'):
            response = completed_export(client, f'/services/export-test/exports/{filename}')
            assert response.status_code == 200, response.text
            with ZipFile(BytesIO(response.content)) as individual, ZipFile(BytesIO(all_exports.read(filename))) as combined:
                assert individual.namelist() == combined.namelist()
                for member in individual.namelist():
                    assert individual.read(member) == combined.read(member)
                if filename == 'raw-scanner-outputs.zip':
                    assert individual.read('grype-json/image-results.json') == grype
                    assert individual.read('trivy-json/chart.json') == trivy
                else:
                    assert individual.read('syft-json/image.json') == syft
                    assert len(individual.namelist()) == 5
