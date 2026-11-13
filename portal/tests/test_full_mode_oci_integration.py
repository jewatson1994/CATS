"""Full-suite integration keeps imported evidence and local workers independent."""
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import main, frontend, replica_sync
from app.models import DeploymentValidationRun, Execution, Service, ServiceImage, User
from test_replica_authorization import replica


def finish(coroutine):
    # These stubbed resource contexts complete without IO or an event loop.
    with pytest.raises(StopIteration):
        coroutine.send(None)


def test_full_lifespan_runs_oci_consumer_alongside_normal_workers(monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setenv('INTELLIGENCE_DATABASE_URL', 'sqlite://')
    events, tasks = [], []

    @asynccontextmanager
    async def consumer():
        events.append('oci-enter')
        try:
            yield
        finally:
            events.append('oci-exit')

    @asynccontextmanager
    async def previews(_session):
        events.append('previews-enter')
        try:
            yield
        finally:
            events.append('previews-exit')

    class Task:
        cancelled = False
        def cancel(self):
            self.cancelled = True
        def __await__(self):
            if False:
                yield
            raise main.asyncio.CancelledError()

    def spawn(coroutine):
        coroutine.close()
        task = Task()
        tasks.append(task)
        return task

    monkeypatch.setattr(main.asyncio, 'create_task', spawn)
    monkeypatch.setattr(replica_sync, 'replica_lifespan', consumer)
    monkeypatch.setattr(main, 'preview_cleanup_lifespan', previews)
    monkeypatch.setattr(main.validator_management, 'recover_operations', lambda: events.append('recover'))
    monkeypatch.setattr(main, 'DEPLOYMENT_VALIDATION_WORKERS', SimpleNamespace(submit=lambda fn: events.append('validation')))
    monkeypatch.setattr(main, '_start_read_model_maintenance', lambda: events.append('read-models'))
    context = main.app_lifespan(None)
    finish(context.__aenter__())
    assert events == ['recover', 'validation', 'read-models', 'previews-enter', 'oci-enter']
    assert len(tasks) == 2
    finish(context.__aexit__(None, None, None))
    assert events[-2:] == ['oci-exit', 'previews-exit']
    assert all(task.cancelled for task in tasks)


def test_full_mode_scan_ingestion_cannot_replace_imported_service(replica, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    with replica.sessions() as db:
        service = db.get(Service, replica.service_id)
        original = service.name
        payload = SimpleNamespace(service=SimpleNamespace(id=service.service_key))
        with pytest.raises(HTTPException) as denied:
            main.ingest_payload(payload, db)
        assert denied.value.status_code == 409
        assert service.name == original


def test_mixed_configuration_and_image_status_preserve_imported_state(replica, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'PUBLIC_JOBS', {'publisher-job': {'status': 'error'},
                                           'missing-local-job': {'status': 'error'}})
    with replica.sessions() as db:
        imported = db.get(Service, replica.service_id)
        local = Service(service_key='local-status', name='Local')
        db.add(local)
        db.flush()
        imported_image = ServiceImage(service_id=imported.id, image_reference='nginx:1',
            scan_status='scanning', scan_job_id='publisher-job')
        local_image = ServiceImage(service_id=local.id, image_reference='nginx:1',
            scan_status='scanning', scan_job_id='missing-local-job')
        db.add_all([imported_image, local_image])
        db.commit()
        configurations = main.configurations_for_services(db, [local, imported], {'overdue_days': '17'})
        assert configurations[local.id]['overdue_days'] == '17'
        assert '_replica_execution_id' not in configurations[local.id]
        assert '_replica_execution_id' in configurations[imported.id]
        assert main.configuration_for_service(db, imported) == configurations[imported.id]
        main.artifact_image_status(imported.service_key, db, None)
        main.artifact_image_status(local.service_key, db, None)
        assert imported_image.scan_status == 'scanning'
        assert local_image.scan_status == 'failed'


@pytest.mark.parametrize('representation', ['orm', 'namespace', 'dict'])
def test_imported_service_page_flags_do_not_switch_full_navigation(replica, monkeypatch, representation):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'SessionLocal', replica.sessions)
    with replica.sessions() as db:
        service = db.get(Service, replica.service_id)
        auth = SimpleNamespace(user=db.get(User, replica.user_id),
            session=SimpleNamespace(id='test', csrf_token='csrf'), csrf_token='csrf',
            effective_assignments=[], accessible_service_ids=lambda permission: set(),
            has=lambda *args: False)
        subject = (SimpleNamespace(id=service.id) if representation == 'namespace'
                   else {'id': service.id} if representation == 'dict' else service)
        context = main.page_context(auth, view={'service': subject})
        assert context['imported_service'] and context['read_only']
        request = Request({'type': 'http', 'method': 'GET', 'path': '/imported-releases',
                           'headers': [], 'query_string': b''})
        page = frontend.page_data(request, 'imported_releases.html', context)
        assert page['page'] == 'imported_releases'
        assert page['data']['cats_mode'] == 'full'
        assert page['data']['imported_service'] is True
        assert page['data']['read_only'] is True


def test_imported_release_page_accepts_service_scoped_readers(monkeypatch):
    monkeypatch.setattr(main, 'page_context', lambda auth: {})
    monkeypatch.setattr(main.templates, 'TemplateResponse', lambda request, name, context: name)
    auth = SimpleNamespace(accessible_service_ids=lambda permission: {42})
    assert main.imported_releases_page(None, auth) == 'imported_releases.html'
    auth.accessible_service_ids = lambda permission: set()
    with pytest.raises(HTTPException) as denied:
        main.imported_releases_page(None, auth)
    assert denied.value.status_code == 403


def test_startup_repairs_only_change_locally_managed_services(replica, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'SessionLocal', replica.sessions)
    with replica.sessions() as db:
        imported = db.get(Service, replica.service_id)
        imported.name, imported.staging_original_name = 'Publisher staged name', 'Publisher original'
        imported.staging_name_generated = True
        local = Service(service_key='repair-local', name='Local staged name',
            staging_original_name='Local original', staging_name_generated=True)
        db.add(local)
        db.commit()
        local_id = local.id
    assert main.reconcile_generated_active_names() == 1
    with replica.sessions() as db:
        imported, local = db.get(Service, replica.service_id), db.get(Service, local_id)
        assert imported.name == 'Publisher staged name' and imported.staging_name_generated
        assert local.name == 'Local original' and not local.staging_name_generated
        imported.lifecycle_status = local.lifecycle_status = 'staged'
        for item in (imported, local):
            db.add(ServiceImage(service_id=item.id, image_reference='nginx:1'))
            db.add(Execution(service_id=item.id, execution_key='repair-'+str(item.id),
                scanned_at=replica.now, complete=True, raw_payload={'policy_findings': [{'finding': 'test'}]}))
        db.commit()
    assert main.promote_staged_services_with_evidence() == 1
    with replica.sessions() as db:
        assert db.get(Service, replica.service_id).lifecycle_status == 'staged'
        assert db.get(Service, local_id).lifecycle_status == 'active'
    repaired = []
    monkeypatch.setattr(main, 'sync_policy_findings', lambda db, service, *args, **kwargs: repaired.append(service.id))
    main.backfill_policy_findings(force=True)
    assert repaired == [local_id]


def test_validation_jobs_and_recovery_preserve_publisher_evidence(replica, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'SessionLocal', replica.sessions)
    monkeypatch.setattr(main, 'deployment_validation_enabled', lambda: False)
    with replica.sessions() as db:
        imported = db.get(Service, replica.service_id)
        local = Service(service_key='validation-local', name='Local validation')
        db.add(local)
        db.flush()
        with pytest.raises(HTTPException) as denied:
            main._new_validation_run(db, imported, None)
        assert denied.value.status_code == 409
        local_run, attempted = main._new_validation_run(db, local, None)
        assert not attempted and local_run.status == 'NOT_ATTEMPTED'
        publisher_run = DeploymentValidationRun(run_key='publisher-validation',
            service_id=imported.id, status='QUEUED', phase='QUEUED',
            cluster_name='publisher-cluster', created_at=replica.now - timedelta(days=2))
        local_run.status = local_run.phase = 'QUEUED'
        local_run.created_at = replica.now - timedelta(days=2)
        local_run.cluster_name = 'local-cluster'
        db.add(publisher_run)
        db.commit()
        imported_run_id, local_run_id = publisher_run.id, local_run.id

    main._validation_progress(imported_run_id, 'PREFLIGHT')
    main._run_deployment_validation(imported_run_id)
    cleaned = []
    monkeypatch.setattr(main, 'cleanup_stale_clusters', lambda names, **kwargs:
        (cleaned.extend(names) or {'deleted': names, 'failed': []}))
    main.recover_stale_validation_runs()
    assert cleaned == ['local-cluster']
    with replica.sessions() as db:
        imported, local = db.get(DeploymentValidationRun, imported_run_id), db.get(DeploymentValidationRun, local_run_id)
        assert (imported.status, imported.phase, imported.started_at, imported.completed_at) == ('QUEUED', 'QUEUED', None, None)
        assert imported.cluster_name == 'publisher-cluster'
        assert local.phase == 'COMPLETE' and local.cleanup_status == 'COMPLETE'


@pytest.mark.parametrize('failure', ['execution', 'scheduling'])
def test_validation_failure_handlers_preserve_imported_runs(replica, monkeypatch, failure):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'SessionLocal', replica.sessions)
    with replica.sessions() as db:
        run = DeploymentValidationRun(run_key='publisher-failure', service_id=replica.service_id,
            status='QUEUED', phase='QUEUED', reason='Captured publisher reason')
        db.add(run)
        db.commit()
        run_id = run.id

    def fail(*args):
        raise RuntimeError('worker unavailable')

    if failure == 'execution':
        monkeypatch.setattr(main, '_execute_deployment_validation', fail)
        main._run_deployment_validation(run_id)
    else:
        monkeypatch.setattr(main, 'DEPLOYMENT_VALIDATION_WORKERS', SimpleNamespace(submit=fail))
        main._submit_validation_run(run_id)
    with replica.sessions() as db:
        run = db.get(DeploymentValidationRun, run_id)
        assert (run.status, run.phase, run.reason, run.completed_at) == ('QUEUED', 'QUEUED', 'Captured publisher reason', None)
