"""Current replica views stay pinned to approval, while scan history is retained."""
from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select

from app import main, models as m
from app.findings_query import prepare_findings_view, load_page_support
from app.portable_release_capture import _finding_decisions
from app.replica_findings import configuration
from app.replica_import import reconcile
from app.replica_models import ReplicaServiceState
from app.service_tab_queries import prepare_service_tab_view
from app.simplified_queries import group_page
from test_replica_import import replica_import, verified


def test_current_views_keep_approved_scan_when_snapshot_has_newer_execution(replica_import, monkeypatch):
    f = replica_import
    finding = m.Finding(service_id=f.service.id, cve='CVE-2026-1234', severity='High',
        first_seen=f.now, episode_started=f.now, last_seen=f.now, active=True)
    f.origin.add(finding)
    f.origin.flush()
    f.origin.add(m.FindingObservation(finding_id=finding.id, execution_id=f.execution.id,
        image='approved-image', package='approved-package', fixed_version='2',
        evidence={'remediation': 'Approved remediation'}))
    f.origin.flush()
    policy = {**main.CONFIG_DEFAULTS, 'compliance_mode': 'raw'}
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'kev_cves', lambda: set())
    monkeypatch.setattr(main, 'epss_scores', lambda: {})
    decisions = _finding_decisions(f.origin, f.service.id, policy, f.now, f.execution.id)
    newer = m.Execution(service_id=f.service.id, service_version_id=f.service.current_version_id,
        execution_key='newer-unapproved-scan', scanned_at=f.now+timedelta(days=1), complete=False,
        raw_payload={**f.execution.raw_payload, 'execution_id': 'newer-unapproved-scan',
            'scanned_at': (f.now+timedelta(days=1)).isoformat(), 'complete': False,
            'skipped_images': ['newer-image']})
    f.origin.add(newer)
    f.origin.flush()
    f.origin.add_all([m.FindingObservation(finding_id=finding.id, execution_id=newer.id,
        image=image, package='newer-package', fixed_version='3',
        evidence={'remediation': 'Newer remediation'}) for image in ('newer-one', 'newer-two')])
    incoming = verified(f)
    incoming['state']['extension'].update(decisions)
    incoming['state']['extension']['display'] = {'configuration': policy, 'captured_at': f.now.isoformat()}
    monkeypatch.setenv('CATS_MODE', 'replica')
    imported = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    service = f.db.get(m.Service, imported['service_id'])
    approved_id = f.db.get(ReplicaServiceState, service.id).active_execution_id
    assert len(service.executions) == 2
    config = configuration(f.db, service.id, main.CONFIG_DEFAULTS)
    view = main.service_view(service, f.now, config)
    assert view['last_execution'] == f.now
    assert view['evidence_state'] == 'Complete' and view['skipped_images'] == []

    for header_only in (False, True):
        header, proxy, current = prepare_service_tab_view(f.db, service, f.now, config,
            main.service_view, header_only=header_only)
        assert current.id == approved_id
        assert [row.id for row in proxy.executions] == [approved_id]
        assert header['last_execution'] == f.now and header['evidence_state'] == 'Complete'

    _, proxy, current = prepare_findings_view(f.db, service, f.now, config, main.service_view)
    assert proxy.findings[0].observations[0].package == 'approved-package'
    assert load_page_support(f.db, service.id, proxy.findings, current) == {proxy.findings[0].id: ['approved-image']}
    groups, _, _ = group_page(f.db, service, current, f.now, config)
    assert groups[0]['package'] == 'approved-package'
    auth = SimpleNamespace(has=lambda *args: True)
    members = main.simplified_members(service.service_key, groups[0]['group_id'], severity=[], db=f.db, auth=auth)
    assert members['items'][0]['image_count'] == 1

    monkeypatch.setattr(main, 'page_context', lambda auth, **values: values)
    monkeypatch.setattr(main, 'remediation_enabled', lambda db: False)
    monkeypatch.setattr(main.templates, 'TemplateResponse', lambda request, template, context: context)
    finding_id = f.db.scalar(select(m.Finding.id).where(m.Finding.service_id == service.id))
    detail = main.finding_detail(service.service_key, finding_id, None, f.db, auth)
    assert detail['evidence']['remediation'] == 'Approved remediation'
    assert [row.image for row in detail['current_observations']] == ['approved-image']
    assert len(detail['history']) == 3

    # The existing full-mode latest-scan behavior is deliberately unchanged.
    monkeypatch.setenv('CATS_MODE', 'full')
    full = main.service_view(service, f.now+timedelta(days=1), policy)
    assert full['last_execution'] == f.now+timedelta(days=1)
    assert full['skipped_images'] == ['newer-image']
