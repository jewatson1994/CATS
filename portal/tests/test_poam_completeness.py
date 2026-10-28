"""Service POA&M includes exception history and mitigations without duplicate requests."""
from collections import Counter
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, insert
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (Service, User, Finding, PolicyFinding, PoamEntry,
                        ExceptionRecord, PolicyExceptionRecord, WorkflowRequest, utcnow)
from app.poam_query import service_poam_page, poam_export_entries, poam_service_summaries


@pytest.fixture
def complete_poam():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key='complete / key', name='Complete')
        other = Service(service_key='hidden', name='Hidden')
        actor = User(username='reviewer', display_name='Reviewer')
        db.add_all([service, other, actor]); db.flush()
        finding = Finding(service_id=service.id, cve='CVE-2026-1000', severity='High',
                          first_seen=now, episode_started=now, last_seen=now)
        hidden = Finding(service_id=other.id, cve='CVE-HIDDEN', severity='Critical',
                         first_seen=now, episode_started=now, last_seen=now)
        policy = PolicyFinding(service_id=service.id, identity_key='config', finding='CFG-1',
            title='Configuration title', description='Scanner description', severity='Medium',
            first_seen=now, episode_started=now, last_seen=now)
        db.add_all([finding, hidden, policy]); db.flush()
        mitigation = PoamEntry(service_id=service.id, finding_id=finding.id, item_type='mitigation',
            title='Patch package', description='Approved mitigation', remediation='Upgrade package',
            created_by_id=actor.id, approved_by_id=actor.id, status='active', due_date=now-timedelta(days=1))
        rejected = PoamEntry(service_id=service.id, item_type='missing_evidence', title='Review evidence',
            description='Evidence needed', remediation='Collect SBOM', created_by_id=actor.id, status='rejected')
        db.add_all([mitigation, rejected]); db.flush()
        for index, status in enumerate(('active', 'expired', 'revoked', 'scheduled')):
            db.add(ExceptionRecord(finding_id=finding.id, justification=f'{status} exception reason',
                approved_by='Reviewer', starts_at=now+timedelta(days=1) if status == 'scheduled' else now-timedelta(days=4),
                expires_at=now if status == 'expired' else now+timedelta(days=4),
                revoked_at=now if status == 'revoked' else None, created_at=now-timedelta(minutes=index)))
        db.add(PolicyExceptionRecord(policy_finding_id=policy.id, justification='Configuration exception reason',
            approved_by='Reviewer', starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=3)))
        for status in ('pending', 'rejected', 'approved'):
            db.add(WorkflowRequest(service_id=service.id, policy_finding_id=policy.id,
                request_type='exception', status=status, justification=f'{status} request reason',
                requested_by_id=actor.id, requested_expires_at=now+timedelta(days=2)))
        db.add(WorkflowRequest(service_id=service.id, finding_id=finding.id, poam_id=mitigation.id,
            request_type='exception', status='pending', justification='Already represented by entry',
            requested_by_id=actor.id, requested_expires_at=now+timedelta(days=2)))
        db.add(ExceptionRecord(finding_id=hidden.id, justification='Hidden exception', approved_by='Reviewer',
            starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=1)))
        service_id, other_id, finding_id, actor_id = service.id, other.id, finding.id, actor.id
        db.commit(); db.expunge_all()
        yield db, service_id, other_id, finding_id, actor_id, now
    engine.dispose()


def test_combined_service_page_history_filters_links_and_counts(complete_poam):
    db, sid, _, _, _, now = complete_poam
    entries, info = service_poam_page(db, sid, now, 'all', 'newest', 1, 25)
    assert info['total_items'] == 9
    assert Counter(entry.status for entry in entries) == {
        'active': 3, 'pending_approval': 1, 'rejected': 2, 'expired': 1, 'revoked': 1, 'scheduled': 1}
    assert len({entry.id for entry in entries}) == len(entries)
    assert all(entry.service_id == sid for entry in entries)
    synthetic = [entry for entry in entries if entry.item_type == 'exception']
    assert len(synthetic) == 7
    assert all(entry.detail_url.startswith('/services/complete%20%2F%20key') for entry in synthetic)
    assert all('approved request reason' != entry.description for entry in entries)
    assert all('Already represented by entry' != entry.description for entry in entries)
    for status, count in [('active', 3), ('pending_approval', 1), ('rejected', 2), ('expired', 1), ('revoked', 1), ('scheduled', 1), ('overdue', 1)]:
        subset, pagination = service_poam_page(db, sid, now, status, 'due', 99, 25)
        assert len(subset) == pagination['total_items'] == count
        assert pagination['page'] == 1
    summary = list(poam_service_summaries(db, [sid], now))[0]
    assert dict(summary) == {'service_id': sid, 'total': 9, 'active': 3, 'pending': 1, 'overdue': 1}


def test_exception_pages_hydrate_only_selected_records(complete_poam):
    db, sid, _, finding_id, _, now = complete_poam
    db.execute(insert(ExceptionRecord), [dict(finding_id=finding_id, justification=f'History {index}',
        approved_by='Reviewer', starts_at=now, expires_at=now+timedelta(days=1),
        created_at=now+timedelta(seconds=index+1)) for index in range(200)])
    db.commit(); db.expunge_all()
    loaded = []
    statements = []
    event.listen(db, 'loaded_as_persistent', lambda session, obj: loaded.append(obj))
    event.listen(db.bind, 'before_cursor_execute', lambda conn, cursor, statement, parameters, context, many: statements.append(statement))
    entries, info = service_poam_page(db, sid, now, 'all', 'newest', 3, 25)
    assert info['total_items'] == 209 and len(entries) == 25
    assert sum(isinstance(obj, ExceptionRecord) for obj in loaded) == 25
    assert sum(isinstance(obj, Finding) for obj in loaded) == 1
    assert not any(isinstance(obj, (PoamEntry, WorkflowRequest, PolicyExceptionRecord)) for obj in loaded)
    assert len(statements) == 5  # Count, page keys, records, finding, service.


def test_purpose_and_complete_and_legacy_exports_have_same_complete_poam(complete_poam):
    from app.purpose_exports import rows_for, workbook_for, default_template
    from app.service_export import build_service_workbook
    from app.main import poam_workbook
    db, sid, _, _, _, now = complete_poam
    service = db.get(Service, sid)
    entries = poam_export_entries(db, [sid], now=now)
    purpose = rows_for(db, service, 'poam')
    assert len(purpose) == len(entries) == 9
    assert Counter(row['item_type'] for row in purpose) == {'exception': 7, 'mitigation': 1, 'missing_evidence': 1}
    assert {row['exception_status'] for row in purpose if row['item_type'] == 'exception'} == {
        'Active', 'Expired', 'Revoked', 'Scheduled', 'Pending Approval', 'Rejected'}
    assert 'Configuration exception reason' in {row['description'] for row in purpose}
    assert any(row['mitigation'] == 'Upgrade package' for row in purpose)
    assert workbook_for(db, service, 'poam', default_template('poam')).active.max_row == 10
    complete = build_service_workbook(service, {}, {}, now, poam_entries=entries)
    assert complete['POA&Ms'].max_row == 10
    assert complete['Exceptions'].max_row == 8
    assert complete['Mitigations'].max_row == 2
    assert dict(complete['Summary'].values)['POA&Ms'] == 9
    legacy = poam_workbook(entries).active
    assert legacy.max_row == 10
    entries[0].description = '=HYPERLINK("https://example.invalid","formula")'
    literal_export = poam_workbook(entries).active
    assert literal_export['E2'].data_type == 's'
    assert literal_export['E2'].value == entries[0].description


def test_export_permissions_and_service_search_include_exception_only_services(complete_poam):
    from app.main import scoped_poam_export_entries
    db, sid, other_id, _, _, _ = complete_poam
    scoped = SimpleNamespace(accessible_service_ids=lambda permission: {sid})
    assert len(scoped_poam_export_entries(db, scoped)) == 9
    assert scoped_poam_export_entries(db, scoped, service_id=other_id) == []
    assert scoped_poam_export_entries(db, scoped, service_term='Hidden') == []
    unrestricted = SimpleNamespace(accessible_service_ids=lambda permission: None)
    assert len(scoped_poam_export_entries(db, unrestricted, service_term='Hidden')) == 1
    assert len(scoped_poam_export_entries(db, scoped, status_filter='pending_approval')) == 1
    assert len(scoped_poam_export_entries(db, scoped, due_overdue=True)) == 1
    with pytest.raises(HTTPException) as denied:
        scoped_poam_export_entries(db, SimpleNamespace(accessible_service_ids=lambda permission: set()))
    assert denied.value.status_code == 403


def test_synthetic_dto_links_and_import_permissions(complete_poam):
    from app.frontend_governance import project_governance
    db, sid, _, _, _, now = complete_poam
    entries, pagination = service_poam_page(db, sid, now, 'all', 'newest', 1, 25)
    context = {'service': db.get(Service, sid), 'entries': entries, **pagination}
    data = {}
    project_governance(data, 'poam_service.html', context, lambda permission, service_id: permission in {'poam.import', 'exception.request'} and service_id == sid, {})
    assert data['review_import_kinds'] == ['poams', 'mitigations', 'exceptions']
    synthetic = [item for item in data['entries'] if item['item_type'] == 'exception']
    assert all(item['detail_url'].startswith('/services/') for item in synthetic)
    assert all(item['source_type'] != 'poam' for item in synthetic)
    assert all(item['approved_by'] == 'Reviewer' for item in synthetic if item['status'] in {'active', 'expired', 'revoked', 'scheduled'})
    denied = {}
    project_governance(denied, 'poam_service.html', context, lambda *args: False, {})
    assert denied['review_import_kinds'] == []
