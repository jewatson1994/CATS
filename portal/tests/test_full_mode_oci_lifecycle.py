"""Reassessment maintenance leaves publisher-owned records untouched."""
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import main, oci_lifecycle as lifecycle
from app.cyber_approvals import CyberApproval, digest
from app.durable_jobs import DurableJob, now
from test_full_mode_imported_writes import mixed


@pytest.mark.parametrize('status', ['approved', 'revoked', 'distribution'])
def test_due_schedule_skips_imported_without_blocking_local(mixed, status):
    clock = now()
    with mixed.sessions() as db:
        rows = [CyberApproval(service_id=identity, source_execution_id=41, variant='current_service',
            status='approved', snapshot={}, snapshot_digest=digest({}))
            for identity in (mixed.local, mixed.imported)]
        if status == 'revoked':
            rows[1].revoked_at = clock
        if status == 'distribution':
            rows[1].snapshot = {'distribution': {'id': 'captured'}}
        db.add_all(rows); db.flush()
        schedules = [lifecycle.OCIReassessmentSchedule(approval_id=row.id, actor_id=mixed.user,
            interval_days=7, next_run=clock-timedelta(days=1)) for row in rows]
        db.add_all(schedules); db.commit()
        retained_due = schedules[1].next_run
        lifecycle.enqueue_due(db, clock)
        assert schedules[1].enabled and schedules[1].next_run == retained_due
        assert schedules[0].next_run == clock+timedelta(days=7)
        assert [job.service_id for job in db.scalars(select(DurableJob))] == [mixed.local]


def test_imported_reassessment_event_is_not_reconciled_or_dispatched(mixed, monkeypatch):
    monkeypatch.setattr(main, 'SessionLocal', mixed.sessions)
    monkeypatch.setattr(main, '_start_public_scan', lambda *a, **k: pytest.fail('Imported scan dispatched'))
    with mixed.sessions() as db:
        rows = [CyberApproval(service_id=identity, source_execution_id=41, variant='current_service',
            status='approved', snapshot={'distribution': {'id': 'captured'}}, snapshot_digest='captured')
            for identity in (mixed.local, mixed.imported)]
        db.add_all(rows); db.flush()
        events = [lifecycle.OCIReassessmentEvent(id=str(row.id), approval_id=row.id) for row in rows]
        db.add_all(events); db.commit()
        imported_id = rows[1].id
        lifecycle.reconcile(db)
        assert events[0].state == 'review_required'
        assert events[1].state == 'queued' and events[1].detail == ''
    ctx = SimpleNamespace(job=SimpleNamespace(id=str(imported_id), service_id=mixed.imported), check=lambda: None)
    with pytest.raises(lifecycle.JobError, match='publisher'):
        lifecycle.handle(ctx, {'approval_id': imported_id})
    with mixed.sessions() as db:
        assert db.get(lifecycle.OCIReassessmentEvent, str(imported_id)).state == 'queued'
