"""Automatic, bounded native VEX work on the existing durable risk worker."""
from datetime import timedelta
from sqlalchemy import select, or_, and_, insert
from .database import SessionLocal
from .durable_jobs import DurableJob, submit
from . import native_vex as nv
from .native_vex_models import VexDispositionService as State, VexDispositionEvaluation as Evaluation, VexDispositionPolicy as Policy
from .risk_profiles import utcnow


def maintenance(session_factory=SessionLocal):
    """Discover pending generations even if queue admission previously failed.

    No scan transaction depends on worker availability or queue capacity.
    Existing installations are discovered in bounded batches without startup work.
    """
    from .models import Service
    from fastapi import HTTPException
    with session_factory() as db:
        missing = list(db.scalars(select(Service.id).where(~select(State.service_id).where(
            State.service_id == Service.id).exists()).order_by(Service.id).limit(100)))
        for service_id in missing:
            dialect = db.get_bind().dialect.name
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            statement = (pg_insert if dialect == 'postgresql' else sqlite_insert)(State).values(service_id=service_id, generation=1)
            db.execute(statement.on_conflict_do_nothing(index_elements=['service_id']))
        db.commit()
        now = utcnow()
        policy = db.get(Policy, 1)
        if policy is None:
            return 0
        busy = select(DurableJob.id).where(DurableJob.kind == 'native_vex', DurableJob.service_id == State.service_id,
            or_(DurableJob.status.in_(('queued', 'running')), and_(DurableJob.status.in_(('failed', 'cancelled')),
                DurableJob.completed_at > now - timedelta(hours=1)))).exists()
        pending = list(db.scalars(select(State.service_id).outerjoin(Evaluation, Evaluation.id == State.evaluation_id).where(
            ~busy, or_(Evaluation.id.is_(None), Evaluation.service_generation != State.generation,
                Evaluation.intelligence_generation != policy.generation, Evaluation.policy_version != policy.policy_version,
                Evaluation.algorithm != nv.ALGORITHM, Evaluation.valid_until <= now))
            .order_by(State.service_id).limit(50)))
        admitted = 0
        for service_id in pending:
            try:
                # Queue-level advisory lock serializes multiple worker processes;
                # the service lock prevents duplicate admission after discovery.
                db.scalar(select(State).where(State.service_id == service_id).with_for_update())
                if db.scalar(select(DurableJob.id).where(DurableJob.kind == 'native_vex',
                        DurableJob.service_id == service_id, DurableJob.status.in_(('queued', 'running'))).limit(1)):
                    db.rollback()
                    continue
                submit(db, kind='native_vex', service_id=service_id, payload={'service_id':service_id})
                admitted += 1
            except HTTPException as exc:
                db.rollback()
                if exc.status_code != 429:
                    raise
                break
        return admitted


def handler(context, payload):
    from .durable_jobs import JobCancelled
    with SessionLocal() as db:
        result = nv.evaluate_service(db, int(payload['service_id']), check=context.check)
        job = context._owned(db)
        if job.cancel_requested:
            raise JobCancelled()
        db.commit()
        return {'evaluation_id': result.id, 'service_id': result.service_id, 'summary': result.summary}
