"""Single-slot, lease-fenced executor for the existing managed-validator queue."""
from datetime import datetime, timedelta, timezone
import json
import os
import threading
import time
import uuid
from sqlalchemy import or_, select, update
from .database import SessionLocal
from .models import ManagedValidator, ManagedValidatorOperation, ValidatorProvisioningAttempt
from .secrets import decrypt_secret
from .diagnostics import build_diagnostic, record_diagnostic, enqueue_diagnostic

LEASE_SECONDS = 3600  # exceeds every bounded external operation
MAX_ATTEMPTS = 3
_DEFAULT_SESSION_FACTORY = SessionLocal


def publish_diagnostic(diagnostic, session_factory):
    if session_factory is _DEFAULT_SESSION_FACTORY:
        enqueue_diagnostic(diagnostic)
    else:
        record_diagnostic(diagnostic, session_factory=session_factory)


def now():
    return datetime.now(timezone.utc)


def operation_diagnostic(attempt, op, error, *, secret_values=(), **kwargs):
    diagnostic = build_diagnostic(error, component="provisioning", operation=op.action,
        correlation_id=op.id, status=op.status,
        resource={"operation_id": op.id, "validator_id": op.validator_id},
        context={"stage": op.phase, "attempts": attempt.attempts, "max_attempts": MAX_ATTEMPTS,
                 "worker_id": os.getenv("HOSTNAME", "provisioning-worker"),
                 "last_successful_stage": next((stage.get("stage") for stage in reversed(attempt.stages or [])
                    if stage.get("stage") != op.phase and stage.get("status") not in {"FAILED", "CANCELLED"}), None)}, **kwargs)
    def redact_known(value):
        if isinstance(value, str):
            for secret in secret_values:
                if isinstance(secret, str) and secret:
                    value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {key: redact_known(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_known(item) for item in value]
        return value
    diagnostic = redact_known(diagnostic)
    attempt.request = {**(attempt.request or {}), "diagnostic": diagnostic}
    return diagnostic


def claim(session_factory=SessionLocal):
    with session_factory() as db:
        moment = now()
        query = select(ValidatorProvisioningAttempt).join(ManagedValidatorOperation,
            ManagedValidatorOperation.id == ValidatorProvisioningAttempt.id).where(
            ValidatorProvisioningAttempt.status.in_(['QUEUED', 'RUNNING']),
            or_(ValidatorProvisioningAttempt.available_at.is_(None), ValidatorProvisioningAttempt.available_at <= moment),
            or_(ValidatorProvisioningAttempt.lease_until.is_(None), ValidatorProvisioningAttempt.lease_until <= moment)
        ).order_by(ValidatorProvisioningAttempt.created_at).limit(1)
        candidate = db.scalar(query)
        if not candidate:
            return None
        if candidate.attempts >= MAX_ATTEMPTS:
            # Finalize here: even a process dying immediately after each claim
            # cannot keep reclaiming credentials or holding the host forever.
            op = db.get(ManagedValidatorOperation, candidate.id)
            candidate.status = op.status = 'CANCELLED' if op.cancel_requested else 'FAILED'
            candidate.failure = op.error = 'Provisioning exhausted worker recovery attempts; correlation ID: ' + candidate.id
            diagnostic = operation_diagnostic(candidate, op, TimeoutError("Provisioning worker recovery attempts exhausted"),
                code="worker_lease_expired", retryable=False)
            candidate.encrypted_credentials = None
            candidate.completed_at = op.finished_at = moment
            candidate.lease_owner = candidate.lease_until = None
            db.get(ManagedValidator, candidate.validator_id).active_operation_id = None
            db.commit()
            publish_diagnostic(diagnostic, session_factory)
            return None
        token = uuid.uuid4().hex
        changed = db.execute(update(ValidatorProvisioningAttempt).where(
            ValidatorProvisioningAttempt.id == candidate.id,
            ValidatorProvisioningAttempt.status.in_(['QUEUED', 'RUNNING']),
            or_(ValidatorProvisioningAttempt.lease_until.is_(None), ValidatorProvisioningAttempt.lease_until <= moment)
        ).execution_options(synchronize_session=False).values(lease_owner=token, lease_until=moment + timedelta(seconds=LEASE_SECONDS), heartbeat_at=moment,
                 status='RUNNING', attempts=ValidatorProvisioningAttempt.attempts + 1, started_at=moment))
        if changed.rowcount != 1:
            db.rollback()
            return None
        op = db.get(ManagedValidatorOperation, candidate.id)
        if not op:
            # Legacy provisioning queue is intentionally not repurposed.
            db.rollback()
            return None
        op.status, op.phase = 'RUNNING', 'RECONCILING'
        db.commit()
        return candidate.id, token


def owns(db, operation_id, token):
    return bool(db.scalar(select(ValidatorProvisioningAttempt.id).where(
        ValidatorProvisioningAttempt.id == operation_id,
        ValidatorProvisioningAttempt.lease_owner == token,
        ValidatorProvisioningAttempt.status == 'RUNNING',
        ValidatorProvisioningAttempt.lease_until > now())))


def heartbeat(operation_id, token, stop, session_factory):
    while not stop.wait(10):
        try:
            with session_factory() as db:
                changed = db.execute(update(ValidatorProvisioningAttempt).where(
                    ValidatorProvisioningAttempt.id == operation_id,
                    ValidatorProvisioningAttempt.lease_owner == token,
                    ValidatorProvisioningAttempt.status == 'RUNNING',
                    ValidatorProvisioningAttempt.lease_until > now()).execution_options(synchronize_session=False).values(
                        heartbeat_at=now(), lease_until=now() + timedelta(seconds=LEASE_SECONDS)))
                db.commit()
                if not changed.rowcount:
                    return
        except Exception:
            # The execution path checks its lease before each externally visible phase.
            continue


def run_once(session_factory=SessionLocal):
    work = claim(session_factory)
    if not work:
        return False
    operation_id, token = work
    stop = threading.Event()
    thread = threading.Thread(target=heartbeat, args=(operation_id, token, stop, session_factory), daemon=True)
    thread.start()
    try:
        from . import managed_validators
        with session_factory() as db:
            attempt = db.get(ValidatorProvisioningAttempt, operation_id)
            if attempt.attempts > MAX_ATTEMPTS:
                op = db.get(ManagedValidatorOperation, operation_id)
                op.status, op.error = 'FAILED', 'Provisioning exhausted worker recovery attempts; correlation ID: ' + operation_id
                db.commit()
                return True
            credentials = json.loads(decrypt_secret(attempt.encrypted_credentials)) if attempt.encrypted_credentials else {}
            arguments = (attempt.validator_id, operation_id, credentials, attempt.request or {})
        managed_validators.run_operation(*arguments, lease_owner=token, session_factory=session_factory)
    except Exception as exc:
        # Never emit decrypted credentials, remote stderr, or exception text.
        with session_factory() as db:
            if owns(db, operation_id, token):
                op = db.get(ManagedValidatorOperation, operation_id)
                op.status, op.error = 'FAILED', 'Provisioning worker failed; correlation ID: ' + operation_id
                attempt = db.get(ValidatorProvisioningAttempt, operation_id)
                diagnostic = operation_diagnostic(attempt, op, exc, summary="Provisioning worker failed",
                    secret_values=(locals().get('credentials') or {}).values())
                db.commit()
        if 'diagnostic' in locals():
            publish_diagnostic(diagnostic, session_factory)
    finally:
        stop.set()
        thread.join(timeout=15)
        with session_factory() as db:
            if owns(db, operation_id, token):
                attempt = db.get(ValidatorProvisioningAttempt, operation_id)
                op = db.get(ManagedValidatorOperation, operation_id)
                row = db.get(ManagedValidator, attempt.validator_id)
                if op.cancel_requested:
                    op.status = 'CANCELLED'
                elif op.status not in {'SUCCEEDED', 'FAILED', 'CANCELLED'}:
                    op.status, op.error = 'FAILED', 'Provisioning returned without a terminal result; correlation ID: ' + operation_id
                retry = op.status == 'FAILED' and attempt.attempts < MAX_ATTEMPTS and not op.cancel_requested
                diagnostic = None
                if op.status == 'FAILED' and not (attempt.request or {}).get('diagnostic'):
                    diagnostic = operation_diagnostic(attempt, op, op.error, retryable=retry)
                attempt.stage, attempt.failure = op.phase, op.error
                attempt.stages = [*(attempt.stages or [])[-79:], {'stage': op.phase, 'status': op.status, 'at': now().isoformat()}]
                attempt.status = 'QUEUED' if retry else op.status
                attempt.lease_until, attempt.lease_owner = None, None
                if retry:
                    attempt.available_at = now() + timedelta(seconds=30 * 2 ** (attempt.attempts - 1))
                    op.status, op.phase, op.finished_at = 'QUEUED', 'RETRY_WAIT', None
                    row.active_operation_id = operation_id
                else:
                    attempt.encrypted_credentials = None
                    attempt.completed_at = now()
                    row.active_operation_id = None
                    op.finished_at = now()
                db.commit()
                if diagnostic:
                    publish_diagnostic(diagnostic, session_factory)
    return True


def main():
    # One slot per service. Compose deploys one service; workers do not contend
    # with the web process for Python execution or Docker privileges.
    from .database import engine
    from .managed_validator_migrations import upgrade_connection
    with engine.begin() as connection:
        upgrade_connection(connection)
    while True:
        try:
            worked = run_once()
        except Exception as exc:
            worked = False
            enqueue_diagnostic(build_diagnostic(exc, component="provisioning", operation="claim",
                context={"worker_id": os.getenv("HOSTNAME", "provisioning-worker")}))
        if not worked:
            time.sleep(2)


if __name__ == '__main__':
    main()
