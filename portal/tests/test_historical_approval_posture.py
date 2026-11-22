import json
from datetime import datetime
from types import SimpleNamespace
from zipfile import ZipFile

from sqlalchemy import select

from app import cyber_approval_evidence, portable_release_capture
from app.cyber_approvals import CyberApproval, digest
from app.history_queries import historical_approval_posture
from app.models import Execution, Service
from test_cyber_approval_evidence import fake_export, seeded
from test_portal import SessionLocal, setup_function


def test_frozen_posture_is_selected_only_for_the_approved_exact_execution(tmp_path, monkeypatch):
    seeded()
    monkeypatch.setattr('app.service_exports.write_all', fake_export)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        snapshot = cyber_approval_evidence.freeze(db, service, SimpleNamespace(),
            cyber_approval_evidence.readiness(db, service), tmp_path)
        posture = snapshot['history_posture']
        with ZipFile(snapshot['evidence']['path']) as archive:
            display = json.loads(archive.read('replica-service.json'))['extension']['display']
            assert json.loads(archive.read('frozen-snapshot.json'))['history_posture'] == posture
        row = display['cyber_row']
        assert posture == {
            'source_execution_id': execution.id, 'posture_captured_at': display['captured_at'],
            'posture': {'GREEN': 'compliant', 'YELLOW': 'warning', 'RED': 'non_compliant'}[row['status']],
            'open_poams': row['poam'], 'overdue_poams': row['poam_overdue'], 'watchlist': row['watchlist'],
        }
        assert datetime.fromisoformat(posture['posture_captured_at']).tzinfo
        approval = CyberApproval(service_id=service.id, source_execution_id=execution.id, variant='current_service',
                                 snapshot=snapshot, snapshot_digest=digest(snapshot))
        db.add(approval)
        db.flush()
        version = snapshot['version']
        assert not historical_approval_posture(db, execution, version)
        approval.status = 'approved'
        db.flush()
        retained = historical_approval_posture(db, execution, version)
        assert retained == {'posture_source': 'approval_capture',
                            **{k: v for k, v in posture.items() if k != 'source_execution_id'}}
        assert not historical_approval_posture(db, execution, 'unrelated-version')
        approval.snapshot = {**snapshot, 'source_payload_digest': 'a' * 64}
        db.flush()
        assert not historical_approval_posture(db, execution, version)
        approval.snapshot = {k: v for k, v in snapshot.items() if k != 'history_posture'}
        db.flush()
        assert not historical_approval_posture(db, execution, version)


def test_approval_posture_not_bound_to_distributions_candidates_or_a_superseded_scan():
    seeded()
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        execution = db.scalar(select(Execution))
        for scope, variant, identity in [('service-distribution-scan', 'current_service', execution.id),
                                         ('proposed-service-scan', 'current_service', execution.id),
                                         ('remediation-candidate', 'cats_remediated', execution.id),
                                         ('current-service-scan', 'current_service', execution.id + 1)]:
            _, summary = portable_release_capture.encode_capture(db, service, {
                'evidence_scope': scope, 'variant': variant, 'source_execution_id': identity})
            assert summary is None
