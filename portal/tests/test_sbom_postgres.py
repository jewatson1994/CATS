"""Opt-in PostgreSQL contracts for retained SBOM identity and invalidation."""

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app import native_vex as nv
from app.models import SbomComponent
from app.native_vex_models import VexDispositionEvaluation, VexDispositionPolicy
from app.risk_models import RiskAssessment
from app.risk_worker import refresh_assessment
from test_native_vex import NOW, enable, excluded
from test_risk_vex_postgres import pgdb
import test_sbom_component_correlation as correlation_cases
import test_sbom_vex_identity as identity_cases


@pytest.mark.parametrize("mutation", ["insert", "update", "delete", "move"])
def test_postgres_component_mutations_invalidate_service_generation(pgdb, mutation):
    correlation_cases.test_component_mutations_invalidate_service_generation(pgdb, mutation)


def test_postgres_replaced_payload_removes_retained_projection(pgdb):
    correlation_cases.test_replaced_execution_payload_cannot_reuse_old_projection(pgdb)


def test_postgres_recovery_deduplicates_requests_and_bounds_candidates(pgdb):
    correlation_cases.test_batched_duplicate_requests_and_candidate_cap(pgdb)


def test_postgres_retained_identity_drives_native_and_risk_consumers(pgdb, monkeypatch):
    identity_cases.test_real_retained_binding_drives_both_consumers_without_changing_scanner_rows(
        pgdb, monkeypatch)


@pytest.mark.parametrize("consumer", ["native", "risk"])
def test_postgres_concurrent_component_change_fences_publication(pgdb, monkeypatch, consumer):
    service, finding, _, _ = identity_cases.retained_setup(pgdb)
    if consumer == "risk":
        identity_cases.prepare_risk(pgdb, service, finding, monkeypatch)
        # Informational assessments must fence identity changes even while native
        # exclusions are disabled, when the native disposition token is constant.
        assert not pgdb.get(VexDispositionPolicy, 1).enabled
    else:
        enable(pgdb)
    service_id = service.id
    component_id = pgdb.scalar(select(SbomComponent.id))
    checks = 0
    changed = False

    def concurrent_change():
        nonlocal checks, changed
        checks += 1
        if checks != 2:
            return
        # The first batch has already consumed the retained identity. Commit on
        # another connection before the evaluator reaches its publication fence.
        with Session(pgdb.get_bind()) as other:
            other.execute(text("SET LOCAL lock_timeout = '5s'"))
            other.execute(delete(SbomComponent).where(SbomComponent.id == component_id))
            other.commit()
        changed = True

    with pytest.raises(ValueError, match="changed"):
        if consumer == "risk":
            refresh_assessment(pgdb, service_id, NOW, check=concurrent_change)
        else:
            nv.evaluate_service(pgdb, service_id, now=NOW, check=concurrent_change)
    pgdb.rollback()
    assert changed
    assert pgdb.get(SbomComponent, component_id) is None
    assert pgdb.scalar(select(func.count()).select_from(RiskAssessment)) == 0
    assert pgdb.scalar(select(func.count()).select_from(VexDispositionEvaluation)) == 0
    assert not excluded(pgdb, finding)
