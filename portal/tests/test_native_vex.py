"""Native disposition must fail open to existing actionability, never to exclusion."""
from datetime import timedelta
import pytest
from sqlalchemy import create_engine, select, update, func
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, Execution, Finding, FindingObservation
from app import native_vex as nv
from app.native_vex_models import VexDispositionPolicy, VexDispositionService, VexObservationDisposition
from app.vex_models import VexSource
from test_vex_repository import NOW, PID, raw, source, ingest

@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()

def setup(db, mixed=False):
    src = source(db)
    ingest(db, src, raw())
    service = Service(name='Native VEX', service_key='native'); db.add(service); db.flush()
    execution = Execution(service_id=service.id, execution_key='native', scanned_at=NOW, complete=True, raw_payload={})
    db.add(execution); db.flush()
    finding = Finding(service_id=service.id, cve='CVE-2026-12345', severity='critical', first_seen=NOW, episode_started=NOW, last_seen=NOW, active=True)
    db.add(finding); db.flush()
    observations = []
    for image, version in [('one', '1.0')] + ([('two', '2.0')] if mixed else []):
        observation = FindingObservation(finding_id=finding.id, execution_id=execution.id, image=image,
            package='libtest', installed_version=version, evidence={'purl': PID.replace('@1.0', '@'+version), 'distro':'wolfi'})
        db.add(observation); observations.append(observation)
    db.commit()
    return service, finding, observations, src

def excluded(db, finding, now=NOW):
    return db.scalar(select(nv.finding_excluded(finding.id, now)))

def enable(db):
    db.get(VexDispositionPolicy, 1).enabled = True
    db.commit()

def test_disabled_preserves_evidence_then_enabled_excludes(db):
    service, finding, observations, src = setup(db)
    result = nv.evaluate_service(db, service.id, now=NOW); db.commit()
    assert result.summary['excluded_observations'] == 1
    assert not excluded(db, finding)
    assert db.scalar(select(nv.finding_excluded(finding.id, NOW, preview=True)))
    enable(db)
    assert excluded(db, finding)
    assert finding.active and finding.resolved_at is None and observations[0].evidence['purl'] == PID
    assert not excluded(db, finding, NOW+timedelta(days=31))

def test_mixed_never_excludes_whole_finding(db):
    service, finding, observations, src = setup(db, True); enable(db)
    result = nv.evaluate_service(db, service.id, now=NOW); db.commit()
    assert result.summary['mixed_findings'] == 1
    assert not excluded(db, finding)
    assert db.scalar(select(nv.observation_excluded(observations[0].id, NOW)))
    assert not db.scalar(select(nv.observation_excluded(observations[1].id, NOW)))

@pytest.mark.parametrize('mutation', ['observation', 'execution', 'trust', 'revision'])
def test_bulk_mutations_invalidate_immediately_without_worker(db, mutation):
    service, finding, observations, src = setup(db); enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    assert excluded(db, finding)
    if mutation == 'observation':
        db.execute(update(FindingObservation).where(FindingObservation.id == observations[0].id).values(installed_version='2.0'))
    elif mutation == 'execution':
        db.execute(update(Execution).where(Execution.id == observations[0].execution_id).values(complete=False))
    elif mutation == 'trust':
        db.execute(update(VexSource).where(VexSource.id == src.id).values(trusted=False))
    else:
        ingest(db, src, raw('affected', issued=NOW+timedelta(seconds=1)))
    db.flush()
    assert not excluded(db, finding)
    assert db.scalar(select(func.count()).select_from(VexObservationDisposition)) == 1

@pytest.mark.parametrize('status', ['fixed', 'affected', 'under_investigation', 'conflicting', 'stale', 'unverified', 'no_vex'])
def test_non_not_affected_never_qualifies(status):
    assert not nv.qualifies({'status': status}, NOW)

@pytest.mark.parametrize('reason', ['candidate_limit', 'alias_limit', 'identity_candidate_limit', 'identity_evidence_conflict', 'stale_mapping'])
def test_uncertain_even_with_positive_status_cannot_qualify(reason):
    result = {'status':'not_affected', 'valid_until':(NOW+timedelta(days=1)).isoformat(),
        'lookup_cves':['CVE-2026-12345'], 'reasons':[reason],
        'statements':[{'accepted':True, 'cve':'CVE-2026-12345', 'status':'not_affected', 'identity_kind':'exact_observed'}]}
    assert not nv.qualifies(result, NOW)

def test_older_evaluation_cannot_publish_after_mutation(db):
    service, finding, observations, src = setup(db); enable(db)
    changed = False
    def change():
        nonlocal changed
        if not changed:
            db.execute(update(FindingObservation).where(FindingObservation.id == observations[0].id).values(installed_version='2.0'))
            changed = True
    with pytest.raises(ValueError, match='changed'):
        nv.evaluate_service(db, service.id, now=NOW, check=change)
    db.rollback()
    assert not excluded(db, finding)
