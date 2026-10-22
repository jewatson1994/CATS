"""The sole effective VEX exclusion rule, shared by reads and action checks."""
from datetime import timedelta
from sqlalchemy import select, and_, func, insert, false
from .native_vex_models import (VexDispositionPolicy as Policy, VexDispositionService as State,
    VexDispositionEvaluation as Evaluation, VexFindingDisposition as FindingResult,
    VexObservationDisposition as ObservationResult)
from .package_identity_resolution import RESOLVER_VERSION
from .risk_profiles import aware, utcnow

ALGORITHM = 'native-vex/v1:' + RESOLVER_VERSION
BATCH = 250
MAX_OBSERVATIONS = 100000
# Explicit native evidence horizon, independent of informational risk profiles.
MAX_SCAN_AGE = timedelta(days=30)


def current_evaluation(now, *, enabled=True):
    from . import database
    # Portal SQL cannot atomically observe authority/revision changes committed
    # to the independent intelligence database. Retain evidence for inspection,
    # but never treat it as an effective exclusion (including preview).
    if database.INTELLIGENCE_SEPARATE:
        return [false()]
    conditions = [State.evaluation_id == Evaluation.id,
        State.generation == Evaluation.service_generation,
        Policy.id == 1, Policy.generation == Evaluation.intelligence_generation,
        Policy.policy_version == Evaluation.policy_version,
        Evaluation.algorithm == ALGORITHM, Evaluation.valid_until > now,
        Evaluation.evaluated_at <= now]
    if enabled:
        conditions.append(Policy.enabled.is_(True))
    return conditions


def finding_excluded(finding_id, now, *, preview=False):
    """SQL predicate: all observations in the fenced, complete current scan qualify."""
    return select(FindingResult.id).select_from(FindingResult).join(
        Evaluation, Evaluation.id == FindingResult.evaluation_id).join(
        State, State.service_id == Evaluation.service_id).join(Policy, Policy.id == 1).where(
        FindingResult.finding_id == finding_id, FindingResult.observations > 0,
        FindingResult.observations == FindingResult.excluded_observations,
        *current_evaluation(now, enabled=not preview)).exists()


def observation_excluded(observation_id, now, *, preview=False):
    return select(ObservationResult.id).select_from(ObservationResult).join(
        Evaluation, Evaluation.id == ObservationResult.evaluation_id).join(
        State, State.service_id == Evaluation.service_id).join(Policy, Policy.id == 1).where(
        ObservationResult.observation_id == observation_id, ObservationResult.excluded.is_(True),
        *current_evaluation(now, enabled=not preview)).exists()


def qualifies(result, now):
    """Fail closed on truncated evaluation and unresolved applicability uncertainty."""
    if result.get('status') != 'not_affected' or not result.get('statements') or not result.get('valid_until'):
        return False
    if aware(result['valid_until']) <= now:
        return False
    reasons = result.get('reasons', [])
    if any(any(word in reason for word in ('limit', 'overflow', 'conflict', 'stale', 'uncertain')) for reason in reasons):
        return False
    accepted = [s for s in result['statements'] if s.get('accepted') and not s.get('reason')]
    cves = result.get('lookup_cves', [])
    return bool(cves) and all(any(s.get('cve') == cve and s.get('status') == 'not_affected'
        and s.get('identity_kind') in ('exact_observed', 'authoritative_resolved') for s in accepted) for cve in cves)


def evaluate_service(db, service_id, *, now=None, check=None):
    """Build evidence in the caller's transaction, then fence publication under locks.

    Any failure rolls back every result. No partially evaluated finding is published.
    Trigger writers use the same state rows, including bulk ingestion/import writers.
    """
    from .models import Finding, FindingObservation, Execution
    from .finding_classification import latest_execution_id
    from .container_intelligence import observation_identity, evaluate_container_batch
    now = aware(now or utcnow())
    policy = db.get(Policy, 1, populate_existing=True)
    state = db.get(State, service_id, populate_existing=True)
    if not policy or not state:
        raise ValueError('Native VEX state has not been initialized')
    generation, intel, policy_version = state.generation, policy.generation, policy.policy_version
    latest = latest_execution_id(db, service_id)
    execution = db.get(Execution, latest) if latest else None
    scan_valid = bool(execution and execution.complete and aware(execution.scanned_at) <= now
                      and aware(execution.scanned_at) + MAX_SCAN_AGE > now)
    expiry = min(now + timedelta(hours=24), aware(execution.scanned_at) + MAX_SCAN_AGE) if scan_valid else now + timedelta(hours=1)
    evaluation = Evaluation(service_id=service_id, execution_id=latest or -1,
        service_generation=generation, intelligence_generation=intel, policy_version=policy_version,
        algorithm=ALGORITHM, evaluated_at=now, valid_until=expiry, summary={})
    db.add(evaluation)
    db.flush()
    cursor, total, aggregate = 0, 0, {}
    while scan_valid:
        if check:
            check()
        rows = db.execute(select(FindingObservation, Finding).join(Finding,
            Finding.id == FindingObservation.finding_id).where(Finding.service_id == service_id,
            Finding.active.is_(True), FindingObservation.execution_id == latest,
            FindingObservation.id > cursor).order_by(FindingObservation.id).limit(BATCH)).all()
        if not rows:
            break
        total += len(rows)
        if total > MAX_OBSERVATIONS:
            raise ValueError('Native VEX observation bound exceeded; findings remain actionable')
        items = []
        for observation, finding in rows:
            identity = observation_identity(observation)
            identity['observed_at'] = aware(execution.scanned_at).isoformat()
            identity['evidence_valid_until'] = (aware(execution.scanned_at) + MAX_SCAN_AGE).isoformat()
            items.append({'cve': finding.cve, 'identity': identity, 'context': identity['context'], 'aliases': identity['aliases']})
        results = evaluate_container_batch(db, items, now)
        if len(results) != len(rows):
            raise ValueError('Incomplete VEX evaluation')
        values = []
        for (observation, finding), result in zip(rows, results):
            excluded = qualifies(result, now)
            if excluded:
                expiry = min(expiry, aware(result['valid_until']))
            counts = aggregate.setdefault(finding.id, [0, 0])
            counts[0] += 1
            counts[1] += int(excluded)
            values.append(dict(evaluation_id=evaluation.id, observation_id=observation.id,
                finding_id=finding.id, excluded=excluded, evidence={**result,
                'component': {'package': observation.package, 'version': observation.installed_version,
                              'image': observation.image, 'digest': observation.image_digest},
                'original_severity': finding.severity}))
        db.execute(insert(ObservationResult), values)
        cursor = rows[-1][0].id
    if aggregate:
        db.execute(insert(FindingResult), [dict(evaluation_id=evaluation.id, finding_id=fid,
            observations=counts[0], excluded_observations=counts[1]) for fid, counts in aggregate.items()])
    # Global -> service lock order is shared by evaluators. A concurrent mutation
    # either wins before this check or invalidates the result after publication.
    policy = db.scalar(select(Policy).where(Policy.id == 1).with_for_update().execution_options(populate_existing=True))
    state = db.scalar(select(State).where(State.service_id == service_id).with_for_update().execution_options(populate_existing=True))
    if (state.generation != generation or policy.generation != intel or policy.policy_version != policy_version
            or latest_execution_id(db, service_id) != latest):
        raise ValueError('Evidence changed during VEX evaluation; retry required')
    evaluation.valid_until = expiry
    evaluation.summary = {'observations': total, 'findings': len(aggregate), 'scan_current': scan_valid,
        'excluded_observations': sum(c[1] for c in aggregate.values()),
        'fully_excluded_findings': sum(c[0] == c[1] for c in aggregate.values()),
        'mixed_findings': sum(0 < c[1] < c[0] for c in aggregate.values())}
    from . import database
    if database.INTELLIGENCE_SEPARATE:
        evaluation.summary['exclusion_unavailable_reason'] = (
            'Separate intelligence database: automatic exclusions require atomic intelligence invalidation')
    from .service_posture import _bump
    _bump(db.connection(), [service_id])
    state.evaluation_id = evaluation.id
    db.flush()
    return evaluation


def excluded_finding_ids(db, service_id, now):
    """Batch bridge for existing Python classification/export evaluators."""
    from .models import Finding
    return set(db.scalars(select(Finding.id).where(Finding.service_id == service_id,
        Finding.active.is_(True), finding_excluded(Finding.id, now)))) if db is not None else set()


def cache_token(db):
    """Global invalidation without visiting the intelligence corpus."""
    row = db.execute(select(Policy.enabled, Policy.generation, Policy.policy_version).where(Policy.id == 1)).first()
    from . import database
    mode = ':split-evidence-only' if database.INTELLIGENCE_SEPARATE else ':atomic'
    return (str(tuple(row)) + ALGORITHM if row else ALGORITHM) + mode
