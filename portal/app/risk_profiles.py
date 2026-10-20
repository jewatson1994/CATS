"""Risk is an explanatory, versioned read model; never an enforcement input."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import math
from sqlalchemy import select, func, text, or_
from sqlalchemy.orm import defer
from .models import Service, ServiceGroup, Group, Finding, FindingObservation, FindingClassification
from .risk_models import RiskPolicyVersion, RiskPolicyGroup, RiskPolicyAssignment, RiskAssessment, RiskDecision

DEFAULT_POLICY = {
    'severity_weights': {'unknown': 40, 'negligible': 5, 'low': 15, 'medium': 35, 'high': 65, 'critical': 85},
    'epss_weight': 15, 'kev_override': 95, 'missing_floor': 40,
    'age_weight': 10, 'age_days': 90, 'exception_multiplier': 1.0, 'fix_weight': 5,
    'uncertainty_weight': 10, 'vex_not_affected_multiplier': 0.25,
    'thresholds': {'low': 0, 'medium': 30, 'high': 60, 'critical': 85},
    'max_age_hours': 24,
    'authority_labels': {'recommendation': 'Cyber recommendation', 'delegated_approval': 'Delegated approval', 'ao_decision': 'Authorizing Official decision'},
}

def utcnow():
    return datetime.now(timezone.utc)

def aware(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime):
        raise ValueError('A valid ISO datetime is required')
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def validate_policy(configuration):
    if not isinstance(configuration, dict) or set(configuration) - set(DEFAULT_POLICY):
        raise ValueError('Unknown policy fields')
    policy = deepcopy(DEFAULT_POLICY)
    policy.update(deepcopy(configuration))
    for key in ('severity_weights', 'thresholds', 'authority_labels'):
        if not isinstance(policy[key], dict) or set(policy[key]) != set(DEFAULT_POLICY[key]):
            raise ValueError('Invalid ' + key)
    numeric = [(k, v, 0, 100) for k, v in policy['severity_weights'].items()]
    numeric += [(k, policy[k], 0, 100) for k in ('epss_weight', 'kev_override', 'missing_floor', 'age_weight', 'fix_weight', 'uncertainty_weight')]
    numeric += [('exception_multiplier', policy['exception_multiplier'], 0, 1), ('vex_not_affected_multiplier', policy['vex_not_affected_multiplier'], 0, 1), ('age_days', policy['age_days'], 1, 3650), ('max_age_hours', policy['max_age_hours'], 1, 720)]
    numeric += [(k, v, 0, 100) for k, v in policy['thresholds'].items()]
    for key, value, low, high in numeric:
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError('Invalid numeric policy value: ' + key)
    thresholds = [policy['thresholds'][k] for k in ('low', 'medium', 'high', 'critical')]
    if thresholds[0] != 0 or any(a >= b for a, b in zip(thresholds, thresholds[1:])):
        raise ValueError('Thresholds must increase strictly from zero')
    if any(not isinstance(v, str) or not v.strip() or len(v) > 120 for v in policy['authority_labels'].values()):
        raise ValueError('Authority labels must be nonempty text')
    return policy

def create_policy(db, name, configuration, actor, parent_policy_id=None, group_id=None):
    if not isinstance(group_id, int) or isinstance(group_id, bool) or not db.get(Group, group_id):
        raise ValueError('An owning group is required')
    if not isinstance(name, str):
        raise ValueError('Profile name is required')
    name = name.strip()
    if not name or len(name) > 120:
        raise ValueError('Profile name is required (maximum 120 characters)')
    configuration = validate_policy(configuration)
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(73488296)'))
    if parent_policy_id is not None:
        owner = db.get(RiskPolicyGroup, parent_policy_id)
        if not owner or owner.group_id != group_id:
            raise ValueError('Source policy must belong to this group')
    # Keep the legacy unique constraint while isolating names/version sequences by group.
    storage_name = 'group:' + str(group_id) + ':' + sha256(name.encode()).hexdigest()
    version = (db.scalar(select(func.max(RiskPolicyVersion.version)).where(RiskPolicyVersion.name == storage_name)) or 0) + 1
    row = RiskPolicyVersion(name=storage_name, version=version, configuration=configuration, digest=digest(configuration), created_by=str(actor), parent_policy_id=parent_policy_id)
    db.add(row)
    db.flush()
    db.add(RiskPolicyGroup(policy_id=row.id, group_id=group_id, display_name=name))
    db.flush()
    return row

def assign_policy(db, scope, scope_id, policy_id, actor):
    if scope != 'group':
        raise ValueError('Risk policy assignments require a group scope')
    if not isinstance(scope_id, int) or isinstance(scope_id, bool) or not db.get(Group, scope_id):
        raise ValueError('Assignment target does not exist')
    if policy_id is not None:
        owner = db.get(RiskPolicyGroup, policy_id)
        if not owner or owner.group_id != scope_id:
            raise ValueError('Policy version must belong to this group')
    row = RiskPolicyAssignment(scope=scope, scope_id=scope_id, policy_id=policy_id, created_by=str(actor))
    db.add(row)
    db.flush()
    return row

def resolve_policy(db, service_id):
    groups = list(db.scalars(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service_id)))
    if len(groups) > 1:
        raise ValueError('Repair conflicting owning groups before assessing risk')
    scopes = []
    seen = set()
    group_id = groups[0] if groups else None
    while group_id is not None:
        if group_id in seen:
            raise ValueError('Group inheritance cycle')
        seen.add(group_id)
        scopes.append(('group', group_id))
        group = db.get(Group, group_id)
        group_id = group.parent_id if group else None
    for scope, scope_id in scopes:
        row = db.scalar(select(RiskPolicyAssignment).where(RiskPolicyAssignment.scope == scope, RiskPolicyAssignment.scope_id == scope_id).order_by(RiskPolicyAssignment.id.desc()).limit(1))
        owner = db.get(RiskPolicyGroup, row.policy_id) if row and row.policy_id is not None else None
        if owner and owner.group_id == scope_id:
            return db.get(RiskPolicyVersion, row.policy_id), {'scope': scope, 'scope_id': scope_id, 'assignment_id': row.id}
    return None, {'scope': 'builtin', 'scope_id': 0, 'assignment_id': None}

def score_observation(policy, *, severity, epss, kev, age_days=0, excepted=False, fixable=False, vex=None, intelligence_current=True, native_vex_excluded=None):
    """Pure deterministic calculation. Uncertain intelligence never reduces risk."""
    vex = vex or {'status': 'unknown'}
    status = vex.get('status', 'unknown')
    severity_key = str(severity).lower()
    valid_epss = isinstance(epss, (int, float)) and not isinstance(epss, bool) and math.isfinite(epss) and 0 <= epss <= 1
    uncertain = (not intelligence_current or not valid_epss or not isinstance(kev, bool)
                 or severity_key not in policy['severity_weights'] or severity_key == 'unknown'
                 or status not in ('affected', 'fixed', 'not_affected')
                 or bool(vex.get('conflict')) or bool(vex.get('stale')))
    score = float(policy['severity_weights'].get(str(severity).lower(), policy['severity_weights']['unknown']))
    reasons = ['Severity contribution']
    if valid_epss:
        score += max(0, min(1, float(epss))) * policy['epss_weight']
    score += min(1, max(0, age_days) / policy['age_days']) * policy['age_weight']
    if fixable:
        score += policy['fix_weight']
    if excepted and not uncertain:
        score *= policy['exception_multiplier']
        reasons.append('Configured exception weighting; no enforcement change')
    if native_vex_excluded is not False and status == 'not_affected' and not uncertain and not vex.get('conflict') and not vex.get('stale'):
        score *= policy['vex_not_affected_multiplier']
        reasons.append('Applicable trusted VEX not affected')
    if uncertain:
        score = max(policy['missing_floor'], score + policy['uncertainty_weight'])
        reasons.append('Uncertainty floor applied')
    if kev is True:
        score = max(score, policy['kev_override'])
        reasons.append('KEV override applied')
    score = round(min(100, max(0, score)), 2)
    band = next(k for k in ('critical', 'high', 'medium', 'low') if score >= policy['thresholds'][k])
    return {'score': score, 'band': band, 'uncertain': uncertain, 'reasons': reasons, 'vex': vex}

def enqueue_assessment(db, service_id, actor_id=None, configuration=None):
    from .durable_jobs import submit
    if not db.get(Service, service_id):
        raise ValueError('Service does not exist')
    payload = {'service_id': service_id}
    if configuration is not None:
        payload['configuration'] = validate_policy(configuration)
    return submit(db, kind='risk_assessment', payload=payload, service_id=service_id, requested_by_id=actor_id, commit=False)

def serialize(row, exclude=()):
    return {column.name: (getattr(row, column.name).isoformat() if isinstance(getattr(row, column.name), datetime) else getattr(row, column.name)) for column in row.__table__.columns if column.name not in exclude}

def record_decision(db, service_id, payload, actor):
    payload = deepcopy(payload)
    kind, decision = payload.get('kind'), payload.get('decision')
    if kind not in DEFAULT_POLICY['authority_labels'] or decision not in ('accept', 'mitigate', 'reject', 'reassess'):
        raise ValueError('Invalid authority kind or decision')
    for key in ('mission_impact', 'controls', 'justification', 'reviewer'):
        if not isinstance(payload.get(key), str) or not payload[key].strip() or len(payload[key]) > 10000:
            raise ValueError(key + ' is required (maximum 10000 characters)')
    refs = payload.get('evidence_refs')
    if not isinstance(refs, list) or not refs or len(refs) > 100 or any(not isinstance(x, str) or not x.strip() or len(x) > 2000 for x in refs):
        raise ValueError('Evidence references are required')
    assessment = db.get(RiskAssessment, int(payload.get('assessment_id') or 0))
    if not assessment or assessment.service_id != service_id or assessment.provenance.get('preview'):
        raise ValueError('Decision must reference a saved assessment for this service')
    expiry = aware(payload.get('expires_at') or '')
    if expiry <= utcnow():
        raise ValueError('Decision expiry must be in the future')
    payload['authority_label'] = assessment.provenance['configuration']['authority_labels'][kind]
    row = RiskDecision(service_id=service_id, assessment_id=assessment.id, kind=kind, decision=decision, payload=payload, created_by=str(actor), expires_at=expiry)
    db.add(row)
    db.flush()
    return row

def latest_assessment(db, service_id, now=None, include_details=True):
    from .finding_classification import latest_execution_id
    from .policy_data import risk_catalog_token
    now = aware(now or utcnow())
    statement = select(RiskAssessment).where(RiskAssessment.service_id == service_id,
        or_(RiskAssessment.provenance['preview'].as_boolean().is_(False), RiskAssessment.provenance['preview'].as_boolean().is_(None))).order_by(RiskAssessment.id.desc()).limit(1)
    if not include_details:
        statement = statement.options(defer(RiskAssessment.details))
    row = db.scalar(statement)
    if row is None:
        return None
    policy, assignment = resolve_policy(db, service_id)
    reasons = []
    from .remediation_jobs import native_vex_token
    if row.provenance.get('native_vex_token') != native_vex_token(db, service_id, now):
        reasons.append('native_vex_changed')
    from .package_identity_resolution import RESOLVER_VERSION
    if row.provenance.get('identity_resolver_version') != RESOLVER_VERSION:
        reasons.append('identity_resolver_changed')
    if aware(row.valid_until) <= now:
        reasons.append('assessment_expired')
    if row.source_execution_id != latest_execution_id(db, service_id):
        reasons.append('source_execution_changed')
    if row.policy_id != (policy.id if policy else None) or row.provenance.get('assignment') != assignment:
        reasons.append('policy_changed')
    if row.provenance.get('catalog_token') != risk_catalog_token():
        reasons.append('intelligence_changed')
    from .packaged_risk_intelligence import packaged_catalog_token
    if row.provenance.get('packaged_catalog_token') != packaged_catalog_token(db):
        reasons.append('packaged_intelligence_changed')
    from .vex_intelligence import intelligence_token
    if row.provenance.get('vex_token') != intelligence_token(db):
        reasons.append('vex_changed')
    from .finding_classification import status, _service_configuration
    if status(db, service_id, _service_configuration(db, service_id), now)[0] != 'current':
        reasons.append('classification_changed')
    from .models import FindingClassificationState
    current_state = db.get(FindingClassificationState, service_id)
    if row.provenance.get('classification_token') != classification_token(current_state):
        reasons.append('classification_rebuilt')
    from .policy_data import intelligence_status
    metadata = {k: {'state': v.get('state'), 'metadata': v.get('metadata', {})} for k, v in intelligence_status().items()}
    if row.provenance.get('catalog_metadata') != metadata:
        reasons.append('catalog_metadata_changed')
    if not row.provenance.get('scan_current', False):
        reasons.append('scan_unavailable_incomplete_or_stale')
    if not row.provenance.get('intelligence_current'):
        reasons.append('intelligence_unavailable_or_stale')
    result = serialize(row, exclude=() if include_details else ('details',))
    result.update(stale=bool(reasons), stale_reasons=reasons)
    return result



def classification_token(state):
    if state is None:
        return None
    return digest({'epoch': state.epoch, 'digest': state.config_digest, 'built_at': aware(state.built_at).isoformat() if state.built_at else None, 'latest': state.latest_execution_id})

def decision_status(row, assessment, now=None):
    now = aware(now or utcnow())
    expired = aware(row.expires_at) <= now
    return {'expired': expired, 'reassessment_required': expired or not assessment or assessment.get('stale', True) or assessment.get('id') != row.assessment_id}
