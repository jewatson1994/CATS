"""Freeze complete service evidence for the trusted replica import path.

Ordinary Service Import deliberately continues to import inputs for reassessment.
This extension uses the same relational records, but retains assessment evidence
only inside the independently signed Cyber release, never as a trust grant.
"""
from datetime import datetime, timezone
from sqlalchemy import LargeBinary, and_, cast, func, select

from . import models as m, service_transfer as transfer
from .service_bundle import encode

FORMAT = 'cats-replica-service-v1'
POLICY_KEYS = frozenset(('overdue_days', 'hardening_overdue_days', 'hardening_noncompliant',
    'warning_days', 'exception_max_days', 'skipped_images_incomplete', 'incomplete_noncompliant',
    'kev_enabled', 'kev_noncompliant', 'epss_enabled', 'epss_threshold', 'epss_rules',
    'minimum_severity', 'compliance_mode', 'raw_due_rules', 'cyber_warning_policy'))


def capture(db, service, approval_snapshot):
    from .policy_data import risk_catalog_token
    from .cyber_release_publication import _public_snapshot
    intelligence_token = risk_catalog_token()
    display = _display(db, service)
    records = transfer.snapshot(db, service, authoritative=False)
    actors, removed = {}, []
    for name, rows in records.items():
        for row in rows:
            for column in transfer.TABLES[name].__table__.columns:
                if column.foreign_keys and next(iter(column.foreign_keys)).column.table.name == 'users' and row[column.name] is not None:
                    user = db.get(m.User, row[column.name])
                    actors[str(row[column.name])] = user.username if user else 'Unavailable original identity'
            if name == 'remediation_executions':
                row['artifact_path'] = None
            if name == 'workflow_requests':
                row.update(bulk_group_id=None, import_batch_id=None, import_row_number=None)
            for field in ('source_reference', 'artifact_reference'):
                value = row.get(field)
                if value and (value.startswith(('/', '\\', 'file:')) or transfer.re.match(r'^[A-Za-z]:', value)):
                    row[field] = None
                    removed.append(name + '/' + field)
    records = transfer.scrub(records, excluded=removed)
    for row in records['service_artifact_revisions']:
        row['files'] = transfer.safe_sources(row['files'], removed)
    for row in records['executions']:
        raw = row['raw_payload']
        raw['helm_source_files'] = transfer.safe_sources(raw.get('helm_source_files', {}), removed)
        if isinstance(raw.get('service'), dict):
            raw['service']['groups'] = []
    activity = [transfer.record(row) for row in db.scalars(select(m.AuditEvent).where(
        m.AuditEvent.target_type == 'service', m.AuditEvent.target_id == str(service.id)))]
    extension = _extensions(db, service.id)
    # Preserve identities used only by approval/risk/provenance history too.
    for name, rows in extension.items():
        table = m.Base.metadata.tables.get(name)
        if table is None:
            continue
        for column in table.columns:
            if column.foreign_keys and next(iter(column.foreign_keys)).column.table.name == 'users':
                for row in rows:
                    identity = row.get(column.name)
                    if identity is not None and str(identity) not in actors:
                        user = db.get(m.User, identity)
                        actors[str(identity)] = user.username if user else 'Unavailable original identity'
    extension['display'] = display
    extension.update(_finding_decisions(db, service.id, display['configuration'],
        datetime.fromisoformat(display['captured_at']), approval_snapshot.get('source_execution_id')))
    if risk_catalog_token() != intelligence_token:
        raise ValueError('Policy intelligence changed during evidence capture. Retry the approval request.')
    # These contextual records remain evidence. They never create local accounts,
    # roles, registry settings, jobs or authoritative local Cyber decisions.
    extension['approval_context'] = transfer.scrub(_public_snapshot(approval_snapshot), excluded=removed)
    return {'format': FORMAT, 'service_key': service.service_key,
            'captured_at': datetime.now(timezone.utc).isoformat(),
            'relational_schema': transfer.schema_signature(),
            'records': records, 'actors': actors,
            'activity': transfer.scrub(activity, excluded=removed),
            'extension': transfer.scrub(extension, excluded=removed),
            'counts': {name: len(rows) for name, rows in records.items()}, 'redactions': removed}


def _display(db, service):
    """Freeze the authoritative dashboard outputs, using its existing aggregation."""
    from . import main, service_posture
    from .dashboard_portfolio import compute_rows
    now = datetime.now(timezone.utc)
    base = main.get_configuration(db)
    configurations = service_posture.resolve_configurations(db, [service.id], base)
    services, _ = main.service_overview_rows_aggregated(db, None, now, base, [service], configurations)
    cyber_base = main.get_global_configuration(db)
    cyber_configuration = service_posture.resolve_configurations(db, [service.id], cyber_base)
    cyber = compute_rows(db, [service], cyber_configuration, cyber_base, now)
    if len(services) != 1 or service.id not in cyber:
        raise ValueError('Complete service dashboard evidence is unavailable')
    return {'captured_at': now.isoformat(), 'services_row': service_posture._services_row(services[0]),
            'cyber_row': service_posture._cyber_row(cyber[service.id]),
            'configuration': {key: configurations[service.id][key] for key in POLICY_KEYS
                              if key in configurations[service.id]}}


def _extensions(db, service_id):
    from .cyber_release_publication import _public_snapshot
    from .risk_models import RiskAssessment, RiskDecision, RiskPolicyVersion
    from .native_vex_models import VexDispositionEvaluation, VexObservationDisposition, VexFindingDisposition
    from .artifact_catalog import GlobalArtifact, ArtifactLocation, ServiceArtifactAssignment, ArtifactPatchLineage
    from .cyber_approvals import CyberApproval
    from .release_revisions import ReleaseRevision, ReleaseRevisionState
    from .discovery_models import DiscoveryDistribution
    models = [RiskAssessment, RiskDecision, VexDispositionEvaluation, ServiceArtifactAssignment,
              CyberApproval, ReleaseRevision, DiscoveryDistribution,
              m.FindingClassification, m.FindingClassificationState, m.FindingClassificationChange]
    result = {}
    for model in models:
        if hasattr(model, 'service_id'):
            result[model.__tablename__] = [transfer.record(row) for row in db.scalars(
                select(model).where(model.service_id == service_id))]
    queries = [
        (RiskPolicyVersion, RiskPolicyVersion.id.in_([r['policy_id'] for r in result['risk_assessments'] if r['policy_id'] is not None])),
        (VexObservationDisposition, VexObservationDisposition.evaluation_id.in_([r['id'] for r in result['vex_disposition_evaluations']])),
        (VexFindingDisposition, VexFindingDisposition.evaluation_id.in_([r['id'] for r in result['vex_disposition_evaluations']])),
        (ReleaseRevisionState, ReleaseRevisionState.revision_id.in_([r['id'] for r in result['release_revisions']])),
    ]
    artifact_ids = [r['artifact_id'] for r in result['service_artifact_assignments']]
    queries.extend([(GlobalArtifact, GlobalArtifact.id.in_(artifact_ids)),
                    (ArtifactLocation, ArtifactLocation.artifact_id.in_(artifact_ids)),
                    (ArtifactPatchLineage, ArtifactPatchLineage.output_artifact_id.in_(artifact_ids))])
    for model, predicate in queries:
        result[model.__tablename__] = [transfer.record(row) for row in db.scalars(select(model).where(predicate))]
    from .vex_models import VexDocument, VexSource, VexStatement
    from .vex_intelligence import MAX_BYTES
    document_ids = {candidate['document_id'] for assessment in result['risk_assessments']
        for finding in assessment.get('details', []) for observation in finding.get('observations', [])
        for key in ('statements', 'rejected_candidates') for candidate in observation.get('vex', {}).get(key, [])
        if candidate.get('document_id') is not None}
    # Enforce the same storage-byte limit as the authoritative original-document
    # endpoint before loading text. Referenced missing evidence fails the freeze.
    size = (func.octet_length(VexDocument.raw_text) if db.get_bind().dialect.name == 'postgresql'
            else func.length(cast(VexDocument.raw_text, LargeBinary)))
    documents = [transfer.record(row) for row in db.scalars(select(VexDocument).where(
        VexDocument.id.in_(document_ids), size <= MAX_BYTES))]
    if {row['id'] for row in documents} != document_ids:
        raise ValueError('Referenced original VEX evidence is unavailable or exceeds its retained evidence limit')
    result['vex_documents'] = documents
    result['vex_statements'] = [transfer.record(row) for row in db.scalars(select(VexStatement).where(
        VexStatement.document_id.in_(document_ids)))]
    result['vex_sources'] = [{key: value for key, value in transfer.record(row).items() if key not in ('etags', 'last_error')}
        for row in db.scalars(select(VexSource).where(VexSource.id.in_({row['source_id'] for row in documents})))]
    # Publication receipts contain local retained paths. Keep approved snapshots
    # and provenance, excluding storage and destination configuration material.
    for row in result['cyber_approvals']:
        row.pop('publication', None)
        row.pop('destination', None)
        row['snapshot'] = _public_snapshot(row['snapshot'])
    return result


def _finding_decisions(db, service_id, configuration, captured_at, execution_id):
    """Freeze canonical classifications and final decisions, independent of caches."""
    from . import finding_classification, main
    from .native_vex import finding_excluded, observation_excluded
    from .policy_data import observation_risk, risk_metadata
    F, O, E = m.Finding, m.FindingObservation, m.ExceptionRecord
    _, statement = finding_classification._classification_select(
        db, service_id, configuration, captured_at, execution_id)
    classifications = [{key: value.isoformat() if isinstance(value, datetime) else value
                        for key, value in row.items()} for row in db.execute(statement).mappings()]
    exception = select(E.id).where(E.finding_id == F.id, E.revoked_at.is_(None),
        E.starts_at <= captured_at, E.expires_at > captured_at).exists()
    eligible, noncompliant, _ = main._risk_finding_expressions(
        db, {service_id: configuration}, captured_at, exception)
    latest = select(func.max(O.id)).where(O.finding_id == F.id).correlate(F).scalar_subquery()
    rows = db.execute(select(F.id, F.cve, eligible.label('eligible'),
        and_(noncompliant, ~exception).label('noncompliant'), exception.label('excepted'),
        and_(finding_excluded(F.id, captured_at), ~exception).label('vex_excluded'), O.evidence)
        .outerjoin(O, O.id == latest).where(F.service_id == service_id)).mappings()
    decisions = []
    for row in rows:
        kev, epss = observation_risk(row['evidence'] or {}, risk_metadata(row['cve']))
        decisions.append({'finding_id': row['id'], 'eligible': row['eligible'],
            'noncompliant': row['noncompliant'], 'excepted': row['excepted'],
            'vex_excluded': row['vex_excluded'], 'kev': bool(kev), 'epss': epss})
    observation_decisions = [{'observation_id': identity, 'excluded': True} for identity in db.scalars(
        select(O.id).join(F, F.id == O.finding_id).where(F.service_id == service_id,
            observation_excluded(O.id, captured_at)))]
    return {'finding_classifications': classifications, 'finding_decisions': decisions,
            'observation_decisions': observation_decisions}


def encode_capture(db, service, approval_snapshot):
    return encode(capture(db, service, approval_snapshot))
