"""Independent scan posture for a runtime image that is attributable to a service."""
from datetime import datetime
from urllib.parse import urlsplit

from sqlalchemy import select

from . import oci_compliance, oci_compliance_imported, replica_authorization
from .cyber_approval_evidence import _identity
from .execution_summaries import payload_digest
from .models import ExceptionRecord, Execution, Finding, FindingObservation, Service
from .replica_models import ReplicaRelease
from .release_validity import utc


def _assessment(status, reason, execution):
    if isinstance(execution, Execution):
        return dict(status=status, reason=reason, source='local_scan', execution_id=execution.id,
                    scanned_at=utc(execution.scanned_at).isoformat())
    return dict(status=status, reason=reason, source='publisher_capture',
                scanned_at=utc(datetime.fromisoformat(execution['scanned_at'])).isoformat())


def _latest_scan(db, service_id):
    """Read and integrity-check one current-version service/image scan per overview."""
    service = db.get(Service, service_id)
    query = select(Execution).where(Execution.service_id == service_id,
             Execution.service_version_id.is_not_distinct_from(service.current_version_id),
             Execution.scan_scope.in_(('service', 'image'))).order_by(
                 Execution.scanned_at.desc(), Execution.id.desc()).limit(1)
    execution = db.scalar(query.execution_options(populate_existing=True))
    if not execution or not execution.complete:
        return None
    raw = execution.raw_payload
    if (not isinstance(raw, dict) or raw.get('complete') is not True
            or (raw.get('service') or {}).get('id') != service.service_key
            or raw.get('scan_scope') != execution.scan_scope
            or execution.payload_digest != payload_digest(raw)):
        return None
    return execution, {pin for _, pin in oci_compliance._coverage(raw)}


def _pin(reference, retained):
    try:
        return _identity(reference, retained)[1]
    except ValueError:
        return None


def _exact_findings(raw, digest):
    return {row['cve'] for row in raw.get('findings', []) if isinstance(row, dict)
            and isinstance(row.get('cve'), str)
            and _pin(row.get('image') or row.get('image_reference'), row.get('image_digest') or row.get('digest')) == digest}


def _posture(db, service_id, timestamp):
    from .main import configuration_for_service, service_overview_rows_aggregated
    service = db.get(Service, service_id, populate_existing=True)
    configuration = configuration_for_service(db, service)
    rows, _ = service_overview_rows_aggregated(db, None, timestamp, configuration,
                                              services=[service], configurations={service_id: configuration})
    return rows[0], configuration


def _failed_observations(cache, db, service_id, execution_id, timestamp):
    from .main import _risk_finding_expressions
    from .native_vex import observation_excluded
    active_exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id,
        ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= timestamp,
        ExceptionRecord.expires_at > timestamp).correlate(Finding).exists()
    _, configuration = cache.get(_posture, db, service_id, timestamp)
    _, noncompliant, _ = _risk_finding_expressions(db, {service_id: configuration}, timestamp, active_exception)
    query = select(Finding.cve, FindingObservation.image, FindingObservation.image_digest).join(
        FindingObservation, FindingObservation.finding_id == Finding.id).where(
        Finding.service_id == service_id, Finding.active.is_(True), noncompliant, ~active_exception,
        FindingObservation.execution_id == execution_id, ~observation_excluded(FindingObservation.id, timestamp))
    return {(cve, _pin(reference, retained)) for cve, reference, retained in db.execute(query)}


def _local(cache, db, mapping, digest, repository, timestamp):
    service_id = mapping.service_id
    evidence = cache.get(_latest_scan, db, service_id)
    if not evidence:
        return None
    execution, pins = evidence
    if digest not in pins:
        return None
    raw = execution.raw_payload
    source = repository
    if not oci_compliance.payload_covers_image(raw, source, digest):
        # A verified publication may relocate the same immutable manifest.
        service = db.get(Service, service_id)
        aliases = oci_compliance._published_sources(db, service, repository, digest)
        source = next((name for name, pin, _ in aliases
                       if pin == digest and oci_compliance.payload_covers_image(raw, name, digest)), None)
        if source is None:
            return None
    # The established validator checks completeness, timestamps and immutable
    # scope. Severity thresholds for OCI pulls are independent of service SLA.
    if oci_compliance.evaluate_payload(raw, source, digest, {'blocked_severity': 'None'},
                                       timestamp, scanned_at=execution.scanned_at) is not None:
        return None
    posture, _ = cache.get(_posture, db, service_id, timestamp)
    if posture.get('evidence_state') != 'Complete':
        return _assessment('unverified', 'scan_image_evidence_unavailable', execution)
    if posture.get('compliant') is True:
        return _assessment('compliant', 'scan_image_compliant', execution)
    cves = _exact_findings(raw, digest)
    if cves:
        # Scope the parameterized SQL by current execution and service.
        failed = cache.get(_failed_observations, cache, db, service_id, execution.id, timestamp)
        if any((cve, digest) in failed for cve in cves):
            return _assessment('noncompliant', 'scan_image_noncompliant', execution)
    return _assessment('unverified', 'scan_image_evidence_unavailable', execution)


def _active_capture(db, service_id, upstream_id, timestamp):
    state = replica_authorization._state(db, service_id)
    if not state or not state.active_release_id or state.upstream_id != upstream_id:
        return None
    release = db.get(ReplicaRelease, state.active_release_id, populate_existing=True)
    if not replica_authorization.trusted_release(db, release, state, timestamp):
        return None
    try:
        execution, display = oci_compliance_imported._captured_execution(release, state)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        return None
    return release, execution, display


def _imported(cache, db, mapping, digest, repository, timestamp):
    capture = cache.get(_active_capture, db, mapping.service_id, mapping.upstream_id, timestamp)
    if not capture:
        return None
    release, execution, display = capture
    sources = {source for artifact in replica_authorization._matches(release, mapping.upstream_repository, digest)
               if artifact.get('kind') == 'image' for source, pin in
               oci_compliance_imported._source_images(artifact, repository) if pin == digest}
    if not sources:
        return None
    raw = execution['raw_payload']
    if execution.get('scan_scope') not in ('service', 'image') or execution.get('complete') is not True or not any(
            oci_compliance.evaluate_payload(raw, source, digest, {'blocked_severity': 'None'}, timestamp,
                scanned_at=execution['scanned_at']) is None for source in sources):
        return None
    row = display.get('services_row', {})
    if row.get('evidence_state') != 'Complete':
        return _assessment('unverified', 'scan_image_evidence_unavailable', execution)
    compliant = row.get('compliant')
    if compliant is True:
        return _assessment('compliant', 'scan_image_compliant', execution)
    if compliant is not False:
        return None
    evidence = release.evidence_state
    records, extension = evidence['records'], evidence['extension']
    cves = _exact_findings(raw, digest)
    ids = {f['id'] for f in records.get('findings', []) if f.get('active') is True and f.get('cve') in cves
           and f.get('service_id') == execution['service_id']}
    failed = {f['finding_id'] for f in extension.get('finding_decisions', []) if f.get('noncompliant') is True
              and f.get('excepted') is False and f.get('vex_excluded') is False}
    excluded = extension.get('observation_decisions')
    if isinstance(excluded, list):
        excluded_ids = {o['observation_id'] for o in excluded if o.get('excluded') is True}
        failing_ids = ids & failed
        for observation in records.get('finding_observations', []):
            if (observation.get('finding_id') in failing_ids and observation.get('id') not in excluded_ids
                    and observation.get('execution_id') == execution['id']
                    and _pin(observation.get('image'), observation.get('image_digest')) == digest):
                return _assessment('noncompliant', 'scan_image_noncompliant', execution)
    return _assessment('unverified', 'scan_image_evidence_unavailable', execution)


def assess(cache, db, mapping, digest, path, timestamp, imported):
    repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + path
    if path != mapping.upstream_repository:
        from .oci_proxy import EffectiveMapping
        mapping = EffectiveMapping(mapping, path)
    if imported:
        return _imported(cache, db, mapping, digest, repository, timestamp)
    return _local(cache, db, mapping, digest, repository, timestamp)
