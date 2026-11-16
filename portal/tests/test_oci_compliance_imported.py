from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography.fernet import Fernet
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import main  # Register all related model tables.
from app.database import Base
from app.models import Execution, Service, ServiceArchiveEvent, User
from app.oci_compliance_imported import authorize_imported_compliance
from app.oci_models import OCIRepository, OCIUpstream
from app.replica_integrity import digest as sealed_digest, seal_record
from app.replica_models import ReplicaRelease, ReplicaServiceState, ReplicaSource


NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
PIN = 'sha256:' + 'a' * 64
CHILD = 'sha256:' + 'b' * 64
OTHER = 'sha256:' + 'c' * 64
SOURCE = 'docker.io/library/nginx'
POLICY = dict(mode='compliance', blocked_severity='Critical', require_service_compliant=False,
              max_scan_age_days=None, group_id=None)


def finding(repository=SOURCE, severity='Critical'):
    return dict(cve='CVE-2026-1234', severity=severity, image=repository + '@' + PIN, image_digest=PIN)


@pytest.fixture
def imported(monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        user = User(username='importer', display_name='Importer')
        service = Service(service_key='local-nginx', name='Imported nginx')
        upstream = OCIUpstream(name='registry', endpoint='https://registry.example')
        db.add_all([user, service, upstream]); db.flush()
        source = ReplicaSource(name='publisher', upstream_id=upstream.id, repository='releases',
            trusted_publishers=['trusted-publisher'], enabled=True, created_by_id=user.id)
        mapping = OCIRepository(public_repository='replica/nginx', upstream_id=upstream.id,
            upstream_repository='published/nginx', service_id=service.id)
        db.add_all([source, mapping]); db.flush()
        state = ReplicaServiceState(service_id=service.id, publisher='trusted-publisher',
            source_service_id='source-nginx', source_id=source.id, upstream_id=upstream.id, high_sequence=1)
        raw = dict(complete=True, scan_scope='service', service={'id': 'source-nginx'},
            scanned_at=NOW.isoformat(), findings=[], fixable_only=True,
            service_overview={'images': [{'image': SOURCE + '@' + PIN, 'digest': PIN}]})
        evidence = dict(format='cats-replica-service-v1', service_key='source-nginx', records={
            'services': [{'id': 41, 'service_key': 'source-nginx'}],
            'executions': [dict(id=42, service_id=41, service_version_id=43, scan_scope='service',
                scanned_at=NOW.isoformat(), complete=True, raw_payload=raw,
                payload_digest='original-unscrubbed-payload-hash')]}, extension={
            'approval_context': dict(service_id=41, source_execution_id=42, source_version_id=43),
            'display': {'services_row': {'compliant': True}}})
        artifact = dict(kind='image', repository='published/nginx', digest=PIN, manifests=[PIN, CHILD],
            blobs=[OTHER], reference='registry.example/published/nginx@' + PIN,
            source_reference=SOURCE + '@' + PIN, source_references=['nginx:1.0'], source_digest=PIN,
            scan_identity_retained=True, identity_resolution='retained-evidence', verification_status='verified')
        manifest = {'artifacts': [artifact]}
        release = ReplicaRelease(service_id=service.id, publisher=state.publisher, source_release_id='release-1',
            sequence=1, manifest=manifest, manifest_digest=sealed_digest(manifest), artifacts=[artifact],
            evidence_state=evidence, key_fingerprint=state.publisher, verified=True, complete=True,
            approved_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1),
            source_reference='releases@' + OTHER)
        seal_record(release)
        db.add_all([release, state]); db.flush()
        state.active_release_id = release.id
        db.commit()
        yield SimpleNamespace(db=db, service=service, source=source, mapping=mapping, state=state,
            release=release, upstream=upstream)
    engine.dispose()


def decision(case, pin=PIN, policy=None, now=NOW):
    return authorize_imported_compliance(case.db, case.mapping, pin, policy or POLICY, now)


def capture(case, change, *, seal=True):
    evidence = deepcopy(case.release.evidence_state)
    change(evidence)
    case.release.evidence_state = evidence
    if seal:
        case.release.evidence_state_digest = sealed_digest(evidence)
        seal_record(case.release)
    case.db.commit()


def raw(evidence):
    return evidence['records']['executions'][0]['raw_payload']


@pytest.mark.parametrize('pin', [PIN, CHILD])
def test_relocated_image_and_verified_child_use_original_captured_scan(imported, pin):
    result = decision(imported, pin)
    assert result.allowed and result.authorization_source == 'compliance'
    assert result.effective_policy['evidence_source'] == 'publisher_capture'
    assert result.service_id == imported.service.id
    assert result.approval_id is None and result.release_id is None and result.execution_id is None


def test_critical_findings_block_even_when_release_is_approved(imported):
    capture(imported, lambda evidence: raw(evidence).update(findings=[finding()]))
    assert decision(imported).reason == 'compliance_blocked_severity'
    capture(imported, lambda evidence: raw(evidence).update(findings=[finding(severity='High')]))
    assert decision(imported).allowed
    assert decision(imported, policy=dict(POLICY, blocked_severity='High')).reason == 'compliance_blocked_severity'


@pytest.mark.parametrize('change', ['expired', 'revoked'])
def test_approval_validity_is_not_a_compliance_mode_criterion(imported, change):
    if change == 'expired':
        imported.release.expires_at = NOW
    else:
        imported.release.revoked_at = NOW
        imported.release.revocation_reason = 'Approval withdrawn'
    seal_record(imported.release); imported.db.commit()
    assert decision(imported).allowed


@pytest.mark.parametrize('change', ['source_disabled', 'publisher_removed', 'unverified', 'incomplete',
    'tampered_graph', 'tampered_seal', 'no_active_release', 'wrong_upstream'])
def test_imported_trust_and_active_inventory_remain_required(imported, change):
    if change == 'source_disabled': imported.source.enabled = False
    if change == 'publisher_removed': imported.source.trusted_publishers = []
    if change == 'unverified': imported.release.verified = False
    if change == 'incomplete': imported.release.complete = False
    if change == 'tampered_graph': imported.release.artifacts = []
    if change == 'tampered_seal': imported.release.integrity_seal = 'forged'
    if change == 'no_active_release': imported.state.active_release_id = None
    if change == 'wrong_upstream': imported.state.upstream_id = 123
    imported.db.commit()
    assert not decision(imported).allowed


def test_no_historical_clean_release_fallback(imported):
    previous = imported.release
    newer = ReplicaRelease(service_id=previous.service_id, publisher=previous.publisher, source_release_id='release-2',
        sequence=2, manifest=deepcopy(previous.manifest), manifest_digest=previous.manifest_digest,
        artifacts=deepcopy(previous.artifacts), evidence_state=deepcopy(previous.evidence_state),
        key_fingerprint=previous.key_fingerprint, verified=True, complete=True,
        approved_at=previous.approved_at, expires_at=previous.expires_at, source_reference='releases@' + CHILD)
    raw(newer.evidence_state)['findings'] = [finding()]
    seal_record(newer)
    imported.db.add(newer); imported.db.flush()
    imported.state.active_release_id = newer.id
    imported.db.commit()
    assert decision(imported).reason == 'compliance_blocked_severity'


@pytest.mark.parametrize('change', ['missing', 'changed_payload', 'wrong_service', 'wrong_execution',
    'wrong_version', 'duplicate_execution', 'no_execution', 'wrong_payload_service', 'wrong_context_service'])
def test_invalid_original_capture_fails_closed(imported, change):
    def mutate(evidence):
        if change == 'missing': evidence.clear()
        if change == 'changed_payload': raw(evidence)['findings'] = [finding()]
        if change == 'wrong_service': evidence['records']['services'][0]['service_key'] = 'another-service'
        if change == 'wrong_execution': evidence['extension']['approval_context']['source_execution_id'] = 99
        if change == 'wrong_version': evidence['records']['executions'][0]['service_version_id'] = 99
        if change == 'duplicate_execution': evidence['records']['executions'].append(deepcopy(evidence['records']['executions'][0]))
        if change == 'no_execution': evidence['records']['executions'] = []
        if change == 'wrong_payload_service': raw(evidence)['service']['id'] = 'another-service'
        if change == 'wrong_context_service': evidence['extension']['approval_context']['service_id'] = 99
    capture(imported, mutate, seal=change not in {'missing', 'changed_payload'})
    assert decision(imported).reason == 'compliance_evidence_invalid'


@pytest.mark.parametrize('change', ['projected_dirty', 'projected_clean'])
def test_local_execution_projection_cannot_change_publisher_decision(imported, change):
    projected = deepcopy(raw(imported.release.evidence_state))
    projected['service']['id'] = imported.service.service_key
    projected['findings'] = [finding()] if change == 'projected_dirty' else []
    execution = Execution(service_id=imported.service.id, execution_key='replica:projected', complete=True,
        scan_scope='service', scanned_at=NOW + timedelta(minutes=1), raw_payload=projected)
    imported.db.add(execution); imported.db.flush()
    imported.state.active_execution_id = execution.id
    imported.db.commit()
    if change == 'projected_clean':
        capture(imported, lambda evidence: raw(evidence).update(findings=[finding()]))
    assert decision(imported).allowed is (change == 'projected_dirty')


@pytest.mark.parametrize('change', ['no_retained_identity', 'unverified_source', 'publication_resolved',
    'wrong_digest', 'wrong_repository', 'missing_images'])
def test_source_identity_must_match_retained_scan(imported, change):
    artifacts = deepcopy(imported.release.artifacts)
    if change == 'no_retained_identity': artifacts[0]['scan_identity_retained'] = False
    if change == 'unverified_source': artifacts[0]['verification_status'] = 'pending'
    if change == 'publication_resolved': artifacts[0]['identity_resolution'] = 'publication'
    if change == 'wrong_digest':
        capture(imported, lambda evidence: raw(evidence)['service_overview'].update(images=[{'image': SOURCE + '@' + OTHER, 'digest': OTHER}]))
    if change == 'wrong_repository':
        capture(imported, lambda evidence: raw(evidence)['service_overview'].update(images=[{'image': 'docker.io/library/other@' + PIN, 'digest': PIN}]))
    if change == 'missing_images':
        capture(imported, lambda evidence: raw(evidence)['service_overview'].update(images=[]))
    imported.release.artifacts = artifacts
    seal_record(imported.release); imported.db.commit()
    assert decision(imported).reason == 'compliance_image_not_scanned'


def test_all_scanned_source_aliases_are_evaluated(imported):
    alias = 'registry.example/source/nginx'
    artifacts = deepcopy(imported.release.artifacts)
    artifacts[0]['source_references'].append(alias + '@' + PIN)
    imported.release.artifacts = artifacts
    seal_record(imported.release); imported.db.commit()
    def add_alias(evidence):
        raw(evidence)['service_overview']['images'].append({'image': alias + '@' + PIN, 'digest': PIN})
        raw(evidence)['findings'] = [finding(repository=alias)]
    capture(imported, add_alias)
    assert decision(imported).reason == 'compliance_blocked_severity'


def test_original_scan_time_controls_freshness(imported):
    limited = dict(POLICY, max_scan_age_days=1)
    assert decision(imported, policy=limited, now=NOW + timedelta(days=1)).reason == 'compliance_scan_stale'
    assert decision(imported, now=NOW + timedelta(days=400)).allowed
    assert decision(imported, now=NOW - timedelta(seconds=1)).reason == 'compliance_scan_not_yet_valid'


@pytest.mark.parametrize('compliant,reason', [(True, 'compliant'), (False, 'service_noncompliant'),
    (None, 'compliance_service_evidence_missing')])
def test_optional_service_status_uses_sealed_publisher_status(imported, compliant, reason):
    capture(imported, lambda evidence: evidence['extension']['display']['services_row'].update(compliant=compliant))
    result = decision(imported, policy=dict(POLICY, require_service_compliant=True))
    assert result.reason == reason
    assert result.allowed is (compliant is True)
    assert decision(imported).allowed


@pytest.mark.parametrize('change', ['staged', 'archived', 'disabled_mapping', 'disabled_upstream', 'suspended'])
def test_local_service_and_transport_controls_still_apply(imported, change):
    if change == 'staged': imported.service.lifecycle_status = 'staged'
    if change == 'archived':
        imported.db.add(ServiceArchiveEvent(service_id=imported.service.id, action='archive',
            reason='Retired', performed_by='operator', created_at=NOW))
    if change == 'disabled_mapping': imported.mapping.enabled = False
    if change == 'disabled_upstream': imported.upstream.enabled = False
    if change == 'suspended': imported.mapping.suspended = True
    imported.db.commit()
    assert not decision(imported).allowed


def test_only_verified_image_graph_is_authorized(imported):
    assert decision(imported, OTHER).reason == 'artifact_not_in_verified_release'
    assert decision(imported, 'latest').reason == 'invalid_digest'
    imported.mapping.upstream_repository = 'other/nginx'
    imported.db.commit()
    assert decision(imported).reason == 'artifact_not_in_verified_release'
