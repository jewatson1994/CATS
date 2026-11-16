from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from app import main, oci_compliance as compliance
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.database import Base
from app.execution_summaries import payload_digest
from app.models import Execution, Service
from test_cyber_approval_evidence import distribution_case, SELECTED
from test_portal import SessionLocal, setup_function

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
PIN = 'sha256:' + 'a' * 64
OTHER = 'sha256:' + 'b' * 64
REPOSITORY = 'registry.example/team/app'
POLICY = dict(mode='compliance', blocked_severity='Critical', require_service_compliant=False,
              max_scan_age_days=None, group_id=None)


def payload(*, findings=None, when=NOW, pin=PIN, complete=True):
    return dict(complete=complete, fixable_only=True, scan_scope='service',
        service={'id': 'app'}, scanned_at=when.isoformat(), findings=findings or [],
        service_overview={'images': [{'image': REPOSITORY + '@' + pin, 'digest': pin}]})


def finding(severity='Critical', repository=REPOSITORY, pin=PIN):
    return dict(cve='CVE-2026-1234', severity=severity, image=repository + '@' + pin, image_digest=pin)


@pytest.fixture
def local():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key='app', name='App')
        db.add(service); db.flush()
        raw = payload()
        scan = Execution(service_id=service.id, execution_key='first', complete=True,
            scanned_at=NOW, scan_scope='service', raw_payload=raw, payload_digest=payload_digest(raw))
        db.add(scan); db.commit()
        mapping = SimpleNamespace(service_id=service.id, enabled=True, suspended=False,
            upstream_repository='team/app', upstream=SimpleNamespace(enabled=True, endpoint='https://registry.example'))
        yield SimpleNamespace(db=db, service=service, scan=scan, mapping=mapping)
    engine.dispose()


@pytest.mark.parametrize('severity,blocked', [('Critical', True), ('High', False), ('Medium', False), ('Low', False),
    ('Negligible', False), ('Informational', False)])
def test_exact_image_threshold(severity, blocked):
    result = compliance.evaluate_payload(payload(findings=[finding(severity)]), REPOSITORY, PIN, POLICY, NOW)
    assert result == ('compliance_blocked_severity' if blocked else None)


def test_different_image_findings_do_not_block_target():
    raw = payload(findings=[finding(repository='registry.example/team/other', pin=OTHER)])
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW) is None
    assert compliance.evaluate_payload(raw, REPOSITORY, OTHER, POLICY, NOW) == 'compliance_image_not_scanned'


@pytest.mark.parametrize('tag_only', [False, True])
def test_same_digest_findings_cannot_be_hidden_by_repository_alias(tag_only):
    alias = 'registry.example/z-critical'
    row = finding(repository=alias)
    if tag_only:
        row = dict(cve=row['cve'], severity='Critical', image=alias + ':latest')
    raw = payload(findings=[row])
    raw['service_overview']['images'].append({'image': alias + '@' + PIN, 'digest': PIN})
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW) == 'compliance_blocked_severity'
    assert compliance.evaluate_payload(raw, alias, PIN, POLICY, NOW) == 'compliance_blocked_severity'


def test_alias_for_other_digest_remains_isolated():
    alias = 'registry.example/z-critical'
    raw = payload(findings=[dict(cve='CVE-2026-1234', severity='Critical', image=alias + ':latest')])
    raw['service_overview']['images'].append({'image': alias + '@' + OTHER, 'digest': OTHER})
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW) is None


@pytest.mark.parametrize('overview_present', [False, True])
def test_schema_string_sbom_images_support_immutable_coverage(overview_present):
    raw = payload()
    if not overview_present:
        raw['service_overview']['images'] = []
    raw['sbom_images'] = [REPOSITORY + '@' + PIN, 'registry.example/other:latest']
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW) is None
    raw['sbom_images'] = [REPOSITORY + ':latest']
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW) == (
        None if overview_present else 'compliance_image_not_scanned')


@pytest.mark.parametrize('change,reason', [
    ('incomplete', 'compliance_scan_incomplete'), ('skipped', 'compliance_scan_incomplete'),
    ('missing_findings', 'compliance_evidence_invalid'), ('missing_image', 'compliance_image_not_scanned'),
    ('mutable_image', 'compliance_image_not_scanned'), ('unknown_severity', 'compliance_evidence_invalid'),
    ('unattributed', 'compliance_evidence_invalid'), ('ambiguous', 'compliance_evidence_invalid'),
])
def test_missing_or_ambiguous_scan_evidence_denies(change, reason):
    raw = payload()
    if change == 'incomplete': raw['complete'] = False
    if change == 'skipped': raw['skipped_images'] = ['unavailable']
    if change == 'missing_findings': raw.pop('findings')
    if change == 'missing_image': raw['service_overview']['images'] = []
    if change == 'mutable_image': raw['service_overview']['images'] = [{'image': REPOSITORY + ':latest'}]
    if change == 'unknown_severity': raw['findings'] = [finding('Unknown')]
    if change == 'unattributed': raw['findings'] = [{'severity': 'Critical'}]
    if change == 'ambiguous':
        raw['service_overview']['images'].append({'image': REPOSITORY + '@' + OTHER, 'digest': OTHER})
        raw['findings'] = [{'severity': 'Critical', 'image': REPOSITORY + ':latest'}]
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW) == reason


def test_scan_age_is_optional_and_bound_to_original_timestamp():
    raw = payload()
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW + timedelta(days=400)) is None
    limited = dict(POLICY, max_scan_age_days=1)
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, limited, NOW + timedelta(days=1)) == 'compliance_scan_stale'
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW - timedelta(seconds=1)) == 'compliance_scan_not_yet_valid'
    assert compliance.evaluate_payload(raw, REPOSITORY, PIN, POLICY, NOW,
        scanned_at=NOW - timedelta(days=1)) == 'compliance_evidence_invalid'


def test_clean_exact_scan_needs_no_cyber_approval(local):
    result = compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW)
    assert result.allowed and result.reason == 'compliant'
    assert result.approval_id is None and result.release_id is None
    assert result.execution_id == local.scan.id and result.authorization_source == 'compliance'
    assert local.db.scalar(select(CyberApproval.id)) is None


@pytest.mark.parametrize('change', ['incomplete', 'critical', 'wrong_digest'])
def test_newest_current_scan_cannot_fall_back_to_old_clean_scan(local, change):
    when = NOW + timedelta(hours=1)
    raw = payload(when=when, complete=change != 'incomplete', pin=OTHER if change == 'wrong_digest' else PIN,
                  findings=[finding()] if change == 'critical' else [])
    newest = Execution(service_id=local.service.id, execution_key='second', complete=raw['complete'],
        scanned_at=when, scan_scope='service', raw_payload=raw, payload_digest=payload_digest(raw))
    local.db.add(newest); local.db.commit()
    result = compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, when)
    assert not result.allowed and result.execution_id == newest.id


def test_newer_target_image_scan_is_not_hidden_by_whole_service_scan(local):
    when = NOW + timedelta(hours=1)
    raw = payload(when=when, findings=[finding()]); raw['scan_scope'] = 'image'
    scan = Execution(service_id=local.service.id, execution_key='image-scan', complete=True,
        scanned_at=when, scan_scope='image', scope_image=REPOSITORY + '@' + PIN,
        raw_payload=raw, payload_digest=payload_digest(raw))
    local.db.add(scan); local.db.commit()
    assert compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, when).reason == 'compliance_blocked_severity'


def test_mismatched_digest_and_cross_repository_evidence_deny(local):
    local.db.execute(update(Execution).where(Execution.id == local.scan.id).values(payload_digest='0' * 64))
    local.db.commit()
    assert compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW).reason == 'compliance_evidence_invalid'
    local.mapping.upstream_repository = 'other/app'
    assert not compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW).allowed


def test_optional_service_compliance_is_an_additional_gate(local, monkeypatch):
    monkeypatch.setattr(main, 'service_view', lambda *args: {'incomplete': False, 'compliant': False})
    assert compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW).allowed
    required = dict(POLICY, blocked_severity='None', require_service_compliant=True)
    assert compliance.authorize_compliance(local.db, local.mapping, PIN, required, NOW).reason == 'service_noncompliant'


@pytest.mark.parametrize('publication_status', ['published', 'queued', 'publishing', 'failed'])
def test_verified_published_identity_can_use_source_scan_without_cyber_authority(local, publication_status):
    snapshot = dict(service_id=local.service.id, source_execution_id=local.scan.id,
        source_payload_digest=local.scan.payload_digest,
        artifacts=[dict(kind='image', reference=REPOSITORY + '@' + PIN, digest=PIN)])
    approval = CyberApproval(service_id=local.service.id, source_execution_id=local.scan.id,
        variant='current', status='approved', revoked_at=NOW, snapshot=snapshot,
        snapshot_digest=snapshot_digest(snapshot), publish_status=publication_status)
    local.db.add(approval); local.db.flush()
    artifact = dict(kind='image', reference='registry.example/published/app@' + PIN,
        digest=PIN, source_digest=PIN, scan_identity_retained=True,
        identity_resolution='retained-evidence', verification_status='verified')
    approval.publication = dict(status='published', verification_status='verified', signature_status='verified',
        artifacts=[artifact], manifest=dict(approval_id=approval.id, snapshot_digest=approval.snapshot_digest,
                                         artifacts=[artifact]))
    local.db.commit(); local.mapping.upstream_repository = 'published/app'
    result = compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW)
    assert result.allowed and result.approval_id is None
    receipt = deepcopy(approval.publication); receipt['artifacts'][0]['source_digest'] = OTHER
    approval.publication = receipt; local.db.commit()
    assert not compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW).allowed


def test_relocated_image_new_incomplete_scan_does_not_borrow_old_distribution(local):
    # The verified source must remain a candidate even when the newest scan
    # retained no positive image coverage; otherwise an older clean assessment
    # could incorrectly win.
    from unittest.mock import patch
    when = NOW + timedelta(hours=1)
    raw = payload(when=when, complete=False); raw['service_overview']['images'] = []
    current = Execution(service_id=local.service.id, execution_key='incomplete', complete=False,
        scanned_at=when, scan_scope='service', raw_payload=raw, payload_digest=payload_digest(raw))
    local.db.add(current); local.db.commit()
    local.mapping.upstream_repository = 'published/app'
    with patch.object(compliance, '_published_sources', return_value=[(REPOSITORY, PIN, None)]), \
            patch.object(compliance, '_distribution_candidates', return_value=[(NOW, local.scan, None)]):
        result = compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, when)
    assert result.reason == 'compliance_scan_incomplete' and result.execution_id == current.id


def test_publication_source_alias_tie_cannot_select_clean_name_for_same_digest(local):
    aliases = ('registry.example/a-clean', 'registry.example/z-critical')
    raw = payload(findings=[finding(repository=aliases[1])])
    raw['service_overview']['images'] = [{'image': reference + '@' + PIN, 'digest': PIN}
                                       for reference in aliases]
    local.scan.raw_payload = raw
    local.scan.payload_digest = payload_digest(raw)
    for source in aliases:
        snapshot = dict(service_id=local.service.id, source_execution_id=local.scan.id,
            source_payload_digest=local.scan.payload_digest,
            artifacts=[dict(kind='image', reference=source + '@' + PIN, digest=PIN)])
        approval = CyberApproval(service_id=local.service.id, source_execution_id=local.scan.id,
            variant='current', status='approved', snapshot=snapshot,
            snapshot_digest=snapshot_digest(snapshot), publish_status='published')
        local.db.add(approval); local.db.flush()
        artifact = dict(kind='image', reference='registry.example/published/app@' + PIN,
            digest=PIN, source_digest=PIN, scan_identity_retained=True,
            identity_resolution='retained-evidence', verification_status='verified')
        approval.publication = dict(status='published', verification_status='verified', signature_status='verified',
            artifacts=[artifact], manifest=dict(approval_id=approval.id, snapshot_digest=approval.snapshot_digest,
                                             artifacts=[artifact]))
    local.db.commit(); local.mapping.upstream_repository = 'published/app'
    decision = compliance.authorize_compliance(local.db, local.mapping, PIN, POLICY, NOW)
    assert not decision.allowed and decision.reason == 'compliance_blocked_severity'


def test_distribution_latest_pending_scan_cannot_reuse_old_clean_scan(distribution_case):
    case = distribution_case
    case.scan([(SELECTED, PIN)])
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == 'payments-service'))
        mapping = SimpleNamespace(service_id=service.id, enabled=True, suspended=False,
            upstream_repository='app', upstream=SimpleNamespace(enabled=True, endpoint='https://source.example'))
        assert compliance.authorize_compliance(db, mapping, PIN, POLICY).allowed
        response = case.client.post(f"/api/services/payments-service/distributions/{case.selected['id']}/scan",
            headers=case.headers, json={})
        assert response.status_code == 200
        result = compliance.authorize_compliance(db, mapping, PIN, POLICY)
        assert not result.allowed and result.reason == 'compliance_scan_incomplete'
