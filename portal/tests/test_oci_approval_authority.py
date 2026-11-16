"""HTTP pulls follow retained Cyber authority even when live posture changes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from app import main
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.models import Execution, Finding, PolicyFinding, Service, ServiceVersion
from app.oci_models import OCIRepository, OCIServicePullAccess
from app.release_validity import new_validity
from test_oci_proxy import digest, project, registry


def _approval_window(approval, start):
    """Keep the fixture's retained publication bound to its approval window."""
    approval.decided_at = start
    approval.snapshot = dict(approval.snapshot, approval_validity=new_validity(start))
    approval.snapshot_digest = snapshot_digest(approval.snapshot)
    if approval.publication:
        receipt = deepcopy(approval.publication)
        receipt['manifest']['snapshot_digest'] = approval.snapshot_digest
        approval.publication = receipt


def _reads(s, path, expected=200):
    for method in ('GET', 'HEAD'):
        for route in ('manifests/' + s.image, 'blobs/' + s.blob):
            response = s.client.request(method, path + route)
            assert response.status_code == expected, (method, route, response.text)
            if expected == 200 and method == 'HEAD':
                assert response.content == b''
    response = s.client.get(path + 'referrers/' + s.image)
    assert response.status_code == expected, response.text


@pytest.mark.parametrize('public', [False, True], ids=['private', 'public'])
@pytest.mark.parametrize('change', ['findings', 'new_scan', 'incomplete_scan', 'new_version', 'age_limits'])
def test_published_release_survives_live_posture_changes(project, public, change):
    s = project
    now = datetime.now(timezone.utc)
    service_id = s.service_ids[s.published]
    path = f'/v2/{s.routes[s.published]}/'
    with s.sessions() as db:
        approval = db.get(CyberApproval, s.approvals[s.published])
        execution = db.get(Execution, approval.source_execution_id)
        # The approval is still within its signed 90-day validity, but older
        # than both legacy one-day mapping limits used below.
        _approval_window(approval, now - timedelta(days=2))
        execution.scanned_at = now - timedelta(days=2)
        db.add(OCIServicePullAccess(service_id=service_id, public=public))
        db.commit()
    if public:
        s.client.headers.pop('Authorization')
    _reads(s, path)

    with s.sessions() as db:
        service = db.get(Service, service_id)
        approval = db.get(CyberApproval, s.approvals[s.published])
        retained_execution = db.get(Execution, approval.source_execution_id)
        if change == 'findings':
            past = now - timedelta(days=200)
            db.add(Finding(service_id=service_id, cve='CVE-2026-9876', severity='Critical',
                first_seen=past, episode_started=past, last_seen=now))
            db.add(PolicyFinding(service_id=service_id, identity_key='new-hardening-finding',
                finding='Privileged container', severity='High', first_seen=past,
                episode_started=past, last_seen=now))
        elif change in ('new_scan', 'incomplete_scan'):
            db.add(Execution(service_id=service_id, execution_key='later-published-scan',
                scanned_at=now, complete=change == 'new_scan', scan_scope='service',
                raw_payload=deepcopy(retained_execution.raw_payload)))
        elif change == 'new_version':
            version = ServiceVersion(service_id=service_id, version='2.0-unapproved')
            db.add(version)
            db.flush()
            service.current_version_id = version.id
            db.add(Execution(service_id=service_id, service_version_id=version.id,
                execution_key='next-version-scan', scanned_at=now, complete=False,
                scan_scope='service', raw_payload={'service': {'version': version.version}}))
        else:
            db.get(OCIRepository, s.mapping_id).policy = {
                'max_scan_age_days': 1, 'max_approval_age_days': 1}
        db.commit()
        if change in ('findings', 'incomplete_scan', 'new_version'):
            # The actual dashboard still reports the current condition. Only
            # the release's distribution authority is independent of it.
            db.expire_all()
            view = main.service_view(db.get(Service, service_id), now,
                                     main.configuration_for_service(db, service))
            assert not view['compliant']

    _reads(s, path)
    # Approval for the retained digest does not carry over to a moved tag or
    # another manifest, even if that manifest references already cached blobs.
    raw = json.dumps({'schemaVersion': 2, 'config': {'digest': s.blob, 'size': 10},
        'layers': [], 'annotations': {'version': 'unapproved'}}).encode()
    s.documents['latest'] = s.documents[digest(raw)] = raw
    for reference in ('latest', digest(raw)):
        assert s.client.get(path + 'manifests/' + reference).status_code == 403


@pytest.mark.parametrize('decision', ['pending', 'denied'])
def test_new_review_does_not_revoke_existing_release(project, decision):
    s = project
    path = f'/v2/{s.routes[s.scanned]}/'
    _reads(s, path)
    with s.sessions() as db:
        original = db.get(CyberApproval, s.approvals[s.scanned])
        snapshot = deepcopy(original.snapshot)
        db.add(CyberApproval(service_id=original.service_id,
            source_execution_id=original.source_execution_id, variant=original.variant,
            status=decision, snapshot=snapshot, snapshot_digest=snapshot_digest(snapshot),
            decided_at=datetime.now(timezone.utc) if decision == 'denied' else None))
        db.commit()
    _reads(s, path)
    with s.sessions() as db:
        db.get(CyberApproval, s.approvals[s.scanned]).revoked_at = datetime.now(timezone.utc)
        db.commit()
    _reads(s, path, 403)


@pytest.mark.parametrize('restriction', ['revoked', 'expired'])
def test_latest_approved_decision_cannot_fall_back_after_restriction(project, restriction):
    s = project
    path = f'/v2/{s.routes[s.scanned]}/'
    _reads(s, path)
    with s.sessions() as db:
        original = db.get(CyberApproval, s.approvals[s.scanned])
        snapshot = deepcopy(original.snapshot)
        latest = CyberApproval(service_id=original.service_id,
            source_execution_id=original.source_execution_id, variant=original.variant,
            status='approved', snapshot=snapshot, snapshot_digest=snapshot_digest(snapshot),
            decided_at=original.decided_at)
        db.add(latest)
        db.commit()
        latest_id = latest.id
    _reads(s, path)
    with s.sessions() as db:
        latest = db.get(CyberApproval, latest_id)
        if restriction == 'revoked':
            latest.revoked_at = datetime.now(timezone.utc)
        else:
            _approval_window(latest, datetime.now(timezone.utc) - timedelta(days=91))
        db.commit()
    _reads(s, path, 403)


def test_release_authority_does_not_remove_private_login_requirement(project):
    s = project
    path = f'/v2/{s.routes[s.published]}/'
    _reads(s, path)
    credentials = s.client.headers.pop('Authorization')
    _reads(s, path, 401)
    s.client.headers['Authorization'] = credentials
    _reads(s, path)
