"""Release attribution and actionable revocation for approvals without revisions."""
import copy

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import main  # noqa: F401 -- register the complete application schema
from app import cyber_approvals as approvals, release_validity
from app.models import User, utcnow
from app.release_revisions import ReleaseRevision
from test_cyber_approvals import auth, db, request  # noqa: F401 -- shared database fixture


def inline(coroutine):
    """Requests here complete without IO; avoid Windows event-loop socket setup."""
    try:
        coroutine.send(None)
    except StopIteration as complete:
        return complete.value
    finally:
        coroutine.close()
    raise AssertionError('Handler unexpectedly suspended')


@pytest.fixture
def release(db):
    requester = User(username='requester', display_name='Service owner')
    reviewer = User(username='cyber.reviewer', display_name='Cyber reviewer')
    db.add_all([requester, reviewer])
    db.flush()
    decided_at = utcnow()
    snapshot = {'version': '1.0', 'approval_validity': release_validity.new_validity(decided_at)}
    row = approvals.CyberApproval(service_id=1, source_execution_id=1,
        requested_by_id=requester.id, decided_by_id=reviewer.id,
        status='approved', publish_status='published', variant='current_service',
        snapshot=snapshot, snapshot_digest=approvals.digest(snapshot), decided_at=decided_at,
        destination={'name': 'Approved', 'endpoint': 'https://registry.example'})
    db.add(row)
    db.commit()
    return row


def test_release_list_and_detail_attribute_the_decision_not_the_request(db, release):
    result = approvals.releases(db=db, auth=auth())['items'][0]
    detail = approvals.release(release.id, db, auth())
    for value in (result, detail):
        assert value['service_id'] == release.service_id
        assert value['requested_by'] == 'Service owner'
        assert value['approved_by'] == 'Cyber reviewer'
        assert value['approved_by_id'] == release.decided_by_id
        assert value['can_revoke'] is True
        assert value['revoked_at'] is None


@pytest.mark.parametrize('status', ['pending', 'denied'])
def test_other_decisions_are_not_presented_as_approvals(db, release, status):
    release.status = status
    db.commit()
    result = approvals.dto(db, release, auth())
    assert result['approved_by'] is None
    assert result['approved_by_id'] is None
    assert result['can_revoke'] is False


def test_approver_falls_back_to_username_when_display_name_is_blank(db, release):
    db.get(User, release.decided_by_id).display_name = '  '
    db.commit()
    assert approvals.dto(db, release, auth())['approved_by'] == 'cyber.reviewer'


def test_missing_attribution_is_not_replaced_with_the_requester(db, release):
    release.decided_by_id = None
    db.commit()
    result = approvals.dto(db, release, auth())
    assert result['approved_by'] is None
    assert result['approved_by_id'] is None
    assert result['requested_by'] == 'Service owner'


def test_retained_actor_id_does_not_fabricate_a_persons_name(db, release):
    release.decided_by_id = 999999
    db.commit()
    result = approvals.dto(db, release, auth())
    assert result['approved_by'] == 'Retained account'
    assert result['approved_by_id'] == 999999


@pytest.mark.parametrize('status', ['queued', 'publishing'])
def test_inflight_publication_disables_and_rejects_revocation(db, release, status):
    release.publish_status = status
    db.commit()
    assert approvals.dto(db, release, auth())['can_revoke'] is False
    with pytest.raises(HTTPException) as error:
        inline(approvals.revoke(release.id, request({'rationale': 'Withdraw release'}), db, auth()))
    assert error.value.status_code == 409
    db.refresh(release)
    assert release.revoked_at is None


@pytest.mark.parametrize('status', ['published', 'failed', 'not_started'])
def test_completed_or_failed_publication_can_be_revoked_without_a_revision(db, release, status, monkeypatch):
    release.publish_status = status
    db.commit()
    assert db.scalar(select(ReleaseRevision.id).where(ReleaseRevision.approval_id == release.id)) is None
    snapshot = copy.deepcopy(release.snapshot)
    events = []
    monkeypatch.setattr(approvals, 'record_audit', lambda *args, **kwargs: events.append(args[2:5]))
    result = inline(approvals.revoke(release.id, request({'rationale': 'Withdraw compromised release'}), db, auth()))
    assert result['revoked'] is True
    assert result['can_revoke'] is False
    assert result['validity_status'] == 'revoked'
    assert result['revoked_at'] == release.revoked_at.isoformat()
    assert result['revocation_reason'] == 'Withdraw compromised release'
    assert result['approved_by'] == 'Cyber reviewer'
    assert release.snapshot == snapshot
    assert events == [('cyber_release.revoke', 'cyber_approval', release.id)]
    with pytest.raises(HTTPException) as repeated:
        inline(approvals.revoke(release.id, request({'rationale': 'Revoke twice'}), db, auth()))
    assert repeated.value.status_code == 409


@pytest.mark.parametrize('actor,expected_status', [
    (auth(permissions=('service.view',)), 403),
    (auth(service=2), 404),
])
def test_revocation_requires_decision_permission_for_this_service(db, release, actor, expected_status):
    assert approvals.dto(db, release, actor)['can_revoke'] is False
    with pytest.raises(HTTPException) as error:
        inline(approvals.revoke(release.id, request({'rationale': 'Withdraw release'}), db, actor))
    assert error.value.status_code == expected_status
    db.refresh(release)
    assert release.revoked_at is None


def test_revocation_requires_csrf_and_a_meaningful_reason(db, release):
    for body, token, expected_status in [({'rationale': 'Withdraw release'}, 'wrong', 403),
                                          ({'rationale': ' '}, 'csrf', 409),
                                          ({'rationale': 'ab'}, 'csrf', 409)]:
        with pytest.raises(HTTPException) as error:
            inline(approvals.revoke(release.id, request(body, token), db, auth()))
        assert error.value.status_code == expected_status
        db.refresh(release)
        assert release.revoked_at is None


def test_failed_signed_revocation_remains_retryable_without_becoming_revocable(db, release):
    release.revoked_at = utcnow()
    release.publish_status = 'failed'
    release.publication = {'revocation': {'portable': {'kind': 'revocation'}}}
    db.commit()
    result = approvals.dto(db, release, auth())
    assert result['can_retry'] is True
    assert result['can_revoke'] is False
    assert result['approved_by'] == 'Cyber reviewer'
    assert approvals.dto(db, release, auth(permissions=('service.view',)))['can_retry'] is False
