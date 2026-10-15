"""Time-limited Cyber authorization, separate from cryptographic authenticity."""
from datetime import datetime, timedelta, timezone
import os

SETTING = 'CATS_CYBER_APPROVAL_VALIDITY_DAYS'
PORTAL_SETTING = 'cyber_approval_validity_days'


def validate_days(value):
    value = str(value)
    if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 3650:
        raise ValueError(f'Cyber approval lifetime ({SETTING}) must be a whole number from 1 to 3650 days')
    return int(value)


def configured_days(settings=None):
    return validate_days((settings or {}).get(PORTAL_SETTING, os.environ.get(SETTING, '90')))


def utc(value):
    # SQLite returns naive UTC values for timezone-aware DateTime columns.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def new_validity(approved_at, settings=None):
    days = configured_days(settings)
    approved_at = utc(approved_at)
    return {'approved_at': approved_at.isoformat(),
            'expires_at': (approved_at + timedelta(days=days)).isoformat(), 'validity_days': days}


def dates(validity):
    try:
        start = datetime.fromisoformat(validity['approved_at'])
        end = datetime.fromisoformat(validity['expires_at'])
        days = validity['validity_days']
        if (start.utcoffset() is None or end.utcoffset() is None or type(days) is not int
                or not 1 <= days <= 3650 or end - start != timedelta(days=days)):
            raise ValueError()
        return start, end
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError('Approval has no valid signed expiry. Request Cyber approval again.') from None


def require_current(row, now=None):
    start, end = dates(row.snapshot.get('approval_validity'))
    if not row.decided_at or utc(row.decided_at) != start:
        raise ValueError('Approval validity does not match the Cyber decision. Request Cyber approval again.')
    now = utc(now or datetime.now(timezone.utc))
    if now < start:
        raise ValueError('Cyber approval is not yet valid. Check the system clock.')
    if now >= end:
        raise ValueError('Cyber approval has expired. Request Cyber approval again.')


def summary(row, now=None):
    if row.status != 'approved':
        return {'validity_status': 'not_approved', 'expires_at': None}
    try:
        start, end = dates(row.snapshot.get('approval_validity'))
        now = utc(now or datetime.now(timezone.utc))
        require_current(row, now)
        status = 'expiring_soon' if end - now <= timedelta(days=7) else 'valid'
    except ValueError:
        try:
            start, end = dates(row.snapshot.get('approval_validity'))
            status = 'expired' if utc(now or datetime.now(timezone.utc)) >= end else 'invalid'
        except ValueError:
            end, status = None, 'reapproval_required'
    return {'validity_status': 'revoked' if row.revoked_at else status,
            'expires_at': end.isoformat() if end else None}


def annotations(release_key, validity):
    dates(validity)
    return {'io.cats.approval.type': 'cyber-approved-v1',
            'io.cats.approval.release': release_key,
            'io.cats.approval.approved-at': validity['approved_at'],
            'io.cats.approval.expires-at': validity['expires_at']}
