from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from app import release_validity as validity

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def row():
    return SimpleNamespace(status='approved', decided_at=START, revoked_at=None,
                           snapshot={'approval_validity': validity.new_validity(START)})


def test_default_and_configurable_lifetime(monkeypatch):
    monkeypatch.delenv(validity.SETTING, raising=False)
    assert validity.new_validity(START)['validity_days'] == 90
    monkeypatch.setenv(validity.SETTING, '30')
    item = row()
    assert validity.dates(item.snapshot['approval_validity']) == (START, START + timedelta(days=30))
    monkeypatch.setenv(validity.SETTING, '180')
    validity.require_current(item, START + timedelta(days=29))
    with pytest.raises(ValueError, match='expired'):
        validity.require_current(item, START + timedelta(days=30))


@pytest.mark.parametrize('value', ['', '0', '-1', '1.5', '3651', 'ninety'])
def test_invalid_setting_is_actionable(monkeypatch, value):
    monkeypatch.setenv(validity.SETTING, value)
    with pytest.raises(ValueError, match=validity.SETTING):
        validity.new_validity(START)


def test_expiry_boundary_and_catalog_status(monkeypatch):
    monkeypatch.setenv(validity.SETTING, '90')
    item = row()
    validity.require_current(item, START)
    assert validity.summary(item, START)['validity_status'] == 'valid'
    assert validity.summary(item, START + timedelta(days=89))['validity_status'] == 'expiring_soon'
    assert validity.summary(item, START + timedelta(days=90))['validity_status'] == 'expired'
    with pytest.raises(ValueError, match='not yet valid'):
        validity.require_current(item, START - timedelta(seconds=1))
    item.revoked_at = START
    assert validity.summary(item, START)['validity_status'] == 'revoked'


@pytest.mark.parametrize('change', [None, {'expires_at':'2026-04-01'}, {'validity_days':True}, {'expires_at':'2030-01-01T00:00:00+00:00'}])
def test_legacy_or_malformed_window_requires_new_approval(change):
    item = row()
    item.snapshot['approval_validity'] = None if change is None else {**item.snapshot['approval_validity'], **change}
    with pytest.raises(ValueError, match='Request Cyber approval again'):
        validity.require_current(item, START)
    assert validity.summary(item, START)['validity_status'] == 'reapproval_required'


def test_decision_timestamp_must_match():
    item = row()
    item.decided_at += timedelta(seconds=1)
    with pytest.raises(ValueError, match='does not match'):
        validity.require_current(item, START)


def test_saved_setting_takes_precedence_over_environment(monkeypatch):
    monkeypatch.setenv(validity.SETTING, 'invalid')
    assert validity.new_validity(START, {validity.PORTAL_SETTING: '45'})['validity_days'] == 45
    with pytest.raises(ValueError, match='whole number'):
        validity.new_validity(START, {validity.PORTAL_SETTING: '0'})
