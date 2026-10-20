"""New work uses current observation disposition; historical evidence survives."""
from copy import deepcopy
from datetime import timedelta
from app import native_vex as nv
from app.remediation_jobs import filter_native_vex_images, native_vex_token
from test_native_vex import db, setup, enable
from test_vex_repository import NOW


def test_new_image_plans_keep_mixed_and_unknown_images(db):
    service, finding, observations, _ = setup(db, True)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    plan = {'images': [{'original': 'one'}, {'original': 'two'}, {'original': 'unknown'}]}
    original = deepcopy(plan)
    filter_native_vex_images(db, service.id, observations[0].execution_id, plan, NOW)
    assert [x['original'] for x in plan['images']] == ['two', 'unknown']
    assert original['images'][0]['original'] == 'one'
    assert finding.active and finding.resolved_at is None


def test_disabled_and_expired_keep_plan_and_invalidate_token(db):
    service, finding, observations, _ = setup(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    plan = {'images': [{'original': 'one'}]}
    filter_native_vex_images(db, service.id, observations[0].execution_id, plan, NOW)
    assert len(plan['images']) == 1
    disabled = native_vex_token(db, service.id, NOW)
    enable(db)
    enabled = native_vex_token(db, service.id, NOW)
    assert disabled != enabled
    expired = NOW + timedelta(days=31)
    assert native_vex_token(db, service.id, expired) != enabled
    filter_native_vex_images(db, service.id, observations[0].execution_id, plan, expired)
    assert len(plan['images']) == 1


def test_mixed_package_in_same_image_remains_candidate(db):
    service, finding, observations, _ = setup(db, True)
    observations[1].image = 'one'; db.commit()
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    entries = [{'cve': finding.cve, 'package': 'libtest', 'installed_version': version} for version in ['1.0', '2.0']]
    plan = {'images': [{'original': 'one', 'vulnerabilities': entries}]}
    filter_native_vex_images(db, service.id, observations[0].execution_id, plan, NOW)
    assert len(plan['images']) == 1
    assert [x['installed_version'] for x in plan['images'][0]['vulnerabilities']] == ['2.0']


def test_enabled_risk_cannot_discount_unmaterialized_vex():
    from app.risk_profiles import score_observation, DEFAULT_POLICY
    arguments = dict(severity='high', epss=.1, kev=False, vex={'status': 'not_affected'})
    legacy = score_observation(DEFAULT_POLICY, **arguments)
    pending = score_observation(DEFAULT_POLICY, **arguments, native_vex_excluded=False)
    assert pending['score'] >= legacy['score']
    assert 'Applicable trusted VEX not affected' not in pending['reasons']


def test_raw_export_retains_excluded_evidence(db, monkeypatch):
    from app import service_exports
    service, finding, observations, _ = setup(db)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    monkeypatch.setattr(service_exports, 'utcnow', lambda: NOW)
    book = service_exports._service_findings_book(service.service_key, db)
    rows = list(book.active.values)
    assert rows[0][-1] == 'Effective Disposition'
    assert rows[1][-1] == 'VEX Excluded'
    assert rows[1][1] == finding.cve


def test_unmapped_payload_entry_cannot_remove_image(db):
    service, finding, observations, _ = setup(db)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    plan = {'images': [{'original': 'one', 'vulnerabilities': [{'cve': 'CVE-UNKNOWN'}]}]}
    filter_native_vex_images(db, service.id, observations[0].execution_id, plan, NOW)
    assert len(plan['images']) == 1
    assert plan['images'][0]['vulnerabilities'] == [{'cve': 'CVE-UNKNOWN'}]



def test_purpose_exports_keep_poam_and_split_asset_counts(db, monkeypatch):
    from app import purpose_exports
    from app.models import PoamEntry, ServiceImage, Execution
    service, finding, observations, _ = setup(db, True)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    monkeypatch.setattr('app.risk_profiles.utcnow', lambda: NOW)
    db.add(ServiceImage(service_id=service.id, image_reference='one'))
    db.add(ServiceImage(service_id=service.id, image_reference='two'))
    entry = PoamEntry(service_id=service.id, finding_id=finding.id, item_type='vulnerability',
        title='Retained', description='Original', remediation='Review', status='active', created_by_id=1)
    db.add(entry); db.commit()
    execution = db.get(Execution, observations[0].execution_id)
    assets = purpose_exports._asset_rows(db, service, execution)
    by_image = {x['image']: x for x in assets}
    assert by_image['one']['vex_excluded_observations'] == 1
    assert by_image['one']['actionable_observations'] == 0
    assert by_image['two']['actionable_observations'] == 1
    rows = purpose_exports._poam_rows(db, service)
    assert rows[0]['poam_status'] == 'active'
    assert rows[0]['effective_disposition'] == 'Existing Policy'
    observations[1].installed_version = '1.0'
    observations[1].evidence = observations[0].evidence.copy()
    db.commit()
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    rows = purpose_exports._poam_rows(db, service)
    assert rows[0]['poam_status'] == 'active'
    assert rows[0]['effective_disposition'] == 'VEX Excluded'
    assert rows[0]['vex_review']


def test_excluded_only_payload_on_mixed_image_cannot_become_unrestricted_patch(db):
    service, finding, observations, _ = setup(db, True)
    observations[1].image = 'one'; db.commit()
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    plan = {'images': [{'original': 'one', 'vulnerabilities': [
        {'cve': finding.cve, 'package': 'libtest', 'installed_version': '1.0'}]}]}
    filter_native_vex_images(db, service.id, observations[0].execution_id, plan, NOW)
    assert plan['images'] == []
    assert finding.active and finding.resolved_at is None
