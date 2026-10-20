"""Consumer behavior uses the same current observation disposition."""
from datetime import timedelta
from sqlalchemy import select
from app import native_vex as nv
from app.findings_sql import get_raw_finding_page
from app.simplified_queries import group_page, member_page
from app.models import Execution, FindingObservation, ExceptionRecord
from test_native_vex import db, setup, enable
from test_vex_repository import NOW


def test_raw_excluded_filter_preserves_scanner_evidence_and_invalidates(db):
    service, finding, observations, _ = setup(db)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    assert get_raw_finding_page(db, service.id, {}, NOW)['total_items'] == 0
    excluded = get_raw_finding_page(db, service.id, {}, NOW, state='vex_excluded')
    assert [row.id for row in excluded['findings']] == [finding.id]
    assert finding.active and observations[0].installed_version == '1.0'
    observations[0].installed_version = '2.0'; db.commit()
    assert get_raw_finding_page(db, service.id, {}, NOW)['total_items'] == 1
    assert get_raw_finding_page(db, service.id, {}, NOW, state='vex_excluded')['total_items'] == 0


def test_mixed_groups_only_include_retained_packages_and_unique_members(db):
    service, finding, observations, _ = setup(db, mixed=True)
    observations[1].package = 'retained'
    observations[1].fixed_version = '3.0'
    db.add(FindingObservation(finding_id=finding.id, execution_id=observations[1].execution_id,
        image='three', package='retained', installed_version='2.0', fixed_version='4.0', evidence={}))
    db.commit(); enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    latest = db.get(Execution, observations[0].execution_id)
    groups, info, _ = group_page(db, service, latest, NOW, {'compliance_mode':'raw'})
    assert info['total_items'] == 1
    assert groups[0]['package'] == 'retained'
    assert groups[0]['image_count'] == 2
    members = member_page(db, service, latest, NOW, {'compliance_mode':'raw'}, groups[0]['group_id'])
    assert members['total_items'] == len(members['items']) == 1
    assert members['items'][0]['image_count'] == 2
    assert members['items'][0]['fixed_version'] == '3.0, 4.0'


def test_posture_snapshot_cannot_bless_a_concurrent_generation(db, monkeypatch):
    from app import main, service_posture
    from app.native_vex_models import VexDispositionService
    service, finding, observations, _ = setup(db)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    original = main.service_overview_rows_aggregated
    def mutate_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        session = args[0]
        state = session.get(VexDispositionService, service.id)
        state.generation += 1
        session.flush()
        return result
    monkeypatch.setattr(main, 'service_overview_rows_aggregated', mutate_after_read)
    service_posture.rebuild(db.get_bind(), 'services', [service.id], now=NOW)
    db.expire_all()
    configurations = service_posture.resolve_configurations(db, [service.id], main.get_configuration(db))
    rows = service_posture._read(db, 'services', [service.id])
    stale, missing = service_posture._classify(db, rows, [service.id], configurations, NOW)
    assert stale == [service.id] and not missing
