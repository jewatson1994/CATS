from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as N

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, Execution, Finding, FindingObservation, ExceptionRecord
from app.simplified_queries import group_page, member_page


def test_members_preserve_normalized_cve_identity_and_are_independently_paged(monkeypatch):
    from app import main
    monkeypatch.setattr(main, 'kev_cves', lambda: set())
    monkeypatch.setattr(main, 'epss_scores', lambda: {})
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    cfg = dict(main.CONFIG_DEFAULTS, compliance_mode='raw', overdue_days='90')
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key='members', name='Members')
        db.add(service); db.flush()
        scan = Execution(service_id=service.id, execution_key='members', scanned_at=now, complete=True, raw_payload={})
        db.add(scan); db.flush()
        for index, cve in enumerate([' cve-a ', 'CVE-A', '', 'straße', 'CVE-B', 'CVE-C']):
            item = Finding(service_id=service.id, cve=cve, severity='High', active=True,
                first_seen=now, episode_started=now, last_seen=now)
            db.add(item); db.flush()
            for image in ('one', 'two'):
                db.add(FindingObservation(finding_id=item.id, execution_id=scan.id,
                    image=image, package='shared', fixed_version='2', evidence={}))
        db.commit()
        service_id, scan_id = service.id, scan.id
        db.expunge_all()
        groups, _, _ = group_page(db, N(id=service_id), N(id=scan_id), now, cfg)
        assert groups[0]['member_count'] == 4
        first = member_page(db, N(id=service_id), N(id=scan_id), now, cfg, groups[0]['group_id'], page_size=2)
        second = member_page(db, N(id=service_id), N(id=scan_id), now, cfg, groups[0]['group_id'], page=2, page_size=2)
        assert [row['cve'] for row in first['items'] + second['items']] == ['CVE-A', 'CVE-B', 'CVE-C', 'STRASSE']
        assert first['items'][0]['id'] == 1
        assert first['total_items'] == 4 and second['total_pages'] == 2
        assert all(row['image_count'] == 2 for row in first['items'] + second['items'])
        assert not db.identity_map
        assert member_page(db, N(id=service_id), N(id=scan_id), now, cfg, 'missing')['items'] == []
    engine.dispose()


def test_member_filters_and_state_match_group_summary(monkeypatch):
    from app import main
    monkeypatch.setattr(main, 'kev_cves', lambda: set())
    monkeypatch.setattr(main, 'epss_scores', lambda: {})
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    cfg = dict(main.CONFIG_DEFAULTS, compliance_mode='raw', overdue_days='90')
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key='filtered', name='Filtered')
        db.add(service); db.flush()
        scan = Execution(service_id=service.id, execution_key='filtered', scanned_at=now, complete=True, raw_payload={})
        db.add(scan); db.flush()
        for index in range(5):
            started = now - timedelta(days=100 if index == 3 else 1)
            item = Finding(service_id=service.id, cve=f'CVE-{index}', severity='Low' if index == 2 else 'High',
                active=index != 4, first_seen=started, episode_started=started, last_seen=now)
            db.add(item); db.flush()
            db.add(FindingObservation(finding_id=item.id, execution_id=scan.id, image='target',
                package='shared', fixed_version='2', evidence={}))
            if index == 1:
                db.add(ExceptionRecord(finding_id=item.id, justification='approved', approved_by='test',
                    starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=1)))
        db.commit()
        for state, expected in [('active', ['CVE-0', 'CVE-2']), ('exceptions', ['CVE-1']),
                                ('noncompliant', ['CVE-3']), ('resolved', ['CVE-4'])]:
            groups, _, _ = group_page(db, service, scan, now, cfg, state=state, resource='target')
            page = member_page(db, service, scan, now, cfg, groups[0]['group_id'], state=state, resource='target')
            assert [item['cve'] for item in page['items']] == expected
            assert page['total_items'] == groups[0]['member_count']
        groups, _, _ = group_page(db, service, scan, now, cfg, severities=['HIGH'], query='CVE-0')
        page = member_page(db, service, scan, now, cfg, groups[0]['group_id'], severities=['HIGH'], query='CVE-0')
        assert [item['cve'] for item in page['items']] == ['CVE-0']
    engine.dispose()
