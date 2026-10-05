from datetime import timedelta
from urllib.parse import parse_qs, urlsplit
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, User, Finding, PoamEntry, utcnow
from app.poam_query import service_poam_page, pagination_base


def test_portfolio_poam_counts_do_not_hydrate_entries(monkeypatch):
    from types import SimpleNamespace
    from sqlalchemy import event, insert
    from app import main
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key='counts', name='Counts')
        user = User(username='counts', display_name='Counts')
        db.add_all([service, user]); db.flush()
        db.execute(insert(PoamEntry), [dict(service_id=service.id, created_by_id=user.id,
            title=str(i), description='', remediation='', item_type='vulnerability', status='active' if i % 2 else 'pending_approval',
            due_date=now-timedelta(days=1) if i % 3 else None) for i in range(1000)])
        db.commit(); db.expunge_all()
        loaded = []
        event.listen(db, 'loaded_as_persistent', lambda session, obj: loaded.append(type(obj)))
        monkeypatch.setattr(main.templates, 'TemplateResponse', lambda request, name, context: context)
        monkeypatch.setattr(main, 'page_context', lambda auth, **context: context)
        monkeypatch.setattr(main, 'utcnow', lambda: now)
        auth = SimpleNamespace(accessible_service_ids=lambda permission: None, has=lambda *args: True)
        result = main.poam_page(SimpleNamespace(), db, auth)
        row = result['service_summaries'][0]
        assert (row['total'], row['active'], row['pending'], row['overdue']) == (1000, 500, 500, 333)
        assert PoamEntry not in loaded
    engine.dispose()


@pytest.mark.parametrize('sort', ['newest', 'due', 'severity'])
def test_order_matches_legacy_with_bounded_hydration(sort):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key='x', name='X')
        user = User(username='x', display_name='X')
        db.add_all([service, user]); db.flush()
        severities = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'critical', 'Unknown']
        records = []
        for index in range(130):
            finding = Finding(service_id=service.id, cve=str(index), severity=severities[index % 7],
                              first_seen=now, episode_started=now, last_seen=now)
            db.add(finding); db.flush()
            title = ['ÄPFEL', 'İTEM', 'σ', 'Σ', 'Zulu'][index % 5]
            due = now + timedelta(days=index % 3) if index % 4 else None
            created = now - timedelta(seconds=index // 2)
            row = PoamEntry(service_id=service.id, finding_id=finding.id, item_type='vulnerability',
                title=title, description='description', remediation='plan', created_by_id=user.id,
                due_date=due, created_at=created, status='active')
            db.add(row); db.flush()
            records.append((row.id, title, due, created, finding.severity))
        service_id = service.id
        db.commit(); db.expunge_all()
        expected = sorted(records, key=lambda r: (-r[3].timestamp(), r[0]))
        if sort == 'due':
            expected.sort(key=lambda r: (r[2] is None, r[2] or now, r[1].lower()))
        elif sort == 'severity':
            ranks = dict(zip(severities[:5], range(5)))
            expected.sort(key=lambda r: (ranks.get(r[4], 5), r[1].lower()))
        entries, info = service_poam_page(db, service_id, now, 'all', sort, 3, 25)
        assert [e.id for e in entries] == [r[0] for r in expected[50:75]]
        assert info == {'page': 3, 'page_size': 25, 'page_count': 6, 'total_items': 130}
        assert sum(isinstance(obj, PoamEntry) for obj in db.identity_map.values()) == 25
        assert sum(isinstance(obj, Finding) for obj in db.identity_map.values()) == 25
        entries, info = service_poam_page(db, service_id, now, 'overdue', sort, 99, 25)
        assert not entries and info['page'] == 1 and info['total_items'] == 0
    engine.dispose()


def test_links_preserve_scope_filter_sort_and_size():
    link = pagination_base('space / ü', 'pending_approval', 'severity', 25)
    assert urlsplit(link).path == '/services/space%20%2F%20%C3%BC'
    assert parse_qs(urlsplit(link).query) == {'poam': ['true'], 'status_filter': ['pending_approval'],
                                            'sort_by': ['severity'], 'page_size': ['25']}


def test_pagination_metadata_is_projected():
    from app.frontend_governance import project_governance
    context = dict(page=2, page_size=25, page_count=4, total_items=80,
                   pagination_base='/services/key?poam=true', entries=[])
    data = {}
    project_governance(data, 'poam_service.html', context, None, {})
    assert all(data[key] == value for key, value in context.items())
