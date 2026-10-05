from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import AuditEvent, utcnow
from app.activity_queries import service_activity_page


def test_activity_sql_pages_are_stable_bounded_and_scoped():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        stamp = utcnow()
        db.add_all([AuditEvent(action='test', target_type='service', detail={'service_id': 7}, created_at=stamp)
                    for _ in range(1000)])
        db.add_all([AuditEvent(action='test', target_type='service', detail={'service_id': True}, created_at=stamp),
                    AuditEvent(action='test', target_type='service', detail={'service_id': 8}, created_at=stamp)])
        db.commit(); db.expunge_all()
        statements = []
        event.listen(engine, 'before_cursor_execute', lambda c, r, s, p, x, m: statements.append(s))
        first = service_activity_page(db, 7, 1, 50)
        second = service_activity_page(db, 7, 2, 50)
        assert first['total_items'] == 1000
        assert first['page_count'] == 20
        assert [e.id for e in first['events']] == list(range(1000, 950, -1))
        assert [e.id for e in second['events']] == list(range(950, 900, -1))
        assert len(db.identity_map) == 100
        assert len(statements) == 4
        assert all('LIMIT' in s for s in statements if 'count(' not in s)




def test_global_activity_retention_action_and_page_cap():
    from datetime import timedelta
    from app.activity_queries import global_activity_page
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    stamp = utcnow()
    with Session(engine) as db:
        db.add_all([AuditEvent(action='keep', target_type='service', detail={}, created_at=stamp)
                    for _ in range(450)])
        db.add(AuditEvent(action='other', target_type='service', detail={}, created_at=stamp))
        db.add(AuditEvent(action='keep', target_type='service', detail={}, created_at=stamp-timedelta(days=400)))
        db.commit(); db.expunge_all()
        result = global_activity_page(db, cutoff=stamp-timedelta(days=365), action='keep', page=2, page_size=10000)
        assert result['retained_count'] == 450
        assert result['page_size'] == 200
        assert result['page_count'] == 3
        assert [item.id for item in result['events']] == list(range(250, 50, -1))
        assert len(db.identity_map) == 200

def test_latest_architecture_evidence_skips_empty_and_loads_one_payload():
    from datetime import timedelta
    from app.models import Service, Execution
    from app.activity_queries import latest_evidence_execution
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    stamp=utcnow()
    with Session(engine) as db:
        db.add(Service(id=1,service_key='evidence',name='Evidence',owner='Owner',poc='Contact'))
        for i, payload in enumerate(({'rendered_resources':[{'kind':'Pod'}]}, {'rendered_resources':[]},
            {'helm_source_files':{}}, {'service_overview':{'rendered_resources':False}}, {})):
            db.add(Execution(service_id=1,execution_key=str(i),scanned_at=stamp+timedelta(days=i),
                             complete=True,raw_payload=payload))
        db.commit(); db.expunge_all()
        chosen=latest_evidence_execution(db,1,architecture=True)
        assert chosen.execution_key=='0'
        assert len(db.identity_map)==1
        assert latest_evidence_execution(db,1).execution_key=='4'