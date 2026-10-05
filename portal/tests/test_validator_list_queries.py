"""List responses share verification within a request, never across requests."""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import ManagedValidator
from app import validator_management as management


def test_listing_verifies_once_per_request_and_preserves_platform_readiness(monkeypatch):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    calls = []
    def inventory():
        calls.append(True)
        return {'available': len(calls) == 1, 'digest': 'a' * 64, 'platforms': [
            {'os': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64'}]}
    monkeypatch.setattr(management, 'payload_status', inventory)
    with Session(engine) as db:
        for index in range(40):
            db.add(ManagedValidator(id=str(index), name=str(index), host='192.168.1.30',
                username='ubuntu', ssh_fingerprint='trusted', preflight={
                    'status': 'supported', 'checks': {'sudo': True, 'api_port': True},
                    'facts': {'os': 'ubuntu', 'os_version': '22.04',
                              'architecture': 'amd64' if index else 'arm64'}}))
        db.add(ManagedValidator(id='removed', name='removed', host='192.168.1.31',
                                username='ubuntu', status='REMOVED'))
        db.commit()
        db.expunge_all()
        statements = []
        event.listen(engine, 'before_cursor_execute',
                     lambda conn, cursor, statement, parameters, context, many: statements.append(statement))
        first = management.listing(db=db, auth=None)
        assert len(calls) == 1
        assert len(first['validators']) == 40
        by_id = {v['id']: v for v in first['validators']}
        assert by_id['1']['provisioning_readiness']['ready']
        assert not by_id['0']['provisioning_readiness']['checks']['payload']['ready']
        assert len(statements) == 1
        assert 'discovered_fingerprint' not in statements[0]
        second = management.listing(db=db, auth=None)
        assert len(calls) == 2
        assert not second['payload']['available']
        assert all(not v['provisioning_readiness']['checks']['payload']['ready']
                   for v in second['validators'])
    engine.dispose()
