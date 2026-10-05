from sqlalchemy import create_engine, text, select
from sqlalchemy.orm import Session
from app.models import ManagedValidator
from app.managed_validator_migrations import upgrade_connection


def test_legacy_records_survive_upgrade_and_new_records_can_be_created():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE managed_validators (id VARCHAR(32) PRIMARY KEY, name VARCHAR(120) NOT NULL, host VARCHAR(253) NOT NULL, ssh_port INTEGER NOT NULL, username VARCHAR(64) NOT NULL, api_port INTEGER NOT NULL, labels JSON NOT NULL, enabled BOOLEAN NOT NULL, status VARCHAR(40) NOT NULL, ssh_fingerprint VARCHAR(100), discovered_fingerprint VARCHAR(100), preflight JSON NOT NULL, health JSON NOT NULL, configuration JSON NOT NULL, certificate JSON NOT NULL, last_seen TIMESTAMP, last_self_test JSON NOT NULL, created_at TIMESTAMP NOT NULL)")
        connection.exec_driver_sql("INSERT INTO managed_validators VALUES ('old', 'Existing', 'host', 22, 'operator', 8443, '{}', 1, 'DRAFT', 'SHA256:existing', NULL, '{}', '{}', '{}', '{}', NULL, '{}', CURRENT_TIMESTAMP)")
        upgrade_connection(connection)
        upgrade_connection(connection)
    with Session(engine) as session:
        old = session.scalar(select(ManagedValidator))
        assert old.ssh_username == "operator"
        assert old.fingerprint == "SHA256:existing"
        assert old.fingerprint_confirmed is False
        assert old.updated_at is not None
        session.add(ManagedValidator(id="new", name="New", host="new-host"))
        session.commit()
        assert len(session.scalars(select(ManagedValidator)).all()) == 2
        assert session.execute(text("SELECT username FROM managed_validators WHERE id='old'")).scalar() == "operator"
