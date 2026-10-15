from sqlalchemy import create_engine, inspect, text
from app.cyber_approval_migrations import upgrade_connection
from app.exchange_migrations import migration_transaction


def test_legacy_approval_migration_preserves_records_indexes_and_foreign_keys(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'legacy.db'))
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE destinations (id INTEGER PRIMARY KEY)')
        connection.exec_driver_sql('CREATE TABLE cyber_approvals (id INTEGER PRIMARY KEY, destination_id INTEGER NOT NULL REFERENCES destinations(id), snapshot TEXT NOT NULL)')
        connection.exec_driver_sql('CREATE INDEX ix_approval_dest ON cyber_approvals(destination_id)')
        connection.exec_driver_sql('CREATE TABLE audit (approval_id INTEGER REFERENCES cyber_approvals(id))')
        connection.exec_driver_sql('INSERT INTO destinations VALUES (1)')
        connection.execute(text('INSERT INTO cyber_approvals VALUES (7, 1, :snapshot)'), {'snapshot':'retained original'})
        connection.exec_driver_sql('INSERT INTO audit VALUES (7)')
    for _ in range(2):
        with migration_transaction(engine) as connection:
            upgrade_connection(connection)
    with engine.begin() as connection:
        assert connection.exec_driver_sql('SELECT * FROM cyber_approvals').all() == [(7, 1, 'retained original')]
        assert inspect(connection).get_indexes('cyber_approvals')[0]['name'] == 'ix_approval_dest'
        assert inspect(connection).get_foreign_keys('cyber_approvals')[0]['referred_table'] == 'destinations'
        connection.exec_driver_sql("INSERT INTO cyber_approvals VALUES (8, NULL, 'new review')")
        assert not connection.exec_driver_sql('PRAGMA foreign_key_check').all()
    engine.dispose()
