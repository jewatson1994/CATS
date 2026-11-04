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


def test_project_mapping_upgrade_preserves_existing_repository_and_cached_links():
    engine = create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE TABLE services (id INTEGER PRIMARY KEY)')
        connection.exec_driver_sql('CREATE TABLE oci_repositories (id INTEGER PRIMARY KEY, public_repository TEXT UNIQUE, service_id INTEGER NOT NULL REFERENCES services(id))')
        connection.exec_driver_sql('CREATE INDEX ix_repository_service ON oci_repositories(service_id)')
        connection.exec_driver_sql('CREATE TABLE oci_object_links (repository_id INTEGER REFERENCES oci_repositories(id))')
        connection.exec_driver_sql('INSERT INTO services VALUES (5)')
        connection.exec_driver_sql("INSERT INTO oci_repositories VALUES (7, 'project/image', 5)")
        connection.exec_driver_sql('INSERT INTO oci_object_links VALUES (7)')
    with migration_transaction(engine) as connection:
        upgrade_connection(connection)
        upgrade_connection(connection)
        connection.exec_driver_sql("INSERT INTO oci_repositories VALUES (8, 'project/*', NULL)")
        assert connection.exec_driver_sql('SELECT * FROM oci_repositories WHERE id = 7').one() == (7, 'project/image', 5)
        assert inspect(connection).get_indexes('oci_repositories')[0]['name'] == 'ix_repository_service'
        assert inspect(connection).get_unique_constraints('oci_repositories')[0]['column_names'] == ['public_repository']
        assert not connection.exec_driver_sql('PRAGMA foreign_key_check').all()
    engine.dispose()
