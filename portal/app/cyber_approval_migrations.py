"""Upgrade nullable references in release and distribution configuration."""
from sqlalchemy import inspect, text, MetaData, Table
from sqlalchemy.schema import CreateTable, CreateIndex


def upgrade_connection(connection):
    _allow_null(connection, 'cyber_approvals', 'destination_id')
    _allow_null(connection, 'oci_repositories', 'service_id')


def _allow_null(connection, table_name, column_name):
    if table_name not in inspect(connection).get_table_names():
        return
    columns = {c['name']: c for c in inspect(connection).get_columns(table_name)}
    if columns[column_name]['nullable']:
        return
    if connection.dialect.name == 'postgresql':
        connection.execute(text(f'ALTER TABLE {table_name} ALTER COLUMN {column_name} DROP NOT NULL'))
    elif connection.dialect.name == 'sqlite':
        if connection.exec_driver_sql('PRAGMA foreign_keys').scalar():
            raise RuntimeError('SQLite upgrade requires foreign_keys disabled before the migration transaction')
        table = Table(table_name, MetaData(), autoload_with=connection)
        indexes = [str(CreateIndex(index).compile(dialect=connection.dialect)) for index in table.indexes]
        table.c[column_name].nullable = True
        table.name = f'{table_name}_upgrade'
        connection.execute(CreateTable(table))
        names = ', '.join(connection.dialect.identifier_preparer.quote(c.name) for c in table.columns)
        connection.exec_driver_sql(f'INSERT INTO {table.name} ({names}) SELECT {names} FROM {table_name}')
        connection.exec_driver_sql(f'DROP TABLE {table_name}')
        connection.exec_driver_sql(f'ALTER TABLE {table.name} RENAME TO {table_name}')
        for statement in indexes:
            connection.exec_driver_sql(statement)
