"""Allow an evidence review to precede publication destination configuration."""
from sqlalchemy import inspect, text, MetaData, Table
from sqlalchemy.schema import CreateTable, CreateIndex


def upgrade_connection(connection):
    table_name = 'cyber_approvals'
    if table_name not in inspect(connection).get_table_names():
        return
    columns = {c['name']: c for c in inspect(connection).get_columns(table_name)}
    if columns['destination_id']['nullable']:
        return
    if connection.dialect.name == 'postgresql':
        connection.execute(text('ALTER TABLE cyber_approvals ALTER COLUMN destination_id DROP NOT NULL'))
    elif connection.dialect.name == 'sqlite':
        if connection.exec_driver_sql('PRAGMA foreign_keys').scalar():
            raise RuntimeError('SQLite approval upgrade requires foreign_keys disabled before the migration transaction')
        table = Table(table_name, MetaData(), autoload_with=connection)
        indexes = [str(CreateIndex(index).compile(dialect=connection.dialect)) for index in table.indexes]
        table.c.destination_id.nullable = True
        table.name = 'cyber_approvals_upgrade'
        connection.execute(CreateTable(table))
        names = ', '.join(connection.dialect.identifier_preparer.quote(c.name) for c in table.columns)
        connection.exec_driver_sql(f'INSERT INTO cyber_approvals_upgrade ({names}) SELECT {names} FROM cyber_approvals')
        connection.exec_driver_sql('DROP TABLE cyber_approvals')
        connection.exec_driver_sql('ALTER TABLE cyber_approvals_upgrade RENAME TO cyber_approvals')
        for statement in indexes:
            connection.exec_driver_sql(statement)
