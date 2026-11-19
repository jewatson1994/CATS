"""Additive, repeatable migration for the local diagnostic history.

Runs under the portal's existing migration transaction/lock. No evidence or
security-audit tables are modified. Existing job JSON accepts diagnostics
without a destructive column migration.
"""
from .diagnostic_store import DiagnosticEvent


def upgrade_connection(connection):
    table = DiagnosticEvent.__table__
    table.create(connection, checkfirst=True)
    # Also repair missing indexes on a pre-created table.
    for index in table.indexes:
        index.create(connection, checkfirst=True)
