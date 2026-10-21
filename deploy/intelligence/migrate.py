"""Copy legacy intelligence data during an operator-controlled maintenance window.

Uses PostgreSQL tools inside Compose containers; requires only Python on the host.
Copy retains source data; retirement requires a separate explicit action.
Never disables destination constraints/triggers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

TABLES = (
    'vex_sources', 'vex_documents', 'vex_statements', 'vex_ingestion_audits',
    'intelligence_records', 'intelligence_package_installs',
    'intelligence_package_catalogs', 'intelligence_package_members',
    'intelligence_package_state',
)
SOURCE = ('db', 'cats', 'cats')
DESTINATION = ('intelligence-db', 'cats_intelligence', 'cats_intelligence')


def command(endpoint, program, *args):
    service, user, database = endpoint
    return ['docker', 'compose', 'exec', '-T', service, 'sh', '-c',
            'export PGPASSWORD="$POSTGRES_PASSWORD"; exec "$@"', 'sh',
            program, '-U', user, '-d', database, *args]


def run(args, **kwargs):
    # Do not include subprocess output in errors (it can contain record contents).
    result = subprocess.run(args, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError('Database command failed; archive retained. Inspect container logs locally.')
    return result


def sql(endpoint, query):
    return run(command(endpoint, 'psql', '-X', '-A', '-t', '-v',
                       'ON_ERROR_STOP=1', '-c', query), stdout=subprocess.PIPE).stdout.decode().strip()


def counts(endpoint):
    return {table: int(sql(endpoint, f'SELECT count(*) FROM public.{table}'))
            for table in TABLES}


def checksum(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def check_boundaries(endpoint):
    names = ','.join("'public." + table + "'::regclass" for table in TABLES)
    # Both inbound and outbound foreign keys must remain wholly within this set.
    count = sql(endpoint, f"SELECT count(*) FROM pg_constraint WHERE contype='f' "
                f"AND ((conrelid IN ({names})) <> (confrelid IN ({names})))")
    if int(count):
        raise RuntimeError('Cross-boundary foreign keys found; migration requires manual review.')


def migrate(directory, maintenance_confirmed=False):
    if not maintenance_confirmed:
        raise RuntimeError('Stop all writers and acknowledge the maintenance window first.')
    directory = Path(directory)
    # Exclusive directory creation protects every existing dump from overwrite.
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    for endpoint in (SOURCE, DESTINATION):
        check_boundaries(endpoint)
    if any(counts(DESTINATION).values()):
        raise RuntimeError('Destination intelligence tables must be empty; nothing was copied.')
    before = counts(SOURCE)
    archive = directory / 'intelligence.dump'
    with archive.open('xb') as output:
        run(command(SOURCE, 'pg_dump', '--format=custom', '--data-only', '--no-owner',
                    '--no-acl', *[f'--table=public.{table}' for table in TABLES]), stdout=output)
    if counts(SOURCE) != before:
        raise RuntimeError('Source changed during dump. Keep writers stopped and retry in a new directory.')
    manifest = {'tables': before, 'sha256': checksum(archive),
                'verified': False, 'source_retained': True}
    manifest_path = directory / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    with archive.open('rb') as source:
        run(command(DESTINATION, 'pg_restore', '--data-only', '--single-transaction',
                    '--exit-on-error', '--no-owner', '--no-acl'), stdin=source, stdout=subprocess.PIPE)
    if counts(DESTINATION) != before:
        raise RuntimeError('Destination counts differ; leave writers stopped and investigate. Source retained.')
    manifest['verified'] = True
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print('Copy verified. Archive and source retained. Complete cutover checks before resuming writers.')


def retire_source(directory, maintenance_confirmed=False):
    if not maintenance_confirmed:
        raise RuntimeError('Stop all writers and acknowledge the maintenance window first.')
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    if (not manifest.get('verified') or set(manifest.get('tables', {})) != set(TABLES)
            or manifest.get('sha256') != checksum(directory / 'intelligence.dump')):
        raise RuntimeError('A verified, intact migration archive is required for source retirement.')
    for endpoint in (SOURCE, DESTINATION):
        check_boundaries(endpoint)
        if counts(endpoint) != manifest['tables']:
            raise RuntimeError('Data changed since copy; source retirement refused.')
    # One DROP statement permits internal dependencies, but RESTRICT rejects any
    # external dependent view/constraint. PostgreSQL rolls back the whole operation.
    tables = ', '.join('public.' + table for table in TABLES)
    sql(SOURCE, f'BEGIN; DROP TABLE {tables} RESTRICT; COMMIT;')
    manifest['source_retained'] = False
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print('Legacy source tables retired. Verified archive retained.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New archive directory (must not exist)')
    parser.add_argument('--maintenance-confirmed', action='store_true',
                        help='Confirm ALL portal, control, importer, external writers are stopped')
    parser.add_argument('--retire-source', action='store_true',
                        help='Explicitly DROP legacy source tables using a previous verified archive')
    options = parser.parse_args()
    try:
        action = retire_source if options.retire_source else migrate
        action(options.output, options.maintenance_confirmed)
    except (RuntimeError, OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
