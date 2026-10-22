import importlib.util
import datetime as dt
import json
import os
import pwd
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('backup', Path(os.environ.get('BACKUP_MODULE', Path(__file__).with_name('backup.py'))))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BackupTests(unittest.TestCase):
    def test_real_postgres_restore_including_legacy_schema(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as backups:
            account = pwd.getpwnam('postgres')
            os.chown(tmp, account.pw_uid, account.pw_gid)
            data = str(Path(tmp) / 'data')
            b.run(['su-exec', 'postgres', 'initdb', '-D', data, '-A', 'trust', '--no-locale'])
            b.run(['su-exec', 'postgres', 'pg_ctl', '-D', data, '-l', str(Path(tmp) / 'log'),
                   '-o', f"-c listen_addresses='' -k {tmp}", '-w', 'start'])
            try:
                b.run(['psql', '-h', tmp, '-U', 'postgres', '-c',
                       'CREATE TABLE services(id integer PRIMARY KEY); CREATE TABLE users(id integer); '
                       'CREATE TABLE executions(id integer); CREATE SCHEMA legacy_intelligence; '
                       'CREATE TABLE legacy_intelligence.history(id integer); '
                       'INSERT INTO legacy_intelligence.history VALUES(42);'])
                with patch.object(b, 'ROOT', Path(backups)), patch.dict(os.environ, {'PGHOST': tmp, 'PGUSER': 'postgres', 'PGDATABASE': 'postgres'}):
                    b.backup()
                    directory = next(Path(backups).glob('backup-*'))
                    self.assertEqual(json.loads((directory / 'manifest.json').read_text())['tables_read'], 4)
                    (directory / 'database.dump').write_bytes(b'broken archive')
                    with self.assertRaises(RuntimeError):
                        b.restore_verify(directory / 'database.dump')
            finally:
                b.run(['su-exec', 'postgres', 'pg_ctl', '-D', data, '-m', 'immediate', '-w', 'stop'])

    def test_real_split_database_backups_restore_rows(self):
        tables = ['intelligence_records', 'intelligence_package_installs',
                  'intelligence_package_catalogs', 'intelligence_package_members',
                  'intelligence_package_state']
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as backups:
            account = pwd.getpwnam('postgres')
            os.chown(tmp, account.pw_uid, account.pw_gid)
            data = str(Path(tmp) / 'data')
            prefix = ['su-exec', 'postgres']
            b.run(prefix + ['initdb', '-D', data, '-A', 'trust', '--no-locale'])
            b.run(prefix + ['pg_ctl', '-D', data, '-l', str(Path(tmp) / 'log'),
                           '-o', f"-c listen_addresses='' -k {tmp}", '-w', 'start'])
            try:
                sql = ['psql', '-h', tmp, '-U', 'postgres', '-X', '-v', 'ON_ERROR_STOP=1', '-At']
                for name, required in [('portal', ['services', 'users', 'executions']),
                                       ('intelligence', tables)]:
                    b.run(sql + ['-d', 'postgres', '-c', f'CREATE DATABASE {name}'])
                    for table in required:
                        b.run(sql + ['-d', name, '-c',
                              f"CREATE TABLE {table}(id integer PRIMARY KEY, value text NOT NULL); "
                              f"INSERT INTO {table} VALUES(42, 'preserved-{table}');"])
                    with patch.object(b, 'ROOT', Path(backups) / name), patch.dict(os.environ, {
                        'PGHOST': tmp, 'PGUSER': 'postgres', 'PGDATABASE': name,
                        'BACKUP_REQUIRED_TABLES': ','.join('public.' + t for t in required),
                    }):
                        b.backup()
                        archive = next(b.ROOT.glob('backup-*'))
                        manifest = json.loads((archive / 'manifest.json').read_text())
                        self.assertTrue(manifest['verified'])
                        self.assertEqual(manifest['tables_read'], len(required))
                        self.assertEqual(manifest['sha256'], b.checksum(archive / 'database.dump'))
                        restored = name + '_restored'
                        b.run(sql + ['-d', 'postgres', '-c', f'CREATE DATABASE {restored}'])
                        b.run(['pg_restore', '-h', tmp, '-U', 'postgres', '-d', restored,
                               '--exit-on-error', '--no-owner', '--no-acl', str(archive / 'database.dump')])
                        for table in required:
                            self.assertEqual(b.run(sql + ['-d', restored, '-c',
                                f'SELECT id, value FROM {table}']).strip(), f'42|preserved-{table}')
                        self.assertEqual(b.main('health'), 0)
            finally:
                b.run(prefix + ['pg_ctl', '-D', data, '-m', 'immediate', '-w', 'stop'])

    def test_schedule(self):
        now = dt.datetime(2026, 10, 21, 3, tzinfo=b.UTC)
        self.assertEqual(b.next_run(now, '03:00'), now + dt.timedelta(days=1))
        with self.assertRaises(ValueError):
            b.next_run(now, '25:00')

    def test_restore_failure_preserves_good_and_never_publishes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'ROOT', Path(tmp)):
            old = Path(tmp) / 'backup-old'
            old.mkdir()
            (old / 'database.dump').write_bytes(b'old')
            (old / 'manifest.json').write_text('{"verified":true}')
            def fake_dump(args):
                Path(args[-1]).write_bytes(b'new')
            with patch.object(b, 'run', side_effect=fake_dump), patch.object(b, 'restore_verify', side_effect=RuntimeError('failure')):
                with self.assertRaises(RuntimeError):
                    b.backup()
            self.assertEqual((old / 'database.dump').read_bytes(), b'old')
            self.assertEqual(list(Path(tmp).glob('.pending-*')), [])
            self.assertEqual(len(list(Path(tmp).glob('backup-*'))), 1)
            self.assertEqual(json.loads((Path(tmp) / 'status.json').read_text())['state'], 'failed')
            self.assertEqual(b.main('health'), 1)

    def test_success_and_retention(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'ROOT', Path(tmp)):
            def fake_dump(args):
                Path(args[-1]).write_bytes(b'archive')
            with patch.object(b, 'run', side_effect=fake_dump), patch.object(b, 'restore_verify', return_value=3):
                b.backup()
            directory = next(Path(tmp).glob('backup-*'))
            info = json.loads((directory / 'manifest.json').read_text())
            self.assertEqual(info['sha256'], b.checksum(directory / 'database.dump'))
            self.assertEqual(b.main('health'), 0)
            unknown = Path(tmp) / 'backup-unknown'
            unknown.mkdir()
            b.retain(1)
            self.assertTrue(unknown.exists())
            self.assertTrue(directory.exists())

    def test_dump_failure_one_shot_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'ROOT', Path(tmp)):
            with patch.object(b, 'run', side_effect=RuntimeError('dump failed')):
                self.assertEqual(b.main('once'), 1)
            self.assertEqual(list(Path(tmp).glob('backup-*')), [])
            self.assertEqual(b.main('health'), 1)


if __name__ == '__main__':
    unittest.main()
