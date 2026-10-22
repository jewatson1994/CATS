import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('migration', Path(__file__).with_name('migrate.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MigrationTests(unittest.TestCase):
    def test_requires_maintenance(self):
        with patch.object(m, 'run') as run:
            for action in (m.migrate, m.retire_source):
                with self.assertRaises(RuntimeError):
                    action('unused')
            run.assert_not_called()

    def test_nonempty_destination_refused(self):
        with tempfile.TemporaryDirectory() as root, patch.object(m, 'check_boundaries'), \
                patch.object(m, 'counts', return_value={'vex_sources': 1}), patch.object(m, 'run') as run:
            with self.assertRaises(RuntimeError):
                m.migrate(Path(root) / 'new', True)
            run.assert_not_called()

    def test_failed_restore_retains_unverified_archive(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'new'
            rows = {table: 3 for table in m.TABLES}
            empty = {table: 0 for table in m.TABLES}
            def fake_run(command, **kwargs):
                if 'pg_dump' in command:
                    kwargs['stdout'].write(b'preserved archive')
                else:
                    self.assertIn('--single-transaction', command)
                    self.assertNotIn('--disable-triggers', command)
                    raise RuntimeError('restore failed')
            with patch.object(m, 'check_boundaries'), \
                    patch.object(m, 'counts', side_effect=[empty, rows, rows]), \
                    patch.object(m, 'run', side_effect=fake_run):
                with self.assertRaises(RuntimeError):
                    m.migrate(directory, True)
            self.assertEqual((directory / 'intelligence.dump').read_bytes(), b'preserved archive')
            self.assertFalse(json.loads((directory / 'manifest.json').read_text())['verified'])

    def test_retirement_requires_intact_verified_copy_and_matching_counts(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            archive = directory / 'intelligence.dump'
            archive.write_bytes(b'archive')
            counts = {table: 2 for table in m.TABLES}
            manifest = {'verified': True, 'tables': counts, 'sha256': m.checksum(archive)}
            receipt = directory / 'manifest.json'
            receipt.write_text(json.dumps(manifest))
            with patch.object(m, 'check_boundaries'), patch.object(m, 'counts', return_value=counts), \
                    patch.object(m, 'sql') as sql:
                m.retire_source(directory, True)
                query = sql.call_args.args[1]
                self.assertIn('RESTRICT', query)
                self.assertNotIn('CASCADE', query)
                self.assertNotIn('native_vex', query)
                self.assertTrue(archive.exists())
            archive.write_bytes(b'tampered')
            with patch.object(m, 'sql') as sql:
                with self.assertRaises(RuntimeError):
                    m.retire_source(directory, True)
                sql.assert_not_called()

    def test_counts_change_blocks_retirement(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            archive = directory / 'intelligence.dump'
            archive.write_bytes(b'archive')
            manifest = {'verified': True, 'tables': {table: 2 for table in m.TABLES},
                        'sha256': m.checksum(archive)}
            (directory / 'manifest.json').write_text(json.dumps(manifest))
            with patch.object(m, 'check_boundaries'), patch.object(m, 'counts', return_value={}), \
                    patch.object(m, 'sql') as sql:
                with self.assertRaises(RuntimeError):
                    m.retire_source(directory, True)
                sql.assert_not_called()


if __name__ == '__main__':
    unittest.main()
