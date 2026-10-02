#!/usr/bin/env python3
"""Offline dependency regressions; Helm is mocked, never a live registry."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
spec = importlib.util.spec_from_file_location('dependencies', SCRIPTS / 'inspect-helm-dependencies.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'dokuwiki'
        self.root.mkdir()
        self.declarations = [{'name': 'common', 'alias': '', 'version': '29.3.4',
                              'repository': 'oci://oci.trueforge.org/truecharts'}]
        self.parent()

    def tearDown(self):
        self.temp.cleanup()

    def parent(self):
        (self.root / 'Chart.yaml').write_text(yaml.safe_dump({'apiVersion': 'v2', 'name': 'dokuwiki',
            'version': '16.3.0', 'dependencies': self.declarations}), encoding='utf-8')

    def unpack(self, directory='common', name='common', version='29.3.4', dependencies=None):
        directory = self.root / 'charts' / directory
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'Chart.yaml').write_text(yaml.safe_dump({'name': name, 'version': version,
            'dependencies': dependencies or []}), encoding='utf-8')
        return directory

    def package(self, filename='common-29.3.4.tgz', name='common', version='29.3.4', extra=None):
        charts = self.root / 'charts'
        charts.mkdir(exist_ok=True)
        with tarfile.open(charts / filename, 'w:gz') as archive:
            data = yaml.safe_dump({'name': name, 'version': version}).encode()
            member = tarfile.TarInfo(f'{name}/Chart.yaml')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
            if extra:
                member = tarfile.TarInfo(extra)
                member.size = 1
                archive.addfile(member, io.BytesIO(b'x'))

    def test_empty_alias_is_structured_and_local(self):
        self.unpack()
        report = module.inspect(self.root)
        self.assertTrue(report['complete'])
        declaration = json.loads(json.dumps(report))['dependencies'][0]
        self.assertEqual((declaration['name'], declaration['alias'], declaration['version']), ('common', '', '29.3.4'))
        self.assertEqual(declaration['repository'], 'oci://oci.trueforge.org/truecharts')

    def test_alias_directory_keeps_original_metadata_identity(self):
        self.declarations[0]['alias'] = 'shared'
        self.parent()
        self.unpack('shared')
        self.assertTrue(module.inspect(self.root)['complete'])

    def test_alias_original_directory(self):
        self.declarations[0]['alias'] = 'shared'
        self.parent()
        self.unpack()
        self.assertTrue(module.inspect(self.root)['complete'])

    def test_packaged_and_alias_packaged(self):
        for alias, filename in [('', 'common-29.3.4.tgz'), ('shared', 'shared-29.3.4.tgz')]:
            with self.subTest(alias=alias):
                self.declarations[0]['alias'] = alias
                self.parent()
                self.package(filename)
                self.assertTrue(module.inspect(self.root)['complete'])

    def test_absent(self):
        self.assertFalse(module.inspect(self.root)['complete'])

    def test_wrong_version_and_identity(self):
        for name, version in [('common', '29.3.3'), ('unrelated', '29.3.4'), ('shared', '29.3.4')]:
            with self.subTest(name=name, version=version):
                self.unpack(name=name, version=version)
                self.assertFalse(module.inspect(self.root)['complete'])

    def test_mixed_dependencies(self):
        self.declarations += [{'name': 'worker', 'alias': 'jobs', 'version': '^1.2.0'}]
        self.parent()
        self.unpack()
        self.package('jobs-1.3.0.tgz', 'worker', '1.3.0')
        self.assertTrue(module.inspect(self.root)['complete'])

    def test_constraints(self):
        for constraint, actual, expected in [('>=29.3.0 <30.0.0', '29.3.4', True), ('~29.3.0', '29.4.0', False),
            ('^29.3.0', '29.4.0', True), ('29.3.*', '29.3.4', True), ('29.x', '30.0.0', False),
            ('29.3.4 || 30.0.0', '30.0.0', True), ('29.3.0 - 29.3.5', '29.3.4', True),
            ('>=1.0.0', '1.1.0-beta.1', False), ('>=1.0.0-0', '1.1.0-beta.1', True),
            ('^0.2.3', '0.3.0', False), ('v29.3.4', '29.3.4+build', True),
            ('>1.2', '1.2.4', False), ('<=1.2', '1.2.4', True), ('!=1.2', '1.2.4', False)]:
            with self.subTest(constraint=constraint):
                self.assertEqual(module.satisfies(actual, constraint), expected)

    def test_malformed_parent_fails_closed(self):
        for content in ['[broken', 'name: dokuwiki\nversion: 16.3.0\ndependencies: false',
                        'name: dokuwiki\nversion: 16.3.0\ndependencies: [{name: ../escape, version: 1.0.0}]']:
            (self.root / 'Chart.yaml').write_text(content)
            with self.assertRaises((ValueError, yaml.YAMLError)):
                module.inspect(self.root)

    def test_metadata_path_threats(self):
        for alias in ['../escape', '/escape', 'a\\b', 'x;echo-secret']:
            self.declarations[0]['alias'] = alias
            self.parent()
            with self.assertRaises(ValueError):
                module.inspect(self.root)

    def test_archive_path_threats_and_wrong_metadata(self):
        for threat in ['../escape', '/escape', 'C:/escape', 'common/../../escape', 'common\\escape']:
            with self.subTest(threat=threat):
                self.package(extra=threat)
                self.assertFalse(module.inspect(self.root)['complete'])
        self.package(name='wrong')
        self.assertFalse(module.inspect(self.root)['complete'])

    def test_archive_links_rejected(self):
        self.package()
        target = self.root / 'charts' / 'common-29.3.4.tgz'
        with tarfile.open(target, 'w:gz') as archive:
            member = tarfile.TarInfo('common/Chart.yaml')
            member.type = tarfile.SYMTYPE
            member.linkname = '/outside/Chart.yaml'
            archive.addfile(member)
        self.assertFalse(module.inspect(self.root)['complete'])

    def test_nested_missing_dependency(self):
        self.unpack(dependencies=[{'name': 'child', 'version': '1.0.0'}])
        self.assertFalse(module.inspect(self.root)['complete'])

    def test_nested_packaged_dependency(self):
        charts = self.root / 'charts'
        charts.mkdir()
        nested = io.BytesIO()
        with tarfile.open(fileobj=nested, mode='w:gz') as archive:
            data = b'name: child\nversion: 1.0.0\n'
            member = tarfile.TarInfo('child/Chart.yaml')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        with tarfile.open(charts / 'common-29.3.4.tgz', 'w:gz') as archive:
            for name, data in [('common/Chart.yaml', b'name: common\nversion: 29.3.4\ndependencies: [{name: child, version: 1.0.0}]\n'),
                               ('common/charts/child-1.0.0.tgz', nested.getvalue())]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.assertTrue(module.inspect(self.root)['complete'])

    def test_null_alias_and_wrong_packaged_version(self):
        self.declarations[0]['alias'] = None
        self.parent()
        self.package(version='29.3.3')
        self.assertFalse(module.inspect(self.root)['complete'])
        self.package()
        self.assertTrue(module.inspect(self.root)['complete'])

    def test_malformed_child_does_not_satisfy(self):
        directory = self.unpack()
        (directory / 'Chart.yaml').write_text('name: common\nversion: 29.3.4\ndependencies: [broken')
        self.assertFalse(module.inspect(self.root)['complete'])

    def test_invalid_constraints_fail_closed(self):
        for constraint in ['1.*.2', '0.0.0 || $(echo secret)', '>=not-a-version', '01.2.3']:
            with self.subTest(constraint=constraint):
                self.declarations[0]['version'] = constraint
                self.parent()
                with self.assertRaises(ValueError):
                    module.inspect(self.root)

    def test_local_repository_escape_rejected_before_build(self):
        self.declarations[0]['repository'] = 'file://../../outside'
        self.parent()
        result = subprocess.run([sys.executable, str(SCRIPTS / 'inspect-helm-dependencies.py'), str(self.root), '--can-build'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('outside', result.stdout)

    def test_no_dependencies(self):
        self.declarations = []
        self.parent()
        self.assertTrue(module.inspect(self.root)['complete'])

    def test_both_phases_share_locality_and_preparation(self):
        for script in ['scan-configurations.sh', 'extract-helm-images.sh']:
            content = (SCRIPTS / script).read_text()
            self.assertIn('source "${SCRIPT_DIRECTORY}/helm-dependency-helpers.sh"', content)
            self.assertNotIn('prepare_chart_dependencies() {', content)
            self.assertNotIn('chart_dependencies_local() {', content)
            self.assertIn('run_dependency_preparation', content)

    def test_preparation_modes_network_and_oci(self):
        bash = shutil.which('bash')
        git_bash = Path('C:/Program Files/Git/bin/bash.exe')
        if os.name == 'nt' and git_bash.exists():
            bash = str(git_bash)
        if not bash:
            self.skipTest('Bash unavailable')
        def bash_path(path):
            value = Path(path).resolve().as_posix()
            return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value
        for present in (False, True):
            if present:
                self.unpack()
            for mode in ('auto', 'vendored', 'local', 'online'):
                for network in ('false', 'true'):
                    with self.subTest(present=present, mode=mode, network=network):
                        log = self.root / 'calls.txt'
                        if log.exists():
                            log.unlink()
                        env = dict(os.environ, SCRIPT_DIRECTORY=bash_path(SCRIPTS),
                            HELM_DEPENDENCY_PYTHON=bash_path(sys.executable), CHART=bash_path(self.root),
                            CALL_LOG=bash_path(log), MODE=mode, HELM_ALLOW_NETWORK=network)
                        code = 'source "$SCRIPT_DIRECTORY/helm-dependency-helpers.sh"; is_true() { [[ "$1" == true ]]; }; helm() { printf "called\\n" >> "$CALL_LOG"; return 1; }; prepare_chart_dependencies "$CHART" "$MODE"'
                        result = subprocess.run([bash, '-c', code], env=env, capture_output=True, text=True)
                        should_build = not present and mode in ('auto', 'online') and network == 'true'
                        self.assertEqual(log.exists(), should_build, result.stderr)
                        self.assertEqual(result.returncode == 0, present, result.stderr)

    def test_build_result_is_revalidated_and_local_mode_is_shared(self):
        git_bash = Path('C:/Program Files/Git/bin/bash.exe')
        bash = str(git_bash) if os.name == 'nt' and git_bash.exists() else shutil.which('bash')
        if not bash:
            self.skipTest('Bash unavailable')
        def bash_path(path):
            value = Path(path).resolve().as_posix()
            return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value
        env = dict(os.environ, SCRIPT_DIRECTORY=bash_path(SCRIPTS),
                   HELM_DEPENDENCY_PYTHON=bash_path(sys.executable), CHART=bash_path(self.root), HELM_ALLOW_NETWORK='true')
        code = 'source "$SCRIPT_DIRECTORY/helm-dependency-helpers.sh"; is_true() { [[ "$1" == true ]]; }; helm() { echo build-called; return 0; }; prepare_chart_dependencies "$CHART" auto'
        result = subprocess.run([bash, '-c', code], env=env, capture_output=True, text=True)
        self.assertIn('build-called', result.stdout)
        self.assertEqual(result.returncode, 1)  # Helm success alone cannot prove locality.
        self.declarations[0]['repository'] = 'file://charts/common'
        self.parent()
        result = subprocess.run([bash, '-c', code.replace('"$CHART" auto', '"$CHART" local')], env=env, capture_output=True, text=True)
        self.assertIn('build-called', result.stdout)
        self.assertEqual(result.returncode, 1)
        self.declarations[0]['name'] = '../escape'
        self.parent()
        result = subprocess.run([bash, '-c', code], env=env, capture_output=True, text=True)
        self.assertNotIn('build-called', result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_chart_metadata_and_directory_symlinks(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (outside / 'Chart.yaml').write_text('name: common\nversion: 29.3.4\n')
        charts = self.root / 'charts'
        charts.mkdir()
        try:
            (charts / 'common').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not permit symlink creation')
        with self.assertRaises(ValueError):
            module.inspect(self.root)


if __name__ == '__main__':
    unittest.main()
