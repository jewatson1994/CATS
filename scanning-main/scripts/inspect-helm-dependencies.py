#!/usr/bin/env python3
"""Inspect vendored Helm metadata without extracting or executing charts.

JSON carries dependency fields (including empty aliases) across the interface.
Unknown/malformed constraints fail closed instead of accepting a wrong chart.
"""
import argparse
import io
from itertools import islice
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

import yaml

MAX_METADATA = 1024 * 1024
MAX_MEMBERS = 10000
MAX_ARCHIVE = 64 * 1024 * 1024
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def version(value):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value)
    if not match:
        raise ValueError("Invalid chart version")
    if any(len(part) > 1 and part.startswith('0') for part in match.group(1, 2, 3)):
        raise ValueError("Invalid chart version")
    if match.group(4) and any(not part or part.isdigit() and len(part) > 1 and part.startswith('0') for part in match.group(4).split('.')):
        raise ValueError("Invalid chart prerelease")
    return tuple(map(int, match.group(1, 2, 3))), match.group(4)


def compare(left, right):
    a, ap = version(left)
    b, bp = version(right)
    if a != b:
        return (a > b) - (a < b)
    if ap == bp:
        return 0
    if ap is None or bp is None:
        return 1 if ap is None else -1
    for x, y in zip(ap.split('.'), bp.split('.')):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return (int(x) > int(y)) - (int(x) < int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return (x > y) - (x < y)
    return (len(ap.split('.')) > len(bp.split('.'))) - (len(ap.split('.')) < len(bp.split('.')))


def satisfies(actual, constraint):
    """Helm's usual exact, comparator, wildcard, tilde, caret and OR ranges."""
    actual_parts, prerelease = version(actual)
    any_match = False
    for alternative in constraint.split('||'):
        alternative = alternative.strip()
        # Helm excludes prereleases unless the range explicitly includes one.
        if prerelease and not re.search(r'\d-\w', alternative):
            continue
        alternative = re.sub(r'(\S+)\s+-\s+(\S+)', r'>=\1 <=\2', alternative)
        tokens = re.findall(r'(?:>=|<=|!=|>|<|=|~|\^)?\s*v?(?:\d+|[xX*])(?:\.(?:\d+|[xX*])){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', alternative)
        if not tokens or re.sub(r'[\s,]', '', ''.join(tokens)) != re.sub(r'[\s,]', '', alternative):
            raise ValueError("Unsupported dependency version constraint")
        matched = True
        for token in tokens:
            match = re.fullmatch(r'(>=|<=|!=|>|<|=|~|\^)?\s*v?(.+)', token)
            op, value = match.groups()
            core = value.split('-')[0].split('+')[0].split('.')
            if any(part in ('*', 'x', 'X') for part in core):
                first = next(i for i, part in enumerate(core) if part in ('*', 'x', 'X'))
                if any(part not in ('*', 'x', 'X') for part in core[first:]):
                    raise ValueError("Invalid wildcard constraint")
            if any(part in ('*', 'x', 'X') for part in core) or len(core) < 3:
                if op not in (None, '=', '~', '^'):
                    if any(part in ('*', 'x', 'X') for part in core):
                        raise ValueError("Invalid wildcard comparator")
                    if '-' in value or '+' in value:
                        raise ValueError("Invalid partial comparator")
                    lower = tuple(map(int, core + ['0'] * (3 - len(core))))
                    index = len(core) - 1
                    upper = tuple(lower[i] if i < index else lower[i] + 1 if i == index else 0 for i in range(3))
                    lower_cmp = compare(actual, '.'.join(map(str, lower)))
                    upper_cmp = compare(actual, '.'.join(map(str, upper)))
                    matched &= {'>': upper_cmp >= 0, '<=': upper_cmp < 0, '!=': lower_cmp < 0 or upper_cmp >= 0,
                                '>=': lower_cmp >= 0, '<': lower_cmp < 0}[op]
                    continue
                elif op not in ('~', '^'):
                    prefix = []
                    for part in core:
                        if part in ('*', 'x', 'X'):
                            break
                        prefix.append(int(part))
                    matched &= actual_parts[:len(prefix)] == tuple(prefix)
                    continue
                value = '.'.join(core + ['0'] * (3 - len(core)))
            result = compare(actual, value)
            if op in ('~', '^'):
                lower, _ = version(value)
                if op == '~':
                    upper = (lower[0] + 1, 0, 0) if len(core) == 1 else (lower[0], lower[1] + 1, 0)
                else:
                    index = next((i for i, n in enumerate(lower) if n), min(len(core) - 1, 2))
                    upper = tuple(lower[i] if i < index else lower[i] + 1 if i == index else 0 for i in range(3))
                matched &= result >= 0 and compare(actual, '.'.join(map(str, upper))) < 0
            else:
                matched &= {None: result == 0, '=': result == 0, '!=': result != 0,
                            '>': result > 0, '<': result < 0, '>=': result >= 0, '<=': result <= 0}[op]
        any_match |= matched
    return any_match


def metadata(data):
    if len(data) > MAX_METADATA:
        raise ValueError("Chart metadata exceeds limit")
    chart = yaml.safe_load(data)
    if not isinstance(chart, dict) or not isinstance(chart.get('name'), str) or not SAFE_NAME.fullmatch(chart['name']):
        raise ValueError("Invalid chart identity")
    if not isinstance(chart.get('version'), str):
        raise ValueError("Invalid chart version")
    version(chart['version'])
    dependencies = chart.get('dependencies', [])
    if not isinstance(dependencies, list) or len(dependencies) > 500:
        raise ValueError("Invalid dependencies")
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("Invalid dependency declaration")
        if dependency.get('alias') is None:
            dependency['alias'] = ''
        for key in ('name', 'alias'):
            value = dependency.get(key, '')
            if not isinstance(value, str) or (value and not SAFE_NAME.fullmatch(value)) or (key == 'name' and not value):
                raise ValueError("Invalid dependency identity/alias")
        if not isinstance(dependency.get('version'), str) or not dependency['version']:
            raise ValueError("Invalid dependency constraint")
        satisfies('0.0.0', dependency['version'])
        if not isinstance(dependency.get('repository', ''), str):
            raise ValueError("Invalid dependency repository")
    return chart


def read_chart(path, root):
    if not path.is_file() or path.is_symlink() or path.resolve() != root and root not in path.resolve().parents:
        raise ValueError("Dependency path escapes chart workspace")
    with path.open('rb') as handle:
        return metadata(handle.read(MAX_METADATA + 1))


def archive_charts(path=None, data=None, depth=0, budget=None):
    if depth > 24 or (path is not None and path.stat().st_size > MAX_ARCHIVE):
        raise ValueError("Dependency archive exceeds limit")
    charts = {}
    packages = {}
    budget = budget if budget is not None else {'bytes': 0, 'members': 0}
    with tarfile.open(path, 'r:gz', fileobj=io.BytesIO(data) if data is not None else None) as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            budget['bytes'] += member.size
            budget['members'] += 1
            if budget['members'] > MAX_MEMBERS or budget['bytes'] > MAX_ARCHIVE or not parts or member.name.startswith('/') or '\\' in member.name or ':' in member.name or '..' in parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ValueError("Unsafe dependency archive")
            if member.isfile() and parts[-1] == 'Chart.yaml':
                if member.size > MAX_METADATA or member.name in charts:
                    raise ValueError("Invalid archive metadata")
                charts[member.name] = metadata(archive.extractfile(member).read(MAX_METADATA + 1))
            elif member.isfile() and member.name.endswith('.tgz'):
                nested, nested_root = archive_charts(data=archive.extractfile(member).read(MAX_ARCHIVE + 1), depth=depth + 1, budget=budget)
                packages[member.name] = (nested, nested_root)
    roots = [name for name in charts if len(PurePosixPath(name).parts) == 2]
    if len(roots) != 1:
        raise ValueError("Dependency archive must contain one root chart")
    return (charts, packages), roots[0]


def inspect(root):
    root = root.resolve()
    records = []

    def check(chart, candidates, depth=0):
        if depth > 24:
            raise ValueError("Dependency nesting exceeds limit")
        complete = True
        for declaration in chart.get('dependencies', []):
            if len(records) >= 2000:
                raise ValueError("Dependency graph exceeds limit")
            dependency = dict(declaration, alias=declaration.get('alias', ''), repository=declaration.get('repository', ''))
            valid = False
            for candidate, children in candidates(dependency):
                # Aliases rename the dependency in the parent's rendered context;
                # the vendored chart's original identity remains its declared name.
                if candidate['name'] == dependency['name'] and satisfies(candidate['version'], dependency['version']):
                    if check(candidate, children, depth + 1):
                        valid = True
                        break
            records.append(dict(dependency, satisfied=valid))
            complete &= valid
        return complete

    def directory_candidates(directory):
        def candidates(dependency):
            charts_dir = directory / 'charts'
            if charts_dir.is_symlink():
                raise ValueError("Unsafe charts directory")
            if not charts_dir.exists():
                return
            if len(list(islice(charts_dir.iterdir(), 1001))) > 1000:
                raise ValueError('Dependency directory exceeds limit')
            for candidate in sorted(charts_dir.iterdir()):
                if candidate.is_symlink():
                    raise ValueError("Unsafe dependency symlink")
                try:
                    if candidate.is_dir() and candidate.name in (dependency['name'], dependency['alias']):
                        yield read_chart(candidate / 'Chart.yaml', root), directory_candidates(candidate)
                    elif candidate.is_file() and candidate.suffix == '.tgz':
                        bundle, parent = archive_charts(candidate)
                        yield bundle[0][parent], archive_candidates(bundle, parent)
                except (ValueError, OSError, RuntimeError, tarfile.TarError, yaml.YAMLError):
                    continue
        return candidates

    def archive_candidates(bundle, parent):
        charts, packages = bundle
        def candidates(dependency):
            prefix = str(PurePosixPath(parent).parent / 'charts') + '/'
            for name, chart in charts.items():
                remainder = name.removeprefix(prefix)
                if name.startswith(prefix) and len(PurePosixPath(remainder).parts) == 2 and PurePosixPath(remainder).parts[0] in (dependency['name'], dependency['alias']):
                    yield chart, archive_candidates(bundle, name)
            for name, (nested, nested_root) in packages.items():
                if name.startswith(prefix) and len(PurePosixPath(name.removeprefix(prefix)).parts) == 1:
                    yield nested[0][nested_root], archive_candidates(nested, nested_root)
        return candidates

    complete = check(read_chart(root / 'Chart.yaml', root), directory_candidates(root))
    return {'complete': complete, 'dependencies': records}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('chart', type=Path)
    parser.add_argument('--local-only', action='store_true')
    parser.add_argument('--can-build', action='store_true')
    args = parser.parse_args()
    try:
        root = args.chart.resolve()
        if args.local_only or args.can_build:
            declarations = read_chart(root / 'Chart.yaml', root).get('dependencies', [])
            allowed = True
            for item in declarations:
                repository = item.get('repository', '')
                if repository.startswith('file://'):
                    destination = (root / repository[7:]).resolve()
                    if destination != root and root not in destination.parents:
                        raise ValueError('Local dependency escapes chart workspace')
                elif args.local_only and repository:
                    allowed = False
            report = {'complete': allowed, 'dependencies': declarations}
        else:
            report = inspect(args.chart)
        print(json.dumps(report))
        return 0 if report['complete'] else 1
    except (ValueError, OSError, RuntimeError, tarfile.TarError, yaml.YAMLError):
        print(json.dumps({'complete': False, 'error': 'Invalid or unsafe Helm dependency metadata'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
