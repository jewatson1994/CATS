"""Snapshot proven native input closures; ambiguous invocations retain full-source rendering."""
from contextlib import contextmanager
from pathlib import Path
import os
import shutil
import tempfile


def _inside(path, base):
    path = Path(path)
    if not path.is_absolute():
        path = base / path
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError()
    path = path.resolve(strict=True)
    if not path.is_relative_to(base):
        raise ValueError()
    return path


def _helm(args, base):
    if len(args) < 3 or args[0] != 'template' or args[1].startswith('-'):
        return None
    chart = _inside(args[2], base)
    if not chart.is_dir() or not (chart / 'Chart.yaml').is_file():
        return None
    selected = [(p, Path('chart') / p.relative_to(chart)) for p in chart.rglob('*') if p.is_file() or p.is_symlink()]
    rewritten = list(args)
    replacements = {2: Path('chart')}
    index = 3
    while index < len(args):
        flag = args[index]
        if flag == '--include-crds':
            index += 1
            continue
        if flag not in ('-f', '--values', '--namespace', '--set') or index + 1 == len(args):
            return None
        if flag in ('-f', '--values'):
            value = _inside(args[index + 1], base)
            if not value.is_file():
                return None
            destination = Path('values') / (str(index) + '.yaml')
            selected.append((value, destination))
            replacements[index + 1] = destination
        index += 2
    return selected, rewritten, replacements


def _kustomize(args, base):
    if len(args) != 2 or args[0] != 'build':
        return None
    from .discovery_kustomize_inputs import collect_inputs
    root = _inside(args[1], base)
    files = collect_inputs(root, base)
    if files is None or not files:
        return None
    common = Path(os.path.commonpath([str(root), *[str(p.parent) for p in files]]))
    selected = [(p, Path('input') / p.relative_to(common)) for p in files]
    return selected, list(args), {1: Path('input') / root.relative_to(common)}


@contextmanager
def render_inputs(tool, args, cwd):
    base = Path(cwd).resolve()
    try:
        selection = _helm(args, base) if tool == 'helm' else _kustomize(args, base) if tool == 'kustomize' else None
    except (ValueError, OSError):
        selection = None
    if selection is None:
        yield args, cwd, False
        return
    files, rewritten, replacements = selection
    # Bound copies and reject any link, including links inside chart directories.
    try:
        if len(files) > 20000 or sum(p.stat().st_size for p, _ in files) > 256 * 1024 * 1024:
            raise ValueError()
        for path, _ in files:
            _inside(path, base)
    except (ValueError, OSError):
        yield args, cwd, False
        return
    with tempfile.TemporaryDirectory(prefix='cats-render-inputs-') as directory:
        target = Path(directory)
        for path, relative in files:
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
        for index, relative in replacements.items():
            rewritten[index] = str(target / relative)
        yield rewritten, str(target), True
