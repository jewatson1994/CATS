"""Bounded, add-only supplemental inputs; source inventories remain immutable."""
import hashlib
from pathlib import Path
import tempfile
from . import compose_ingestion as compose

MAX_SUPPLEMENTS = 8


def apply_supplements(base, supplements):
    if len(supplements) > MAX_SUPPLEMENTS:
        raise compose.ComposeInputError('Too many supplemental uploads.')
    base = Path(base)
    records = []
    for item in supplements:
        source = Path(item['plaintext'])
        prefix = compose._relative(item.get('target_path', '.'))
        with tempfile.TemporaryDirectory(prefix='cats-supplement-') as scratch:
            with source.open('rb') as stream:
                staged = compose.stage_uploads(Path(scratch), [(stream, source.name)])
            existing = {p.relative_to(base).as_posix().casefold(): p for p in base.rglob('*')}
            files = [p for p in existing.values() if p.is_file()]
            incoming = [(p, compose._relative((Path(prefix) / p.relative_to(staged['root'])).as_posix()))
                        for p in Path(staged['root']).rglob('*') if p.is_file()]
            if len(files) + len(incoming) > compose.MAX_FILES or sum(p.stat().st_size for p in files) + sum(p.stat().st_size for p, _ in incoming) > compose.MAX_TOTAL:
                raise compose.ComposeInputError('Combined discovery inputs exceed limits.')
            for _, name in incoming:
                if name.casefold() in existing or any(parent.as_posix().casefold() in existing and existing[parent.as_posix().casefold()].is_file() for parent in Path(name).parents):
                    raise compose.ComposeInputError('Supplemental paths must not replace existing inputs.')
                compose._inside(base, name)
            hashes = []
            for p, name in sorted(incoming, key=lambda entry: entry[1]):
                data = p.read_bytes()
                target = compose._inside(base, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(data)
                hashes.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest()})
            records.append({key: item[key] for key in ('source_id', 'source_hash', 'target_path', 'parent_job_id', 'parent_inventory_id', 'parent_content_hash')} | {'files': hashes})
    return records


def remove_supplement_sources(root, jobs):
    """Call only after confirming the shared base source has no active jobs."""
    import re
    root = Path(root).resolve()
    for job in jobs:
        for item in job.payload.get('supplements', []):
            identity = item.get('source_id', '')
            if not re.fullmatch(r'[a-f0-9]{32}', identity):
                continue
            folder = root / identity
            path = folder / item.get('filename', '')
            if folder.is_symlink() or path.is_symlink() or path.parent != folder or not path.resolve().is_relative_to(root):
                continue
            if path.is_file():
                path.unlink()
