"""Resolve a runtime Helm chart to an original upload confirmed for this service."""
from pathlib import PurePosixPath
import re
import shutil
from types import SimpleNamespace

from fastapi import HTTPException

from .discovery_distributions import _selection
from .discovery_models import DiscoveryConfirmation, DiscoveryInventory, confirmed_inventories
from .discovery_sources import decrypted_source
from .discovery_worker import upload_root
from .durable_jobs import DurableJob
from .helm_archives import compressed_limit
from .runtime_candidates import checksum


def confirmed_charts(db, service, asset, confirmation_id=None):
    """Join on original bytes, then restrict the render and dependencies to the confirmed chart."""
    digest = asset.get('digest') or ''
    if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
        return
    query = confirmed_inventories(service.id).where(DiscoveryInventory.source_hash == digest[7:])
    if confirmation_id:
        query = query.where(DiscoveryConfirmation.id == confirmation_id)
    for confirmation, item in db.execute(query.order_by(DiscoveryConfirmation.created_at.desc(), DiscoveryConfirmation.id)):
        inventory = item.inventory
        if (inventory.get('archive_hash') != item.source_hash or checksum(inventory) != item.content_hash
                or inventory.get('supplemental_sources') or inventory.get('gitlab_source')):
            continue
        roots = [r for r in inventory.get('roots', []) if r['id'] in confirmation.root_ids and
                 r.get('technology') == 'helm' and r.get('chart_name') == asset['name']
                 and r.get('chart_version') == asset['version'] and r.get('path') == asset['name']]
        if len(roots) != 1:
            continue
        root = roots[0]['id']
        # Reuse Discovery's own rendered-component, diagnostics and recursive dependency checks.
        try:
            selection = _selection(service.id, asset['name'], SimpleNamespace(
                id=confirmation.id, root_ids=[root], acknowledge_partial=confirmation.acknowledge_partial), item, [root])
        except HTTPException:
            continue
        job = db.get(DurableJob, item.job_id)
        if (not job or job.kind != 'discovery' or job.status != 'completed'
                or job.payload.get('group_id') != item.group_id or job.payload.get('source_hash') != item.source_hash
                or job.result.get('inventory_id') != item.id):
            continue
        chart = next(row for row in selection['charts'] if row['id'] == root)
        dependencies = []
        pending = [(root, child) for child in chart['dependencies']]
        while pending:
            parent_id, child = pending.pop()
            dependencies.append(dict(id=child['id'], parent_id=parent_id, name=child['label'],
                version=child['version'], enabled=child.get('enabled'), digest_kind=child['digest_kind'],
                sha256=child['content_digest']))
            pending.extend((child['id'], nested) for nested in child['dependencies'])
        yield dict(confirmation_id=confirmation.id, inventory_id=item.id, root_id=root, content_hash=item.content_hash,
                   name=asset['name'], version=asset['version'], digest=digest,
                   dependencies=sorted(dependencies, key=lambda row: (row['parent_id'], row['id']))), job


def copy_upload(discovery, target):
    evidence, job = discovery
    identity = job.payload.get('source_id') or ''
    filename = job.payload.get('filename') or ''
    if (job.result.get('source_expired') or not re.fullmatch('[0-9a-f]{32}', identity)
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,180}', filename)
            or not filename.lower().endswith(('.tgz', '.tar.gz'))):
        raise ValueError('The confirmed original chart upload is unavailable.')
    root = upload_root().resolve()
    folder = root / identity
    path = folder / filename
    if (folder.is_symlink() or path.is_symlink() or path.resolve().parent != folder or not path.is_file()
            or path.stat().st_size > compressed_limit() + 64):
        raise ValueError('The confirmed original chart upload is unavailable or exceeds the scan limit.')
    with decrypted_source(path, identity, evidence['digest'][7:]) as original:
        shutil.copyfile(original, target)


def check_chart_package(folder, chart_name):
    """A repository archive containing a chart cannot become that chart's signed archive."""
    if len(PurePosixPath(chart_name).parts) != 1:
        raise ValueError('Invalid Helm chart name.')
    packages = list((folder / 'input' / 'charts').iterdir())
    if len(packages) != 1 or [item.name for item in packages[0].iterdir()] != [chart_name]:
        raise ValueError('The discovery upload must contain a single packaged Helm chart.')
    if not (packages[0] / chart_name / 'Chart.yaml').is_file():
        raise ValueError('The discovery upload must contain a Helm chart at its package root.')
