"""Durable discovery execution; native renderers run in a separate sandbox."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import uuid
import tempfile
from sqlalchemy import select
from . import models, discovery_models
from .durable_jobs import JobError, run_worker
from .discovery_models import DiscoveryInventory
from .discovery_sources import decrypted_source, SourceStorageError

def upload_root():
    return Path(os.environ.get('CATS_DISCOVERY_UPLOAD_ROOT', '/data/discovery-uploads'))

def configured_artifact_resolver():
    # Only process configuration can select manifests; job payloads cannot.
    from .discovery_artifacts import (LocalArtifactResolver, ApprovedHTTPSArtifactResolver,
                                     ArtifactResolverChain, ArtifactResolutionError)
    def admin_path(name):
        configured = os.environ.get(name, '').strip()
        if not configured:
            return None
        path = Path(configured)
        if not path.is_absolute() or path.resolve().is_relative_to(upload_root().resolve()):
            raise JobError('Discovery artifact mirror configuration is invalid.')
        return path
    local_path = admin_path('CATS_DISCOVERY_ARTIFACT_MANIFEST')
    remote_path = admin_path('CATS_DISCOVERY_HTTPS_ARTIFACT_MANIFEST')
    ca_file = admin_path('CATS_DISCOVERY_ARTIFACT_CA_FILE')
    try:
        local = LocalArtifactResolver(local_path) if local_path else None
        remote = ApprovedHTTPSArtifactResolver(remote_path, ca_file=ca_file, cache_directory=(Path(tempfile.gettempdir()) / 'cats-discovery-artifact-cache') if os.getenv('CATS_DISCOVERY_RENDER_CACHE', '').lower() == 'true' else None) if remote_path else None
        return ArtifactResolverChain(local, remote) if local and remote else local or remote
    except ArtifactResolutionError:
        raise JobError('Discovery artifact mirror configuration is invalid.') from None



def handle(ctx, payload):
    from .discovery_engine import run_discovery, DiscoveryError
    from .discovery_renderer import isolated_runner, tool_version
    from .discovery_render_cache import RenderCache
    import tempfile
    token = payload.get('source_id', '')
    if len(token) != 32 or any(c not in '0123456789abcdef' for c in token):
        raise JobError('Invalid discovery source identity')
    source = upload_root() / token / payload.get('filename', 'source.zip')
    if source.parent.resolve() != (upload_root() / token).resolve() or not source.is_file() or source.is_symlink() or not source.resolve().is_relative_to(upload_root().resolve()):
        raise JobError('Discovery source expired or unavailable; upload it again.')
    ctx.stage('Detecting deployment sources', 5)
    def progress(*args, **kwargs):
        ctx.check()
        if args and isinstance(args[0], dict):
            update = args[0]
            ctx.stage(str(update.get('stage', 'Discovering')))
            ctx.checkpoint({'metrics': {k:v for k,v in update.items() if k != 'stage'}})
        if args and isinstance(args[0], str):
            ctx.stage(args[0], kwargs.get('progress'))
    selected = dict(payload.get('options', {}))
    artifact_resolver = configured_artifact_resolver()
    runner = isolated_runner
    if os.getenv('CATS_DISCOVERY_RENDER_CACHE', '').lower() == 'true':
        runner = RenderCache(isolated_runner, Path(tempfile.gettempdir()) / 'cats-discovery-render-cache',
                             str(payload['group_id']) + ':' + token, tool_version)
    try:
        with ExitStack() as stack:
            plaintext = stack.enter_context(decrypted_source(source, token, payload['source_hash'], ctx.check))
            supplements = []
            from .discovery_supplements import MAX_SUPPLEMENTS
            if len(payload.get('supplements', [])) > MAX_SUPPLEMENTS:
                raise JobError('Too many supplemental uploads.')
            for item in payload.get('supplements', []):
                identity = item['source_id']
                if len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
                    raise JobError('Invalid supplemental source identity')
                path = upload_root() / identity / item['filename']
                if path.parent.resolve() != (upload_root() / identity).resolve() or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(upload_root().resolve()):
                    raise JobError('Supplemental source expired or unavailable.')
                plain = stack.enter_context(decrypted_source(path, identity, item['source_hash'], ctx.check))
                supplements.append({**item, 'plaintext': plain})
            input_path = plaintext
            if plaintext.name == 'chart-reference.txt':
                selected.update(reference=plaintext.read_text().strip(), reference_kind='chart')
                input_path = None
            inventory = run_discovery(input_path, options=selected, runner=runner, progress=progress, artifact_resolver=artifact_resolver, supplemental_inputs=supplements)
    except SourceStorageError as exc:
        raise JobError(str(exc)) from None
    except DiscoveryError:
        inventory = {'schema_version':'1.0', 'roots':[], 'nodes':[], 'edges':[], 'images':[],
            'completeness':'invalid', 'diagnostics':[{'code':'invalid_source','message':'Source is malformed, unsafe, or exceeds discovery limits.'}],
            'metrics':{}, 'tool_versions':{}}
    if isinstance(runner, RenderCache):
        inventory.setdefault('metrics', {}).update(render_cache_hits=runner.hits, render_cache_misses=runner.misses, dependency_scoped_renders=runner.scoped_renders)
    if payload.get('supplements'):
        inventory['supplemental_sources'] = payload['supplements']
    inventory['selection'] = selected
    inventory['archive_hash'] = payload['source_hash']
    ctx.check()
    content = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    with ctx.session_factory() as db:
        job = ctx._owned(db)
        if job.cancel_requested:
            from .durable_jobs import JobCancelled
            raise JobCancelled()
        existing = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id == job.id))
        if existing is None:
            existing = DiscoveryInventory(id=uuid.uuid4().hex, job_id=job.id, group_id=payload['group_id'],
                source_hash=payload['source_hash'], content_hash=content, inventory=inventory)
            db.add(existing)
        job.result = {**job.result, 'inventory_id': existing.id, 'completeness': existing.inventory.get('completeness'), 'metrics': existing.inventory.get('metrics', {})}
        db.commit()
        return dict(job.result)

if __name__ == '__main__':
    run_worker(['discovery'], handle)
