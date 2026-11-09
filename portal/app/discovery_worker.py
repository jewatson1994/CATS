"""Durable discovery execution; native renderers run in a separate sandbox."""
from contextlib import ExitStack
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import uuid
import tempfile
from sqlalchemy import select, update
from . import models, discovery_models
from .durable_jobs import DurableJob, JobError, LeaseLost, run_worker
from .discovery_models import DiscoveryInventory
from .discovery_sources import decrypted_source, SourceStorageError

def upload_root():
    return Path(os.environ.get('CATS_DISCOVERY_UPLOAD_ROOT', '/data/discovery-uploads'))

def configured_artifact_resolver(settings=None):
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
        resolver = ArtifactResolverChain(local, remote) if local and remote else local or remote
        if os.getenv('HELM_ALLOW_NETWORK', '').strip().lower() in {'1', 'true', 'yes', 'on'}:
            from .discovery_helm_network import HelmNetworkResolver
            settings = settings or {}
            def rows(value):
                parsed = json.loads(value) if isinstance(value, str) else value
                if not isinstance(parsed, list):
                    raise ArtifactResolutionError('Expected a configuration list.')
                return parsed
            network = HelmNetworkResolver(
                allowed_sources=rows(os.getenv('CATS_DISCOVERY_HELM_SOURCES', '[]')),
                oci_registries=rows(settings.get('oci_registries', [])),
                trusted_ca_certificates=rows(settings.get('trusted_ca_certificates', [])),
                allowed_redirect_origins=rows(os.getenv('CATS_DISCOVERY_HELM_ORIGINS', '[]')),
                allowed_token_origins=rows(os.getenv('CATS_DISCOVERY_HELM_TOKEN_ORIGINS', '[]')),
                ca_file=ca_file)
            # An exact mirror entry remains authoritative, including hash failures.
            class PreferMirrors:
                def resolve(self, kind, reference, version):
                    key = (kind, reference, version)
                    for mirror in (local, remote):
                        if mirror is not None and key in mirror._entries:
                            return mirror.resolve(*key)
                    return network.resolve(*key)
            return PreferMirrors()
        return resolver
    except (ArtifactResolutionError, ValueError, TypeError):
        raise JobError('Discovery artifact mirror configuration is invalid.') from None



def handle(ctx, payload):
    from .discovery_engine import run_discovery, DiscoveryError
    from .rendering import render_action, tool_version
    from .discovery_limits import limit
    from .discovery_render_cache import RenderCache, cache_directory
    import tempfile
    token = payload.get('source_id', '')
    if len(token) != 32 or any(c not in '0123456789abcdef' for c in token):
        raise JobError('Invalid discovery source identity')
    source = upload_root() / token / payload.get('filename', 'source.zip')
    if source.parent.resolve() != (upload_root() / token).resolve() or not source.is_file() or source.is_symlink() or not source.resolve().is_relative_to(upload_root().resolve()):
        raise JobError('Discovery source expired or unavailable. Submit the source again.')
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
    # Read current global configuration at execution time, never from uploaded input.
    with ctx.session_factory() as db:
        settings = {row.key: row.value for row in db.scalars(select(models.PortalSetting).where(
            models.PortalSetting.group_id.is_(None),
            models.PortalSetting.key.in_(['oci_registries', 'trusted_ca_certificates'])))}
    artifact_resolver = configured_artifact_resolver(settings)
    runner = partial(render_action, check_cancelled=ctx.check, max_output=limit('RENDERED_BYTES'))
    if os.getenv('CATS_DISCOVERY_RENDER_CACHE', 'true').lower() == 'true':
        runner = RenderCache(runner, cache_directory(),
                             str(payload['group_id']) + ':' + token + ':output-limit=' + str(limit('RENDERED_BYTES')),
                             tool_version, source_id=token)
    try:
        with ExitStack() as stack:
            plaintext = stack.enter_context(decrypted_source(source, token, payload['source_hash'], ctx.check))
            supplements = []
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
            inventory = run_discovery(input_path, options=selected, runner=runner, progress=progress,
                artifact_resolver=artifact_resolver, supplemental_inputs=supplements, check_cancelled=ctx.check,
                gitlab_archive='gitlab_source' in payload)
    except (OSError, MemoryError) as exc:
        import errno
        if isinstance(exc, MemoryError) or getattr(exc, 'errno', None) == errno.ENOMEM:
            raise JobError('Discovery exhausted available memory; increase worker memory or reduce concurrent work.') from None
        if getattr(exc, 'errno', None) in (errno.ENOSPC, errno.EDQUOT):
            raise JobError('Discovery storage is full; increase available scratch or upload disk space.') from None
        raise JobError('Discovery storage could not be accessed.') from None
    except SourceStorageError as exc:
        raise JobError(str(exc)) from None
    except DiscoveryError as exc:
        inventory = {'schema_version':'1.0', 'roots':[], 'nodes':[], 'edges':[], 'images':[],
            'completeness':'invalid', 'diagnostics':[{'code':'invalid_source','message':str(exc)}],
            'metrics':{}, 'tool_versions':{}}
    if isinstance(runner, RenderCache):
        inventory.setdefault('metrics', {}).update(render_cache_hits=runner.hits, render_cache_misses=runner.misses, dependency_scoped_renders=runner.scoped_renders)
    if payload.get('supplements'):
        inventory['supplemental_sources'] = payload['supplements']
    if 'gitlab_source' in payload:
        inventory['gitlab_source'] = payload['gitlab_source']
    redacted_overrides = inventory.pop('_redacted_component_overrides', [])
    if redacted_overrides:
        # Do not reintroduce values the engine withheld after inspecting Secrets.
        # Empty tombstones also prevent a later refinement from inheriting them.
        selected['component_overrides'] = {key: '' if key in redacted_overrides else value
            for key, value in selected.get('component_overrides', {}).items()}
    inventory['selection'] = selected
    inventory['archive_hash'] = payload['source_hash']
    if payload.get('previous_job_id'):
        inventory['previous_job_id'] = payload['previous_job_id']
    ctx.check()
    with ctx.session_factory() as db:
        job = ctx._owned(db)
        if job.cancel_requested:
            from .durable_jobs import JobCancelled
            raise JobCancelled()
        inventory['workspace_id'] = payload.get('workspace_id', job.id)
        content = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        existing = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id == job.id))
        if existing is None:
            existing = DiscoveryInventory(id=uuid.uuid4().hex, job_id=job.id, group_id=payload['group_id'],
                source_hash=payload['source_hash'], content_hash=content, inventory=inventory)
            db.add(existing)
        result = {**job.result, 'inventory_id': existing.id, 'completeness': existing.inventory.get('completeness'), 'metrics': existing.inventory.get('metrics', {})}
        publication = {'result': result}
        if redacted_overrides:
            publication['payload'] = {**job.payload, 'options': {**job.payload.get('options', {}),
                'component_overrides': selected['component_overrides']}}
        # SQLite has no SELECT FOR UPDATE. Fence publication with the same
        # active lease and cancellation flag in the inventory transaction.
        changed = db.execute(update(DurableJob).where(DurableJob.id == job.id, DurableJob.status == 'running',
            DurableJob.lease_token == job.lease_token, DurableJob.cancel_requested.is_(False)).values(**publication))
        if not changed.rowcount:
            db.rollback()
            ctx.check()
            raise LeaseLost()
        db.commit()
        return result

if __name__ == '__main__':
    run_worker(['discovery'], handle)
