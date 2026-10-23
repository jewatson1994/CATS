"""Bounded offline inventory. Native rendering is delegated to an isolated runner."""
from __future__ import annotations
from dataclasses import dataclass
import base64
import hashlib
import json
import stat
import re
import shutil
import tempfile
from pathlib import Path
import yaml
from .discovery_limits import limit
from . import compose_ingestion as compose
from . import service_definitions as legacy

SCHEMA_VERSION = '1.0'
# Repository extraction budgets; direct Compose uploads keep their smaller defaults.
MAX_REPOSITORY_ENTRIES = limit("FILES")
MAX_REPOSITORY_BYTES = limit("EXTRACTED_BYTES")
MAX_REPOSITORY_FILE_BYTES = limit("FILE_BYTES")

def _exceeds(value, limit):
    return bool(limit and value > limit)

def _file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
@dataclass(frozen=True)
class DiscoveryAdapter:
    """Trusted format adapter. Custom handlers receive bounded staged inputs.

    detector(path, documents) identifies roots; handler(root_path, options, runner)
    returns a canonical fragment: nodes(kind/name/state), images(reference/name),
    and diagnostics(code). Payload fields outside this allowlist are discarded.
    """
    technology: str
    filenames: tuple[str, ...] = ()
    tool: str | None = None
    prefix: tuple[str, ...] = ()
    detector: object = None
    handler: object = None

    def matches(self, path, documents=()):
        return Path(path).name in self.filenames or bool(self.detector and self.detector(path, documents))

NativeAdapter = DiscoveryAdapter

def _has_resource(documents, flux):
    return any(isinstance(doc, dict) and doc.get('apiVersion') and doc.get('kind')
               and ('toolkit.fluxcd.io/' in str(doc['apiVersion'])) == flux for doc in documents)

def _legacy_match(path, documents):
    return any(legacy._matches(doc, adapter) for doc in documents for adapter in legacy.ADAPTERS.values())

ADAPTERS = [
    DiscoveryAdapter('helm', ('Chart.yaml',), 'helm', ('template', 'discovery')),
    DiscoveryAdapter('kustomize', ('kustomization.yaml', 'kustomization.yml', 'Kustomization'), 'kustomize', ('build',)),
    DiscoveryAdapter('compose', ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')),
    DiscoveryAdapter('kubernetes', detector=lambda path, docs: _has_resource(docs, False)),
    DiscoveryAdapter('flux', detector=lambda path, docs: _has_resource(docs, True)),
    DiscoveryAdapter('legacy', detector=_legacy_match),
    DiscoveryAdapter('images', ('images.txt', 'image-list.txt')),
]

def register_adapter(adapter):
    """Register trusted server code; uploaded data cannot register handlers."""
    if not isinstance(adapter, DiscoveryAdapter) or any(a.technology == adapter.technology for a in ADAPTERS):
        raise ValueError('Invalid or duplicate discovery adapter.')
    if adapter.handler is None or not callable(adapter.handler):
        raise ValueError('Custom adapter requires a handler.')
    ADAPTERS.append(adapter)

class DiscoveryError(ValueError):
    pass

def _id(*parts):
    return hashlib.sha256(json.dumps(parts, separators=(',', ':')).encode()).hexdigest()[:24]

def _documents(text):
    if not isinstance(text, str) or _exceeds(len(text.encode()), MAX_REPOSITORY_FILE_BYTES):
        raise DiscoveryError('Document exceeds limits.')
    class BoundedLoader(yaml.SafeLoader):
        structural_nodes = 0
        structural_depth = 0
        def compose_node(self, parent, index):
            self.structural_nodes += 1
            self.structural_depth += 1
            try:
                if self.structural_nodes > 30000 or self.structural_depth > 50:
                    raise DiscoveryError('Document structure exceeds limits.')
                return super().compose_node(parent, index)
            finally:
                self.structural_depth -= 1
    loader = BoundedLoader(text)
    result, count = [], 0
    try:
        while loader.check_data():
            node = loader.get_node()
            def check(n, parents=frozenset(), depth=0):
                nonlocal count
                count += 1
                if count > 30000 or depth > 50 or id(n) in parents:
                    raise DiscoveryError('Document structure exceeds limits.')
                if isinstance(n, yaml.MappingNode):
                    keys = [k.value for k, _ in n.value if isinstance(k, yaml.ScalarNode)]
                    if len(keys) != len(set(keys)):
                        raise DiscoveryError('Duplicate document keys.')
                children = ([c for pair in n.value for c in pair] if isinstance(n, yaml.MappingNode)
                            else n.value if isinstance(n, yaml.SequenceNode) else [])
                for child in children:
                    check(child, parents | {id(n)}, depth + 1)
            check(node)
            document = loader.construct_document(node)
            try:
                json.dumps(document, allow_nan=False)
            except (TypeError, ValueError):
                raise DiscoveryError('Unsupported document scalar type.') from None
            result.append(document)
        return result
    finally:
        loader.dispose()

def _merge(a, b):
    out = dict(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out

def _text(v):
    return v if isinstance(v, str) and len(v) <= 512 and not any(ord(c) < 32 for c in v) else '[invalid]'

def _image(v):
    return isinstance(v, str) and len(v) <= 512 and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/:@+-]*', v))

def run_discovery(source_path, options=None, runner=None, progress=None, artifact_resolver=None, supplemental_inputs=None, check_cancelled=None):
    options = options or {}
    if not isinstance(options, dict):
        raise DiscoveryError('Options must be a mapping.')
    for key in ('profiles', 'values_files'):
        selected = options.get(key, [])
        if not isinstance(selected, list) or len(selected) > 50 or any(not isinstance(value, str) or len(value) > 500 for value in selected):
            raise DiscoveryError('Invalid discovery option list.')
    source_map = options.get('source_map', {})
    if not isinstance(source_map, dict) or len(source_map) > 200 or any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 500 or len(v) > 500 for k, v in source_map.items()):
        raise DiscoveryError('Invalid local source mapping.')
    source_map = dict(source_map)
    mapping = options.get('chart_map', {})
    if not isinstance(mapping, dict) or len(mapping) > 200 or any(not isinstance(k, str) or not isinstance(v, str) for k, v in mapping.items()):
        raise DiscoveryError('Invalid local chart mapping.')
    if progress:
        progress({'stage': 'reading'})
    result = dict(schema_version=SCHEMA_VERSION, source_hash='', roots=[], nodes=[], edges=[], images=[],
                  diagnostics=[], completeness='complete', metrics={}, tool_versions={})
    secret_values = set()
    root_ids, node_ids, image_ids = set(), set(), set()
    pending_refs, definitions, workloads, services, edge_ids = [], {}, [], [], set()
    definition_origins, ambiguous_definitions = {}, set()
    def collect_secrets(documents):
        for document in documents:
            if isinstance(document, dict) and document.get('kind') == 'List' and isinstance(document.get('items'), list):
                collect_secrets(document['items'])
            if not isinstance(document, dict) or document.get('kind') != 'Secret':
                continue
            for field in ('data', 'stringData'):
                values = document.get(field, {})
                if not isinstance(values, dict):
                    continue
                for value in values.values():
                    if not isinstance(value, str):
                        continue
                    if field == 'data':
                        try:
                            value = base64.b64decode(value, validate=True).decode()
                        except (ValueError, UnicodeError):
                            continue
                    if len(value) >= 4:
                        secret_values.add(value)
    def clean(value):
        text = _text(value)
        return '[redacted]' if any(secret in text for secret in secret_values) else text
    def issue(code, rid=None, path=None):
        if len(result['diagnostics']) >= 30000:
            raise DiscoveryError('Diagnostic limit exceeded.')
        result['diagnostics'].append(dict(code=code, severity='warning', root_id=rid, path=path,
                                          message=code.replace('_', ' ') + '.', blocking=True))
        result['completeness'] = 'partial'
        for item in result['roots']:
            if item['id'] == rid:
                item['completeness'] = 'partial'
    def root(path, technology):
        item = dict(id=_id('root', path, technology), path=path, technology=technology, completeness='complete')
        if item['id'] not in root_ids:
            if len(root_ids) >= 5000:
                raise DiscoveryError('Root limit exceeded.')
            root_ids.add(item['id'])
            result['roots'].append(item)
        return item['id']
    def node(rid, kind, name, path, state='declared', namespace=''):
        item = dict(id=_id(rid, kind, namespace, name, path), root_id=rid, kind=clean(kind), name=clean(name),
                    namespace=clean(namespace), completeness='partial' if state == 'unresolved' else 'complete', state=state if state in ('declared', 'selected', 'rendered', 'unresolved') else 'unresolved', provenance=[dict(path=path)])
        if item['id'] not in node_ids:
            if len(node_ids) >= 30000:
                raise DiscoveryError('Node limit exceeded.')
            node_ids.add(item['id'])
            result['nodes'].append(item)
        return item['id']
    def image(ref, rid, nid, path):
        if isinstance(ref, str) and any(secret in ref for secret in secret_values):
            issue('secret_derived_image_not_retained', rid, path)
            return
        if _image(ref):
            item = dict(reference=ref, root_id=rid, component_id=nid, completeness='complete', provenance=[dict(path=path)])
            identity = (ref, rid, nid, path)
            if identity not in image_ids:
                if len(image_ids) >= 30000:
                    raise DiscoveryError('Image limit exceeded.')
                image_ids.add(identity)
                result['images'].append(item)
        elif ref:
            issue('unresolved_image_reference', rid, path)
    def edge(source, target, kind):
        identity = (source, target, kind)
        if identity not in edge_ids:
            if len(edge_ids) >= 30000:
                raise DiscoveryError('Edge limit exceeded.')
            edge_ids.add(identity)
            result['edges'].append(dict(source=source, target=target, kind=kind))
    def reference(source, kind, name, namespace, rid, path, relation='references'):
        if not isinstance(name, str) or not name:
            return
        if len(pending_refs) >= 30000:
            raise DiscoveryError('Reference limit exceeded.')
        pending_refs.append((source, kind, name, namespace or 'default', rid, path, relation))
    def manifests(docs, rid, path, state='declared'):
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get('kind') == 'List':
                manifests(doc.get('items', []), rid, path, state)
                continue
            kind, meta = doc.get('kind'), doc.get('metadata', {})
            if not isinstance(kind, str) or not isinstance(meta, dict):
                continue
            nid = node(rid, kind, meta.get('name', '[unnamed]'), path, state, namespace=meta.get('namespace', ''))
            namespace = meta.get('namespace') or 'default'
            definition_key = (kind, namespace, str(meta.get('name', '')))
            origin = _id(path, doc)
            if definition_key in definition_origins and definition_origins[definition_key] != origin:
                ambiguous_definitions.add(definition_key)
                issue('ambiguous_resource_identity', rid, path)
            else:
                definition_origins[definition_key] = origin
                definitions[definition_key] = nid
            if kind == 'Secret':
                continue
            pod = None
            api_group = str(doc.get('apiVersion', '')).split('/')[0]
            standard_kind = (kind in ('Pod', 'ReplicationController') and api_group == 'v1'
                             or kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet') and api_group == 'apps'
                             or kind in ('Job', 'CronJob') and api_group == 'batch')
            spec = doc.get('spec', {})
            if standard_kind and kind == 'Pod':
                pod = spec
            elif standard_kind and kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'ReplicationController', 'Job'):
                if isinstance(spec, dict) and isinstance(spec.get('template'), dict):
                    pod = spec['template'].get('spec')
            elif standard_kind and kind == 'CronJob':
                try:
                    pod = spec['jobTemplate']['spec']['template']['spec']
                except (KeyError, TypeError):
                    pass
            if isinstance(spec, dict) and kind == 'Service' and isinstance(spec.get('selector'), dict) and spec['selector']:
                services.append((nid, namespace, spec['selector'], rid, path))
            if isinstance(spec, dict) and kind == 'PersistentVolumeClaim':
                reference(nid, 'PersistentVolume', spec.get('volumeName'), 'default', rid, path, 'binds')
                reference(nid, 'StorageClass', spec.get('storageClassName'), 'default', rid, path, 'uses_storage_class')
            if isinstance(pod, dict):
                template = spec if kind == 'Pod' else spec.get('template', {})
                if kind == 'CronJob':
                    template = spec.get('jobTemplate', {}).get('spec', {}).get('template', {})
                labels = meta.get('labels', {}) if kind == 'Pod' else template.get('metadata', {}).get('labels', {})
                if isinstance(labels, dict):
                    workloads.append((nid, namespace, labels))
                def config_refs(value, source=nid):
                    if not isinstance(value, dict):
                        return
                    for key, target_kind in (('configMapKeyRef', 'ConfigMap'), ('configMapRef', 'ConfigMap'), ('secretKeyRef', 'Secret'), ('secretRef', 'Secret')):
                        target = value.get(key)
                        if isinstance(target, dict):
                            reference(source, target_kind, target.get('name'), namespace, rid, path, 'uses_configuration')
                for volume in pod.get('volumes', []) if isinstance(pod.get('volumes', []), list) else []:
                    if not isinstance(volume, dict):
                        continue
                    vid = node(rid, 'PodVolume', str(meta.get('name', '')) + '/' + str(volume.get('name', '')), path, state, namespace)
                    edge(nid, vid, 'uses_volume')
                    for key, target_kind, name_key in (('configMap', 'ConfigMap', 'name'), ('secret', 'Secret', 'secretName'), ('persistentVolumeClaim', 'PersistentVolumeClaim', 'claimName')):
                        value = volume.get(key)
                        if isinstance(value, dict):
                            reference(vid, target_kind, value.get(name_key), namespace, rid, path, 'backed_by')
                    projected = volume.get('projected', {})
                    for value in projected.get('sources', []) if isinstance(projected, dict) and isinstance(projected.get('sources', []), list) else []:
                        if isinstance(value, dict):
                            for key, target_kind in (('configMap', 'ConfigMap'), ('secret', 'Secret')):
                                if isinstance(value.get(key), dict):
                                    reference(vid, target_kind, value[key].get('name'), namespace, rid, path, 'backed_by')
                for field in ('containers', 'initContainers', 'ephemeralContainers'):
                    containers = pod.get(field, [])
                    if not isinstance(containers, list):
                        issue('invalid_workload_container_list', rid, path)
                        continue
                    for container in containers:
                        if isinstance(container, dict):
                            image(container.get('image'), rid, nid, path)
                            for value in container.get('envFrom', []) if isinstance(container.get('envFrom', []), list) else []:
                                config_refs(value)
                            for value in container.get('env', []) if isinstance(container.get('env', []), list) else []:
                                if isinstance(value, dict):
                                    config_refs(value.get('valueFrom'))
            elif kind not in {'Secret', 'ConfigMap', 'Service', 'Namespace', 'ServiceAccount', 'Role', 'RoleBinding',
                              'ClusterRole', 'ClusterRoleBinding', 'PersistentVolume', 'PersistentVolumeClaim',
                              'StorageClass', 'Ingress', 'IngressClass', 'NetworkPolicy', 'PodDisruptionBudget',
                              'HorizontalPodAutoscaler', 'CustomResourceDefinition', 'ResourceQuota', 'LimitRange'}:
                if 'toolkit.fluxcd.io/' not in str(doc.get('apiVersion', '')):
                    issue('custom_resource_workloads_not_evaluated', rid, path)
    if options.get('reference') and source_path is None:
        reference = options['reference']
        result['source_hash'] = 'sha256:' + hashlib.sha256(str(reference).encode()).hexdigest()
        rid = root('reference', 'helm' if options.get('reference_kind') == 'chart' else 'images')
        if options.get('reference_kind') == 'chart':
            if artifact_resolver is not None:
                try:
                    artifact = artifact_resolver.resolve('helm', reference, options.get('reference_version', ''))
                    with tempfile.TemporaryDirectory(prefix='cats-discovery-mirror-') as mirror:
                        staged_artifact = artifact.stage(Path(mirror), check=check_cancelled)
                        nested_options = {k: v for k, v in options.items() if k not in ('reference', 'reference_kind', 'reference_version')}
                        resolved = run_discovery(staged_artifact['root'], nested_options, runner, progress, artifact_resolver, supplemental_inputs, check_cancelled)
                        resolved['artifact_provenance'] = [staged_artifact['provenance'], *resolved.get('artifact_provenance', [])]
                        return resolved
                except (ValueError, OSError):
                    issue('approved_artifact_unavailable', rid, 'reference')
            issue('remote_chart_requires_local_artifact', rid, 'reference')
            result['completeness'] = 'blocked'
        else:
            nid = node(rid, 'Image', reference if _image(reference) else '[unresolved]', 'reference')
            image(reference, rid, nid, 'reference')
        result['metrics'] = dict(files=0, roots=1, nodes=len(result['nodes']), images=len(result['images']))
        return result
    with tempfile.TemporaryDirectory(prefix='cats-discovery-') as temporary:
        staging, source = Path(temporary), Path(source_path)
        def check():
            if check_cancelled:
                check_cancelled()
        try:
            if source.is_symlink():
                raise DiscoveryError('Source links are not allowed.')
            if source.is_dir():
                destination = staging / '.cats-compose'
                destination.mkdir()
                seen, total = set(), 0
                for p in source.rglob('*'):
                    check()
                    if p.is_symlink():
                        raise DiscoveryError('Source links are not allowed.')
                    if '.git' in p.relative_to(source).parts or p.is_dir():
                        continue
                    if not stat.S_ISREG(p.stat().st_mode):
                        raise DiscoveryError('Source special files are not allowed.')
                    name = compose._relative(p.relative_to(source).as_posix())
                    if name.casefold() in seen:
                        raise DiscoveryError('Duplicate source paths.')
                    seen.add(name.casefold())
                    total += p.stat().st_size
                    if (_exceeds(len(seen), MAX_REPOSITORY_ENTRIES) or
                            _exceeds(total, MAX_REPOSITORY_BYTES) or
                            _exceeds(p.stat().st_size, MAX_REPOSITORY_FILE_BYTES)):
                        raise DiscoveryError('Source exceeds configured discovery limits.')
                    target = compose._inside(destination, name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with p.open('rb') as incoming, target.open('xb') as output:
                        while chunk := incoming.read(1024 * 1024):
                            check()
                            output.write(chunk)
                staged = {'root': destination}
            elif source.is_file():
                with source.open('rb') as stream:
                    staged = compose.stage_uploads(staging, [(stream, source.name)],
                        max_files=MAX_REPOSITORY_ENTRIES, max_total=MAX_REPOSITORY_BYTES,
                        max_file=MAX_REPOSITORY_FILE_BYTES, max_archive_bytes=limit("UPLOAD_BYTES"), check=check)
            else:
                raise DiscoveryError('Source is unavailable.')
        except compose.ComposeInputError as exc:
            raise DiscoveryError(str(exc)) from None
        except OSError as exc:
            import errno
            if exc.errno in (errno.ENOSPC, errno.EDQUOT):
                raise DiscoveryError('Discovery scratch storage is full; increase available disk space.') from None
            raise DiscoveryError('Discovery source could not be read or staged.') from None
        base = Path(staged['root'])
        if supplemental_inputs:
            from .discovery_supplements import apply_supplements
            try:
                result['supplemental_provenance'] = apply_supplements(base, supplemental_inputs, check=check)
            except compose.ComposeInputError as exc:
                raise DiscoveryError(str(exc)) from None
            except ValueError:
                raise DiscoveryError('Supplemental inputs are unsafe, conflict, or exceed limits.') from None
        files = sorted(p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file())
        digest = hashlib.sha256()
        for path in files:
            source_file = base / path
            digest.update(len(path.encode()).to_bytes(8, 'big') + path.encode() + source_file.stat().st_size.to_bytes(8, 'big'))
            with source_file.open('rb') as stream:
                while chunk := stream.read(1024 * 1024):
                    check()
                    digest.update(chunk)
        result['source_hash'] = 'sha256:' + digest.hexdigest()
        parsed = {}
        charts = [p for p in files if Path(p).name == 'Chart.yaml']
        kustomizations = [p for p in files if Path(p).name in ('kustomization.yaml', 'kustomization.yml', 'Kustomization')]
        compose_files = [p for p in files if Path(p).name in ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')]
        for path in files:
            if Path(path).suffix.lower() not in ('.yaml', '.yml', '.json') or '/templates/' in '/' + path:
                continue
            try:
                parsed[path] = _documents((base / path).read_text(encoding='utf-8-sig'))
            except (ValueError, yaml.YAMLError, UnicodeError, RecursionError):
                # Compose owns custom tags such as !reset and !override. Its
                # native/fallback pass below reports invalid selected inputs.
                if path not in compose_files and Path(path).name not in ('compose.override.yaml', 'compose.override.yml', 'docker-compose.override.yaml', 'docker-compose.override.yml'):
                    issue('invalid_or_unsupported_document', path=path)
        kustomizations = [p for p in kustomizations if not any(isinstance(doc, dict) and 'toolkit.fluxcd.io/' in str(doc.get('apiVersion', '')) for doc in parsed.get(p, []))]
        collect_secrets([doc for docs in parsed.values() for doc in docs])
        managed_paths = {p for p in parsed if any(Path(k).parent == Path('.') or Path(k).parent in Path(p).parents for k in kustomizations)}
        rendered_documents = []
        resources = {}
        resource_origins, ambiguous_resources = {}, set()
        def index_resource(document, path):
            metadata = document.get('metadata', {})
            key = (document.get('kind'), metadata.get('namespace', 'default'), metadata.get('name'))
            origin = _id(path, document)
            if key in resource_origins and resource_origins[key] != origin:
                ambiguous_resources.add(key)
                resources.pop(key, None)
            elif key not in ambiguous_resources:
                resource_origins[key] = origin
                resources[key] = document
        flux_build_paths = set()
        for documents in parsed.values():
            for document in documents:
                if not isinstance(document, dict) or document.get('kind') != 'Kustomization' or 'kustomize.toolkit.fluxcd.io/' not in str(document.get('apiVersion', '')):
                    continue
                spec = document.get('spec', {})
                ref = spec.get('sourceRef', {}) if isinstance(spec, dict) else {}
                if not isinstance(ref, dict):
                    continue
                key = '/'.join(str(v) for v in (ref.get('kind'), ref.get('namespace', document.get('metadata', {}).get('namespace', 'default')), ref.get('name')))
                if key in source_map:
                    try:
                        artifact = compose._inside(base, source_map[key])
                        local = compose._inside(artifact, spec.get('path', '.'))
                        flux_build_paths.add(local.relative_to(base).as_posix())
                    except (ValueError, TypeError, compose.ComposeInputError):
                        pass
        acquired_sources = {}
        staged_artifacts = {}
        helm_source_declarations, resolved_helm_sources = [], set()
        artifact_file_count = len(files)
        artifact_bytes = sum((base / p).stat().st_size for p in files)
        def stage_artifact(artifact, identity):
            nonlocal artifact_file_count, artifact_bytes
            if identity in staged_artifacts:
                return staged_artifacts[identity]
            with tempfile.TemporaryDirectory(prefix='.discovery-artifact-', dir=base) as artifact_dir:
                staged_artifact = artifact.stage(Path(artifact_dir), check=check_cancelled)
                artifact_files = list(Path(staged_artifact['root']).rglob('*'))
                artifact_files = [p for p in artifact_files if p.is_file()]
                new_size = sum(p.stat().st_size for p in artifact_files)
                if _exceeds(artifact_file_count + len(artifact_files), MAX_REPOSITORY_ENTRIES) or _exceeds(artifact_bytes + new_size, MAX_REPOSITORY_BYTES):
                    raise ValueError()
                destination = base / ('.discovery-source-' + _id(*identity))
                if destination.exists():
                    raise ValueError()
                Path(staged_artifact['root']).rename(destination)
            for artifact_file in destination.rglob('*'):
                if artifact_file.is_file() and artifact_file.suffix.lower() in ('.yaml', '.yml', '.json') and 'templates' not in artifact_file.relative_to(destination).parts:
                    try:
                        collect_secrets(_documents(artifact_file.read_text(encoding='utf-8-sig')))
                    except (ValueError, yaml.YAMLError, UnicodeError, RecursionError):
                        # Helm values and templates need not be standalone Kubernetes YAML.
                        pass
            artifact_file_count += len(artifact_files)
            artifact_bytes += new_size
            result.setdefault('artifact_provenance', []).append(staged_artifact['provenance'])
            staged_artifacts[identity] = destination
            return destination
        def local_source(source_key):
            mapping_key = '/'.join(source_key)
            if mapping_key in source_map:
                return compose._inside(base, source_map[mapping_key])
            if source_key in acquired_sources:
                return acquired_sources[source_key]
            if artifact_resolver is None or source_key in ambiguous_resources or source_key not in resources:
                raise ValueError()
            source_document = resources[source_key]
            source_spec = source_document.get('spec', {})
            source_kind = {'GitRepository': 'git', 'OCIRepository': 'oci'}.get(source_key[0])
            ref = source_spec.get('ref', {})
            allowed = ('commit', 'tag', 'branch') if source_kind == 'git' else ('digest', 'tag')
            if not source_kind or not isinstance(ref, dict) or len(ref) != 1 or next(iter(ref)) not in allowed:
                raise ValueError()
            artifact = artifact_resolver.resolve(source_kind, source_spec.get('url'), next(iter(ref.values())))
            destination = stage_artifact(artifact, source_key)
            acquired_sources[source_key] = destination
            return destination
        rendered_releases = set()
        def prepare_chart(directory, rid, path, ancestry=()):
            """Acquire only explicitly configured dependencies; Helm owns render semantics."""
            nonlocal artifact_file_count, artifact_bytes
            if len(ancestry) >= 20:
                issue('helm_dependency_depth_exceeded', rid, path)
                return False
            metadata = yaml.safe_load((directory / 'Chart.yaml').read_text(encoding='utf-8-sig')) or {}
            dependencies = metadata.get('dependencies', [])
            if not isinstance(dependencies, list) or len(dependencies) > 500:
                issue('invalid_helm_dependencies', rid, path)
                return False
            ready = True
            for dependency in dependencies:
                if not isinstance(dependency, dict):
                    issue('invalid_helm_dependency', rid, path)
                    ready = False
                    continue
                name, version = dependency.get('name'), str(dependency.get('version', ''))
                repository = dependency.get('repository', '')
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) or not isinstance(repository, str):
                    issue('invalid_helm_dependency', rid, path)
                    ready = False
                    continue
                identity = ('helm', repository.rstrip('/') + '/' + name, version)
                local = directory / 'charts' / name
                # Packaged dependencies remain for Helm to validate and unpack natively.
                if not (local / 'Chart.yaml').is_file() and list((directory / 'charts').glob(name + '-*.tgz')):
                    continue
                try:
                    if identity in ancestry:
                        raise ValueError('cycle')
                    if not (local / 'Chart.yaml').is_file():
                        if artifact_resolver is None or not repository:
                            raise ValueError('missing')
                        artifact = artifact_resolver.resolve(*identity)
                        package = stage_artifact(artifact, identity)
                        candidates = list(package.rglob('Chart.yaml'))
                        depth = min(len(p.relative_to(package).parts) for p in candidates)
                        candidates = [p for p in candidates if len(p.relative_to(package).parts) == depth]
                        if len(candidates) != 1 or local.exists():
                            raise ValueError('ambiguous')
                        chart_metadata = yaml.safe_load(candidates[0].read_text(encoding='utf-8-sig'))
                        if chart_metadata.get('name') != name:
                            raise ValueError('identity')
                        copied_files = [p for p in candidates[0].parent.rglob('*') if p.is_file()]
                        copied_bytes = sum(p.stat().st_size for p in copied_files)
                        if _exceeds(artifact_file_count + len(copied_files), MAX_REPOSITORY_ENTRIES) or _exceeds(artifact_bytes + copied_bytes, MAX_REPOSITORY_BYTES):
                            raise ValueError('budget')
                        artifact_file_count += len(copied_files)
                        artifact_bytes += copied_bytes
                        local.parent.mkdir(exist_ok=True)
                        shutil.copytree(candidates[0].parent, local)
                    if not prepare_chart(local, rid, path, (*ancestry, identity)):
                        ready = False
                except (ValueError, OSError, TypeError, yaml.YAMLError) as exc:
                    from .discovery_artifacts import ArtifactResolutionError
                    reason = str(exc) if isinstance(exc, ArtifactResolutionError) else 'Supply the chart under charts/ or configure an approved artifact source.'
                    issue('helm_dependency_unavailable', rid, path)
                    result['diagnostics'][-1].update(
                        dependency=clean(name), version=clean(version),
                        message=f"Required Helm chart {clean(name)} ({clean(version)}) is unavailable. {clean(reason)}")
                    ready = False
            return ready

        def render(tool, args, rid, path, postrenderers=None, output_transform=None):
            if runner is None:
                issue('native_renderer_unavailable', rid, path)
                return
            try:
                if tool == 'helm' and not prepare_chart(Path(args[2]), rid, path):
                    return
                output = runner(tool, args, str(base))
                if isinstance(output, dict):
                    result['tool_versions'][tool] = _text(output.get('version', 'unknown'))
                    output = output['stdout']
                else:
                    result['tool_versions'].setdefault(tool, 'unknown')
                if output_transform is not None:
                    output = output_transform(output)
                documents = _documents(output)
                for index, postrenderer in enumerate(postrenderers or []):
                    if index >= 10 or not isinstance(postrenderer, dict) or set(postrenderer) != {'kustomize'}:
                        raise DiscoveryError('Unsupported post-renderer.')
                    transform = postrenderer['kustomize']
                    if not isinstance(transform, dict) or set(transform) - {'patches', 'images'}:
                        raise DiscoveryError('Unsupported post-renderer fields.')
                    patches = transform.get('patches', [])
                    if not isinstance(patches, list) or any(not isinstance(patch, dict) or set(patch) - {'patch', 'target'} or not isinstance(patch.get('patch'), str) for patch in patches):
                        raise DiscoveryError('Only inline patches are allowed.')
                    with tempfile.TemporaryDirectory(prefix='.discovery-post-', dir=base) as postdir:
                        postbase = Path(postdir)
                        (postbase / 'resources.yaml').write_text(yaml.safe_dump_all(documents), encoding='utf-8')
                        configuration = {'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization', 'resources': ['resources.yaml'], **transform}
                        (postbase / 'kustomization.yaml').write_text(yaml.safe_dump(configuration), encoding='utf-8')
                        output = runner('kustomize', ['build', str(postbase)], str(base))
                        if isinstance(output, dict):
                            result['tool_versions']['kustomize'] = _text(output.get('version', 'unknown'))
                            output = output['stdout']
                        else:
                            result['tool_versions'].setdefault('kustomize', 'unknown')
                        documents = _documents(output)
                collect_secrets(documents)
                evidence_hash = hashlib.sha256(yaml.safe_dump_all(documents).encode()).hexdigest()
                before_nodes, before_images = len(result['nodes']), len(result['images'])
                manifests(documents, rid, path, 'rendered')
                for item in result['nodes'][before_nodes:] + result['images'][before_images:]:
                    item['provenance'][0].update(rendered_sha256=evidence_hash, tool=tool)
                for document in documents:
                    if not isinstance(document, dict):
                        continue
                    metadata = document.get('metadata', {})
                    if isinstance(metadata, dict) and all(isinstance(v, str) for v in (document.get('kind'), metadata.get('namespace', 'default'), metadata.get('name'))):
                        index_resource(document, path)
                    if 'toolkit.fluxcd.io/' in str(document.get('apiVersion', '')):
                        rendered_documents.append((path, document, True))
            except (MemoryError, OSError):
                raise
            except Exception as exc:
                issue('native_render_failed', rid, path)
                diagnostic = result['diagnostics'][-1]
                diagnostic['message'] = 'Rendering could not produce workloads. Review the chart configuration and select appropriate values files below. Required values may be reported one at a time; rerun after each correction.'
                from .discovery_renderer import RendererError
                if isinstance(exc, RendererError):
                    if str(exc) in ('Discovery renderer exceeded time limit', 'Discovery renderer exceeded output limit'):
                        diagnostic['message'] = str(exc) + '. Increase the configured budget or reduce the render scope.'
                    diagnostic['value_paths'] = [clean(value) for value in exc.value_paths]

        referenced_charts = set(options.get('chart_map', {}).values())
        for documents in parsed.values():
            for document in documents:
                if isinstance(document, dict) and document.get('kind') == 'HelmRelease':
                    try:
                        chart = document['spec']['chart']['spec']['chart']
                        if isinstance(chart, str):
                            referenced_charts.add(chart)
                    except (KeyError, TypeError):
                        pass
        def vendored_chart(path):
            directory = Path(path).parent
            for parent_chart in charts:
                parent = Path(parent_chart).parent
                if parent == directory or not directory.is_relative_to(parent):
                    continue
                relative = directory.relative_to(parent)
                if relative.parts and relative.parts[0] == 'charts':
                    return True
            return directory.as_posix() in referenced_charts
        for adapter in ADAPTERS:
            if not adapter.tool:
                continue
            for path in (p for p in files if adapter.matches(p, parsed.get(p, [])) and not (adapter.tool == 'helm' and vendored_chart(p))):
                if adapter.tool == 'kustomize' and (path not in kustomizations or Path(path).parent.as_posix() in flux_build_paths):
                    continue
                rid = root(Path(path).parent.as_posix(), adapter.technology)
                args = [*adapter.prefix, str(base / Path(path).parent)]
                if adapter.tool == 'helm':
                    for value_file in options.get('values_files', []):
                        try:
                            value_path = compose._inside(base, value_file)
                            if not value_path.is_file():
                                raise ValueError()
                            args += ['-f', str(value_path)]
                        except (ValueError, TypeError):
                            issue('values_file_unavailable', rid, path)
                render(adapter.tool, args, rid, path)
        for path in compose_files:
            rid = root(path, 'compose')
            selection = [path]
            for suffix in ('compose.override.yaml', 'compose.override.yml', 'docker-compose.override.yaml', 'docker-compose.override.yml'):
                candidate = (Path(path).parent / suffix).as_posix()
                if candidate in files:
                    selection.append(candidate)
                    break
            model = compose.discover(base, selection, profiles=options.get('profiles'), max_file=MAX_REPOSITORY_FILE_BYTES, max_files=MAX_REPOSITORY_ENTRIES, max_total=MAX_REPOSITORY_BYTES, max_selected_files=0)
            native_services = None
            if runner is not None:
                args = ['--project-name', 'discovery']
                for selected in selection:
                    args += ['-f', str(base / selected)]
                dotenv = base / Path(path).parent / '.env'
                if dotenv.is_file():
                    args += ['--env-file', str(dotenv)]
                for profile in options.get('profiles', []):
                    args += ['--profile', str(profile)]
                args += ['config', '--format', 'json']
                try:
                    output = runner('compose', args, str(base))
                    if isinstance(output, dict):
                        result['tool_versions']['compose'] = _text(output.get('version', 'unknown'))
                        output = output['stdout']
                    else:
                        result['tool_versions'].setdefault('compose', 'unknown')
                    documents = _documents(output)
                    if len(documents) != 1:
                        raise ValueError()
                    native_services = documents[0]['services']
                    if not isinstance(native_services, dict):
                        raise ValueError()
                except Exception:
                    issue('compose_native_render_failed', rid, path)
            else:
                issue('compose_native_renderer_unavailable', rid, path)
            if native_services is not None:
                for configuration in native_services.values():
                    if not isinstance(configuration, dict):
                        continue
                    environment = configuration.get('environment', {})
                    if isinstance(environment, dict):
                        secret_values.update(str(value) for key, value in environment.items() if compose._SECRET_NAME.search(str(key)) and value is not None and len(str(value)) >= 4)
                for name, service in native_services.items():
                    if not isinstance(service, dict):
                        issue('invalid_compose_native_output', rid, path)
                        continue
                    nid = node(rid, 'ComposeService', name, path, 'rendered')
                    safe_service = next((item for item in model['services'] if item['name'] == name), None)
                    sensitive_image = any(d.get('code') == 'sensitive_interpolation' and d.get('service') == name for d in model['issues'])
                    if sensitive_image and safe_service is not None and safe_service.get('image') is None:
                        issue('compose_image_requires_safe_resolution', rid, path)
                    else:
                        image(service.get('image'), rid, nid, path)
                    if service.get('build'):
                        issue('compose_build_not_executed', rid, path)
            else:
                for service in model['services']:
                    nid = node(rid, 'ComposeService', service['name'], path, 'selected')
                    image(service.get('image'), rid, nid, path)
            if native_services is not None:
                service_nodes = {n['name']: n['id'] for n in result['nodes'] if n['root_id'] == rid and n['kind'] == 'ComposeService'}
                for name, configuration in native_services.items():
                    if not isinstance(configuration, dict) or name not in service_nodes:
                        continue
                    source_id = service_nodes[name]
                    dependencies = configuration.get('depends_on', {})
                    for dependency in dependencies if isinstance(dependencies, (dict, list)) else []:
                        target = service_nodes.get(dependency)
                        if target is None:
                            target = node(rid, 'ComposeServiceReference', dependency, path, 'unresolved')
                            issue('compose_dependency_unresolved', rid, path)
                        edge(source_id, target, 'depends_on')
                    networks = configuration.get('networks', {})
                    for name in networks if isinstance(networks, (dict, list)) else []:
                        edge(source_id, node(rid, 'ComposeNetwork', name, path, 'rendered'), 'uses_network')
                    volumes = configuration.get('volumes', [])
                    for volume in volumes if isinstance(volumes, list) else []:
                        if isinstance(volume, dict):
                            name = volume.get('source') if volume.get('type') == 'volume' else volume.get('target')
                            if name:
                                edge(source_id, node(rid, 'ComposeVolume', name, path, 'rendered'), 'uses_volume')
            # Native config owns Compose syntax, merging, interpolation, includes,
            # extends and profile selection. The conservative fallback cannot
            # veto those semantics after a successful native resolution.
            native_resolved = {
                'unsupported_feature', 'invalid_input', 'compose_schema',
                'required_variable', 'unresolved_variable', 'interpolation',
                'unsupported_dotenv', 'unresolved_image', 'unresolved_profiles',
                'missing_dependency', 'no_active_services',
            }
            if native_services is not None and not native_services:
                issue('no_active_services', rid, path)
            for diagnostic in model['issues']:
                if native_services is not None and diagnostic.get('code') in native_resolved:
                    continue
                issue(diagnostic.get('code', 'compose_input_incomplete'), rid, path)
        for path, documents in parsed.items():
            if not next(a for a in ADAPTERS if a.technology == 'legacy').matches(path, documents):
                continue
            rid = root(path, 'legacy')
            try:
                definition = legacy.parse_definition((base / path).read_text(encoding='utf-8-sig'))
                for component in definition['components']:
                    nid = node(rid, 'ChartReference', component['logical_name'], path, 'unresolved')
                    mapped = options.get('chart_map', {}).get(component.get('reference'))
                    if mapped:
                        local = compose._inside(base, mapped)
                        if not (local / 'Chart.yaml').is_file():
                            raise ValueError()
                        render('helm', ['template', 'discovery', str(local)], rid, path)
                    else:
                        issue('legacy_chart_requires_local_artifact', rid, path)
            except (ValueError, OSError):
                issue('legacy_definition_unresolved', rid, path)
        for path, docs in parsed.items():
            if path in managed_paths:
                continue
            for doc in docs:
                if isinstance(doc, dict) and isinstance(doc.get('metadata'), dict):
                    meta = doc['metadata']
                    if all(isinstance(v, str) for v in (doc.get('kind'), meta.get('namespace', 'default'), meta.get('name'))):
                        index_resource(doc, path)
        queue = [(path, doc, False) for path, docs in parsed.items() for doc in docs if path not in managed_paths] + rendered_documents
        rendered_documents.clear()
        cursor = 0
        while cursor < len(queue):
            if cursor > 2000:
                issue('render_graph_limit_exceeded')
                break
            path, doc, generated = queue[cursor]
            cursor += 1
            if not isinstance(doc, dict) or not doc.get('apiVersion') or not doc.get('kind'):
                continue
            flux = 'toolkit.fluxcd.io/' in str(doc.get('apiVersion', ''))
            rid = root(path, 'flux' if flux else 'kubernetes')
            manifests([doc], rid, path, 'rendered' if generated else 'declared')
            if not flux:
                continue
            spec = doc.get('spec', {})
            if doc.get('kind') == 'Kustomization' and isinstance(spec, dict):
                build_key = _id(path, doc)
                if build_key in rendered_releases:
                    continue
                rendered_releases.add(build_key)
                meta = doc.get('metadata', {})
                namespace = meta.get('namespace') or 'default'
                resource_id = definitions.get(('Kustomization', namespace, str(meta.get('name', ''))))
                try:
                    ref = spec.get('sourceRef', {})
                    source_key = (ref.get('kind'), ref.get('namespace', namespace), ref.get('name'))
                    reference(resource_id, source_key[0], source_key[2], source_key[1], rid, path, 'uses_source')
                    mapping_key = '/'.join(source_key)
                    if source_key in ambiguous_resources or source_key not in resources:
                        raise ValueError()
                    artifact = local_source(source_key)
                    local = compose._inside(artifact, spec.get('path', '.'))
                    if not local.is_dir() or not any((local / name).is_file() for name in ('kustomization.yaml', 'kustomization.yml', 'Kustomization')):
                        raise ValueError()
                    # Rendering-changing controller fields require their own implementation.
                    supported = {'sourceRef', 'path', 'interval', 'retryInterval', 'timeout', 'prune', 'wait', 'force', 'postBuild', 'dependsOn', 'suspend', 'targetNamespace', 'namePrefix', 'nameSuffix', 'images', 'patches'}
                    if set(spec) - supported or spec.get('suspend'):
                        issue('flux_kustomization_options_not_evaluated', rid, path)
                        continue
                    if spec.get('dependsOn') or spec.get('wait'):
                        issue('flux_dependency_readiness_not_verified', rid, path)
                    post = spec.get('postBuild') or {}
                    if not isinstance(post, dict) or set(post) - {'substitute', 'substituteFrom'}:
                        raise ValueError()
                    substitutions = {}
                    substitution_refs = post.get('substituteFrom', [])
                    if not isinstance(substitution_refs, list):
                        raise ValueError()
                    for entry in substitution_refs:
                        if not isinstance(entry, dict) or entry.get('kind') != 'ConfigMap':
                            raise ValueError()
                        substitution_key = ('ConfigMap', namespace, entry.get('name'))
                        reference(resource_id, 'ConfigMap', entry.get('name'), namespace, rid, path, 'uses_configuration')
                        if substitution_key in ambiguous_resources:
                            raise ValueError()
                        config = resources.get(substitution_key)
                        if config is None and entry.get('optional') is True:
                            continue
                        if config is None or not isinstance(config.get('data', {}), dict):
                            raise ValueError()
                        substitutions.update(config.get('data', {}))
                    inline = post.get('substitute', {})
                    if not isinstance(inline, dict):
                        raise ValueError()
                    substitutions.update(inline)
                    if any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k) or compose._SECRET_NAME.search(k) or not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9_.:/@+\-]*', v) or any(secret in v for secret in secret_values) for k, v in substitutions.items()):
                        raise ValueError()
                    transform = {key: spec[key] for key in ('namePrefix', 'nameSuffix', 'images', 'patches') if key in spec}
                    if 'targetNamespace' in spec:
                        transform['namespace'] = spec['targetNamespace']
                    patches = transform.get('patches', [])
                    if not isinstance(patches, list) or any(not isinstance(patch, dict) or set(patch) - {'patch', 'target'} or not isinstance(patch.get('patch'), str) for patch in patches):
                        raise ValueError()
                    def substitute_output(output):
                        if transform:
                            with tempfile.TemporaryDirectory(prefix='.discovery-flux-', dir=base) as transformdir:
                                transformbase = Path(transformdir)
                                (transformbase / 'resources.yaml').write_text(output, encoding='utf-8')
                                configuration = {'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization', 'resources': ['resources.yaml'], **transform}
                                (transformbase / 'kustomization.yaml').write_text(yaml.safe_dump(configuration), encoding='utf-8')
                                output = runner('kustomize', ['build', str(transformbase)], str(base))
                                if isinstance(output, dict):
                                    result['tool_versions']['kustomize'] = _text(output.get('version', 'unknown'))
                                    output = output['stdout']
                        if not post:
                            return output
                        rendered = []
                        for item in _documents(output):
                            metadata = item.get('metadata', {}) if isinstance(item, dict) else {}
                            disabled = any(isinstance(metadata.get(field), dict) and metadata[field].get('kustomize.toolkit.fluxcd.io/substitute') == 'disabled' for field in ('labels', 'annotations'))
                            text = yaml.safe_dump(item)
                            if not disabled:
                                # Only simple variable expansion is supported. Unknown/default/operator
                                # expressions fail closed instead of emulating a shell imperfectly.
                                def replace(match):
                                    name = match.group(1)
                                    if name not in substitutions:
                                        raise ValueError()
                                    return substitutions[name]
                                text = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', replace, text)
                                if '$' in text:
                                    raise ValueError()
                            rendered.append(text)
                        return '\n---\n'.join(rendered)
                    render('kustomize', ['build', str(local)], rid, path, output_transform=substitute_output)
                    queue.extend(rendered_documents)
                    rendered_documents.clear()
                except (ValueError, TypeError, AttributeError, OSError, compose.ComposeInputError):
                    issue('flux_kustomization_source_or_substitution_unresolved', rid, path)
                continue
            if doc.get('kind') == 'HelmChart' or (doc.get('kind') == 'HelmRepository' and artifact_resolver is not None):
                meta = doc.get('metadata', {})
                helm_source_declarations.append(((doc.get('kind'), meta.get('namespace', 'default'), meta.get('name')), rid, path))
                continue
            if doc.get('kind') in ('GitRepository', 'OCIRepository', 'Bucket'):
                meta = doc.get('metadata', {})
                mapping_key = '/'.join(str(v) for v in (doc.get('kind'), meta.get('namespace', 'default'), meta.get('name')))
                if mapping_key in source_map:
                    continue
                try:
                    local_source((doc.get('kind'), meta.get('namespace', 'default'), meta.get('name')))
                    continue
                except (ValueError, TypeError, AttributeError, OSError, compose.ComposeInputError):
                    pass
            if doc.get('kind') != 'HelmRelease' or not isinstance(spec, dict):
                issue('flux_controller_semantics_not_evaluated', rid, path)
                continue
            release_meta = doc.get('metadata', {})
            release_ns = release_meta.get('namespace') or 'default'
            release_id = definitions.get(('HelmRelease', release_ns, str(release_meta.get('name', ''))))
            for dependency in spec.get('dependsOn', []) if isinstance(spec.get('dependsOn', []), list) else []:
                if isinstance(dependency, dict):
                    reference(release_id, 'HelmRelease', dependency.get('name'), dependency.get('namespace', release_ns), rid, path, 'depends_on')
            chart_spec = spec.get('chart', {}).get('spec', {}) if isinstance(spec.get('chart'), dict) else {}
            chart_ref = spec.get('chartRef')
            chart_ref_key = None
            if chart_ref is not None:
                try:
                    if not isinstance(chart_ref, dict) or set(chart_ref) - {'kind', 'name', 'namespace'} or 'chart' in spec:
                        raise ValueError()
                    chart_ref_key = (chart_ref.get('kind'), chart_ref.get('namespace', release_ns), chart_ref.get('name'))
                    reference(release_id, chart_ref_key[0], chart_ref_key[2], chart_ref_key[1], rid, path, 'uses_source')
                    if chart_ref_key in ambiguous_resources or chart_ref_key not in resources:
                        raise ValueError()
                    if chart_ref_key[0] == 'HelmChart':
                        chart_spec = resources[chart_ref_key].get('spec', {})
                        if not isinstance(chart_spec, dict) or set(chart_spec) - {'chart', 'version', 'sourceRef', 'interval', 'reconcileStrategy', 'suspend', 'valuesFiles', 'ignoreMissingValuesFiles'} or chart_spec.get('suspend'):
                            raise ValueError()
                    elif chart_ref_key[0] != 'OCIRepository':
                        raise ValueError()
                except (ValueError, TypeError):
                    issue('flux_chart_reference_unresolved', rid, path)
                    continue
            source_ref = chart_spec.get('sourceRef', {}) if isinstance(chart_spec, dict) else {}
            if isinstance(source_ref, dict):
                reference(release_id, source_ref.get('kind', 'HelmRepository'), source_ref.get('name'), source_ref.get('namespace', chart_ref_key[1] if chart_ref_key else release_ns), rid, path, 'uses_source')
            release_key = _id(path, doc)
            if release_key in rendered_releases:
                continue
            rendered_releases.add(release_key)
            values = {}
            targets = []
            namespace = doc.get('metadata', {}).get('namespace', 'default')
            refs = spec.get('valuesFrom', []) or []
            if not isinstance(refs, list):
                issue('invalid_flux_values_reference', rid, path)
                refs = []
            for ref in refs:
                if not isinstance(ref, dict):
                    issue('invalid_flux_values_reference', rid, path)
                    continue
                if (set(ref) - {'kind', 'name', 'valuesKey', 'targetPath', 'optional'}
                        or ref.get('kind', 'Secret') not in ('Secret', 'ConfigMap')
                        or not all(isinstance(v, str) and v for v in (namespace, ref.get('name'), ref.get('valuesKey', 'values.yaml')))
                        or ('optional' in ref and not isinstance(ref['optional'], bool))):
                    issue('invalid_flux_values_reference', rid, path)
                    continue
                resource_key = (ref.get('kind', 'Secret'), namespace, ref.get('name'))
                if resource_key not in resources and resource_key not in ambiguous_resources and ref.get('optional') is True:
                    # Flux optional applies only to an absent object, not missing keys or Secrets.
                    continue
                reference(release_id, ref.get('kind', 'Secret'), ref.get('name'), namespace, rid, path, 'uses_values')
                if resource_key in ambiguous_resources:
                    issue('ambiguous_flux_values_reference', rid, path)
                    continue
                resource = resources.get(resource_key)
                if resource is None:
                    if not ref.get('optional'):
                        issue('missing_flux_values_reference', rid, path)
                    continue
                if ref.get('kind', 'Secret') == 'Secret':
                    issue('secret_values_not_rendered', rid, path)
                    continue
                try:
                    raw_value = resource.get('data', {}).get(ref.get('valuesKey', 'values.yaml'))
                    target = ref.get('targetPath')
                    if target is not None and target != '':
                        # Delegate Helm strvals syntax, escaping, lists and scalar typing to Helm.
                        if not isinstance(target, str) or len(target) > 500 or not isinstance(raw_value, str) or _exceeds(len(raw_value), MAX_REPOSITORY_FILE_BYTES):
                            raise ValueError()
                        if any(ord(c) < 32 for c in target):
                            raise ValueError()
                        targets += ['--set', target + '=' + raw_value]
                        continue
                    value = _documents(raw_value)[0]
                    if not isinstance(value, dict):
                        raise ValueError()
                    values = _merge(values, value)
                except Exception:
                    issue('unsupported_flux_values_input', rid, path)
            if isinstance(spec.get('values', {}), dict):
                values = _merge(values, spec.get('values', {}))
            else:
                issue('invalid_flux_inline_values', rid, path)
            if spec.get('dependsOn'):
                issue('flux_dependency_readiness_not_verified', rid, path)
            try:
                chart = chart_spec.get('chart')
                chart = options.get('chart_map', {}).get(chart, chart)
                local = compose._inside(base, str(chart))
                if chart_ref_key and chart_ref_key[0] == 'OCIRepository':
                    package = local_source(chart_ref_key)
                    candidates = list(package.rglob('Chart.yaml'))
                    if not candidates:
                        raise ValueError()
                    depth = min(len(p.relative_to(package).parts) for p in candidates)
                    candidates = [p for p in candidates if len(p.relative_to(package).parts) == depth]
                    if len(candidates) != 1:
                        raise ValueError()
                    local = candidates[0].parent
                if not (local / 'Chart.yaml').is_file():
                    source_key = (source_ref.get('kind', 'HelmRepository'), source_ref.get('namespace', chart_ref_key[1] if chart_ref_key else release_ns), source_ref.get('name'))
                    source_document = resources.get(source_key)
                    if source_key in ambiguous_resources or not isinstance(source_document, dict):
                        raise ValueError()
                    if source_key[0] in ('GitRepository', 'OCIRepository'):
                        local = compose._inside(local_source(source_key), str(chart))
                    elif source_key[0] == 'HelmRepository' and artifact_resolver is not None:
                        source_spec = source_document.get('spec', {})
                        repository = source_spec.get('url')
                        if not isinstance(repository, str) or not isinstance(chart, str):
                            raise ValueError()
                        chart_reference = repository.rstrip('/') + '/' + chart
                        artifact = artifact_resolver.resolve('helm', chart_reference, chart_spec.get('version', ''))
                        package = stage_artifact(artifact, ('helm', chart_reference, chart_spec.get('version', '')))
                        candidates = list(package.rglob('Chart.yaml'))
                        if not candidates:
                            raise ValueError()
                        depth = min(len(p.relative_to(package).parts) for p in candidates)
                        candidates = [p for p in candidates if len(p.relative_to(package).parts) == depth]
                        if len(candidates) != 1:
                            raise ValueError()
                        local = candidates[0].parent
                        resolved_helm_sources.add(source_key)
                    if not (local / 'Chart.yaml').is_file():
                        raise ValueError()
                if chart_ref_key:
                    resolved_helm_sources.add(chart_ref_key)
                child_rid = root(local.relative_to(base).as_posix(), 'helm')
                if any(d['root_id'] == rid and d['code'] in ('ambiguous_flux_values_reference', 'missing_flux_values_reference', 'secret_values_not_rendered', 'unsupported_flux_values_input', 'invalid_flux_inline_values', 'invalid_flux_values_reference') for d in result['diagnostics']):
                    issue('flux_render_blocked_by_values', rid, path)
                    continue
                chart_values = None
                if (not isinstance(chart_spec.get('valuesFiles', []), list)
                        or not isinstance(chart_spec.get('ignoreMissingValuesFiles', False), bool)):
                    issue('unsupported_flux_chart_values_files', rid, path)
                    continue
                if chart_spec.get('valuesFiles'):
                    try:
                        selected_files = chart_spec['valuesFiles']
                        if (not isinstance(selected_files, list) or len(selected_files) > 50
                                or not isinstance(chart_spec.get('ignoreMissingValuesFiles', False), bool)):
                            raise ValueError()
                        values_base = local
                        if source_ref.get('kind') in ('GitRepository', 'OCIRepository'):
                            values_base = local_source((source_ref['kind'], source_ref.get('namespace', chart_ref_key[1] if chart_ref_key else release_ns), source_ref.get('name')))
                        chart_values = {}
                        for selected_file in selected_files:
                            if not isinstance(selected_file, str) or not selected_file or len(selected_file) > 500:
                                raise ValueError()
                            value_file = compose._inside(values_base, selected_file)
                            if not value_file.exists() and chart_spec.get('ignoreMissingValuesFiles') is True:
                                continue
                            if not value_file.is_file() or _exceeds(value_file.stat().st_size, MAX_REPOSITORY_FILE_BYTES):
                                raise ValueError()
                            value_documents = _documents(value_file.read_text(encoding='utf-8-sig'))
                            if len(value_documents) != 1 or not isinstance(value_documents[0], dict):
                                raise ValueError()
                            chart_values = _merge(chart_values, value_documents[0])
                    except (ValueError, TypeError, OSError, UnicodeError, compose.ComposeInputError, yaml.YAMLError):
                        issue('unsupported_flux_chart_values_files', rid, path)
                        continue
                values_path = base / ('.discovery-values-' + rid + '.yaml')
                if values_path.exists():
                    raise ValueError()
                values_path.write_text(yaml.safe_dump(values), encoding='utf-8')
                release_name = spec.get('releaseName', doc.get('metadata', {}).get('name', 'discovery'))
                release_namespace = spec.get('targetNamespace', namespace)
                if not all(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', value) for value in (release_name, release_namespace)):
                    raise ValueError()
                def render_release(chart_directory):
                    render('helm', ['template', release_name, str(chart_directory), '--namespace', release_namespace, '--include-crds', '-f', str(values_path), *targets], rid, path, spec.get('postRenderers'))
                if chart_values is None:
                    render_release(local)
                else:
                    # Flux replaces chart defaults with the ordered selection; Helm -f alone
                    # would incorrectly preserve omitted defaults. Never mutate a shared chart.
                    with tempfile.TemporaryDirectory(prefix='.discovery-chart-', dir=base) as chartdir:
                        prepared_chart = Path(chartdir) / 'chart'
                        shutil.copytree(local, prepared_chart, ignore=lambda directory, names: [Path(chartdir).name] if Path(directory) == base else [])
                        (prepared_chart / 'values.yaml').write_text(yaml.safe_dump(chart_values), encoding='utf-8')
                        render_release(prepared_chart)
                values_path.unlink()
                result['edges'].append(dict(source=rid, target=child_rid, kind='renders'))
            except (ValueError, TypeError, OSError, AttributeError, compose.ComposeInputError):
                issue('flux_chart_source_unavailable', rid, path)
            if any(key in spec for key in ('kubeConfig',)):
                issue('flux_controller_semantics_not_evaluated', rid, path)
            queue.extend(rendered_documents)
            rendered_documents.clear()
        for source_key, source_rid, source_path in helm_source_declarations:
            if source_key not in resolved_helm_sources:
                issue('flux_controller_semantics_not_evaluated', source_rid, source_path)
        for adapter in ADAPTERS:
            if adapter.handler is None:
                continue
            for path in files:
                if not adapter.matches(path, parsed.get(path, [])):
                    continue
                rid = root(path, adapter.technology)
                try:
                    fragment = adapter.handler(base / path, dict(options), runner)
                    if not isinstance(fragment, dict) or sum(len(fragment.get(k, [])) for k in ('nodes', 'images', 'diagnostics')) > 2000:
                        raise ValueError()
                    components = {}
                    for item in fragment.get('nodes', []):
                        components[item.get('name')] = node(rid, item.get('kind', 'Component'), item.get('name'), path, item.get('state', 'unresolved'))
                    for item in fragment.get('images', []):
                        nid = components.get(item.get('name')) or node(rid, 'Image', '[image]', path)
                        image(item.get('reference'), rid, nid, path)
                    for item in fragment.get('diagnostics', []):
                        issue('adapter_input_unresolved', rid, path)
                except Exception:
                    issue('adapter_failed', rid, path)
        for path in files:
            if Path(path).name.lower() in ('images.txt', 'image-list.txt'):
                rid = root(path, 'images')
                for line in (base / path).read_text(encoding='utf-8-sig').splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        nid = node(rid, 'Image', line if _image(line) else '[unresolved]', path)
                        image(line, rid, nid, path)
        for source_id, kind, name, namespace, rid, path, relation in pending_refs:
            key = (kind, namespace, name)
            target = definitions.get(key) if kind != 'Secret' and key not in ambiguous_definitions else None
            if key in ambiguous_definitions:
                issue('ambiguous_resource_reference', rid, path)
            if target is None:
                target = node(rid, kind + 'Reference', name, path, 'unresolved', namespace)
                issue('secret_reference_not_evaluated' if kind == 'Secret' else 'resource_reference_unresolved', rid, path)
            edge(source_id, target, relation)
        for service_id, namespace, selector, rid, path in services:
            matches = [wid for wid, ns, labels in workloads if ns == namespace and all(labels.get(k) == v for k, v in selector.items())]
            for wid in matches:
                edge(service_id, wid, 'selects_workload')
            if not matches:
                issue('service_selector_no_local_workload', rid, path)
        for path in files:
            with (base / path).open('rb') as stream:
                is_lfs = stream.read(43).startswith(b'version https://git-lfs.github.com/spec/v1')
            if is_lfs:
                issue('missing_lfs_object', path=path)
            if Path(path).name == '.gitmodules':
                for subpath in re.findall(r'^\s*path\s*=\s*(.+)$', (base / path).read_text(errors='replace'), re.MULTILINE):
                    try:
                        target = compose._inside(base, subpath.strip())
                        if not target.is_dir() or not any(target.iterdir()):
                            issue('missing_submodule_content', path=path)
                    except (ValueError, compose.ComposeInputError):
                        issue('missing_submodule_content', path=path)
        if not result['roots']:
            issue('no_supported_deployment_roots')
        if result['completeness'] == 'partial' and not result['images'] and not result['nodes']:
            result['completeness'] = 'invalid' if any(d['code'] == 'invalid_or_unsupported_document' for d in result['diagnostics']) else 'blocked'
        for item in result['nodes']:
            for field in ('name', 'namespace', 'kind'):
                item[field] = clean(item[field])
        retained_images = []
        for item in result['images']:
            if any(secret in item['reference'] for secret in secret_values):
                issue('secret_derived_image_not_retained', item['root_id'], item['provenance'][0]['path'])
            else:
                retained_images.append(item)
        result['images'] = retained_images
        partial_roots = {item['id'] for item in result['roots'] if item['completeness'] != 'complete'}
        for item in result['nodes'] + result['images']:
            item['completeness'] = 'partial' if item['root_id'] in partial_roots or item.get('state') == 'unresolved' else 'complete'
            for provenance in item['provenance']:
                source_file = base / provenance['path']
                if source_file.is_file():
                    provenance['sha256'] = _file_hash(source_file)
        candidates = {}
        for source_file in files:
            parts = Path(source_file).parts
            for index, part in enumerate(parts[:-1]):
                if part in ('environments', 'envs', 'overlays') and index + 1 < len(parts) - 1:
                    label = parts[index + 1]
                    boundary = Path(*parts[:index + 2]).as_posix()
                    candidate = candidates.setdefault(boundary, dict(name=clean(label), path=boundary, evidence=[], root_ids=[], selected=False, confidence='candidate'))
                    candidate['evidence'].append(source_file)
        for boundary, candidate in candidates.items():
            candidate['root_ids'] = [item['id'] for item in result['roots'] if item['path'] == boundary or item['path'].startswith(boundary + '/')]
        result['candidate_environments'] = list(candidates.values())
        result['candidate_values_files'] = [source_file for source_file in files
            if Path(source_file).suffix.lower() in ('.yaml', '.yml')
            and ('values' in Path(source_file).stem.lower() or
                 (source_file in parsed and any(isinstance(doc, dict) and not any(key in doc for key in ('apiVersion', 'kind', 'services')) for doc in parsed[source_file])))
            and '/templates/' not in '/' + source_file]

        result['metrics'] = dict(files=len(files), roots=len(result['roots']), nodes=len(result['nodes']), images=len(result['images']))
        if progress:
            progress(dict(stage='complete', **result['metrics']))
    return result
