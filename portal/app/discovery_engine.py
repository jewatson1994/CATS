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
from .discovery_artifacts import ArtifactResolutionError
from .discovery_helm_network import _url as validate_helm_url
from . import compose_ingestion as compose
from . import service_definitions as legacy

SCHEMA_VERSION = '1.0'
# Repository extraction budgets; direct Compose uploads keep their smaller defaults.
MAX_REPOSITORY_ENTRIES = limit("FILES")
MAX_REPOSITORY_BYTES = limit("EXTRACTED_BYTES")
MAX_REPOSITORY_FILE_BYTES = limit("FILE_BYTES")
_CHART_VERSION = re.compile(r'v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?')

def _exceeds(value, limit):
    return bool(limit and value > limit)

def _file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def _tree_hash(directory, paths, check):
    digest = hashlib.sha256()
    for path in paths:
        source_file = directory / path
        encoded = path.encode()
        digest.update(len(encoded).to_bytes(8, 'big') + encoded + source_file.stat().st_size.to_bytes(8, 'big'))
        with source_file.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                check()
                digest.update(chunk)
    return digest.hexdigest()

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

def _package_chart(package):
    charts = sorted(package.rglob('Chart.yaml'), key=lambda p: len(p.parts))
    if not charts or (len(charts) > 1 and len(charts[0].parts) == len(charts[1].parts)):
        raise ValueError('Expected a single top-level chart.')
    return charts[0].parent

def _dependency_values(directory, options):
    """Read the same values layers passed to Helm, only to report dependency conditions."""
    if '--set' in options:
        return None  # Helm strvals may override any condition or tag.
    paths = [directory / 'values.yaml', *(Path(p) for i, p in enumerate(options) if i and options[i - 1] == '-f')]
    values = {}
    for path in paths:
        if path.is_file():
            try:
                document = _documents(path.read_text(encoding='utf-8-sig'))
            except (ValueError, OSError, UnicodeError, yaml.YAMLError):
                return None
            if len(document) != 1 or not isinstance(document[0], dict):
                return None
            values = _merge(values, document[0])
    return values

def _dependency_enabled(dependency, values):
    if not dependency.get('condition') and not dependency.get('tags'):
        return True
    if values is None:
        return None
    for condition in str(dependency.get('condition', '')).split(','):
        value = values
        for part in condition.strip().split('.'):
            value = value.get(part) if isinstance(value, dict) else None
        if isinstance(value, bool):
            return value
    tags = dependency.get('tags') or []
    switches = values.get('tags', {})
    if isinstance(tags, list) and isinstance(switches, dict):
        flags = [switches[tag] for tag in tags if isinstance(tag, str) and isinstance(switches.get(tag), bool)]
        if flags:
            return any(flags)
    return None

def run_discovery(source_path, options=None, runner=None, progress=None, artifact_resolver=None, supplemental_inputs=None, check_cancelled=None, *, gitlab_archive=False):
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
                  diagnostics=[], completeness='complete', metrics={}, tool_versions={}, configurable_components=[])
    secret_values = set()
    roots_by_id, nodes_by_id, image_ids = {}, {}, set()
    pending_refs, definitions, workloads, services, edge_ids = [], {}, [], [], set()
    definition_origins, ambiguous_definitions, owned_definitions = {}, set(), {}
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
    diagnostic_component = None
    def issue(code, rid=None, path=None):
        if len(result['diagnostics']) >= 30000:
            raise DiscoveryError('Diagnostic limit exceeded.')
        result['diagnostics'].append(dict(code=code, severity='warning', root_id=rid, path=path,
                                          message=code.replace('_', ' ') + '.', blocking=True))
        if diagnostic_component:
            result['diagnostics'][-1].update(component_id=diagnostic_component[0], component_name=clean(diagnostic_component[1]))
        result['completeness'] = 'partial'
        if rid in roots_by_id:
            roots_by_id[rid]['completeness'] = 'partial'
    def root(path, technology, **metadata):
        item = dict(id=_id('root', path, technology), path=path, technology=technology, completeness='complete', **metadata)
        if item['id'] not in roots_by_id:
            if len(roots_by_id) >= 5000:
                raise DiscoveryError('Root limit exceeded.')
            roots_by_id[item['id']] = item
            result['roots'].append(item)
        return item['id']
    def values_argument(selected_file, source_root):
        value_path = compose._inside(source_root, selected_file)
        documents = _documents(value_path.read_text(encoding='utf-8-sig'))
        if ('templates' in value_path.relative_to(source_root).parts or len(documents) != 1
                or not isinstance(documents[0], dict) or any(key in documents[0] for key in ('apiVersion', 'kind'))):
            raise ValueError()
        return str(value_path)
    def stage_values(component_id, values):
        value_path = base / ('.discovery-values-' + component_id + '.yaml')
        with value_path.open('x', encoding='utf-8') as output:
            yaml.safe_dump(values, output)
        return value_path
    def component_values(component_id, label, path, rid, inherited=(), previous_id=None):
        selections = options.get('component_values', {})
        selected = selections.get(component_id, selections.get(previous_id, []))
        result['configurable_components'].append(dict(id=component_id, label=clean(label), path=path,
            technology='helm', root_id=rid, values_origin=list(inherited), selected_values=list(selected)))
        arguments = []
        for selected_file in selected:
            try:
                arguments += ['-f', values_argument(selected_file, base)]
            except (ValueError, TypeError, OSError, yaml.YAMLError):
                issue('component_values_file_unavailable', rid, clean(selected_file))
                result['diagnostics'][-1].update(component_id=component_id, message='Selected component values are missing or are not an ordinary values mapping. Select a current non-secret values file.')
                return None
        return arguments

    def node(rid, kind, name, path, state='declared', namespace='', owner=None):
        identity = _id(rid, kind, namespace, name, path, owner) if owner else _id(rid, kind, namespace, name, path)
        item = dict(id=identity, root_id=rid, kind=clean(kind), name=clean(name),
                    namespace=clean(namespace), completeness='partial' if state == 'unresolved' else 'complete', state=state if state in ('declared', 'selected', 'rendered', 'unresolved') else 'unresolved', provenance=[dict(path=path)])
        if identity not in nodes_by_id:
            if len(nodes_by_id) >= 30000:
                raise DiscoveryError('Node limit exceeded.')
            nodes_by_id[identity] = item
            result['nodes'].append(item)
        if owner:
            edge(owner, identity, 'declares')
        return identity
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
    def manifests(docs, rid, path, state='declared', owner=None):
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get('kind') == 'List':
                manifests(doc.get('items', []), rid, path, state, owner)
                continue
            kind, meta = doc.get('kind'), doc.get('metadata', {})
            if not isinstance(kind, str) or not isinstance(meta, dict):
                continue
            nid = node(rid, kind, meta.get('name', '[unnamed]'), path, state, namespace=meta.get('namespace', ''), owner=owner)
            namespace = meta.get('namespace') or 'default'
            definition_key = (kind, namespace, str(meta.get('name', '')))
            origin = _id(path, doc)
            if definition_key in definition_origins and definition_origins[definition_key] != origin:
                ambiguous_definitions.add(definition_key)
                issue('ambiguous_resource_identity', rid, path)
            else:
                definition_origins[definition_key] = origin
                definitions[definition_key] = nid
                if owner:
                    owned_definitions[rid, definition_key] = nid
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
                              'HorizontalPodAutoscaler', 'CustomResourceDefinition', 'ResourceQuota', 'LimitRange'} and not (
                    api_group == 'admissionregistration.k8s.io' and kind in {
                        'MutatingWebhookConfiguration', 'ValidatingWebhookConfiguration'}):
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
                        if not supplemental_inputs:
                            package = Path(staged_artifact['root'])
                            try:
                                chart_path = _package_chart(package).relative_to(package).as_posix()
                            except ValueError:
                                chart_path = None
                            for target in resolved['roots']:
                                if target['technology'] == 'helm' and target['path'] == chart_path:
                                    target.update(chart_digest_kind='archive', chart_sha256=staged_artifact['provenance']['sha256'])
                        return resolved
                except (ValueError, OSError) as exc:
                    issue('approved_artifact_unavailable', rid, 'reference')
                    if isinstance(exc, ArtifactResolutionError):
                        result['diagnostics'][-1]['message'] = clean(str(exc))
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
        if gitlab_archive:
            # GitLab wraps the checkout in a revision-specific directory. Paths
            # selected in the portal and recorded in inventory are repo-relative.
            entries = list(base.iterdir()) if base.is_dir() else []
            if len(entries) != 1 or not entries[0].is_dir():
                raise DiscoveryError('The GitLab archive did not contain a repository directory.')
            base = entries[0]
        if supplemental_inputs:
            from .discovery_supplements import apply_supplements
            try:
                result['supplemental_provenance'] = apply_supplements(base, supplemental_inputs, check=check)
            except compose.ComposeInputError as exc:
                raise DiscoveryError(str(exc)) from None
            except ValueError:
                raise DiscoveryError('Supplemental inputs are unsafe, conflict, or exceed limits.') from None
        files = sorted(p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file())
        source_digest = _tree_hash(base, files, check)
        result['source_hash'] = 'sha256:' + source_digest
        parsed = {}
        charts = [p for p in files if Path(p).name == 'Chart.yaml']
        helm_templates = {Path(chart).parent / 'templates' for chart in charts}
        kustomizations = {p for p in files if Path(p).name in ('kustomization.yaml', 'kustomization.yml', 'Kustomization')
                          and helm_templates.isdisjoint(Path(p).parents)}
        compose_files = [p for p in files if Path(p).name in ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')]
        for index, path in enumerate(files):
            if index % 25 == 0:
                check()
            if path not in kustomizations and (Path(path).suffix.lower() not in ('.yaml', '.yml', '.json') or '/templates/' in '/' + path):
                continue
            try:
                parsed[path] = _documents((base / path).read_text(encoding='utf-8-sig'))
            except (ValueError, yaml.YAMLError, UnicodeError, RecursionError):
                # Compose owns custom tags such as !reset and !override. Its
                # native/fallback pass below reports invalid selected inputs.
                if path not in compose_files and Path(path).name not in ('compose.override.yaml', 'compose.override.yml', 'docker-compose.override.yaml', 'docker-compose.override.yml'):
                    issue('invalid_or_unsupported_document', path=path)
        kustomizations = {p for p in kustomizations if not any(isinstance(doc, dict) and 'toolkit.fluxcd.io/' in str(doc.get('apiVersion', '')) for doc in parsed.get(p, []))}
        collect_secrets([doc for docs in parsed.values() for doc in docs])
        managed_paths = {p for p in parsed if any(Path(k).parent == Path('.') or Path(k).parent in Path(p).parents for k in kustomizations)}
        # Components contribute through a consuming overlay. Keep their raw
        # resources managed, but do not run a standalone build for a Component.
        kustomize_roots = {p for p in kustomizations
                           if not any(isinstance(doc, dict) and doc.get('kind') == 'Component'
                                      and str(doc.get('apiVersion', '')).startswith('kustomize.config.k8s.io/')
                                      for doc in parsed.get(p, []))}
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
        archive_hashes = {}
        chart_hashes = {base: dict(chart_digest_kind='tree', chart_sha256=source_digest)}
        source_paths = set(files)
        def chart_hash(directory):
            if directory not in chart_hashes:
                # Exclude dependencies added to the staged upload by a previous render.
                uploaded = (directory / 'Chart.yaml').relative_to(base).as_posix() in source_paths
                paths = sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*')
                               if p.is_file() and (not uploaded or p.relative_to(base).as_posix() in source_paths))
                chart_hashes[directory] = dict(chart_digest_kind='tree', chart_sha256=_tree_hash(directory, paths, check))
            return chart_hashes[directory]
        def record_reference(evidence, reference):
            # Repository declarations may be untrusted even for a vendored chart.
            try:
                validate_helm_url(reference)
            except ArtifactResolutionError:
                return
            evidence['reference'] = clean(reference)
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
            archive_hashes[destination] = staged_artifact['provenance']['sha256']
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
        def packaged_chart(package):
            local = _package_chart(package)
            chart_hashes[local] = dict(chart_digest_kind='archive', chart_sha256=archive_hashes[package])
            return local
        def acquire_chart(identity):
            package = staged_artifacts.get(identity)
            if package is None:
                package = stage_artifact(artifact_resolver.resolve(*identity), identity)
            return packaged_chart(package)
        def bundled_chart(packaged):
            from .discovery_artifacts import ResolvedArtifact
            package_key = ('bundled-helm', packaged.relative_to(base).as_posix())
            if package_key not in staged_artifacts:
                with packaged.open('rb') as stream:
                    artifact = ResolvedArtifact(stream, packaged.name, _file_hash(packaged), 'helm',
                                                _id(*package_key), 'uploaded-chart')
                    stage_artifact(artifact, package_key)
                result['artifact_provenance'][-1]['integrity'] = 'source-archive'
            return packaged_chart(staged_artifacts[package_key])
        def catalog_chart(component, identity, directory, source_root):
            _, reference, version = identity
            name = component['chart_name']
            mapped = mapping.get(reference + ':' + version) or mapping.get(reference) or mapping.get(component['reference'])
            packaged = directory / 'charts' / f'{name}-{version}.tgz'
            unpacked = directory / 'charts' / name
            if mapped:
                local = compose._inside(base, mapped)
            elif (unpacked / 'Chart.yaml').is_file():
                local = unpacked
            elif packaged.is_file():
                local = bundled_chart(packaged)
                source_root = local
            elif artifact_resolver is not None:
                local = acquire_chart(identity)
                source_root = local
            else:
                return None
            metadata = _documents((local / 'Chart.yaml').read_text(encoding='utf-8-sig'))
            if (len(metadata) != 1 or not isinstance(metadata[0], dict)
                    or metadata[0].get('name') != name or str(metadata[0].get('version')) != version):
                raise ValueError()
            return local, source_root if local.is_relative_to(source_root) else base
        rendered_releases = set()
        def prepare_chart(directory, rid, path, owner, options, inherited=None, ancestry=(), packaged=False):
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
            if not dependencies:
                return True
            locked = []
            lock_path = directory / 'Chart.lock'
            if lock_path.is_file():
                try:
                    lock, = _documents(lock_path.read_text(encoding='utf-8-sig'))
                    if not isinstance(lock, dict) or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(lock.get('digest', ''))):
                        raise ValueError('Invalid lock digest')
                    locked = lock.get('dependencies')
                    if (not isinstance(locked, list) or len(locked) != len(dependencies)
                            or any(not isinstance(row, dict) for row in locked)):
                        raise ValueError('Invalid lock dependencies')
                except (OSError, ValueError, yaml.YAMLError):
                    issue('invalid_helm_dependency_lock', rid, path)
                    return False
            values = _dependency_values(directory, options)
            if ancestry:
                values = _merge(values, inherited) if values is not None and isinstance(inherited, dict) else None
            ready = True
            for index, dependency in enumerate(dependencies):
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
                reference = repository.rstrip('/') + '/' + name
                alias = dependency.get('alias', name)
                if not isinstance(alias, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', alias):
                    issue('invalid_helm_dependency', rid, path)
                    ready = False
                    continue
                dep_id = node(rid, 'HelmDependency', alias, path, 'unresolved', owner=owner)
                evidence = nodes_by_id[dep_id]['provenance'][0]
                evidence.update(chart=clean(name), declared_version=clean(version), selection_scope='parent')
                if repository:
                    record_reference(evidence, reference)
                if isinstance(dependency.get('condition'), str):
                    evidence['condition'] = clean(dependency['condition'])
                if isinstance(dependency.get('tags'), list):
                    evidence['tags'] = [clean(s) for s in dependency['tags'] if isinstance(s, str)]
                enabled = _dependency_enabled(dependency, values)
                if enabled is not None:
                    evidence['enabled'] = enabled
                local = directory / 'charts' / name
                try:
                    exact = version.strip().removeprefix('=').strip()
                    expected = exact if _CHART_VERSION.fullmatch(exact) else None
                    if locked:
                        # Helm writes one lock row per declaration in the same order, including aliases.
                        pin = locked[index]
                        if pin.get('name') != name or pin.get('repository', '') != repository:
                            raise ArtifactResolutionError('Chart.lock does not match this dependency declaration.')
                        locked_version = str(pin.get('version', ''))
                        if _CHART_VERSION.fullmatch(locked_version):
                            if expected and expected != locked_version:
                                raise ArtifactResolutionError('Chart.lock does not match the declared chart version.')
                            expected = locked_version
                            evidence['locked_version'] = clean(locked_version)
                        elif locked_version != version:
                            raise ArtifactResolutionError('Chart.lock does not contain a matching chart version.')
                    identity = ('helm', reference, expected or version)
                    if identity in ancestry:
                        raise ValueError('cycle')
                    packages = list((directory / 'charts').glob(name + '-*.tgz'))
                    in_archive = packaged
                    acquired = None
                    if not (local / 'Chart.yaml').is_file() and packages:
                        if len(packages) != 1:
                            raise ValueError('ambiguous')
                        local = bundled_chart(packages[0])
                        in_archive = True
                    elif not (local / 'Chart.yaml').is_file():
                        if packaged or artifact_resolver is None or not repository:
                            raise ValueError('missing')
                        acquired = acquire_chart(identity)
                        if local.exists():
                            raise ValueError('ambiguous')
                    child = _documents(((acquired or local) / 'Chart.yaml').read_text(encoding='utf-8-sig'))
                    if len(child) != 1 or not isinstance(child[0], dict) or child[0].get('name') != name:
                        raise ValueError('identity')
                    actual_version = str(child[0].get('version') or '')
                    if not actual_version or (expected and actual_version != expected):
                        raise ArtifactResolutionError(f'The chart metadata declares version {clean(actual_version)!r}. Expected {clean(expected or version)!r}.')
                    if acquired:
                        copied_files = [p for p in acquired.rglob('*') if p.is_file()]
                        copied_bytes = sum(p.stat().st_size for p in copied_files)
                        if _exceeds(artifact_file_count + len(copied_files), MAX_REPOSITORY_ENTRIES) or _exceeds(artifact_bytes + copied_bytes, MAX_REPOSITORY_BYTES):
                            raise ValueError('budget')
                        artifact_file_count += len(copied_files)
                        artifact_bytes += copied_bytes
                        local.parent.mkdir(exist_ok=True)
                        shutil.copytree(acquired, local)
                        chart_hashes[local] = chart_hash(acquired)
                    evidence.update(version=clean(actual_version), **chart_hash(local))
                    nodes_by_id[dep_id]['state'] = 'resolved'
                    if (dependency.get('condition') or dependency.get('tags')) and enabled is not True:
                        issue('helm_dependency_images_not_verified', rid, path)
                        result['diagnostics'][-1].update(component_id=dep_id, component_name=clean(alias),
                            message='This optional dependency is available. Its images cannot be verified independently from the parent Helm render.')
                    scoped_values = values.get(alias, {}) if values is not None else None
                    if not prepare_chart(local, rid, path, dep_id, [], scoped_values, (*ancestry, identity), in_archive):
                        ready = False
                except (ValueError, OSError, TypeError, yaml.YAMLError) as exc:
                    reason = str(exc) if isinstance(exc, ArtifactResolutionError) else 'Supply the chart under charts/ or configure an approved artifact source.'
                    issue('helm_dependency_unavailable', rid, path)
                    result['diagnostics'][-1].update(
                        component_id=dep_id, component_name=clean(alias), dependency=clean(name), version=clean(version),
                        message=f"Required Helm chart {clean(name)} ({clean(version)}) is unavailable. {clean(reason)}")
                    ready = False
            return ready

        def render(tool, args, rid, path, postrenderers=None, output_transform=None, owner=None, catalog_scope=None):
            check()
            if runner is None:
                issue('native_renderer_unavailable', rid, path)
                return
            try:
                if tool == 'helm' and not prepare_chart(Path(args[2]), rid, path, owner or rid, args[3:]):
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
                manifests(documents, rid, path, 'rendered', owner)
                for item in result['nodes'][before_nodes:] + result['images'][before_images:]:
                    item['provenance'][0].update(rendered_sha256=evidence_hash, tool=tool)
                for document in documents:
                    if not isinstance(document, dict):
                        continue
                    metadata = document.get('metadata', {})
                    if isinstance(metadata, dict) and all(isinstance(v, str) for v in (document.get('kind'), metadata.get('namespace', 'default'), metadata.get('name'))):
                        index_resource(document, path)
                    if 'toolkit.fluxcd.io/' in str(document.get('apiVersion', '')) and isinstance(metadata, dict):
                        controller = node(rid, document.get('kind'), metadata.get('name', '[unnamed]'), path,
                                          'rendered', namespace=metadata.get('namespace', ''), owner=owner)
                        if not owner:
                            edge(rid, controller, 'declares')
                        rendered_documents.append((path, document, True, (rid, catalog_scope or owner or rid, controller)))
                return True
            except (MemoryError, OSError):
                raise
            except Exception as exc:
                check()
                issue('native_render_failed', rid, path)
                diagnostic = result['diagnostics'][-1]
                diagnostic['renderer'] = tool
                diagnostic['message'] = 'Rendering could not produce workloads. Review the chart configuration and select appropriate values files below. Required values may be reported one at a time; rerun after each correction.'
                if tool == 'kustomize':
                    diagnostic['message'] = 'Kustomize build failed. Review this overlay, its resources, bases, components and patches; Helm values files do not configure Kustomize.'
                from .discovery_renderer import RendererError
                if isinstance(exc, RendererError):
                    if exc.infrastructure:
                        diagnostic['code'] = 'worker_isolation_unavailable'
                        diagnostic['message'] = 'The worker cannot start its isolated rendering tools. Check the worker health and host AppArmor/seccomp configuration, then rediscover. Changing chart values will not fix this failure.'
                    elif str(exc) in ('Offline action exceeded time limit', 'Offline action exceeded output limit'):
                        diagnostic['message'] = str(exc) + '. Increase the configured budget or reduce the render scope.'
                    diagnostic['value_paths'] = [clean(value) for value in exc.value_paths]

        applied_catalog_inputs = set()
        inline_origins = {}
        product_directories = set()
        catalog_entries = 0

        def discover_chart_values(directory, layers, source_root, rid, parent, ancestry):
            # Helm defaults and the selected parent files describe one catalog.
            # Retain only the service section. Other chart values can be sensitive.
            paths = [directory / 'values.yaml', *layers]
            catalog = {}
            catalog_files = []
            for value_file in paths:
                if not value_file.is_file():
                    continue
                relative = value_file.relative_to(base).as_posix()
                applied_catalog_inputs.add(relative)
                try:
                    docs = parsed.get(relative)
                    if docs is None:
                        docs = _documents(value_file.read_text(encoding='utf-8-sig'))
                except (ValueError, yaml.YAMLError):
                    issue('invalid_or_unsupported_document', rid, relative)
                    return
                if len(docs) == 1 and isinstance(docs[0], dict) and 'services' in docs[0]:
                    catalog = _merge(catalog, {'services': docs[0]['services']})
                    catalog_files.append(value_file)
            if not catalog_files or not _legacy_match('', [catalog]):
                return False
            product_directories.add(directory)
            origin = catalog_files[0].relative_to(base).as_posix()
            origin = inline_origins.get(origin, origin)
            try:
                # The service importer also rejects duplicate and YAML merge keys in source.
                for value_file in catalog_files:
                    legacy._load(value_file.read_bytes(), legacy._limits())
                definition = legacy.parse_definition_mapping(catalog)
            except legacy.DefinitionError:
                issue('legacy_definition_unresolved', rid, origin)
                return True
            discover_catalog(definition, catalog, origin, directory, source_root, rid, parent, ancestry)
            return True

        def discover_catalog(definition, document, path, directory, source_root, rid, parent, ancestry):
            nonlocal diagnostic_component, catalog_entries
            entries = legacy._field(document, legacy.ADAPTERS[definition['adapter']].collection)
            for component in definition['components']:
                check()
                catalog_entries += 1
                if catalog_entries > 5000:
                    raise DiscoveryError('Service catalog component limit exceeded.')
                name = component['logical_name']
                entry = entries[name]
                enabled = entry.get('enabled') if isinstance(entry, dict) else None
                nid = node(rid, 'ChartReference', name, path, 'unresolved', owner=parent)
                item = nodes_by_id[nid]
                if isinstance(enabled, bool):
                    item['provenance'][0]['enabled'] = enabled
                previous = diagnostic_component
                diagnostic_component = (nid, name)
                inline_path = None
                try:
                    if component['status'] != 'normalized':
                        issue('catalog_chart_unresolved', rid, path)
                        result['diagnostics'][-1]['message'] = clean(component['reason'])
                        continue
                    chart, version = component['chart_name'], component['version']
                    reference = component['repository']
                    if component['source_type'] == 'helm':
                        reference = reference.rstrip('/') + '/' + chart
                    identity = ('helm', reference, version)
                    item['provenance'][0].update(chart=clean(chart), version=clean(version), reference=clean(reference))
                    if identity in ancestry or len(ancestry) >= 20:
                        issue('catalog_chart_cycle_or_depth_exceeded', rid, path)
                        continue
                    origins = ['chart defaults', 'ordered catalog values files']
                    if entry.get('values'):
                        origins.append('inline catalog values')
                    overrides = component_values(nid, name, path, rid, origins)
                    if overrides is None:
                        continue
                    declared = entry.get('valuesFiles', entry.get('values_files', []))
                    if not isinstance(declared, list) or len(declared) > 50 or not all(isinstance(p, str) for p in declared):
                        issue('catalog_values_file_unavailable', rid, path)
                        result['diagnostics'][-1]['message'] = 'Declare valuesFiles as an ordered list of up to 50 paths.'
                        continue
                    arguments = []
                    try:
                        for value_file in declared:
                            arguments += ['-f', values_argument(value_file, source_root)]
                    except compose.ComposeInputError:
                        issue('catalog_values_file_unavailable', rid, path)
                        result['diagnostics'][-1]['message'] = 'A declared values file path is unsafe. Use a path inside the supplied source.'
                        continue
                    except (ValueError, TypeError, OSError, yaml.YAMLError):
                        issue('catalog_values_file_unavailable', rid, path)
                        result['diagnostics'][-1]['message'] = f'The declared values file {clean(value_file)} is missing or is not a values mapping.'
                        continue
                    try:
                        location = catalog_chart(component, identity, directory, source_root)
                        if location is None:
                            issue('legacy_chart_requires_local_artifact', rid, path)
                            result['diagnostics'][-1]['message'] = f'Supply {clean(chart)} ({clean(version)}) under charts/, through a local chart mapping or from an approved artifact source.'
                            continue
                        local, child_source = location
                        item['provenance'][0].update(chart_hash(local))
                    except (ValueError, OSError, yaml.YAMLError) as exc:
                        issue('catalog_chart_unavailable', rid, path)
                        reason = str(exc) if isinstance(exc, ArtifactResolutionError) else 'Check the chart name, version and local mapping.'
                        result['diagnostics'][-1]['message'] = f'Could not acquire {clean(chart)} ({clean(version)}). {clean(reason)}'
                        continue
                    unsupported = [field for field in ('valuesFrom', 'postRenders') if entry.get(field)]
                    if unsupported:
                        issue('unsupported_catalog_override', rid, path)
                        result['diagnostics'][-1]['message'] = 'Discovery cannot apply the catalog ' + ', '.join(unsupported) + ' configuration.'
                        continue
                    postrenderers = entry.get('postRenderers')
                    if postrenderers and not isinstance(postrenderers, list):
                        issue('invalid_catalog_postrenderers', rid, path)
                        continue
                    inline = entry.get('values')
                    if inline is not None and not isinstance(inline, dict):
                        issue('invalid_catalog_inline_values', rid, path)
                        result['diagnostics'][-1]['message'] = 'Declare inline catalog values as a YAML mapping.'
                        continue
                    if inline:
                        try:
                            inline_path = stage_values(nid, inline)
                        except FileExistsError:
                            issue('catalog_values_path_conflict', rid, path)
                            continue
                        inline_origins[inline_path.relative_to(base).as_posix()] = path
                        arguments += ['-f', str(inline_path)]
                    arguments += overrides
                    release = name if re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,51}[a-z0-9])?', name) else 'discovery-' + nid
                    chart_path = (local / 'Chart.yaml').relative_to(base).as_posix()
                    if render('helm', ['template', release, str(local), *arguments], rid, chart_path, postrenderers, owner=nid):
                        item['state'] = 'rendered'
                    layers = [Path(p) for p in arguments[1::2]]
                    discover_chart_values(local, layers, child_source, rid, nid, (*ancestry, identity))
                finally:
                    if inline_path is not None:
                        inline_path.unlink()
                    diagnostic_component = previous

        top_directories = {Path(p).parts[0] for p in files}
        upload_root = base
        if not gitlab_archive and len(top_directories) == 1 and (base / next(iter(top_directories))).is_dir():
            # GitLab source archives wrap the checkout in a revision-named directory.
            upload_root = base / next(iter(top_directories))
        referenced_charts = set(mapping.values())
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
                if adapter.tool == 'kustomize' and (path not in kustomize_roots or Path(path).parent.as_posix() in flux_build_paths):
                    continue
                directory = (base / path).parent
                metadata = {}
                if adapter.tool == 'helm' and len(parsed.get(path, ())) == 1 and isinstance(parsed[path][0], dict):
                    metadata.update(chart_hash(directory))
                    for field in ('name', 'version'):
                        value = parsed[path][0].get(field)
                        if isinstance(value, str):
                            metadata['chart_' + field] = clean(value)
                rid = root(Path(path).parent.as_posix(), adapter.technology, **metadata)
                args = [*adapter.prefix, str(directory)]
                if adapter.tool == 'helm':
                    args[1] = metadata.get('chart_name') or directory.name
                    roots_by_id[rid]['state'] = 'unresolved'
                    missing_selection = False
                    for value_file in options.get('values_files', []):
                        try:
                            value_path = compose._inside(base, value_file)
                            if not value_path.is_file():
                                raise ValueError()
                            args += ['-f', str(value_path)]
                        except (ValueError, TypeError):
                            issue('values_file_unavailable', rid, path)
                            missing_selection = True
                    overrides = component_values(rid, Path(path).parent.name or 'Root chart', path, rid, ['chart defaults', 'ordered parent values selection'])
                    if overrides is None or missing_selection:
                        defaults = (Path(path).parent / 'values.yaml').as_posix()
                        applied_catalog_inputs.add(defaults)
                        if _legacy_match(defaults, parsed.get(defaults, [])):
                            product_directories.add(directory)
                        continue
                    args += overrides
                nodes_before_render = len(nodes_by_id)
                product = adapter.tool == 'helm' and discover_chart_values(directory, [Path(p) for p in args[4::2]], upload_root, rid, rid, ())
                rendered = render(adapter.tool, args, rid, path, owner=rid if product else None)
                if adapter.tool == 'helm':
                    if rendered:
                        roots_by_id[rid]['state'] = 'rendered'
                    if metadata and files == [path] and len(nodes_by_id) == nodes_before_render and not parsed[path][0].get('dependencies'):
                        roots_by_id[rid]['state'] = 'unresolved'
                        issue('chart_metadata_only', rid, path)
                        result['diagnostics'][-1]['message'] = 'Only Chart.yaml was supplied. Enter the GitLab repository URL, upload a chart package or source archive containing values.yaml and the templates, or upload the service-definition values.yaml on its own.'
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
                    check()
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
            if (path in applied_catalog_inputs or not _legacy_match(path, documents)
                    or any(directory in product_directories for directory in (base / path).parents)):
                continue
            rid = root(path, 'legacy')
            try:
                definition = legacy.parse_definition((base / path).read_bytes())
            except legacy.DefinitionError:
                issue('legacy_definition_unresolved', rid, path)
                continue
            discover_catalog(definition, documents[0], path, (base / path).parent, upload_root, rid, rid, ())
        for path, docs in parsed.items():
            if path in managed_paths:
                continue
            for doc in docs:
                if isinstance(doc, dict) and isinstance(doc.get('metadata'), dict):
                    meta = doc['metadata']
                    if all(isinstance(v, str) for v in (doc.get('kind'), meta.get('namespace', 'default'), meta.get('name'))):
                        index_resource(doc, path)
        queue = [(path, doc, False, None) for path, docs in parsed.items() for doc in docs if path not in managed_paths] + rendered_documents
        rendered_documents.clear()
        cursor = 0
        while cursor < len(queue):
            if cursor % 100 == 0:
                check()
            diagnostic_component = None
            if cursor > 2000:
                issue('render_graph_limit_exceeded')
                break
            path, doc, generated, ownership = queue[cursor]
            cursor += 1
            if not isinstance(doc, dict) or not doc.get('apiVersion') or not doc.get('kind'):
                continue
            flux = 'toolkit.fluxcd.io/' in str(doc.get('apiVersion', ''))
            catalog_scope = controller = None
            if ownership:
                # Rendering already recorded this controller under its originating root.
                rid, catalog_scope, controller = ownership
            else:
                rid = root(path, 'flux' if flux else 'kubernetes')
                manifests([doc], rid, path, 'rendered' if generated else 'declared')
            if not flux:
                continue
            spec = doc.get('spec', {})
            if doc.get('kind') == 'Kustomization' and isinstance(spec, dict):
                build_key = _id(catalog_scope, path, doc)
                if build_key in rendered_releases:
                    continue
                rendered_releases.add(build_key)
                meta = doc.get('metadata', {})
                namespace = meta.get('namespace') or 'default'
                resource_id = controller or definitions.get(('Kustomization', namespace, str(meta.get('name', ''))))
                try:
                    ref = spec.get('sourceRef', {})
                    source_key = (ref.get('kind'), ref.get('namespace', namespace), ref.get('name'))
                    reference(resource_id, source_key[0], source_key[2], source_key[1], rid, path, 'uses_source')
                    mapping_key = '/'.join(source_key)
                    if source_key in ambiguous_resources or source_key not in resources:
                        raise ValueError()
                    artifact = local_source(source_key)
                    local = compose._inside(artifact, spec.get('path', '.'))
                    build_file = next((local / name for name in ('kustomization.yaml', 'kustomization.yml', 'Kustomization')
                                       if (local / name).is_file()), None)
                    if build_file is None:
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
                    build_path = build_file.relative_to(base).as_posix() if ownership else path
                    render('kustomize', ['build', str(local)], rid, build_path, output_transform=substitute_output,
                           owner=controller, catalog_scope=catalog_scope)
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
            release_name = release_meta.get('name', '[unnamed]')
            release_id = controller or node(rid, 'HelmRelease', release_name, path, namespace=release_meta.get('namespace', ''))
            release_key = _id(catalog_scope, path, doc)
            if release_key in rendered_releases:
                continue
            rendered_releases.add(release_key)
            nodes_by_id[release_id]['state'] = 'unresolved'
            diagnostic_component = (release_id, str(release_name))
            evidence = nodes_by_id[release_id]['provenance'][0]
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
            if isinstance(chart_spec, dict):
                if isinstance(chart_spec.get('chart'), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', chart_spec['chart']):
                    evidence['chart'] = clean(chart_spec['chart'])
                if isinstance(chart_spec.get('version'), str):
                    evidence['version'] = clean(chart_spec['version'])
            if isinstance(source_ref, dict):
                reference(release_id, source_ref.get('kind', 'HelmRepository'), source_ref.get('name'), source_ref.get('namespace', chart_ref_key[1] if chart_ref_key else release_ns), rid, path, 'uses_source')
            release_diagnostic_start = len(result['diagnostics'])
            previous_id = _id('helm-release', path, release_ns, release_meta.get('name', '')) if not controller or catalog_scope == rid else None
            overrides = component_values(release_id, str(release_name), path, rid, ['chart defaults', 'ordered Flux valuesFrom', 'inline Flux values', 'Flux targetPath (highest Helm precedence)'], previous_id)
            if overrides is None:
                continue
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
                    source_spec = resources[chart_ref_key].get('spec', {})
                    record_reference(evidence, source_spec.get('url'))
                    package = local_source(chart_ref_key)
                    local = packaged_chart(package) if package in archive_hashes else _package_chart(package)
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
                        record_reference(evidence, chart_reference)
                        local = acquire_chart(('helm', chart_reference, chart_spec.get('version', '')))
                        resolved_helm_sources.add(source_key)
                    if not (local / 'Chart.yaml').is_file():
                        raise ValueError()
                if chart_ref_key:
                    resolved_helm_sources.add(chart_ref_key)
                chart_metadata = _documents((local / 'Chart.yaml').read_text(encoding='utf-8-sig'))
                if len(chart_metadata) != 1 or not isinstance(chart_metadata[0], dict):
                    raise ValueError()
                for field, attribute in [('name', 'chart'), ('version', 'version')]:
                    if isinstance(chart_metadata[0].get(field), (str, int, float)):
                        evidence[attribute] = clean(str(chart_metadata[0][field]))
                evidence.update(chart_hash(local))
                child_rid = root(local.relative_to(base).as_posix(), 'helm', **chart_hash(local))
                if any(d['root_id'] == rid and d['code'] in ('ambiguous_flux_values_reference', 'missing_flux_values_reference', 'secret_values_not_rendered', 'unsupported_flux_values_input', 'invalid_flux_inline_values', 'invalid_flux_values_reference') for d in result['diagnostics'][release_diagnostic_start:]):
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
                values_path = stage_values(release_id, values)
                release_name = spec.get('releaseName', doc.get('metadata', {}).get('name', 'discovery'))
                release_namespace = spec.get('targetNamespace', namespace)
                if not all(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', value) for value in (release_name, release_namespace)):
                    raise ValueError()
                def render_release(chart_directory):
                    chart_path = (local / 'Chart.yaml').relative_to(base).as_posix() if ownership else path
                    if render('helm', ['template', release_name, str(chart_directory), '--namespace', release_namespace, '--include-crds', '-f', str(values_path), *overrides, *targets],
                              rid, chart_path, spec.get('postRenderers'), owner=release_id, catalog_scope=catalog_scope):
                        nodes_by_id[release_id]['state'] = 'rendered'
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
                edge(release_id, child_rid, 'renders')
            except (ValueError, TypeError, OSError, AttributeError, compose.ComposeInputError) as exc:
                issue('flux_chart_source_unavailable', rid, path)
                if isinstance(exc, ArtifactResolutionError):
                    result['diagnostics'][-1]['message'] = clean(str(exc))
            if any(key in spec for key in ('kubeConfig',)):
                issue('flux_controller_semantics_not_evaluated', rid, path)
            queue.extend(rendered_documents)
            rendered_documents.clear()
        diagnostic_component = None
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
                    check()
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
            target = None
            if kind != 'Secret' and key not in ambiguous_definitions:
                target = owned_definitions.get((rid, key)) or definitions.get(key)
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
        if result['completeness'] == 'partial' and not result['images'] and all(
                n['kind'] == 'HelmDependency' and n['state'] == 'unresolved' for n in result['nodes']):
            result['completeness'] = 'invalid' if any(d['code'] == 'invalid_or_unsupported_document' for d in result['diagnostics']) else 'blocked'
        for item in result['nodes']:
            for field in ('name', 'namespace', 'kind'):
                item[field] = clean(item[field])
        for item in result['roots']:
            for field in ('chart_name', 'chart_version'):
                if field in item:
                    item[field] = clean(item[field])
        for item in result['diagnostics']:
            if 'component_name' in item:
                item['component_name'] = clean(item['component_name'])
                item['message'] = clean(item['message'])
        for item in result['configurable_components']:
            item['label'] = clean(item['label'])
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
                for field in ('chart', 'version', 'reference'):
                    if field in provenance:
                        provenance[field] = clean(provenance[field])
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
            and '/templates/' not in '/' + source_file
            and len(parsed.get(source_file, [])) == 1
            and isinstance(parsed[source_file][0], dict)
            and not any(key in parsed[source_file][0] for key in ('apiVersion', 'kind'))]

        result['metrics'] = dict(files=len(files), roots=len(result['roots']), nodes=len(result['nodes']), images=len(result['images']))
        if progress:
            progress(dict(stage='complete', **result['metrics']))
    return result
