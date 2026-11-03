"""Bounded declarative catalog parsing; no fetching or mutation of source documents.

``parse_definition(text, adapter='auto')`` returns JSON-safe adapter metadata,
components and counts. Each component has a logical_name, source_type,
repository, reference, chart_name, version, status and reason. Only normalized
components are acquisition-ready. Register additional trusted Adapter instances
with register_adapter; field paths are tuples, never executable expressions.
"""
from dataclasses import dataclass
import os
import re
from urllib.parse import urlsplit

import yaml

from .helm_sources import normalize_chart_reference


class DefinitionError(ValueError):
    """Safe public diagnostic which never includes source values."""


def _limit(suffix, default):
    try:
        value = int(os.getenv('CATS_SERVICE_DEFINITION_MAX_' + suffix, default))
        if value <= 0:
            raise ValueError()
        return value
    except ValueError:
        raise DefinitionError('Invalid service definition resource limit') from None


def _limits():
    return {k: _limit(k, v) for k, v in {
        'BYTES': 10 * 1024 * 1024, 'NODES': 200000, 'DEPTH': 64,
        'STRING_BYTES': 1024 * 1024, 'COMPONENTS': 1000,
    }.items()}


def _load(text, limits):
    if not isinstance(text, (str, bytes)):
        raise DefinitionError('Definition must be UTF-8 text')
    if len(text if isinstance(text, bytes) else text.encode('utf-8')) > limits['BYTES']:
        raise DefinitionError('Definition exceeds byte limit')

    class Loader(yaml.SafeLoader):
        depth = 0
        nodes = 0

        def compose_node(self, parent, index):
            self.depth += 1
            self.nodes += 1
            try:
                if self.depth > limits['DEPTH'] or self.nodes > limits['NODES']:
                    raise DefinitionError('Definition exceeds structural limits')
                node = super().compose_node(parent, index)
                if isinstance(node, yaml.ScalarNode) and len(node.value.encode('utf-8')) > limits['STRING_BYTES']:
                    raise DefinitionError('Definition exceeds string limit')
                return node
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                if key_node.tag != 'tag:yaml.org,2002:str':
                    raise DefinitionError('Mapping keys must be strings; merge keys are not supported')
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise DefinitionError('Duplicate mapping key')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        return yaml.load(text, Loader=Loader)
    except DefinitionError:
        raise
    except (yaml.YAMLError, UnicodeError, ValueError, RecursionError):
        raise DefinitionError('Invalid or unsupported YAML definition') from None


def _check_structure(document, limits, check_strings):
    # Check the combined catalog after layering and count every alias use.
    count = 0
    checked_strings = set()
    string_bytes = 0

    def check_string(value):
        nonlocal string_bytes
        if not check_strings or id(value) in checked_strings:
            return
        if len(value) > limits['STRING_BYTES']:
            raise DefinitionError('Definition exceeds string limit')
        size = len(value.encode('utf-8'))
        if size > limits['STRING_BYTES']:
            raise DefinitionError('Definition exceeds string limit')
        string_bytes += size
        if string_bytes > limits['BYTES']:
            raise DefinitionError('Definition exceeds byte limit')
        checked_strings.add(id(value))

    def visit(value, ancestors, depth):
        nonlocal count
        count += 1
        if count > limits['NODES'] or depth > limits['DEPTH']:
            raise DefinitionError('Definition exceeds structural limits')
        if isinstance(value, str):
            check_string(value)
        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in ancestors:
                raise DefinitionError('Cyclic YAML aliases are not supported')
            ancestors.add(identity)
            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        raise DefinitionError('Mapping keys must be strings')
                    check_string(key)
                    visit(child, ancestors, depth + 1)
            else:
                for child in value:
                    visit(child, ancestors, depth + 1)
            ancestors.remove(identity)

    try:
        visit(document, set(), 1)
    except (UnicodeError, RecursionError):
        raise DefinitionError('Invalid or unsupported YAML definition') from None


@dataclass(frozen=True)
class SourceMapping:
    source_type: str
    repository: tuple[str, ...]
    chart_name: tuple[str, ...]
    version: tuple[str, ...]
    fallback_chart_name: tuple[str, ...] = ()
    sibling_chart_name: tuple[str, ...] = ()
    sibling_version: tuple[str, ...] = ()
    alternate_repository: tuple[str, ...] = ()
    alternate_chart_name: tuple[str, ...] = ()


@dataclass(frozen=True)
class Adapter:
    name: str
    label: str
    collection: tuple[str, ...]
    source_type: tuple[str, ...]
    sources: tuple[SourceMapping, ...]


ADAPTERS = {}


def register_adapter(adapter: Adapter):
    if adapter.name in ADAPTERS:
        raise ValueError('Adapter already registered')
    ADAPTERS[adapter.name] = adapter


register_adapter(Adapter('singularity', 'Singularity', ('services',), ('sourceType',), (
    SourceMapping('helm', ('helmRepo', 'url'), ('helmRepo', 'chartName'),
                  ('helmRepo', 'version'), ('helmRepo', 'repoName'),
                  alternate_repository=('helmRepo', 'repoUrl'), alternate_chart_name=('helmRepo', 'chart')),
    SourceMapping('oci', ('ociRepo', 'url'), ('ociRepo', 'repoName'), ('ociRepo', 'tag'),
                  sibling_chart_name=('repoName',), sibling_version=('tag',)),
)))


def _field(value, path):
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _first_field(entry, *paths):
    for path in paths:
        if path:
            value = _field(entry, path)
            if value is not None:
                return value


def _matches(document, adapter):
    collection = _field(document, adapter.collection)
    return isinstance(collection, dict) and any(
        _field(entry, adapter.source_type) == source.source_type
        for entry in collection.values() for source in adapter.sources
    )


def _component(name, entry, adapter):
    output = dict(logical_name=name, source_type='unknown', repository=None,
                  reference=None, chart_name=None, version=None,
                  status='unresolved', reason='Component must be a mapping')
    if not isinstance(entry, dict):
        return output
    source_type = _field(entry, adapter.source_type)
    source = next((item for item in adapter.sources if item.source_type == source_type), None)
    if source is None:
        output.update(status='unsupported' if source_type is not None else 'unresolved',
                      reason='Unsupported source type' if source_type is not None else 'Source type is missing')
        return output
    output['source_type'] = source.source_type
    repository = _first_field(entry, source.repository, source.alternate_repository)
    chart = _first_field(entry, source.chart_name, source.alternate_chart_name, source.fallback_chart_name)
    version = _field(entry, source.version)
    chart_from_sibling = chart is None and bool(source.sibling_chart_name)
    if chart_from_sibling:
        chart = _field(entry, source.sibling_chart_name)
    if version is None and source.sibling_version:
        version = _field(entry, source.sibling_version)
    for label, value in (('Repository URL', repository), ('Chart name', chart), ('Exact version or tag', version)):
        if not isinstance(value, str) or not value.strip():
            output['reason'] = f'{label} must be a non-empty string'
            return output
    repository, chart, version = (value.strip() for value in (repository, chart, version))
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,239}', chart):
        output['reason'] = 'Invalid chart name'
        return output
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]{0,119}', version):
        output['reason'] = 'A valid chart version or tag is required'
        return output
    try:
        parsed = urlsplit(repository)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError()
        normalized = normalize_chart_reference(repository)
        if source.source_type == 'helm':
            if not normalized.startswith(('http://', 'https://')):
                raise ValueError()
            reference = normalized
        else:
            if not normalized.startswith('oci://'):
                raise ValueError()
            tail = normalized.rsplit('/', 1)[-1]
            if ':' in tail:
                normalized, embedded = normalized.rsplit(':', 1)
                if embedded != version:
                    raise ValueError()
            if chart_from_sibling and normalized.rsplit('/', 1)[-1] != chart:
                normalized = normalize_chart_reference(normalized + '/' + chart)
            # OCI URLs identify the chart; nested repoName may be a release
            # alias (e.g. confluence-postgresql). Sibling fields above retain
            # the existing repository-base + chart-name shorthand.
            chart = urlsplit(normalized).path.rstrip('/').rsplit('/', 1)[-1]
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,239}', chart):
                raise ValueError()
            reference = normalize_chart_reference(normalized + ':' + version)
    except ValueError:
        output['reason'] = 'Invalid repository reference or conflicting version; credentials are not allowed'
        return output
    if len(reference) > 240:
        output['reason'] = 'Repository reference exceeds retained artifact limit'
        return output
    output.update(repository=normalized, reference=reference, chart_name=chart,
                  version=version, status='normalized', reason=None)
    return output


def parse_definition(text, adapter='auto'):
    """Parse every declared entry; deployment configuration never affects scope."""
    limits = _limits()
    return _parse_document(_load(text, limits), adapter, limits, check_strings=False)


def parse_definition_mapping(document, adapter='auto'):
    """Normalize a catalog already decoded by a size-bounded, safe YAML loader."""
    return _parse_document(document, adapter, _limits(), check_strings=True)


def _parse_document(document, adapter, limits, *, check_strings):
    _check_structure(document, limits, check_strings)
    if adapter == 'auto':
        matches = [item for item in ADAPTERS.values() if _matches(document, item)]
        if len(matches) != 1:
            raise DefinitionError('Select a service definition adapter explicitly')
        selected = matches[0]
    else:
        selected = ADAPTERS.get(adapter)
        if selected is None:
            raise DefinitionError('Unknown service definition adapter')
    collection = _field(document, selected.collection)
    if not isinstance(collection, dict):
        raise DefinitionError('Service definition component collection must be a mapping')
    if len(collection) > limits['COMPONENTS']:
        raise DefinitionError('Definition exceeds component limit')
    if any(not isinstance(name, str) or not name.strip() or len(name) > 240 for name in collection):
        raise DefinitionError('Component names must be non-empty text of at most 240 characters')
    components = [_component(name, entry, selected) for name, entry in collection.items()]
    return dict(adapter=selected.name, adapter_label=selected.label, components=components,
                counts=dict(declared=len(components), **{
                    status: sum(item['status'] == status for item in components)
                    for status in ('normalized', 'unsupported', 'unresolved')}))
