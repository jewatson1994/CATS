"""Explicit projections for definitions, spreadsheet exchange and template editors."""
from collections.abc import Mapping
from .exchange import META, FIELDS


def value(source, key, default=None):
    return source.get(key, default) if isinstance(source, Mapping) else getattr(source, key, default)


def scalar(item):
    return item if item is None or isinstance(item, (str, int, float, bool)) else None


def fields(source, keys):
    return {key: scalar(value(source, key)) for key in keys if value(source, key) is not None}


def scalars(source, allowed=None):
    return {str(key): scalar(item) for key, item in (source or {}).items() if allowed is None or key in allowed}


def permit(context, permission, service_id=None):
    can = context.get('can')
    return bool(can(permission, service_id)) if callable(can) and service_id is not None else bool(can(permission)) if callable(can) else False


def component(source):
    result = fields(source, ('logical_name', 'source_type', 'repository', 'chart_name', 'version', 'resolved_version', 'chart_app_version', 'status', 'reason', 'scan_job_id'))
    if source.get('acquisition_diagnostic'):
        result['acquisition_diagnostic'] = fields(source['acquisition_diagnostic'], ('acquisition_stage', 'failure_category', 'attempted_reference', 'helm_exit_code', 'safe_stderr_summary', 'safe_stdout_summary'))
    return result


def definition_state(source):
    result = fields(source, ('adapter', 'adapter_label'))
    result['counts'] = fields(source.get('counts', {}), ('declared', 'normalized', 'unsupported', 'unresolved'))
    result['components'] = [component(row) for row in source.get('components', [])]
    result['run_history'] = [{'run_id': scalar(row.get('run_id')), 'components': [component(item) for item in row.get('components', [])]} for row in source.get('run_history', [])]
    return result


def service_definitions_data(context):
    service = context.get('service')
    data = {'service': fields(service, ('id', 'name', 'service_key')), 'may_edit': permit(context, 'service.edit', value(service, 'id')), 'definitions': []}
    for item in context.get('definitions', []):
        row = fields(item, ('id', 'source_reference'))
        row['revision_count'] = len(value(item, 'revisions', []))
        row['source_metadata'] = definition_state(value(item, 'source_metadata', {}) or {})
        data['definitions'].append(row)
    if 'preview' in context:
        data.update(fields(context, ('preview_token', 'preview_filename')))
        data['preview'] = definition_state(context['preview'])
    return data


def template(source):
    data = fields(source, ('name', 'description', 'dataset', 'enabled', 'block_missing'))
    data['layout'] = fields(source.get('layout', {}), ('sheet', 'banner', 'header_color', 'row_height'))
    for section in ('metadata', 'columns'):
        data[section] = [fields(row, ('field', 'label', 'direction', 'default', 'required', 'width')) for row in source.get(section, [])]
    return data


def exchange_data(context):
    if 'bundle_mode' in context:
        data = {'bundle_mode': True, **fields(context, ('token', 'target_key', 'import_mode'))}
        if 'bundle_manifest' in context:
            source = context['bundle_manifest']
            manifest = fields(source, ('format', 'schema_version', 'semantics', 'assessment', 'exported_at', 'exported_by', 'service_key', 'service_name', 'current_version', 'warning'))
            for key in ('versions', 'included', 'excluded', 'redactions'):
                if key in source:
                    manifest[key] = [scalar(v) for v in source[key]]
            if 'compatibility' in source:
                manifest['compatibility'] = fields(source['compatibility'], ('relational_schema', 'application'))
            if 'counts' in source:
                manifest['counts'] = {str(k): v for k, v in source['counts'].items() if isinstance(v, int)}
            manifest['files'] = {key: fields(source.get('files', {}).get(key), ('bytes', 'sha256')) for key in ('service.json', 'evidence.json') if key in source.get('files', {})}
            data['bundle_manifest'] = manifest
        if context.get('history_counts'):
            data['history_counts'] = fields(context['history_counts'], ('new', 'duplicates'))
        return data
    if 'template_catalog' in context:
        return {'template_catalog': {str(key): template(item) for key, item in context['template_catalog'].items()}, 'field_catalog': {'metadata': dict(META), 'datasets': {key: dict(item) for key, item in FIELDS.items()}}, 'may_manage_templates': permit(context, 'template.manage')}
    service = context.get('service')
    data = {'service': fields(service, ('id', 'name', 'service_key')), **fields(context, ('version', 'selected_template', 'token', 'import_error', 'row_count'))}
    if 'preview' in context:
        source = context['preview']
        preview = fields(source, ('recognized', 'worksheet', 'header_row', 'new'))
        for key in ('mapped', 'ignored', 'errors', 'conflicts'):
            preview[key] = [scalar(v) for v in source.get(key, [])]
        allowed = set(META).union(*(set(dataset) for dataset in FIELDS.values()))
        preview['rows'] = [{'key': scalar(row.get('key')), 'values': scalars(row.get('values'), allowed)} for row in source.get('rows', [])]
        data['preview'] = preview
        return data
    definition = context.get('definition', {})
    data['definition'] = template(definition)
    data['catalog'] = {str(key): fields(item, ('name', 'enabled')) for key, item in context.get('catalog', {}).items()}
    data['versions'] = [scalar(v) for v in context.get('versions', [])]
    data['missing'] = [scalar(v) for v in context.get('missing', [])]
    data['metadata_groups'] = {group: [fields(item, ('key', 'label')) for item in items] for group, items in context.get('metadata_groups', {}).items()}
    data['metadata'] = scalars(context['metadata'], META) if context.get('metadata') is not None else None
    data['export_preview'] = [{**fields(item, ('label', 'field', 'section')), 'counts': fields(item.get('counts', {}), ('Automatic', 'Configured', 'Default', 'Missing required', 'Missing optional'))} for item in context.get('export_preview', [])]
    sid = value(service, 'id')
    for key, permission in {'may_import': str(definition.get('dataset'))+'.import', 'may_export': str(definition.get('dataset'))+'.export', 'may_edit_metadata': 'metadata.edit', 'may_import_bundle': 'bundle.import'}.items():
        data[key] = permit(context, permission, sid)
    data['may_view_templates'] = permit(context, 'template.view')
    return data


def purpose_export_template_data(context):
    data = fields(context, ('kind', 'name', 'source', 'mode', 'group_id', 'saved'))
    data['columns'] = [fields(row, ('field', 'heading', 'enabled')) for row in context.get('columns', [])]
    keys = {row['field'] for row in data['columns']}
    data['labels'] = scalars(context.get('labels'), keys)
    data['defaults'] = scalars(context.get('defaults'), keys)
    return data
