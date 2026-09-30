"""Public result projections deliberately exclude worker credentials and paths."""
from collections.abc import Mapping


def fields(source, names):
    source = source if isinstance(source, Mapping) else {}
    return {key: source[key] for key in names if key in source and (source[key] is None or isinstance(source[key], (str, int, float, bool)))}


def rows(source, names):
    return [fields(row, names) for row in (source or []) if isinstance(row, Mapping)]


def public_results_data(context):
    data = fields(context, ('vulnerability_count', 'configuration_count'))
    data['job'] = fields(context.get('job'), ('job_id', 'status', 'started_at', 'finished_at'))
    data['service'] = fields(context.get('service'), ('name',))
    data['missing_evidence'] = bool(context.get('skipped_images') or context.get('skipped_charts'))
    data['rows'] = rows(context.get('rows'), ('type', 'finding', 'title', 'scanner', 'severity', 'state', 'image', 'target', 'kev', 'epss', 'details', 'remediation'))
    data['simplified_rows'] = []
    for row in context.get('simplified_rows', []):
        item = fields(row, ('type', 'count', 'severity', 'image', 'remediation'))
        item['finding_ids'] = [v for v in row.get('finding_ids', []) if isinstance(v, str)]
        item['finding_indices'] = [v for v in row.get('finding_indices', []) if isinstance(v, int)]
        data['simplified_rows'].append(item)
    overview = context.get('overview_data') or {}
    data['overview_data'] = fields(overview, ('source', 'description'))
    for key, names in {'missing_evidence': ('type', 'item', 'reason', 'source_file'), 'ports': ('port', 'protocol', 'service', 'declared_by', 'provenance'), 'accounts': ('name', 'scope', 'relationships'), 'artifacts': ('type', 'registry', 'repository', 'artifact', 'version', 'discovered_from', 'digest')}.items():
        data['overview_data'][key] = rows(overview.get(key), names)
    data['overview_data']['warnings'] = []
    for warning in overview.get('warnings', []):
        item = fields(warning, ('message', 'chart', 'source', 'original_error'))
        item['unrecognized_images'] = [v for v in warning.get('unrecognized_images', []) if isinstance(v, str)]
        data['overview_data']['warnings'].append(item)
    return data


def patch_results_data(context):
    data = {'job': fields(context.get('job'), ('job_id', 'status', 'started_at', 'finished_at', 'source_image'))}
    result = context.get('result') or {}
    data['result'] = fields(result, ('status', 'source_image', 'patched_image', 'reason', 'delivery_status', 'delivery_error', 'signature_status', 'immutable_destination', 'vulnerabilities_before', 'vulnerabilities_after', 'vulnerabilities_removed', 'vulnerabilities_unresolved', 'vulnerabilities_remaining', 'patch_status', 'output_mode', 'artifact_available', 'destination_image'))
    if result.get('signature'):
        data['result']['signature'] = fields(result['signature'], ('key_fingerprint', 'verified_at', 'generator', 'generator_version'))
    data['result']['vulnerability_results'] = []
    for row in result.get('vulnerability_results') or []:
        item = fields(row, ('id', 'severity', 'package', 'before_version', 'after_version', 'result'))
        item['fixed_versions'] = [v for v in row.get('fixed_versions', []) if isinstance(v, str)]
        data['result']['vulnerability_results'].append(item)
    return data
