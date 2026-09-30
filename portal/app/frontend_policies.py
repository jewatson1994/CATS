"""Safe, explicit policy administration projections (no authentication settings)."""
from .frontend_exchange import fields, value, scalar, permit

CONFIG_FIELDS = ('audit_retention_days', 'log_level', 'skipped_images_incomplete', 'incomplete_noncompliant', 'warning_days', 'exception_max_days', 'hardening_overdue_days', 'hardening_noncompliant', 'compliance_mode', 'overdue_days', 'minimum_severity', 'kev_enabled', 'kev_noncompliant', 'epss_enabled')


# Names used by record_audit calls. Unknown fields and nested objects never cross
# this boundary; adding a new audit payload requires an explicit review here.
AUDIT_FIELDS = ('actor_username', 'service_id', 'service_key', 'group_id', 'parent_id', 'name', 'previous_name', 'username', 'display_name', 'user_id', 'role_id', 'scope', 'scope_id', 'enabled', 'reason', 'review_reason', 'image', 'replacement', 'template', 'enabled_fields', 'mode', 'purl', 'ecosystem', 'version_constraint', 'count', 'format', 'provider', 'issuer', 'claim_path', 'expected_value', 'endpoint', 'client_certificate_changed', 'client_key_changed', 'ca_changed', 'success', 'source', 'version', 'registry_id', 'registry_action', 'status', 'key_fingerprint', 'removed', 'os_id', 'verify_tls', 'verify_packages')


def safe_detail(item):
    result = fields(item, AUDIT_FIELDS)
    for key in ('changed', 'permissions', 'conditions'):
        values = item.get(key)
        if isinstance(values, list):
            result[key] = [entry for entry in values if isinstance(entry, str)]
    return result


def policies_data(context, formatter=None):
    data = fields(context, ('saved', 'selected_group_id', 'shown_count', 'retained_count'))
    data['configuration'] = fields(context.get('configuration', {}), CONFIG_FIELDS)
    data['groups'] = [fields(group, ('id', 'name')) for group in context.get('groups', [])]
    data['selected_group'] = fields(context['selected_group'], ('id', 'parent_id')) if context.get('selected_group') else None
    data['may_manage'] = permit(context, 'config.manage')
    data['may_audit'] = permit(context, 'audit.view')
    data['may_manage_users'] = permit(context, 'user.manage')
    data['export_templates'] = [fields(item, ('kind', 'name', 'mode', 'source', 'enabled_count')) for item in context.get('export_templates', [])]
    data['raw_due_rules'] = [fields(rule, ('severity', 'days')) for rule in context.get('raw_due_rules', [])]
    data['epss_rules'] = [fields(rule, ('severity', 'threshold', 'noncompliant')) for rule in context.get('epss_rules', [])]
    data['entries'] = [fields(entry, ('id', 'purl', 'ecosystem', 'name', 'version_constraint', 'enabled')) for entry in context.get('entries', [])]
    data['events'] = []
    if data['may_audit']:
        for event in context.get('events', []):
            row = fields(event, ('action', 'target_type', 'target_id'))
            created = value(event, 'created_at')
            row['created_at'] = str(formatter(created)) if callable(formatter) else created.isoformat() if hasattr(created, 'isoformat') else scalar(created)
            detail = value(event, 'detail') or {}
            row['actor'] = value(value(event, 'actor'), 'username') or detail.get('actor_username') or 'system'
            row['detail'] = safe_detail(detail)
            data['events'].append(row)
    return data
