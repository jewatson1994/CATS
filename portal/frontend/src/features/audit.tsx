import {can, type PageData} from '../api';
import {DataGrid, type GridColumn} from '../components/DataGrid';
import {EmptyState} from '../components/ui';

const auditColumns: GridColumn<any>[] = [
  // Display-formatted timestamps: the server order (newest first) is authoritative, so Time is not re-sorted here.
  {key: 'time', header: 'Time', render: event => event.created_at},
  {key: 'actor', header: 'Actor', value: event => event.actor, render: event => event.actor},
  {key: 'action', header: 'Action', hideable: false, value: event => event.action, render: event => <code>{event.action}</code>},
  {key: 'target', header: 'Target', value: event => `${event.target_type} ${event.target_id}`, render: event => `${event.target_type} ${event.target_id}`},
  {key: 'details', header: 'Details', wrap: true, minWidth: 260, maxWidth: 900, render: event => <code className="audit-detail">{JSON.stringify(event.detail)}</code>},
];
import {AdminTabs, Heading, Hidden, Post, Saved} from './admin_shared';
export function Page({data}: {data: PageData}) {
  const group = data.selected_group_id, suffix = group ? `?group_id=${group}` : '';
  return <><Heading title="Audit Policy" description="Configure audit retention and review the latest portal activity."/><AdminTabs data={data} selected="audit"/><section className="panel padded configuration-panel"><Saved data={data} message="Audit policy saved successfully."/>{data.groups?.length > 0 && <div className="group-scope-bar"><label>Group Scope<select defaultValue={group} onChange={event => window.location.assign(`/admin/audit?group_id=${encodeURIComponent(event.target.value)}`)}>{data.groups.map((row: any) => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label><span>Editing: <strong>{data.groups.find((row: any) => row.id === group)?.name}</strong></span></div>}{can(data, 'config.manage') && <Post data={data} action={`/admin/audit-policy${suffix}`}><Hidden name="group_id" value={group}/><div className="config-grid"><label>Audit retention (days)<input type="number" name="audit_retention_days" min={0} max={3650} defaultValue={data.configuration.audit_retention_days}/><small>0 keeps all events. Otherwise events older than this are outside the retained view.</small></label><label>Application logging<select name="log_level" defaultValue={data.configuration.log_level}>{['DEBUG', 'INFO', 'WARNING', 'ERROR'].map(value => <option key={value}>{value}</option>)}</select><small>Controls portal operational log verbosity.</small></label><label>Tool integration<select name="audit_tool_integration"><option value="planned">Not configured (planned)</option></select><small>Mattermost and email integrations can be added here later.</small></label></div><div className="config-actions"><button>Save audit policy</button><span>Changes are recorded in the audit log.</span></div></Post>}</section><section className="panel audit-logs"><div className="panel-heading"><div><h2>Logs</h2><p>Showing {data.shown_count} of {data.retained_count} retained events. Page {data.page} of {data.page_count}.</p></div>{data.page < data.page_count && <a className="secondary-button" href={`${data.pagination_base}&page=${data.page + 1}`}>Show older events</a>}</div><DataGrid<any> id="audit-events" label="Audit events" columns={auditColumns} rows={data.events || []} rowKey={(event: any, index: number) => event.id || index}
        // Events are paged newest-first by the server; sort only when a single page holds them all.
        sort={Number(data.page_count || 1) <= 1 ? {mode: 'client'} : {mode: 'none'}} empty={<EmptyState title="No audit events."/>}/>{data.page > 1 && <div className="log-actions"><a className="secondary-button" href={`${data.pagination_base}&page=${data.page - 1}`}>Newer events</a></div>}</section></>;
}
