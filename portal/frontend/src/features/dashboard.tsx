import { useRef } from 'react';
import {ServiceSecurityMatrix} from '../components/ServiceSecurityMatrix';
import {useDashboard} from '../hooks/useDashboard';
import {ErrorState, Loading, MetricCard, MetricGrid, PageHeader} from '../components/ui';

const lifecycleLabels: Record<string, { title: string; label: string; description: string }> = {
  active: { title: 'Service Snapshot', label: 'Active', description: 'Fixable CVE exposure tracked continuously across container images.' },
  staged: { title: 'Staged services', label: 'Staged', description: 'Services prepared for their first pipeline submission.' },
  archived: { title: 'Archived services', label: 'Archived', description: 'Retired services preserved with their historical evidence.' },
};

function Pagination({ data, position }: { data: any; position: string }) {
  if (data.total_pages <= 1) return null;
  const page = Number(data.page || 1);
  const pageSize = Number(data.page_size || 25);
  const total = Number(data.total_count || 0);
  const pageHref = (value: number) => `${data.pagination_base}${String(data.pagination_base).includes('?') ? '&' : '?'}page=${value}`;
  return <nav className={`pagination pagination-${position}`} aria-label="Service pages"><span>Showing {total ? (page - 1) * pageSize + 1 : 0}–{Math.min(page * pageSize, total)} of {total} <span className="pagination-page" aria-current="page">· Page {page} of {data.total_pages}</span></span><span className="pagination-controls">{page > 1 ? <a className="secondary-button" href={pageHref(page - 1)}>Previous</a> : <button className="secondary-button" type="button" disabled>Previous</button>}{page < data.total_pages ? <a className="secondary-button" href={pageHref(page + 1)}>Next</a> : <button className="secondary-button" type="button" disabled>Next</button>}</span></nav>;
}

export function Page({data: pageData}: {data: any}) {
  const {data, error, retry} = useDashboard(pageData);
  if (!data) return <><PageHeader title="Services"/><section className="panel" aria-busy={!error}>{error ? <ErrorState title="Dashboard data could not be loaded" onRetry={retry} retryLabel="Retry dashboard">{error}</ErrorState> : <Loading label="Loading dashboard data…"/>}</section></>;
  return <Dashboard data={data}/>;
}

function Dashboard({ data }: { data: any }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const lifecycle = data.lifecycle || 'active';
  const labels = lifecycleLabels[lifecycle] || lifecycleLabels.active;
  const groups = data.stage_groups || [];
  const canStage = lifecycle === 'active' && groups.length > 0;
  return <>
    <PageHeader eyebrow="Production service cyber hygiene" title={labels.title} description={labels.description} actions={<><span className="stamp">As of {data.now_display}</span>{canStage && <button type="button" className="secondary-button" onClick={() => dialog.current?.showModal()}>Stage Service</button>}</>}/>
    {data.posture_preparing > 0 ? <p className="page-refresh-notice" role="status">Posture is still being prepared for {data.posture_preparing} {data.posture_preparing === 1 ? 'service' : 'services'}; {data.posture_preparing === 1 ? 'it is' : 'they are'} not listed yet and totals exclude {data.posture_preparing === 1 ? 'it' : 'them'}. Refresh shortly.</p>
      : data.posture_refreshing && <p className="page-refresh-notice" role="status">Service posture is being refreshed after a portfolio-wide change; some rows may briefly show their previous values.</p>}
    <MetricGrid label="Service summary"><MetricCard label="Services" value={data.total_count ?? 0}/><MetricCard label="Compliant" value={data.compliant_count} tone={data.compliant_count ? 'success' : undefined}/><MetricCard label="Non-compliant" value={data.noncompliant_count} tone={data.noncompliant_count ? 'danger' : undefined}/><MetricCard label="Active POA&Ms" value={data.poam_active_count} hint={`${data.poam_pending_count ?? 0} pending · ${data.poam_overdue_count ?? 0} overdue`} tone={data.poam_overdue_count ? 'warning' : undefined}/></MetricGrid>
    <section className="panel cyber-matrix"><div className="panel-head"><div><h2>Service Security Matrix</h2><p>Per-service evidence, risk and workflow counts.</p>{lifecycle === 'archived' && <p>Historical records do not affect active compliance totals.</p>}{lifecycle === 'staged' && <p>Staged records are excluded from the active service snapshot.</p>}</div><div className="panel-actions"><nav className="request-tabs lifecycle-tabs" aria-label="Service lifecycle">{['active', 'staged', 'archived'].map(value => <a href={`/?lifecycle=${value}`} key={value} className={value === lifecycle ? 'selected' : ''} aria-current={value === lifecycle ? 'page' : undefined}>{lifecycleLabels[value].label} <span className="tab-count">{data.lifecycle_counts?.[value] || 0}</span></a>)}</nav><a className="secondary-button" href="/exports/services.xlsx">Export Excel</a></div></div>
      <Pagination data={data} position="top" />
      <ServiceSecurityMatrix data={data}/>
      <Pagination data={data} position="bottom" />
    </section>
    {canStage && <dialog ref={dialog} id="stage-service-dialog" className="review-dialog" aria-labelledby="stage-service-title"><form method="post" action="/admin/services/stage"><input type="hidden" name="csrf_token" value={data.csrf_token || ''} /><input type="hidden" name="next_path" value={data.next_path || '/'} /><h3 id="stage-service-title">Stage Service</h3><p>Stage the service before its first pipeline submission.</p><label>Service ID<input name="service_id" required maxLength={120} placeholder="service-id" /></label>{groups.length === 1 ? <><input type="hidden" name="group_id" value={groups[0].id} /><p className="muted">Group: <strong>{groups[0].name}</strong></p></> : <label>Group<select name="group_id" required defaultValue=""><option value="">Select a group</option>{groups.map((group: any) => <option value={group.id} key={group.id}>{group.name}</option>)}</select></label>}<div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => dialog.current?.close()}>Cancel</button><button>Stage Service</button></div></form></dialog>}
  </>;
}
