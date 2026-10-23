import {useRef} from 'react';
import {LifecycleTabs, lifecycleLabels, ServiceSecurityMatrix} from '../components/ServiceSecurityMatrix';
import {useDashboard} from '../hooks/useDashboard';
import {ErrorState, MetricCard, MetricGrid, PageHeader} from '../components/ui';

export function Page({data: pageData}: {data: any}) {
  const {data, error, retry} = useDashboard(pageData);
  if (!data) return <><PageHeader title="Services"/>
    {error ? <section className="panel"><ErrorState title="Dashboard data could not be loaded" onRetry={retry} retryLabel="Retry dashboard">{error}</ErrorState></section>
      : <section aria-busy="true"><p className="sr-only" role="status">Loading dashboard data…</p>
        <div className="metric-grid skeleton-metrics" aria-hidden="true">{[0, 1, 2, 3].map(index => <div key={index} className="metric"><span className="skeleton-bar skeleton-short"/><span className="skeleton-bar skeleton-value"/></div>)}</div>
        <div className="panel skeleton-panel" aria-hidden="true">{Array.from({length: 8}, (_, index) => <span key={index} className="skeleton-bar"/>)}</div></section>}</>;
  return <Dashboard data={data}/>;
}

function Dashboard({data}: {data: any}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const lifecycle = data.lifecycle || 'active';
  const labels = lifecycleLabels[lifecycle] || lifecycleLabels.active;
  const groups = data.stage_groups || [];
  const canStage = lifecycle === 'active' && groups.length > 0;
  const preparing = Number(data.posture_preparing || 0);
  const pending = preparing > 0 && !data.rows?.length && !Number(data.total_count || 0);
  return <>
    <PageHeader eyebrow="Production service cyber hygiene" title={labels.title} description={labels.description}
      actions={<><span className="stamp">As of {data.now_display}</span><LifecycleTabs data={data}/>{canStage && <button type="button" className="secondary-button" onClick={() => dialog.current?.showModal()}>Stage Service</button>}</>}/>
    {preparing > 0 ? <p className="page-refresh-notice" role="status">Posture is still being prepared for {preparing} {preparing === 1 ? 'service' : 'services'}; {preparing === 1 ? 'it is' : 'they are'} not listed yet and totals exclude {preparing === 1 ? 'it' : 'them'}. Refresh shortly.</p>
      : data.posture_refreshing && <p className="page-refresh-notice" role="status">Service posture is being refreshed after a portfolio-wide change; some rows may briefly show their previous values.</p>}
    <MetricGrid label="Service summary" className="metric-grid-compact">
      <MetricCard label="Services" value={pending ? 'Pending' : data.total_count ?? 0}/>
      <MetricCard label="Compliant" value={pending ? 'Pending' : data.compliant_count} tone={data.compliant_count ? 'success' : undefined}/>
      <MetricCard label="Non-compliant" value={pending ? 'Pending' : data.noncompliant_count} tone={data.noncompliant_count ? 'danger' : undefined}/>
      <MetricCard label="Active POA&Ms" value={pending ? 'Pending' : data.poam_active_count} hint={pending ? undefined : `${data.poam_pending_count ?? 0} pending · ${data.poam_overdue_count ?? 0} overdue`} tone={data.poam_overdue_count ? 'warning' : undefined}/>
    </MetricGrid>
    <section className="panel cyber-matrix" aria-label="Service Security Matrix">
      <ServiceSecurityMatrix data={data}/>
    </section>
    {canStage && <dialog ref={dialog} id="stage-service-dialog" className="review-dialog" aria-labelledby="stage-service-title"><form method="post" action="/admin/services/stage"><input type="hidden" name="csrf_token" value={data.csrf_token || ''}/><input type="hidden" name="next_path" value={data.next_path || '/'}/><h3 id="stage-service-title">Stage Service</h3><p>Stage the service before its first pipeline submission.</p><label>Service ID<input name="service_id" required maxLength={120} placeholder="service-id"/></label>{groups.length === 1 ? <><input type="hidden" name="group_id" value={groups[0].id}/><p className="muted">Group: <strong>{groups[0].name}</strong></p></> : <label>Group<select name="group_id" required defaultValue=""><option value="">Select a group</option>{groups.map((group: any) => <option value={group.id} key={group.id}>{group.name}</option>)}</select></label>}<div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => dialog.current?.close()}>Cancel</button><button>Stage Service</button></div></form></dialog>}
  </>;
}
