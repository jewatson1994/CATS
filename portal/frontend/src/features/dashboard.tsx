import { useRef } from 'react';

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

export function Page({ data }: { data: any }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const lifecycle = data.lifecycle || 'active';
  const labels = lifecycleLabels[lifecycle] || lifecycleLabels.active;
  const views = data.views || [];
  const groups = data.stage_groups || [];
  const canStage = lifecycle === 'active' && groups.length > 0;
  return <>
    <section className="heading"><div><p className="eyebrow">PRODUCTION SERVICE CYBER HYGIENE</p><h1>{labels.title}</h1><p>{labels.description}</p></div><div className="heading-actions"><div className="stamp">As of {data.now_display}</div>{canStage && <button type="button" className="secondary-button" onClick={() => dialog.current?.showModal()}>Stage Service</button>}</div></section>
    <section className="metrics"><article><span>Services</span><strong>{views.length}</strong></article><article><span>Compliant</span><strong>{data.compliant_count}</strong></article><article><span>Non-compliant</span><strong className="danger">{data.noncompliant_count}</strong></article><article><span>Active POA&amp;Ms</span><strong>{data.poam_active_count}</strong><small>{data.poam_pending_count} pending · {data.poam_overdue_count} overdue</small></article></section>
    <section className="panel"><div className="panel-head"><div><h2>{labels.label} services</h2>{lifecycle === 'archived' && <p>Historical records do not affect active compliance totals.</p>}{lifecycle === 'staged' && <p>Staged records are excluded from the active service snapshot.</p>}</div><div className="panel-actions"><a className="secondary-button" href="/exports/services.xlsx">Export Excel</a>{['active', 'staged', 'archived'].map(value => <a className="secondary-button" href={`/?lifecycle=${value}`} key={value}>{value === 'active' ? 'Active' : `View ${lifecycleLabels[value].label}`} ({data.lifecycle_counts?.[value] || 0})</a>)}</div></div>
      <form className="snapshot-filter" method="get" action="/"><input type="hidden" name="lifecycle" value={lifecycle} /><label>Search<input name="q" defaultValue={data.query || ''} placeholder="Filter services…" aria-label="Filter services" /></label><label>Sort<select name="sort" defaultValue={data.sort || 'name'}>{[['name', 'Name'], ['version', 'Version'], ['owner', 'Owner'], ['findings', 'Active findings'], ['overdue', 'Overdue findings'], ['oldest', 'Oldest evidence']].map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label><label>Per page<select name="page_size" defaultValue={data.page_size || 25}>{[10, 25, 50, 100].map(value => <option value={value} key={value}>{value}</option>)}</select></label><button className="secondary-button">Apply</button></form>
      <Pagination data={data} position="top" />
      <div className="table-wrap"><table><thead><tr>{['Service', 'Version', 'Owner', 'Compliance', 'Evidence', 'Active Findings', 'Overdue Findings', 'Excepted', 'Oldest'].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead><tbody>{views.length ? views.map((view: any) => <tr data-row="" key={view.service.id || view.service.service_key}><td><a href={`/services/${encodeURIComponent(view.service.service_key)}?overview=true`}><strong>{view.service.name}</strong><small>{view.service.service_key}</small></a></td><td><strong>{view.version || 'Unknown'}</strong></td><td>{view.service.owner || 'Unassigned'}</td><td><span className={`status ${view.compliant ? 'ok' : 'bad'}`}>{view.compliant ? 'Compliant' : 'Non-Compliant'}</span></td><td>{view.evidence_state}</td><td>{view.active_count}</td><td>{view.noncompliant_count}</td><td>{view.excepted_count ?? view.exception_count}</td><td>{view.oldest_age != null ? `${view.oldest_age} days` : '—'}</td></tr>) : <tr><td colSpan={9} className="empty">No services match this lifecycle and filter.</td></tr>}</tbody></table></div>
      <Pagination data={data} position="bottom" />
    </section>
    {canStage && <dialog ref={dialog} id="stage-service-dialog" className="review-dialog" aria-labelledby="stage-service-title"><form method="post" action="/admin/services/stage"><input type="hidden" name="csrf_token" value={data.csrf_token || ''} /><input type="hidden" name="next_path" value={data.next_path || '/'} /><h3 id="stage-service-title">Stage Service</h3><p>Stage the service before its first pipeline submission.</p><label>Service ID<input name="service_id" required maxLength={120} placeholder="service-id" /></label>{groups.length === 1 ? <><input type="hidden" name="group_id" value={groups[0].id} /><p className="muted">Group: <strong>{groups[0].name}</strong></p></> : <label>Group<select name="group_id" required defaultValue=""><option value="">Select a group</option>{groups.map((group: any) => <option value={group.id} key={group.id}>{group.name}</option>)}</select></label>}<div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => dialog.current?.close()}>Cancel</button><button>Stage Service</button></div></form></dialog>}
  </>;
}
