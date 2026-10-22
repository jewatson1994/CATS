import {VexEvidence} from './native_vex';
import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { can, requestJson, type PageData } from '../api';
import { ServiceHeader, ServiceTabs } from '../components/ServiceHeader';
const Remediate = lazy(() => import('./remediations').then(module => ({default:module.Remediate})));
import { EmptyState, ErrorState, Loading, SeverityBadge, StatusBadge } from '../components/ui';
import { DataGrid, type GridColumn } from '../components/DataGrid';
import { Pager } from '../components/Pager';

type Action = { kind: 'exception' | 'poam' | 'mitigation' | 'evidence' | 'detail'; item: any; policy?: boolean };
const states: Record<string, string> = { active: 'Active Fixable Findings', noncompliant: 'Active Non-Compliance', overdue: 'Active Non-Compliance', exceptions: 'Active Exceptions', resolved: 'Resolved Findings', warnings: 'Warnings', vex_excluded: 'VEX Excluded' };

function Images({ images = [] }: { images?: string[] }) {
  return images.length ? <>{images.map(image => <code className="image-ref" title={image} key={image}>{image}</code>)}</> : <>—</>;
}

function Pagination({ data }: { data: PageData }) {
  const page = Number(data.page || 1), size = Number(data.page_size || 50), total = Number(data.total_items || 0), pages = Number(data.total_pages || 1);
  const link = (value: number) => `${data.pagination_base}${String(data.pagination_base).includes('?') ? '&' : '?'}page=${value}`;
  return <Pager label="Finding pages" page={page} pageCount={pages} total={total} pageSize={size} hrefFor={link} unit="findings"/>;
}

function FindingActions({ data, item, policy = false, evidence = false, open }: { data: PageData; item: any; policy?: boolean; evidence?: boolean; open: (action: Action) => void }) {
  const id = data.view.service.id;
  const root = `/services/${encodeURIComponent(data.view.service.service_key)}`;
  const exceptionAllowed = can(data, 'exception.request', id), poamAllowed = can(data, 'poam.request', id);
  if (item.exception) return <div className="row-actions"><StatusBadge value="excepted" label={`Accepted until ${item.exception.expires_at}`} />{can(data, 'exception.revoke', id) && <form method="post" action={`/${policy ? 'policy-exceptions' : 'exceptions'}/${item.exception.id}/revoke`}><input type="hidden" name="csrf_token" value={data.csrf_token || ''} /><button className="link-button">Revoke</button></form>}</div>;
  if (!policy && (item.vex_excluded || item.effective_disposition === "vex_not_affected" || data.finding_state === "vex_excluded")) return <span>VEX Excluded — scanner evidence retained</span>;
  if (item.active === false) return <>—</>;
  if (evidence) return poamAllowed ? <div className="row-actions"><button type="button" className="secondary-button" onClick={() => open({ kind: 'evidence', item })}>Add POA&amp;M Entry</button><button type="button" className="secondary-button" onClick={() => open({ kind: 'mitigation', item })}>Add Mitigation</button><a className="secondary-button" href={`${root}?artifacts=true`}>Locate/Add Evidence</a><a className="secondary-button" href={`/scan?service=${encodeURIComponent(data.view.service.service_key)}`}>Scan</a><a className="secondary-button" href={`${root}?artifacts=true#container-images`}>Replace / Remove</a></div> : <>—</>;
  return <div className="row-actions">{policy && <><StatusBadge value={item.remediation_classification || 'NOT REMEDIABLE'} label={item.remediation_classification || 'NOT REMEDIABLE'} tone={item.remediation_classification && item.remediation_classification !== 'NOT REMEDIABLE' ? 'info' : 'neutral'} className="remediation-classification" />{item.remediation_reason && <span className="sr-only">{item.remediation_reason}</span>}{data.remediation_enabled && can(data, 'remediation.execute', id) && item.remediation_classification && item.remediation_classification !== 'NOT REMEDIABLE' && <Suspense fallback={<button disabled>Loading remediation...</button>}><Remediate data={{...data,service:data.view.service}} finding_type="configuration" finding_id={item.id || item.policy_finding_id}/></Suspense>}</>}{exceptionAllowed && <button type="button" className="secondary-button exception-action" onClick={() => open({ kind: 'exception', item, policy })}>Request Exception</button>}{poamAllowed && <><button type="button" className="secondary-button poam-action" onClick={() => open({ kind: 'poam', item, policy })}>Add POA&amp;M Entry</button><button type="button" className="secondary-button mitigation-action" onClick={() => open({ kind: 'mitigation', item, policy })}>Add Mitigation</button></>}{!exceptionAllowed && !poamAllowed && '—'}</div>;
}

function ActionDialog({ data, action, close }: { data: PageData; action: Action | null; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (action) dialog.current?.showModal(); }, [action]);
  if (!action) return null;
  const { kind, item, policy } = action;
  const label = item.cve || item.finding || item.item || '';
  const findingId = item.id ?? item.finding_id;
  const policyId = item.policy_finding_id ?? (policy ? findingId : undefined);
  const prefix = policy ? 'policy-findings' : 'findings';
  const root = `/services/${encodeURIComponent(data.view.service.service_key)}`;
  const target = kind === 'exception' ? `/${prefix}/${policy ? policyId : findingId}/exceptions` : kind === 'poam' ? `/${prefix}/${policy ? policyId : findingId}/poams` : kind === 'evidence' ? '/poam' : `${root}/mitigations`;
  const title = kind === 'exception' ? 'Request Exception' : kind === 'mitigation' ? 'Add Mitigation' : kind === 'evidence' ? 'Add missing evidence to POA&M' : 'Add finding to POA&M';
  const imageList = (item.images || []).join(', ');
  return <dialog ref={dialog} className={`review-dialog ${kind === 'detail' ? 'policy-detail-dialog' : 'poam-dialog'}`} aria-labelledby="finding-dialog-title" onCancel={close} onClose={close}>{kind === 'detail' ? <><h3 id="finding-dialog-title">{label}{item.title ? ` — ${item.title}` : ''}</h3><dl className="policy-detail-list">{[['severity', 'Severity'], ['framework', 'Framework'], ['target', 'Target'], ['description', 'Issue'], ['remediation', 'Recommended remediation']].map(([key, name]) => <div key={key}><dt>{name}</dt><dd>{item[key] || '—'}</dd></div>)}</dl><div className="dialog-actions"><button type="button" className="secondary-button" onClick={close}>Close</button></div></> : <form method="post" action={target} key={`${kind}:${findingId}:${policyId}`}><input type="hidden" name="csrf_token" value={data.csrf_token || ''} /><h3 id="finding-dialog-title">{title}</h3>{kind === 'exception' ? <><p>{label}</p><label>Justification and compensating controls<textarea name="justification" required /></label><label>Requested expiration<input type="datetime-local" name="expires_at" required /></label></> : <><p>Cybersecurity approval is required before activation.</p>{kind === 'mitigation' && <><input type="hidden" name="finding_id" value={policy ? '' : findingId || ''} /><input type="hidden" name="policy_finding_id" value={policyId || ''} /></>}{kind === 'evidence' && <><input type="hidden" name="service_id" value={data.view.service.id} /><input type="hidden" name="item_type" value="missing_evidence" /><input type="hidden" name="finding_id" value="" /></>}<label>Title<input name="title" minLength={3} required defaultValue={kind === 'evidence' ? `Missing evidence for ${imageList}` : kind === 'mitigation' ? label ? `Mitigate ${label}` : 'Add mitigation' : `Remediate ${label}`} /></label>{(kind === 'evidence' || kind === 'mitigation') && <label>{kind === 'evidence' ? 'Evidence details' : 'Issue details'}<textarea name="description" minLength={3} required defaultValue={kind === 'evidence' ? `${item.reason}: ${imageList}` : ''} /></label>}<label>{kind === 'mitigation' ? 'Mitigation plan' : 'Remediation plan'}<textarea name="remediation" minLength={3} required /></label><label>Due date<input type="datetime-local" name="due_date" /></label></>}<label>Ticket<input name="ticket" /></label>{kind === 'exception' && <><label className="bulk-scope-option"><input type="checkbox" name="bulk_scope" value="group" /> Request this for all matching services in the Cybersecurity group</label><small className="muted">Cybersecurity must explicitly confirm the group-wide scope before it is applied.</small></>}<div className="dialog-actions"><button type="button" className="secondary-button" onClick={close}>Cancel</button><button>{kind === 'exception' ? 'Submit request' : 'Create for approval'}</button></div></form>}</dialog>;
}

type Members = { items: any[]; page: number; total_pages: number; total_items: number };
/** Findings of one remediation group, loaded on first expansion and cached for the page's lifetime. */
function GroupMembers({ data, item, open, cache }: { data: PageData; item: any; open: (action: Action) => void; cache: Map<string, Members> }) {
  const [members, setMembers] = useState<Members | null>(() => cache.get(item.group_id) || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const root = `/services/${encodeURIComponent(data.view.service.service_key)}`;
  async function load(page: number) {
    setLoading(true); setError('');
    const params = new URLSearchParams({ page: String(page), page_size: '50', finding_state: data.finding_state || 'active', finding_type: data.finding_type || 'all', q: data.query || '', resource: data.resource || '' });
    for (const severity of data.severity || []) params.append('severity', severity);
    try {
      const value = await requestJson<Members>(`/api/v1/services/${encodeURIComponent(data.view.service.service_key)}/findings/simplified/${encodeURIComponent(item.group_id)}/members?${params}`);
      cache.set(item.group_id, value); setMembers(value);
    }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to load group members.'); }
    finally { setLoading(false); }
  }
  // Load once on first expansion; a cached page renders immediately.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (!members) void load(1); }, []);
  return <section className="group-members" aria-label={`Findings for ${item.package}`}>
    {loading && <Loading inline label="Loading findings…" />}{error && <ErrorState title="Group findings could not be loaded" onRetry={() => void load(members?.page || 1)}>{error}</ErrorState>}
    {members && <><table><thead><tr><th scope="col">CVE / finding</th><th scope="col">Severity</th><th scope="col">Affected images</th><th scope="col">Actions</th></tr></thead><tbody>{members.items.map((member: any) => <tr key={member.id}><td><a className="finding-link" href={`${root}/findings/${member.id}`}>{member.cve}</a></td><td><SeverityBadge severity={member.severity} /></td><td>{member.representative_image && <code>{member.representative_image}</code>}<br />{member.image_count || 0} images</td><td><FindingActions data={data} item={member} open={open} /></td></tr>)}</tbody></table><nav className="pagination" aria-label={`Member pages for ${item.package}`}><span>Page {members.page} of {members.total_pages} · {members.total_items} findings</span><span className="pagination-controls"><button type="button" className="secondary-button" disabled={loading || members.page <= 1} onClick={() => void load(members.page - 1)}>Previous findings</button><button type="button" className="secondary-button" disabled={loading || members.page >= members.total_pages} onClick={() => void load(members.page + 1)}>Next findings</button></span></nav></>}
  </section>;
}

export function Page({ data }: { data: PageData }) {
  const [action, setAction] = useState<Action | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const members = useRef(new Map<string, Members>());
  const view = data.view, service = view.service;
  const root = `/services/${encodeURIComponent(service.service_key)}`;
  const simplified = data.selected_findings_view === 'simplified' || data.page_name === 'service_simplified';
  const state = data.finding_state || 'active';
  const filters = Boolean(data.query || data.resource || data.severity?.length);
  const link = (id: number) => `${root}/findings/${id}`;
  const vex = new URLSearchParams(window.location.search).get("vex_evidence") === "true";
  // Findings are paged by the server without a sort parameter: headers sort only when the whole result is on one page.
  const sort = Number(data.total_pages || 1) <= 1 ? { mode: 'client' as const } : { mode: 'none' as const };
  const findingTabs = <nav className="finding-view-selector" aria-label="Finding detail view">{['simplified', 'raw'].map(value => <a className={`secondary-button ${!vex && (simplified ? 'simplified' : 'raw') === value ? 'active selected' : ''}`} aria-current={!vex && (simplified ? 'simplified' : 'raw') === value ? 'page' : undefined} key={value} href={`${root}?findings=true&findings_view=${value}&finding_state=${encodeURIComponent(state)}&finding_type=${encodeURIComponent(data.finding_type || 'all')}&page_size=${data.page_size || 50}`}>{value === 'raw' ? 'Raw' : 'Simplified'}</a>)}<a className={`secondary-button ${vex ? "active selected" : ""}`} aria-current={vex ? "page" : undefined} href={`${root}?findings=true&findings_view=raw&vex_evidence=true`}>VEX evidence</a></nav>;
  if(vex)return <><ServiceHeader data={data}/><ServiceTabs serviceKey={service.service_key}/>{findingTabs}<p><a href={`${root}?findings=true&findings_view=raw&finding_state=vex_excluded`}>View VEX Excluded findings</a></p><VexEvidence serviceKey={service.service_key} expanded/></>;

  const toggle = (id: string) => setExpanded(previous => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  const simplifiedColumns: GridColumn<any>[] = [
    { key: 'package', header: 'Package / remediation', identifier: true, hideable: false, wrap: true, minWidth: 200, value: item => item.package, render: item => <span className="cell-stack"><strong>{item.package}</strong><small>{item.remediation}</small></span> },
    { key: 'cves', header: 'CVEs', value: item => item.member_count, render: item => <span className="cell-stack"><span>{item.representative_cve || '—'}</span><small>{item.member_count} findings</small></span> },
    { key: 'severity', header: 'Severity', type: 'severity', hideable: false, value: item => item.severity, render: item => <SeverityBadge severity={item.severity} /> },
    { key: 'fixed', header: 'Fixed version', value: item => item.fixed_version, render: item => item.fixed_version },
    { key: 'images', header: 'Affected images', type: 'number', value: item => item.image_count || 0, render: item => `${item.image_count || 0} images` },
    { key: 'due', header: 'Due date', render: item => item.due || '—' },
    { key: 'actions', header: 'Actions', render: item => <button type="button" className="secondary-button" aria-expanded={expanded.has(item.group_id)} onClick={() => toggle(item.group_id)}>{expanded.has(item.group_id) ? 'Hide findings' : 'View findings'}</button> },
  ];
  const itemColumns: GridColumn<any>[] = [
    { key: 'type', header: 'Type', value: item => item.type, render: item => item.type === 'CVE' ? 'Vulnerability' : item.type },
    { key: 'item', header: 'Item', identifier: true, hideable: false, value: item => item.item, render: item => item.href || item.type === 'CVE' ? <a className="finding-link" href={item.href || link(item.finding_id)}>{item.item}</a> : <strong>{item.item}</strong> },
    ...(state !== 'warnings' ? [{ key: 'details', header: 'Details', wrap: true, minWidth: 200, maxWidth: 360, render: (item: any) => <Images images={item.images} /> }] : []),
    { key: 'reason', header: 'Reason', wrap: true, minWidth: 220, maxWidth: 560, render: item => <>{item.reason}{item.source_file && <small className="muted"><br />Source: <code>{item.source_file}</code></small>}</> },
    { key: 'due', header: 'Due date', render: item => item.due || '—' },
    ...(state !== 'warnings' ? [{ key: 'actions', header: 'Actions', minWidth: 160, className: 'finding-actions', render: (item: any) => <FindingActions data={data} item={item} policy={item.type === 'Configuration'} evidence={!['CVE', 'Configuration'].includes(item.type)} open={setAction} /> }] : []),
  ];
  const rawColumns: GridColumn<{ item: any; policy: boolean }>[] = [
    { key: 'type', header: 'Type', value: ({ policy }) => policy ? 'Configuration' : 'Vulnerability', render: ({ policy }) => policy ? 'Configuration' : 'Vulnerability' },
    { key: 'finding', header: 'Finding', identifier: true, hideable: false, minWidth: 140, value: ({ item, policy }) => policy ? item.finding : item.cve, render: ({ item, policy }) => policy ? <button className="finding-link policy-detail-action" type="button" onClick={() => setAction({ kind: 'detail', item, policy })}><strong>{item.finding}</strong>{item.title && <><br />{item.title}</>}</button> : <a className="finding-link" href={link(item.id)}><strong>{item.cve}</strong></a> },
    { key: 'severity', header: 'Severity', type: 'severity', hideable: false, value: ({ item }) => item.severity, render: ({ item }) => <SeverityBadge severity={item.severity} /> },
    { key: 'state', header: 'State', hideable: false, wrap: true, minWidth: 110, render: ({ item, policy }) => <>{!policy && (item.vex_excluded || item.effective_disposition === 'vex_not_affected' || state === 'vex_excluded') ? <StatusBadge value="vex_excluded" label="VEX Excluded"/> : item.active ? 'Active' : <StatusBadge value="resolved" label="Resolved" />}{!policy && item.effective_disposition !== 'vex_not_affected' && item.vex_excluded_observations > 0 && <small><br/>{item.vex_excluded_observations} observation(s) VEX Excluded; remaining observations actionable</small>}</> },
    { key: 'episode', header: 'Current episode', type: 'number', value: ({ item }) => item.active ? item.episode_days : null, render: ({ item }) => item.active ? `${item.episode_days} days` : '—' },
    { key: 'due', header: 'Due date', render: ({ item }) => item.active ? item.due || '—' : '—' },
    { key: 'last_seen', header: 'Last seen', render: ({ item }) => item.last_seen || '—' },
    { key: 'kev', header: 'KEV', hideable: false, value: ({ item, policy }) => policy ? null : item.kev ? 1 : 0, type: 'number', align: 'start', render: ({ item, policy }) => policy ? '—' : item.kev ? <StatusBadge value="kev" label="Yes" tone="danger" size="sm" /> : 'No' },
    { key: 'epss', header: 'EPSS', type: 'number', value: ({ item, policy }) => policy ? null : Number(item.epss || 0), render: ({ item, policy }) => policy ? '—' : Number(item.epss || 0).toFixed(2) },
    { key: 'images', header: 'Affected images', wrap: true, minWidth: 200, maxWidth: 360, render: ({ item, policy }) => <><Images images={policy ? item.target ? [item.target] : [] : item.images} />{policy && item.framework && <><br /><small>{item.framework}</small></>}</> },
    { key: 'actions', header: 'Actions', minWidth: 160, className: 'finding-actions', render: ({ item, policy }) => <FindingActions data={data} item={item} policy={policy} open={setAction} /> },
  ];
  const itemRows = state === 'warnings' ? data.warning_items || [] : data.noncompliance_items || [];
  const rawRows = [...(data.findings || []).map((item: any) => ({ item, policy: false })), ...(data.policy_findings || []).map((item: any) => ({ item, policy: true }))];
  const heading = simplified ? 'Simplified Findings' : states[state];
  const summary = simplified ? 'CVEs that share the same package update and remediation are grouped together. Versions remain visible so the remediation scope is clear.' : undefined;
  const severityFilter = <div className="finding-filter-field"><span>Severity</span><details className="multi-select-filter"><summary>{data.severity?.length ? `${data.severity.length} selected` : 'All severities'}</summary><div className="multi-select-options">{(data.severity_options || []).map((value: string) => <label key={value}><input type="checkbox" name="severity" value={value} defaultChecked={data.severity?.includes(value)} />{value}</label>)}</div></details></div>;
  const filterForm = <form className="finding-filters" method="get" action={root} role="search" aria-label="Filter findings"><input type="hidden" name="findings_view" value={simplified ? 'simplified' : 'raw'} /><input type="hidden" name="overview" value="false" /><input type="hidden" name="finding_state" value={state} /><input type="hidden" name="page" value="1" /><label className="finding-filter-field">Search findings<input name="q" defaultValue={data.query || ''} placeholder="CVE, package, image, resource…" /></label>{severityFilter}<label className="finding-filter-field">Resource<input name="resource" defaultValue={data.resource || ''} placeholder="Image, target, namespace…" /></label><label>Type<select name="finding_type" defaultValue={data.finding_type || 'all'}>{[['all', 'All findings'], ['vulnerability', 'Vulnerabilities'], ['configuration', 'Configuration'], ['evidence', 'Evidence'], ...(state === 'warnings' ? [['watchlist', 'Dependency Watchlist']] : [])].map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label><label>Rows<select name="page_size" defaultValue={data.page_size || 50}>{[50, 100, 250].map(value => <option value={value} key={value}>{value}</option>)}</select></label><button className="secondary-button">Apply filters</button>{filters && <><a className="link-button" href={data.clear_filters_url}>Clear filters</a><StatusBadge value="selected" label="Filters active" tone="info" size="sm" className="filter-active" /></>}</form>;
  const emptyState = (title: string) => <EmptyState kind={filters ? 'filtered' : 'empty'} title={title} action={filters && data.clear_filters_url ? <a className="secondary-button" href={data.clear_filters_url}>Clear filters</a> : undefined} />;
  const grid = simplified
    ? <DataGrid id="service-findings-simplified" label="Simplified Findings" title={heading} description={summary} columns={simplifiedColumns} rows={data.simplified_findings || []} rowKey={item => item.group_id} sort={sort}
        rowDetail={item => expanded.has(item.group_id) ? <GroupMembers data={data} item={item} open={setAction} cache={members.current} /> : null}
        empty={emptyState('No vulnerability remediation groups match these filters.')} footer={<Pagination data={data} />} />
    : ['noncompliant', 'overdue', 'warnings'].includes(state)
      ? <DataGrid id={state === 'warnings' ? 'service-warnings' : 'service-noncompliance'} label={heading} title={heading} columns={itemColumns} rows={itemRows} sort={{ mode: 'client' }}
          rowKey={(item, index) => `${item.type}:${item.finding_id || item.policy_finding_id || item.item}:${index}`}
          empty={emptyState(state === 'warnings' ? 'No warnings for this service.' : 'No non-compliance items for this service.')} />
      : <DataGrid id="service-findings-raw" label={heading} title={heading} columns={rawColumns} rows={rawRows} rowKey={({ item, policy }) => `${policy ? 'policy' : 'cve'}:${item.id}`} sort={sort}
          rowClassName={({ item, policy }) => !policy && item.kev ? 'row-kev' : undefined}
          empty={emptyState('No findings in this category.')} footer={<Pagination data={data} />} />;
  return <><ServiceHeader data={data} /><ServiceTabs serviceKey={service.service_key} />{findingTabs}{!simplified && <p className="muted finding-scope-note">Raw findings preserve original scanner evidence. VEX Excluded observations are available in their separate view. Vulnerabilities are grouped by CVE across images and packages; Scan counts individual observations and may also include vulnerabilities without fixes. Exceptions and resolved findings have separate views.</p>}{['skipped_images', 'skipped_charts'].map(key => view[key]?.length > 0 && <span className="sr-only" key={key}>Skipped {key === 'skipped_images' ? 'images' : 'charts'} ({view[key].length}): {view[key].join(', ')}</span>)}
    <section className="panel service-findings">{filterForm}{grid}</section>
    {view.archive && can(data, 'service.delete', service.id) && <section className="danger-zone" aria-labelledby="danger-zone-title"><h2 id="danger-zone-title">Permanent deletion</h2><p>Permanent deletion removes every execution, finding, observation, and exception.</p><form method="post" action={`${root}/delete`}><input type="hidden" name="csrf_token" value={data.csrf_token || ''} /><label>Reason<input name="reason" required /></label><label>Type <code>{service.service_key}</code> to confirm<input name="confirmation" required autoComplete="off" /></label><button className="danger-button">Permanently delete</button></form></section>}
    <ActionDialog data={data} action={action} close={() => setAction(null)} />
  </>;
}
