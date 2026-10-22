import {useMemo, type ReactNode} from 'react';
import {DataGrid, type GridColumn} from './DataGrid';
import {FilterChips, FilterDrawer, hrefWithout, QuickSearch, type ActiveFilter} from './FilterDrawer';
import {Pager} from './Pager';
import {EmptyState, Icon, StatusBadge} from './ui';
import '../features/cybersecurity.css';

interface SecurityRow {
  service: {service_key: string; name: string}; status: string;
  critical: number; high: number; medium: number; low: number; kev: number; watchlist: number; patchable: number;
  poam: number; poam_overdue: number; missing: boolean; sbom: boolean; kind: string;
  last_scan?: string | null; last_scan_display: string; warning_reasons?: string[];
}

const title = (value: string) => value[0].toUpperCase() + value.slice(1).toLowerCase();
const attentionLabels: Record<string, string> = {kev: 'KEV', watchlist: 'Watchlist', poam: 'POA&M', missing: 'Missing evidence', kind: 'Deployment validation (Kind)'};
const statusLabels: Record<string, string> = {GREEN: 'Green — compliant', YELLOW: 'Yellow — compliant with warnings', RED: 'Red — non-compliant'};
export const MATRIX_FORM = 'service-matrix-filters';
export const lifecycleLabels: Record<string, {title: string; label: string; description: string}> = {
  active: {title: 'Service Snapshot', label: 'Active', description: 'Fixable CVE exposure tracked continuously across container images.'},
  staged: {title: 'Staged services', label: 'Staged', description: 'Services prepared for their first pipeline submission.'},
  archived: {title: 'Archived services', label: 'Archived', description: 'Retired services preserved with their historical evidence.'},
};

/** A count cell: zero is visually quiet, non-zero severe counts carry emphasis (and the number itself). */
function Count({value, tone, href, label}: {value: number; tone?: 'danger' | 'warning'; href?: string; label?: string}) {
  const amount = Number(value || 0);
  const className = amount === 0 ? 'count-zero' : tone === 'danger' ? 'text-danger' : tone === 'warning' ? 'count-warning' : undefined;
  const text = <span className={className}>{amount}</span>;
  return href ? <a href={href} aria-label={label}>{text}</a> : text;
}

const flag = (value: boolean, attention: boolean) => <span className={value === attention ? 'flag flag-attention' : 'flag'}>{value ? 'Yes' : 'No'}</span>;

/** Filter parameters the backend accepts for the matrix, in display order. */
function activeFilters(data: any, base: {pathname: string; search: string}): ActiveFilter[] {
  const entries: [string, string, ReactNode][] = [];
  if (data.q) entries.push(['q', 'Search', data.q]);
  if (data.cve) entries.push(['cve', 'CVE', data.cve]);
  if (data.component) entries.push(['component', 'Component / image', data.component]);
  if (data.since) entries.push(['since', 'Scanned since', data.since]);
  if (data.status && data.status !== 'all') entries.push(['status', 'Status', title(data.status)]);
  if (data.severity && data.severity !== 'all') entries.push(['severity', 'Severity', title(data.severity)]);
  if (data.attention && data.attention !== 'all') entries.push(['attention', 'Attention', attentionLabels[data.attention] || data.attention]);
  return entries.map(([name, label, value]) => ({key: name, label, value, removeHref: hrefWithout({[name]: null}, base)}));
}

/** Lifecycle switch for the Services page: it changes the whole page (title, totals and rows). */
export function LifecycleTabs({data}: {data: any}) {
  const lifecycle = data.lifecycle || 'active';
  return <nav className="request-tabs lifecycle-tabs" aria-label="Service lifecycle">{['active', 'staged', 'archived'].map(value =>
    <a href={`/?lifecycle=${value}`} key={value} className={value === lifecycle ? 'selected' : ''} aria-current={value === lifecycle ? 'page' : undefined}>
      {lifecycleLabels[value].label} <span className="tab-count">{data.lifecycle_counts?.[value] || 0}</span></a>)}</nav>;
}

export function ServiceSecurityMatrix({data}: {data: any}) {
  const lifecycle = data.lifecycle || 'active';
  const base = useMemo(() => {
    const url = new URL(String(data.pagination_base || `/?lifecycle=${lifecycle}`), 'http://cats.invalid');
    return {pathname: url.pathname, search: url.search};
  }, [data.pagination_base, lifecycle]);
  const filters = activeFilters(data, base);
  const drawerFilters = filters.filter(filter => filter.key !== 'q').length;
  const page = Number(data.page || 1);
  const pageSize = Number(data.page_size || 50);
  const total = Number(data.total_count ?? data.rows?.length ?? 0);
  const pageCount = Number(data.total_pages || 1);
  const pageHref = (value: number) => `${data.pagination_base || '/'}${String(data.pagination_base || '/').includes('?') ? '&' : '?'}page=${value}`;
  const select = (name: string, label: string, options: string[], labels: Record<string, string> = {}) => <label>{label}
    <select name={name} defaultValue={data[name] || 'all'}><option value="all">All</option>{options.map(value => <option key={value} value={value}>{labels[value] || title(value)}</option>)}</select></label>;

  const columns = useMemo<GridColumn<SecurityRow>[]>(() => [
    {key: 'service', header: 'Service', identifier: true, hideable: false, width: 220, minWidth: 140, value: row => row.service.name,
      render: row => <a className="matrix-service" href={`/services/${encodeURIComponent(row.service.service_key)}?overview=true`}>{row.service.name}</a>},
    {key: 'status', header: 'Status', hideable: false, width: 160, minWidth: 130, wrap: true,
      value: row => ({RED: 2, YELLOW: 1, GREEN: 0} as Record<string, number>)[row.status] ?? -1, type: 'number', align: 'start',
      description: 'Compliance follows the configured CATS policy; a warning icon marks compliant services with warnings.',
      render: row => {
        const servicePath = `/services/${encodeURIComponent(row.service.service_key)}`;
        const compliant = row.status === 'GREEN' || row.status === 'YELLOW';
        const reasons = row.warning_reasons?.length ? row.warning_reasons : ['Review warning findings for this service'];
        return <span className="matrix-status"><StatusBadge value={row.status} label={compliant ? 'Compliant' : 'Non-compliant'} tone={compliant ? 'success' : 'danger'}/>
          {row.status === 'YELLOW' && <a className="service-warning-indicator" href={`${servicePath}?finding_state=warnings`}
            aria-label={`Warnings for ${row.service.name}: ${reasons.join('; ')}`} title={reasons.join('\n')}><Icon name="alert" label="Warnings present"/></a>}</span>;
      }},
    {key: 'critical', header: 'Critical', type: 'number', hideable: false, width: 84, value: row => row.critical, render: row => <Count value={row.critical} tone="danger"/>},
    {key: 'high', header: 'High', type: 'number', hideable: false, width: 74, value: row => row.high, render: row => <Count value={row.high} tone="warning"/>},
    {key: 'medium', header: 'Medium', type: 'number', width: 84, value: row => row.medium || 0, render: row => <Count value={row.medium}/>},
    {key: 'low', header: 'Low', type: 'number', width: 68, value: row => row.low || 0, render: row => <Count value={row.low}/>},
    {key: 'kev', header: 'KEV', type: 'number', hideable: false, width: 68, value: row => row.kev, description: 'Known exploited vulnerabilities (CISA KEV)',
      render: row => <Count value={row.kev} tone="danger"/>},
    {key: 'watchlist', header: 'Watchlist', type: 'number', width: 96, value: row => row.watchlist, description: 'Dependency watchlist matches',
      render: row => <Count value={row.watchlist} href={`/services/${encodeURIComponent(row.service.service_key)}?finding_state=warnings`}/>},
    {key: 'patchable', header: 'Patchable', type: 'number', width: 96, value: row => row.patchable, render: row => <Count value={row.patchable}/>},
    {key: 'poam', header: 'POA&M', type: 'number', width: 80, value: row => row.poam,
      render: row => <Count value={row.poam} href={`/poam/services/${encodeURIComponent(row.service.service_key)}`}/>},
    {key: 'overdue', header: 'Overdue', type: 'number', width: 84, value: row => row.poam_overdue, description: 'Overdue POA&M entries',
      render: row => <Count value={row.poam_overdue} tone="danger"/>},
    {key: 'missing', header: 'Missing Evidence', width: 130, value: row => row.missing ? 1 : 0, type: 'number', align: 'start', render: row => flag(row.missing, true)},
    {key: 'sbom', header: 'SBOM', width: 72, value: row => row.sbom ? 1 : 0, type: 'number', align: 'start', render: row => flag(row.sbom, false)},
    {key: 'kind', header: 'Kind', width: 150, value: row => row.kind, description: 'Deployment validation (Kind) result', wrap: true,
      render: row => <a className="status-link" href={`/services/${encodeURIComponent(row.service.service_key)}?validation=true`}><StatusBadge value={row.kind} size="sm"/></a>},
    {key: 'last_scan', header: 'Last scan', type: 'date', width: 130, value: row => row.last_scan, render: row => row.last_scan_display || '—'},
  ], []);

  const rows: SecurityRow[] = data.rows || [];
  const filtered = filters.length > 0;


  return <DataGrid<SecurityRow> id="service-security-matrix" label="Service Security Matrix" className="matrix-grid"
    title="Service Security Matrix"
    description={lifecycle === 'archived' ? 'Historical records do not affect active compliance totals.' : lifecycle === 'staged' ? 'Staged records are excluded from the active service snapshot.' : 'Per-service evidence, risk and workflow counts.'}
    actions={<>
      <QuickSearch form={MATRIX_FORM} name="q" defaultValue={data.q || ''} label="Search" placeholder="Search service name or key"/>
      <FilterDrawer id={MATRIX_FORM} action="/" title="Filter services" activeCount={drawerFilters}
        description="Filters apply to the selected lifecycle. Portfolio totals above are not affected."
        hidden={[['lifecycle', lifecycle], ['page_size', pageSize]]} resetHref={`/?lifecycle=${lifecycle}`}>
        <label>CVE<input name="cve" defaultValue={data.cve || ''} placeholder="CVE-2026-12345 or 2026-12345" title="Find services with an active finding for this exact CVE; CVE- is optional"/></label>
        <label>Component / image<input name="component" defaultValue={data.component || ''} placeholder="Package, image or repository"/></label>
        <label>Scanned since<input name="since" type="date" defaultValue={data.since || ''}/></label>
        {select('status', 'Status', ['GREEN', 'YELLOW', 'RED'], statusLabels)}
        {select('severity', 'Severity', ['Critical', 'High', 'Medium', 'Low'])}
        {select('attention', 'Attention', ['kev', 'watchlist', 'poam', 'missing', 'kind'], attentionLabels)}
      </FilterDrawer>
    </>}
    trailingActions={<a className="secondary-button" href="/exports/services.xlsx"><Icon name="download"/>Export Excel</a>}
    above={<FilterChips filters={filters} clearHref={`/?lifecycle=${lifecycle}`}/>}
    columns={columns} rows={rows} rowKey={row => row.service.service_key}
    // The backend pages this dataset in a fixed order and offers no sort
    // parameter, so headers sort only when every matching row is on screen.
    sort={pageCount <= 1 ? {mode: 'client'} : {mode: 'none'}}
    rowClassName={row => row.status === 'RED' ? 'row-noncompliant' : undefined}
    empty={<EmptyState kind={filtered ? 'filtered' : 'empty'} title={filtered ? 'No services match these filters.' : `No ${lifecycleLabels[lifecycle]?.label.toLowerCase() || ''} services.`}
      action={filtered ? <a className="secondary-button" href={`/?lifecycle=${lifecycle}`}>Clear filters</a> : undefined}/>}
    footer={<Pager label="Service pages" page={page} pageCount={pageCount} total={total} pageSize={pageSize} hrefFor={pageHref} unit="services" pageSizes={[10, 25, 50, 100]}/>}
  />;
}
