import type { PageData } from '../api';

interface SecurityRow {
  service: { service_key: string; name: string }; status: string;
  critical: number; high: number; kev: number; watchlist: number; patchable: number;
  poam: number; poam_overdue: number; missing: boolean; sbom: boolean; kind: string;
  last_scan_display: string;
}
interface SecurityData extends PageData {
  rows: SecurityRow[]; metrics: Record<string, number>;
  q: string; component: string; since: string; status: string; severity: string; attention: string;
}
const title = (value: string) => value[0].toUpperCase() + value.slice(1).toLowerCase();
export function Page({ data: pageData }: { data: PageData }) {
  const data = pageData as SecurityData;
  const metrics = data.metrics || {};
  const cards: [string, string | number][] = [
    ['Cyber Attention', metrics.attention], ['Services / scanned', `${metrics.services} / ${metrics.scanned}`],
    ['Vulnerabilities', metrics.vulnerabilities], ['Critical / High', metrics.critical_high], ['KEV', metrics.kev],
    ['Watchlist', metrics.watchlist], ['Patchable', metrics.patchable], ['Open POA&M', metrics.poam],
    ['Overdue POA&M', metrics.poam_overdue], ['SBOM coverage', `${metrics.sbom_coverage} / ${metrics.scanned}`],
    ['Missing Evidence', metrics.missing], ['Kind failures', metrics.kind_failed],
  ];
  const select = (name: string, label: string, options: string[]) => <label>{label}<select name={name} defaultValue={data[name] || 'all'}><option value="all">All</option>{options.map(value => <option key={value} value={value}>{title(value)}</option>)}</select></label>;
  return <>
    <section className="heading"><div><p className="eyebrow">CURRENT POSTURE</p><h1>Cybersecurity</h1><p>Service evidence requiring review. Green means compliant, yellow means compliant with warnings, and red follows the configured CATS compliance policy.</p></div></section>
    <section className="metrics">{cards.map(([label, value]) => <article key={label}><span>{label}</span><strong>{value}</strong></article>)}</section>
    <section className="panel padded"><h2>Service Security Matrix</h2>
      <form method="get" action="/cybersecurity" className="finding-controls" key={JSON.stringify([data.q, data.component, data.since, data.status, data.severity, data.attention])}>
        <label>Search<input name="q" defaultValue={data.q || ''} placeholder="Service name or key" /></label>
        <label>Component / image<input name="component" defaultValue={data.component || ''} /></label>
        <label>Scanned since<input name="since" type="date" defaultValue={data.since || ''} /></label>
        {select('status', 'Status', ['GREEN', 'YELLOW', 'RED'])}{select('severity', 'Severity', ['Critical', 'High', 'Medium', 'Low'])}{select('attention', 'Attention', ['kev', 'watchlist', 'poam', 'missing', 'kind'])}<button>Filter</button>
      </form>
      <div className="table-wrap"><table><thead><tr>{['Service', 'Status', 'Critical', 'High', 'KEV', 'Watchlist', 'Patchable', 'POA&M', 'Overdue', 'Missing Evidence', 'SBOM', 'Kind', 'Last scan'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
        <tbody>{data.rows?.length ? data.rows.map(row => {
          const servicePath = `/services/${encodeURIComponent(row.service.service_key)}`;
          return <tr key={row.service.service_key}><td><a href={servicePath}>{row.service.name}</a></td><td><span className={`status ${row.status === 'GREEN' ? 'ok' : row.status === 'YELLOW' ? 'excepted' : 'bad'}`}>{row.status}</span></td><td>{row.critical}</td><td>{row.high}</td><td>{row.kev}</td><td><a href={`${servicePath}?finding_state=warnings`}>{row.watchlist}</a></td><td>{row.patchable}</td><td><a href={`/poam/services/${encodeURIComponent(row.service.service_key)}`}>{row.poam}</a></td><td>{row.poam_overdue}</td><td>{row.missing ? 'Yes' : 'No'}</td><td>{row.sbom ? 'Yes' : 'No'}</td><td><a href={`${servicePath}?validation=true`}>{row.kind}</a></td><td>{row.last_scan_display || '—'}</td></tr>;
        }) : <tr><td colSpan={13}>No services match these filters.</td></tr>}</tbody>
      </table></div>
    </section>
  </>;
}
