import {StatusBadge} from './ui';
import '../features/cybersecurity.css';
interface SecurityRow {
  service: { service_key: string; name: string }; status: string;
  critical: number; high: number; medium: number; low: number; kev: number; watchlist: number; patchable: number;
  poam: number; poam_overdue: number; missing: boolean; sbom: boolean; kind: string;
  last_scan_display: string;
}
const title = (value: string) => value[0].toUpperCase() + value.slice(1).toLowerCase();
export function ServiceSecurityMatrix({data}: {data: any}) {
  const select = (name: string, label: string, options: string[]) => <label>{label}<select name={name} defaultValue={data[name] || 'all'}><option value="all">All</option>{options.map(value => <option key={value} value={value}>{title(value)}</option>)}</select></label>;
  return <>
      <form method="get" action="/" className="cyber-filters" key={JSON.stringify([data.q, data.component, data.since, data.status, data.severity, data.attention])}>
        <input type="hidden" name="lifecycle" value={data.lifecycle || "active"} /><label>Search<input name="q" defaultValue={data.q || ''} placeholder="Service name or key" /></label>
        <label>Component / image<input name="component" defaultValue={data.component || ''} /></label>
        <label>Scanned since<input name="since" type="date" defaultValue={data.since || ''} /></label>
        {select('status', 'Status', ['GREEN', 'YELLOW', 'RED'])}{select('severity', 'Severity', ['Critical', 'High', 'Medium', 'Low'])}{select('attention', 'Attention', ['kev', 'watchlist', 'poam', 'missing', 'kind'])}<label>Per page<select name="page_size" defaultValue={data.page_size || 50}>{[10, 25, 50, 100].map(value => <option value={value} key={value}>{value}</option>)}</select></label><button className="secondary-button">Filter</button>
      </form>
      <div className="table-wrap"><table><thead><tr>{['Service', 'Status', 'Critical', 'High', 'Medium / Low', 'KEV', 'Watchlist', 'Patchable', 'POA&M', 'Overdue', 'Missing Evidence', 'SBOM', 'Kind', 'Last scan'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
        <tbody>{data.rows?.length ? data.rows.map((row: SecurityRow) => {
          const servicePath = `/services/${encodeURIComponent(row.service.service_key)}`;
          return <tr key={row.service.service_key}><td><a href={servicePath}>{row.service.name}</a></td><td><StatusBadge value={row.status} label={row.status === 'GREEN' ? 'Compliant' : row.status === 'YELLOW' ? 'Warnings' : 'Non-compliant'} tone={row.status === 'GREEN' ? 'success' : row.status === 'YELLOW' ? 'warning' : 'danger'}/></td><td className={row.critical ? 'num text-danger' : 'num'}>{row.critical}</td><td className="num">{row.high}</td><td>{row.medium || 0} / {row.low || 0}</td><td>{row.kev}</td><td><a href={`${servicePath}?finding_state=warnings`}>{row.watchlist}</a></td><td>{row.patchable}</td><td><a href={`/poam/services/${encodeURIComponent(row.service.service_key)}`}>{row.poam}</a></td><td>{row.poam_overdue}</td><td>{row.missing ? 'Yes' : 'No'}</td><td>{row.sbom ? 'Yes' : 'No'}</td><td><a href={`${servicePath}?validation=true`}>{row.kind}</a></td><td>{row.last_scan_display || '—'}</td></tr>;
        }) : <tr><td colSpan={14}>No services match these filters.</td></tr>}</tbody>
      </table></div>
  </>;
}
