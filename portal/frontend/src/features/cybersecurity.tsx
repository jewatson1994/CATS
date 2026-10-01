import { useState } from 'react';
import type { PageData } from '../api';
import './cybersecurity.css';

const levels = ['Critical', 'High', 'Medium', 'Low', 'Unknown'] as const;
interface Snapshot { execution_id: number; version: string; scanned_at: string; complete: boolean; counts: Record<string, number>; total: number }
interface History { service_key: string; name: string; trend: Snapshot[]; versions: Snapshot[] }
function Bars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...levels.map(level => counts[level] || 0));
  return <div className="cyber-bars">{levels.map(level => <div className="cyber-bar-row" key={level}><span>{level}</span><div className="cyber-bar-track"><div className={`cyber-bar cyber-${level.toLowerCase()}`} style={{ width: `${(counts[level] || 0) / max * 100}%` }} /></div><strong>{counts[level] || 0}</strong></div>)}</div>;
}
function HistoryPanel({ history }: { history: History[] }) {
  const [selected, setSelected] = useState('');
  const service = history.find(item => item.service_key === selected) || history[0];
  const latest = service?.versions[0]; const previous = service?.versions[1];
  const max = Math.max(1, ...[latest, previous].flatMap(scan => levels.map(level => scan?.counts[level] || 0)));
  return <section className="panel padded cyber-history"><div className="cyber-section-heading"><div><p className="eyebrow">SERVICE EXPLORER</p><h2>Version changes & scan trend</h2></div><label>Compare service<select value={service?.service_key || ''} onChange={event => setSelected(event.target.value)}><option value="" disabled>Select a service</option>{history.map(item => <option key={item.service_key} value={item.service_key}>{item.name}</option>)}</select></label></div>
    {!service ? <p className="cyber-empty">No service scan history is available yet.</p> : <><p className="cyber-muted">Unique CVEs observed in service-wide scans. Comparing the most recently scanned distinct versions, not release order. Counts reflect each scan’s scope and settings.</p>
      {latest && previous ? <><div className="cyber-comparison-summary"><span>Previous <strong>{previous.version}</strong> · {previous.total} CVEs</span><span>Latest <strong>{latest.version}</strong> · {latest.total} CVEs</span><span>Change <strong>{latest.total - previous.total > 0 ? '+' : ''}{latest.total - previous.total}</strong></span></div>
        {(!latest.complete || !previous.complete) && <p className="cyber-caution" role="note">Incomplete scan: these are observed counts only. A decrease does not establish that vulnerabilities were resolved.</p>}
        <p className="cyber-muted">Previous scan: {previous.scanned_at.slice(0, 10)} · Latest scan: {latest.scanned_at.slice(0, 10)}</p>
        <div className="cyber-comparison">{levels.map(level => { const delta = (latest.counts[level] || 0) - (previous.counts[level] || 0); return <div key={level}><div className="cyber-comparison-label"><strong>{level}</strong><span>{delta > 0 ? '+' : ''}{delta}</span></div>{[previous, latest].map((scan, index) => <div className="cyber-version-bar" key={scan.execution_id}><span>{index ? 'Latest' : 'Previous'}</span><div className="cyber-bar-track"><div className={`cyber-bar cyber-${level.toLowerCase()} ${index ? '' : 'cyber-previous'}`} style={{ width: `${(scan.counts[level] || 0) / max * 100}%` }} /></div><strong>{scan.counts[level] || 0}</strong></div>)}</div>; })}</div></> : <p className="cyber-empty">Two distinct versioned service scans are needed for a version comparison.</p>}
      <h3>Recent scan trend</h3>{service.trend.length ? <div className="cyber-trend" role="list" aria-label="Recent service scans">{service.trend.map(scan => <div role="listitem" key={scan.execution_id}><div className="cyber-trend-column" aria-hidden="true">{levels.map(level => <div key={level} className={`cyber-${level.toLowerCase()}`} style={{ height: `${(scan.counts[level] || 0) / Math.max(1, ...service.trend.map(item => item.total)) * 120}px` }} />)}</div><strong>{scan.total}</strong><span>{scan.version}</span><time dateTime={scan.scanned_at}>{scan.scanned_at.slice(0, 10)}</time>{!scan.complete && <span className="cyber-caution">Incomplete</span>}<span className="sr-only">{levels.map(level => `${level}: ${scan.counts[level] || 0}`).join(', ')}</span></div>)}</div> : <p>No service-wide scans available.</p>}</>}
  </section>;
}

interface SecurityRow {
  service: { service_key: string; name: string }; status: string;
  critical: number; high: number; medium: number; low: number; kev: number; watchlist: number; patchable: number;
  poam: number; poam_overdue: number; missing: boolean; sbom: boolean; kind: string;
  last_scan_display: string;
}
interface SecurityData extends PageData {
  rows: SecurityRow[]; metrics: Record<string, number>;
  history: History[];
  q: string; component: string; since: string; status: string; severity: string; attention: string;
}
const title = (value: string) => value[0].toUpperCase() + value.slice(1).toLowerCase();
export function Page({ data: pageData }: { data: PageData }) {
  const data = pageData as SecurityData;
  const metrics = data.metrics || {};
  const cards: [string, string | number][] = [
    ['Cyber Attention', metrics.attention || 0], ['Services / scanned', `${metrics.services || 0} / ${metrics.scanned || 0}`],
    ['Active vulnerabilities', metrics.vulnerabilities || 0], ['Critical / High', metrics.critical_high || 0],
    ['Patchable', metrics.patchable || 0], ['Missing Evidence', metrics.missing || 0],
  ];
  const select = (name: string, label: string, options: string[]) => <label>{label}<select name={name} defaultValue={data[name] || 'all'}><option value="all">All</option>{options.map(value => <option key={value} value={value}>{title(value)}</option>)}</select></label>;
  return <>
    <section className="heading"><div><p className="eyebrow">CURRENT POSTURE</p><h1>Cybersecurity</h1><p>Service evidence requiring review. Green means compliant, yellow means compliant with warnings, and red follows the configured CATS compliance policy.</p></div></section>
    <section className="metrics cyber-metrics">{cards.map(([label, value]) => <article key={label}><span>{label}</span><strong>{value || 0}</strong></article>)}</section>
    <div className="cyber-chart-grid"><section className="panel padded"><p className="eyebrow">VULNERABILITY DISTRIBUTION</p><h2>Active findings by severity</h2><p className="cyber-muted">Across all services you can access; table filters do not change these totals.</p><Bars counts={Object.fromEntries(levels.map(level => [level, metrics[level.toLowerCase()] || 0]))} /></section>
      <section className="panel padded"><p className="eyebrow">POLICY & COVERAGE</p><h2>Service posture</h2><div className="cyber-posture"><div className="cyber-donut" role="img" aria-label={`Service posture: ${metrics.green || 0} compliant, ${metrics.yellow || 0} warnings, ${metrics.red || 0} non-compliant`} style={{ background: metrics.services ? `conic-gradient(#69d5ad 0 ${(metrics.green || 0) / metrics.services * 100}%, #e5b960 ${(metrics.green || 0) / metrics.services * 100}% ${((metrics.green || 0) + (metrics.yellow || 0)) / metrics.services * 100}%, #f07983 ${((metrics.green || 0) + (metrics.yellow || 0)) / metrics.services * 100}% 100%)` : undefined }}><div><strong>{metrics.services || 0}</strong><span>services</span></div></div><dl className="cyber-coverage">{[['Compliant', metrics.green], ['Warnings', metrics.yellow], ['Non-compliant', metrics.red], ['SBOM coverage', `${metrics.sbom_coverage || 0} / ${metrics.scanned || 0}`], ['KEV / watchlist', `${metrics.kev || 0} / ${metrics.watchlist || 0}`], ['Open / overdue POA&M', `${metrics.poam || 0} / ${metrics.poam_overdue || 0}`], ['Validation failures', metrics.kind_failed]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || 0}</dd></div>)}</dl></div><p className="cyber-muted">No findings does not mean complete evidence. Posture follows your configured compliance policy.</p></section></div>
    <HistoryPanel history={data.history || []} />
    <section className="panel padded"><h2>Service Security Matrix</h2>
      <form method="get" action="/cybersecurity" className="cyber-filters" key={JSON.stringify([data.q, data.component, data.since, data.status, data.severity, data.attention])}>
        <label>Search<input name="q" defaultValue={data.q || ''} placeholder="Service name or key" /></label>
        <label>Component / image<input name="component" defaultValue={data.component || ''} /></label>
        <label>Scanned since<input name="since" type="date" defaultValue={data.since || ''} /></label>
        {select('status', 'Status', ['GREEN', 'YELLOW', 'RED'])}{select('severity', 'Severity', ['Critical', 'High', 'Medium', 'Low'])}{select('attention', 'Attention', ['kev', 'watchlist', 'poam', 'missing', 'kind'])}<button>Filter</button>
      </form>
      <div className="table-wrap"><table><thead><tr>{['Service', 'Status', 'Critical', 'High', 'Medium / Low', 'KEV', 'Watchlist', 'Patchable', 'POA&M', 'Overdue', 'Missing Evidence', 'SBOM', 'Kind', 'Last scan'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
        <tbody>{data.rows?.length ? data.rows.map(row => {
          const servicePath = `/services/${encodeURIComponent(row.service.service_key)}`;
          return <tr key={row.service.service_key}><td><a href={servicePath}>{row.service.name}</a></td><td><span className={`status ${row.status === 'GREEN' ? 'ok' : row.status === 'YELLOW' ? 'excepted' : 'bad'}`}>{row.status}</span></td><td>{row.critical}</td><td>{row.high}</td><td>{row.medium || 0} / {row.low || 0}</td><td>{row.kev}</td><td><a href={`${servicePath}?finding_state=warnings`}>{row.watchlist}</a></td><td>{row.patchable}</td><td><a href={`/poam/services/${encodeURIComponent(row.service.service_key)}`}>{row.poam}</a></td><td>{row.poam_overdue}</td><td>{row.missing ? 'Yes' : 'No'}</td><td>{row.sbom ? 'Yes' : 'No'}</td><td><a href={`${servicePath}?validation=true`}>{row.kind}</a></td><td>{row.last_scan_display || '—'}</td></tr>;
        }) : <tr><td colSpan={14}>No services match these filters.</td></tr>}</tbody>
      </table></div>
    </section>
  </>;
}
