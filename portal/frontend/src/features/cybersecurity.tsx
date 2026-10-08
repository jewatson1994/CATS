import { useEffect, useRef, useState } from 'react';
import {ErrorState, Loading, MetricCard, MetricGrid, PageHeader, type Tone} from '../components/ui';
import {requestJson, type PageData} from '../api';
import {useDashboard} from '../hooks/useDashboard';
import './cybersecurity.css';

const levels = ['Critical', 'High', 'Medium', 'Low', 'Unknown'] as const;
interface Snapshot { execution_id: number; version: string; scanned_at: string; complete: boolean; counts: Record<string, number>; total: number }
interface History { service_key: string; name: string; trend: Snapshot[]; versions: Snapshot[]; comparison_limited?: boolean; candidate_limit?: number }
function Bars({ counts, onSelect }: { counts: Record<string, number>; onSelect: (key: string, label: string) => void }) {
  const max = Math.max(1, ...levels.map(level => counts[level] || 0));
  return <div className="cyber-bars">{levels.map(level => <button type="button" className="cyber-bar-row cyber-detail-trigger" key={level} onClick={() => onSelect(level.toLowerCase(), `${level} active findings`)}><span>{level}</span><div className="cyber-bar-track"><div className={`cyber-bar cyber-${level.toLowerCase()}`} style={{ width: `${(counts[level] || 0) / max * 100}%` }} /></div><strong>{counts[level] || 0}</strong></button>)}</div>;
}
function HistoryPanel({history, services, asynchronous}: {history: History[]; services: {service_key: string; name: string}[]; asynchronous: boolean}) {
  const [selected, setSelected] = useState('');
  const key = services.some(item => item.service_key === selected) ? selected : services[0]?.service_key || '';
  const [result, setResult] = useState<{key: string; history?: History; error?: string} | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!asynchronous || !key) return;
    const controller = new AbortController();
    setResult(null);
    requestJson<History>(`/api/dashboard/cybersecurity/services/${encodeURIComponent(key)}/history`, {signal: controller.signal})
      .then(value => {if (!controller.signal.aborted) setResult({key, history: value});})
      .catch(error => {if (!controller.signal.aborted) setResult({key, error: error instanceof Error ? error.message : 'Unable to load history.'});});
    return () => controller.abort();
  }, [asynchronous, key, attempt]);
  const current = result?.key === key ? result : null;
  const service = asynchronous ? current?.history : history.find(item => item.service_key === key);
  const latest = service?.versions[0]; const previous = service?.versions[1];
  const max = Math.max(1, ...[latest, previous].flatMap(scan => levels.map(level => scan?.counts[level] || 0)));
  return <section className="panel padded cyber-history"><div className="cyber-section-heading"><div><p className="eyebrow">SERVICE EXPLORER</p><h2>Version changes & scan trend</h2></div><label>Compare service<select value={key} onChange={event => setSelected(event.target.value)}><option value="" disabled>Select a service</option>{services.map(item => <option key={item.service_key} value={item.service_key}>{item.name}</option>)}</select></label></div>
    {current?.error ? <div role="alert"><p>{current.error}</p><button onClick={() => setAttempt(value => value + 1)}>Retry history</button></div> : asynchronous && key && !service ? <p role="status">Loading service history…</p> : !service ? <p className="cyber-empty">No service scan history is available yet.</p> : <><p className="cyber-muted">Unique CVEs observed in service-wide scans. Comparing the most recently scanned distinct versions, not release order. Counts reflect each scan’s scope and settings.</p>
      {latest && previous ? <><div className="cyber-comparison-summary"><span>Previous <strong>{previous.version}</strong> · {previous.total} CVEs</span><span>Latest <strong>{latest.version}</strong> · {latest.total} CVEs</span><span>Change <strong>{latest.total - previous.total > 0 ? '+' : ''}{latest.total - previous.total}</strong></span></div>
        {(!latest.complete || !previous.complete) && <p className="cyber-caution" role="note">Incomplete scan: these are observed counts only. A decrease does not establish that vulnerabilities were resolved.</p>}
        <p className="cyber-muted">Previous scan: {previous.scanned_at.slice(0, 10)} · Latest scan: {latest.scanned_at.slice(0, 10)}</p>
        <div className="cyber-comparison">{levels.map(level => { const delta = (latest.counts[level] || 0) - (previous.counts[level] || 0); return <div key={level}><div className="cyber-comparison-label"><strong>{level}</strong><span>{delta > 0 ? '+' : ''}{delta}</span></div>{[previous, latest].map((scan, index) => <div className="cyber-version-bar" key={scan.execution_id}><span>{index ? 'Latest' : 'Previous'}</span><div className="cyber-bar-track"><div className={`cyber-bar cyber-${level.toLowerCase()} ${index ? '' : 'cyber-previous'}`} style={{ width: `${(scan.counts[level] || 0) / max * 100}%` }} /></div><strong>{scan.counts[level] || 0}</strong></div>)}</div>; })}</div></> : <p className="cyber-empty">Two distinct versioned service scans are needed for a version comparison.</p>}
      <h3>Recent scan trend</h3>{service.trend.length ? <div className="cyber-trend" role="list" aria-label="Recent service scans">{service.trend.map(scan => <div role="listitem" key={scan.execution_id}><div className="cyber-trend-column" aria-hidden="true">{levels.map(level => <div key={level} className={`cyber-${level.toLowerCase()}`} style={{ height: `${(scan.counts[level] || 0) / Math.max(1, ...service.trend.map(item => item.total)) * 120}px` }} />)}</div><strong>{scan.total}</strong><span>{scan.version}</span><time dateTime={scan.scanned_at}>{scan.scanned_at.slice(0, 10)}</time>{!scan.complete && <span className="cyber-caution">Incomplete</span>}<span className="sr-only">{levels.map(level => `${level}: ${scan.counts[level] || 0}`).join(', ')}</span></div>)}</div> : <p>No service-wide scans available.</p>}</>}
    {service?.comparison_limited && <p className="cyber-muted" role="note">Version comparison searches the latest {service.candidate_limit || 128} service scans. An older distinct version may exist outside this window.</p>}
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

export function Page({ data: pageData }: { data: PageData }) {
  const {data, error, retry} = useDashboard(pageData);
  if (!data) return <><PageHeader title="Cybersecurity"/><section className="panel" aria-busy={!error}>{error ? <ErrorState title="Dashboard data could not be loaded" onRetry={retry} retryLabel="Retry dashboard">{error}</ErrorState> : <Loading label="Loading dashboard data…"/>}</section></>;
  return <Portfolio data={data} asynchronous={Boolean(pageData.dashboard_url)}/>;
}
function Portfolio({data: pageData, asynchronous}: {data: PageData; asynchronous: boolean}) {
  const data = pageData as SecurityData;
  const metrics = data.metrics || {};
  const cards: [string, string | number, Tone?][] = [
    ['Cyber Attention', metrics.attention || 0, metrics.attention ? 'warning' : undefined], ['Services / scanned', `${metrics.services || 0} / ${metrics.scanned || 0}`],
    ['Active vulnerabilities', metrics.vulnerabilities || 0], ['Critical / High', metrics.critical_high || 0, metrics.critical_high ? 'danger' : undefined],
    ['Patchable', metrics.patchable || 0], ['Missing Evidence', metrics.missing || 0, metrics.missing ? 'warning' : undefined],
  ];
  const [detail, setDetail] = useState<{key: string; label: string} | null>(null);
  const openDetail = (key: string, label: string) => setDetail({key, label});
  return <>
    <PageHeader eyebrow="Current posture" title="Cybersecurity" description="Service evidence requiring review. Green means compliant, yellow means compliant with warnings, and red follows the configured CATS compliance policy."/>
    {data.posture_preparing > 0 ? <p className="page-refresh-notice" role="status">Posture is still being prepared for {data.posture_preparing} {data.posture_preparing === 1 ? 'service' : 'services'}; {data.posture_preparing === 1 ? 'it is' : 'they are'} not listed yet and totals exclude {data.posture_preparing === 1 ? 'it' : 'them'}. Refresh shortly.</p>
      : data.posture_refreshing && <p className="page-refresh-notice" role="status">Service posture is being refreshed after a portfolio-wide change; some rows may briefly show their previous values.</p>}
    <MetricGrid className="cyber-metrics" label="Posture summary">{cards.map(([label, value, tone]) => <MetricCard key={label} label={label} value={value || 0} tone={tone} onClick={() => openDetail(["attention", "services", "vulnerabilities", "critical_high", "patchable", "missing"][cards.findIndex(card => card[0] === label)], label)}/>)}</MetricGrid>
    <div className="cyber-chart-grid"><section className="panel padded"><p className="eyebrow">VULNERABILITY DISTRIBUTION</p><h2>Active findings by severity</h2><p className="cyber-muted">Across all services you can access; table filters do not change these totals.</p><Bars onSelect={openDetail} counts={Object.fromEntries(levels.map(level => [level, metrics[level.toLowerCase()] || 0]))} /></section>
      <section className="panel padded"><p className="eyebrow">POLICY & COVERAGE</p><h2>Service posture</h2><div className="cyber-posture"><div className="cyber-donut" role="img" aria-label={`Service posture: ${metrics.green || 0} compliant, ${metrics.yellow || 0} warnings, ${metrics.red || 0} non-compliant`} style={{ background: metrics.services ? `conic-gradient(var(--success) 0 ${(metrics.green || 0) / metrics.services * 100}%, var(--warning) ${(metrics.green || 0) / metrics.services * 100}% ${((metrics.green || 0) + (metrics.yellow || 0)) / metrics.services * 100}%, var(--danger) ${((metrics.green || 0) + (metrics.yellow || 0)) / metrics.services * 100}% 100%)` : undefined }}><div><strong>{metrics.services || 0}</strong><span>services</span></div></div><dl className="cyber-coverage">{[['Compliant', metrics.green], ['Warnings', metrics.yellow], ['Non-compliant', metrics.red], ['SBOM coverage', `${metrics.sbom_coverage || 0} / ${metrics.scanned || 0}`], ['KEV / watchlist', `${metrics.kev || 0} / ${metrics.watchlist || 0}`], ['Open / overdue POA&M', `${metrics.poam || 0} / ${metrics.poam_overdue || 0}`], ['Validation failures', metrics.kind_failed]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{label === 'KEV / watchlist' || label === 'Open / overdue POA&M' || label === 'SBOM coverage' ? <>{(label === 'KEV / watchlist' ? [['kev', 'KEV', metrics.kev], ['watchlist', 'Watchlist', metrics.watchlist]] : label === 'Open / overdue POA&M' ? [['poam', 'Open POA&M', metrics.poam], ['poam_overdue', 'Overdue POA&M', metrics.poam_overdue]] : [['sbom_coverage', 'SBOM coverage', metrics.sbom_coverage], ['scanned', 'Scanned services', metrics.scanned]]).map(([key, name, count], index) => <span key={key}>{index > 0 && ' / '}<button type="button" className="cyber-detail-trigger" aria-label={String(name)} onClick={() => openDetail(String(key), String(name))}>{count || 0}</button></span>)}</> : <button type="button" className="cyber-detail-trigger" aria-label={String(label)} onClick={() => openDetail(({Compliant: 'green', Warnings: 'yellow', 'Non-compliant': 'red', 'Validation failures': 'kind_failed'} as Record<string, string>)[String(label)], String(label))}>{value || 0}</button>}</dd></div>)}</dl></div><p className="cyber-muted">No findings does not mean complete evidence. Posture follows your configured compliance policy.</p></section></div>
    <HistoryPanel history={data.history || []} services={data.services || data.history || []} asynchronous={asynchronous}/>
    <p className="cyber-muted">Explore per-service evidence and filters in the <a href="/">Services security matrix</a>.</p>
    {detail && <MetricDetails metric={detail.key} label={detail.label} onClose={() => setDetail(null)}/>}
  </>;
}

interface DetailData {
  title: string; description: string;
  services: {service_key: string; name: string; count: number}[];
  cves: {cve: string; count: number}[];
  packages: {package: string; count: number}[];
}
function MetricDetails({metric, label, onClose}: {metric: string; label: string; onClose: () => void}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [data, setData] = useState<DetailData | null>(null);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    dialog.current?.showModal();
    const controller = new AbortController();
    setData(null); setError('');
    requestJson<DetailData>(`/api/dashboard/cybersecurity/metrics/${encodeURIComponent(metric)}`, {signal: controller.signal})
      .then(value => {if (!controller.signal.aborted) setData(value);})
      .catch(reason => {if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : 'Details could not be loaded.');});
    return () => controller.abort();
  }, [metric, attempt]);
  return <dialog ref={dialog} className="review-dialog cyber-detail-dialog" aria-labelledby="metric-detail-title" onCancel={onClose} onClose={onClose}>
    <div className="cyber-section-heading"><h2 id="metric-detail-title">{data?.title || label}</h2><button type="button" className="secondary-button" onClick={() => dialog.current?.close()}>Close</button></div>
    {error ? <ErrorState onRetry={() => setAttempt(value => value + 1)}>{error}</ErrorState> : !data ? <Loading label="Loading metric details…"/> : <>
      <p>{data.description}</p><p className="cyber-muted">Top 10 in each group, across active services you can access. Select a service to investigate its evidence.</p>
      {data.services.length > 0 && <section><h3>Affected services</h3><ol>{data.services.map(row => <li key={row.service_key}><a href={`/services/${encodeURIComponent(row.service_key)}`}>{row.name}</a><strong>{row.count}</strong></li>)}</ol></section>}
      {data.cves.length > 0 && <section><h3>Most frequent CVEs</h3><ol>{data.cves.map(row => <li key={row.cve}><span>{row.cve}</span><strong>{row.count}</strong></li>)}</ol></section>}
      {data.packages.length > 0 && <section><h3>Most frequent packages</h3><ol>{data.packages.map(row => <li key={row.package}><span>{row.package}</span><strong>{row.count}</strong></li>)}</ol></section>}
      {!data.services.length && !data.cves.length && !data.packages.length && <p>No matching evidence is available.</p>}
    </>}
  </dialog>;
}
