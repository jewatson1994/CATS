import {Fragment, useMemo, useState} from 'react';
import {SeverityBadge} from '../components/ui';

type Row = Record<string, any>;
const levels = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];
const text = (value: any): string => typeof value === 'string' || typeof value === 'number' ? String(value) : '';
const score = (value: any): number | null => {
  if (!['string', 'number'].includes(typeof value) || String(value).trim() === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 && number <= 1 ? number : null;
};
const flag = (value: any): boolean | null => {
  if ([true, 1, 'true', 'yes', 'Yes'].includes(value)) return true;
  if ([false, 0, 'false', 'no', 'No'].includes(value)) return false;
  return null;
};
export type ReviewFinding = {id: string; severity: string; image: string; package: string; version: string; fixed: string; epss: number | null; kev: boolean | null; scanner: string; raw: Row};

// Read only retained evidence. Never enrich an immutable review with today's feeds.
export function reviewFindings(findings: any, intelligence?: Row): ReviewFinding[] {
  const result: ReviewFinding[] = [];
  function add(row: Row, image = '', scanner = '') {
    if (!row || typeof row !== 'object') return;
    const vulnerability = row.vulnerability || {}, evidence = row.evidence || {};
    const rawSeverity = text(row.severity || vulnerability.severity || row.Severity).toLowerCase();
    const epss = row.epss ?? row.epss_score ?? evidence.epss ?? evidence.epss_score ?? vulnerability.epss?.[0]?.epss;
    const exploited = vulnerability.knownExploited;
    result.push({id: text(row.cve || row.finding || row.VulnerabilityID || vulnerability.id) || 'Unidentified finding',
      severity: levels.includes(rawSeverity) ? rawSeverity : 'unknown',
      image: text(row.image) || image, package: text(row.package?.name || row.package || row.artifact?.name || row.PkgName),
      version: text(row.installed_version || row.version || row.artifact?.version || row.InstalledVersion),
      fixed: text(row.fixed_version || row.FixedVersion) || (Array.isArray(vulnerability.fix?.versions) ? vulnerability.fix.versions.join(', ') : ''),
      epss: score(epss), kev: flag(row.kev ?? row.known_exploited ?? evidence.kev ?? evidence.known_exploited)
        ?? (Array.isArray(exploited) ? exploited.length > 0 : null), scanner: text(row.scanner) || scanner, raw: row});
  }
  if (Array.isArray(findings)) findings.forEach(row => {if (row && typeof row === 'object') add(row);});
  else if (findings && typeof findings === 'object') {
    const rows = findings.vulnerabilities || findings.findings;
    if (Array.isArray(rows)) rows.forEach(row => {if (row && typeof row === 'object') add(row);});
    Object.entries(findings.vulnerability_scans || {}).forEach(([image, scan]: [string, any]) => {
      if (Array.isArray(scan?.matches)) scan.matches.forEach((row: Row) => add(row, text(scan.source?.target?.userInput) || image, 'Grype'));
      if (Array.isArray(scan?.Results)) scan.Results.forEach((target: Row) => {
        if (Array.isArray(target?.Vulnerabilities)) target.Vulnerabilities.forEach((row: Row) => add(row, scan.ArtifactName || image, 'Trivy'));
      });
    });
  }
  if (intelligence?.basis === 'approval-request') {
    for (const row of result) {
      const lookup = intelligence.findings?.[row.id.toUpperCase()];
      row.kev = flag(lookup?.kev);
      row.epss = score(lookup?.epss);
    }
  }
  return result;
}

const percent = (value: number | null) => value == null ? 'Not recorded' : `${(value * 100).toFixed(2)}%`;
const recorded = (value: any) => text(value) || 'Not recorded';
export function ApprovalFindings({findings, intelligence}: {findings: any; intelligence?: Row}) {
  const rows = useMemo(() => reviewFindings(findings, intelligence), [findings, intelligence]);
  const [query, setQuery] = useState(''), [severity, setSeverity] = useState('all'), [signal, setSignal] = useState('all');
  const [threshold, setThreshold] = useState(90), [sort, setSort] = useState('risk'), [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [selectedImage, setSelectedImage] = useState('');
  const counts = levels.map(level => rows.filter(row => row.severity === level).length);
  const topImages = useMemo(() => {
    const images = new Map<string, number>();
    let unattributed = 0;
    for (const row of rows) {
      if (row.severity !== severity) continue;
      if (!row.image) {unattributed++; continue;}
      images.set(row.image, (images.get(row.image) || 0) + 1);
    }
    return {items: [...images].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5), unattributed};
  }, [rows, severity]);
  const kev = rows.filter(row => row.kev === true).length, epss = rows.filter(row => row.epss != null && row.epss >= threshold / 100).length;
  const filtered = useMemo(() => rows.map((row, index) => ({...row, index})).filter(row =>
    (severity === 'all' || row.severity === severity) &&
    (!selectedImage || row.image === selectedImage) &&
    (!query || [row.id, row.image, row.package, row.scanner].join(' ').toLowerCase().includes(query.toLowerCase())) &&
    (signal === 'all' || signal === 'kev' && row.kev === true || signal === 'epss' && row.epss != null && row.epss >= threshold / 100 ||
      signal === 'fix' && !!row.fixed || signal === 'unknown' && (row.epss == null || row.kev == null)))
    .sort((a, b) => {
      const bySeverity = levels.indexOf(a.severity) - levels.indexOf(b.severity);
      if (sort === 'id') return a.id.localeCompare(b.id);
      if (sort === 'severity') return bySeverity || a.id.localeCompare(b.id);
      if (sort === 'epss') return (b.epss ?? -1) - (a.epss ?? -1) || bySeverity;
      return Number(b.kev === true) - Number(a.kev === true) || (b.epss ?? -1) - (a.epss ?? -1) || bySeverity;
    }), [rows, query, severity, signal, threshold, sort, selectedImage]);
  const pages = Math.max(1, Math.ceil(filtered.length / 25)), current = Math.min(page, pages - 1);
  const reset = () => {setPage(0); setExpanded(null);};
  return <section className="approval-risk" aria-labelledby="approval-findings-title">
    <div className="approval-risk-title"><div><p className="eyebrow">RETAINED SCAN RESULTS</p><h2 id="approval-findings-title">Vulnerability findings</h2><p>Explore the findings captured when this request was submitted.</p></div><span className="approval-count">{rows.length.toLocaleString()} observations</span></div>
    <div className="approval-risk-stats">
      {[['Critical / high', counts[0] + counts[1], 'critical'], ['Known exploited · KEV', kev, 'kev'], [`EPSS ≥ ${threshold}%`, epss, 'epss'], ['Fix reported', rows.filter(row => row.fixed).length, 'fix']].map(([name, count, key]) =>
        <div className={`approval-stat approval-stat-${key}`} key={key}><span>{name}</span><strong>{Number(count).toLocaleString()}</strong></div>)}
    </div>
    <div className="approval-risk-overview">
      <div className="approval-severity-chart" role="group" aria-label="Finding observations by severity">
        <h3>Severity distribution</h3><p>Select a bar to see the top five container images and filter the table.</p>
        {levels.map((level, i) => <button key={level} type="button" className={`approval-chart-row level-${level}`} aria-label={`${level}: ${counts[i]} observations`} aria-pressed={severity === level} onClick={() => {setSeverity(severity === level ? 'all' : level); reset();}}>
          <span>{level}</span><span className="approval-bar-track"><span style={{width:`${counts[i] / Math.max(1, ...counts) * 100}%`}}/></span><strong>{counts[i].toLocaleString()}</strong>
        </button>)}
        {severity !== 'all' && <section className="approval-top-images" aria-label={`Top containers for ${severity}`} aria-live="polite">
          <h4>Top 5 containers · {severity}</h4><p>Ranked by {severity} finding observations across this snapshot, independent of the table’s search and risk filters.</p>
          <p>Select a container to filter its findings. Select it again to clear the container filter.</p>
          {topImages.items.length ? <ol>{topImages.items.map(([image, count]) => <li key={image}><button type="button" className="approval-top-image" aria-label={`Filter container ${image}`} aria-pressed={selectedImage === image} onClick={() => {setSelectedImage(selectedImage === image ? '' : image); reset();}}><code>{image}</code><strong>{count.toLocaleString()} <span>observations</span></strong></button></li>)}</ol> : <p>No container images recorded for this severity.</p>}
          {!!topImages.unattributed && <small>{topImages.unattributed.toLocaleString()} observations have no recorded image and are excluded from this ranking.</small>}
        </section>}
      </div>
      <aside className="approval-intelligence"><h3>Exploit intelligence</h3><p><strong>KEV</strong> identifies findings marked as known exploited in the retained evidence.</p><p><strong>EPSS</strong> is shown as a probability percentage. The cutoff below changes this review view only, not compliance policy.</p>
        <div className="approval-feed-versions">
          <h4>Intelligence dataset versions</h4>
          <p>{intelligence?.basis === 'approval-request' ? <>Captured at request: <time>{recorded(intelligence.captured_at)}</time>. These lookups are frozen for this review; the original scan evidence remains available below.</> : 'Dataset provenance was not retained for this snapshot. The values below come from the retained scan evidence.'}</p>
          <dl>
            <dt>KEV catalog version</dt><dd>{recorded(intelligence?.kev?.metadata?.catalog_version)}</dd>
            <dt>KEV release date</dt><dd>{recorded(intelligence?.kev?.metadata?.date_released)}</dd>
            <dt>EPSS model version</dt><dd>{recorded(intelligence?.epss?.metadata?.model_version)}</dd>
            <dt>EPSS score date</dt><dd>{recorded(intelligence?.epss?.metadata?.score_date)}</dd>
          </dl>
          {intelligence && <small>KEV catalog: {recorded(intelligence.kev?.state)} · EPSS catalog: {recorded(intelligence.epss?.state)}</small>}
        </div>
        <label>EPSS review cutoff (%)<input type="number" min="0" max="100" step="1" value={threshold} onChange={event => {setThreshold(Math.min(100, Math.max(0, Number(event.target.value)))); reset();}}/></label>
        <div className="approval-coverage"><span>EPSS recorded <strong>{rows.filter(row => row.epss != null).length.toLocaleString()} / {rows.length.toLocaleString()}</strong></span><span>KEV status recorded <strong>{rows.filter(row => row.kev != null).length.toLocaleString()} / {rows.length.toLocaleString()}</strong></span></div>
        <small>Missing intelligence is not a negative result. Counts are finding observations; the same CVE can affect several packages or images.</small>
      </aside>
    </div>
    <div className="approval-findings-filters" role="search" aria-label="Review finding filters">
      <label>Search findings<input type="search" placeholder="CVE, package, image, scanner…" value={query} onChange={event => {setQuery(event.target.value); reset();}}/></label>
      <label>Severity<select value={severity} onChange={event => {setSeverity(event.target.value); reset();}}><option value="all">All severities</option>{levels.map(level => <option key={level} value={level}>{level}</option>)}</select></label>
      <label>Risk signal<select value={signal} onChange={event => {setSignal(event.target.value); reset();}}><option value="all">All findings</option><option value="kev">KEV hits</option><option value="epss">EPSS above cutoff</option><option value="fix">Fix reported</option><option value="unknown">Missing intelligence</option></select></label>
      <label>Sort findings<select value={sort} onChange={event => {setSort(event.target.value); reset();}}><option value="risk">KEV, then EPSS</option><option value="severity">Severity</option><option value="epss">Highest EPSS</option><option value="id">Finding ID</option></select></label>
    </div>
    {selectedImage && <div className="approval-container-filter"><span>Container: <code>{selectedImage}</code></span><button type="button" onClick={() => {setSelectedImage(''); reset();}}>Clear container filter</button></div>}
    <div className="approval-findings-table" tabIndex={0} role="region" aria-label="Retained vulnerability findings">
      <table><thead><tr>{['Finding / package', 'Severity', 'Affected image', 'KEV', 'EPSS', 'Fix version'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead><tbody>
        {filtered.slice(current * 25, (current + 1) * 25).map(row => <Fragment key={row.index}><tr>
          <td><button className="approval-finding-link" type="button" aria-expanded={expanded === row.index} aria-controls={`review-finding-${row.index}`} onClick={() => setExpanded(expanded === row.index ? null : row.index)}>{row.id}</button><small>{row.package || 'Package not recorded'}{row.version && ` · ${row.version}`}</small>{row.scanner && <small>{row.scanner}</small>}</td>
          <td><SeverityBadge severity={row.severity}/></td><td><code>{row.image || 'Not recorded'}</code></td>
          <td><span className={row.kev === true ? 'approval-signal kev' : 'approval-muted'}>{row.kev === true ? 'KEV hit' : row.kev === false ? 'No' : 'Not recorded'}</span></td>
          <td><span className={row.epss != null && row.epss >= threshold / 100 ? 'approval-signal epss' : ''}>{percent(row.epss)}</span></td><td>{row.fixed || 'Not reported'}</td>
        </tr>{expanded === row.index && <tr id={`review-finding-${row.index}`}><td colSpan={6}><strong>Retained finding evidence</strong><pre className="approval-json">{JSON.stringify(row.raw, null, 2)}</pre></td></tr>}</Fragment>)}
        {!filtered.length && <tr><td colSpan={6} className="empty">{rows.length ? 'No findings match these filters.' : 'No vulnerability observations were retained in a supported scan format. Check scan coverage and the complete snapshot below.'}</td></tr>}
      </tbody></table>
    </div>
    <div className="approval-pagination"><span role="status">{filtered.length ? `${current * 25 + 1}–${Math.min((current + 1) * 25, filtered.length)} of ${filtered.length.toLocaleString()} observations` : '0 observations'}</span><div><button type="button" disabled={current === 0} onClick={() => {setPage(current - 1); setExpanded(null);}}>Previous</button><span>Page {current + 1} of {pages}</span><button type="button" disabled={current + 1 >= pages} onClick={() => {setPage(current + 1); setExpanded(null);}}>Next</button></div></div>
  </section>;
}
