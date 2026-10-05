const severities = ['Critical', 'High', 'Medium', 'Low'] as const;
const count = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;

export function ComparisonCharts({before, after, validation = [], deploymentStatus}: {before: any, after: any, validation?: any[], deploymentStatus?: string}) {
  const rows = severities.map(severity => ({severity, before: count(before?.vulnerabilities?.[severity]), after: count(after?.vulnerabilities?.[severity])}));
  const maximum = Math.max(1, ...rows.flatMap(row => [row.before ?? 0, row.after ?? 0]));
  return <div className="remediation-comparison">
    <section className="comparison-card" aria-label="Vulnerabilities before and after">
      <p className="eyebrow">VULNERABILITY DISTRIBUTION</p><h3>Findings by severity</h3>
      <p>Before and after candidate scan observations. Missing evidence is not zero.</p>
      {rows.map(row => <div className="comparison-severity" key={row.severity} data-severity={row.severity}>
        <strong>{row.severity}</strong>
        {(['before', 'after'] as const).map(period => <div className={`comparison-bar-row ${period}`} key={period}>
          <span>{period === 'before' ? 'Before' : 'After'}</span><div className="comparison-track" aria-hidden="true"><div style={{width: `${(row[period] ?? 0) / maximum * 100}%`}}/></div><b>{row[period] ?? 'Unavailable'}</b>
        </div>)}
      </div>)}
    </section>
    <section className="comparison-card" aria-label="Assessment metric changes">
      <p className="eyebrow">BEFORE / AFTER</p><h3>Assessment changes</h3>
      <p>Candidate results do not imply delivery or deployment verification.</p>
      {[['patchable_vulnerabilities', 'Patchable vulnerabilities'], ['configuration_findings', 'Configuration observations'], ['kev', 'Known exploited vulnerabilities'], ['images', 'Images assessed']].map(([key, label]) => {
        const original = count(before?.[key]), candidate = count(after?.[key]);
        const delta = original !== null && candidate !== null ? candidate - original : null;
        return <div className="comparison-metric" key={key}><strong>{label}</strong>{(['before','after'] as const).map(period => {
          const value = period === 'before' ? original : candidate;
          return <div className={`comparison-bar-row ${period}`} key={period}><span>{period === 'before' ? 'Before' : 'After'}</span><div className="comparison-track" aria-hidden="true"><div style={{width:`${(value ?? 0) / Math.max(1,original ?? 0,candidate ?? 0) * 100}%`}}/></div><b>{value ?? 'Unavailable'}</b></div>;
        })}<small>{delta === null ? 'Comparison unavailable' : delta === 0 ? 'No count change' : `${Math.abs(delta)} ${delta < 0 ? 'fewer' : 'more'}`}</small></div>;
      })}
    </section>
    <section className="comparison-card" aria-label="Validation and risk"><p className="eyebrow">CHECKS / RISK</p><h3>Validation and risk</h3>
      {[
        ['Helm rendering', 'Can the chart produce Kubernetes manifests? This does not verify deployment.', before?.helm_render, validation.find(row => row.name === 'helm_template')?.status],
        ['Configuration policy', 'PASS means no configuration findings were reported; FAIL means findings remain.', before?.policy_validation, after?.policy_validation],
        ['Deployment validation', 'Checks the candidate in a runtime environment. Not run means deployment has not been verified.', undefined, deploymentStatus || 'NOT RUN'],
      ].map(([label,description,original,candidate]) => <div className="comparison-metric" key={label}><strong>{label}</strong><p>{description}</p><div><span>Before <span className="badge">{original || 'Unavailable'}</span></span><span>After <span className="badge">{candidate || 'Unavailable'}</span></span></div></div>)}
      <div className="comparison-metric"><strong>Highest EPSS score</strong><p>The highest estimated exploitation probability among the assessed vulnerabilities. Unavailable means no score was retained.</p><div>{(['before','after'] as const).map(period => {const value = count((period === 'before' ? before : after)?.epss_max);return <span key={period}>{period === 'before' ? 'Before' : 'After'} <b>{value === null ? 'Unavailable' : `${(value * 100).toFixed(2)}%`}</b></span>;})}</div></div>
    </section>
  </div>;
}
