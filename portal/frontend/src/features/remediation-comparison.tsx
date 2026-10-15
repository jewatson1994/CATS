import {StatusBadge} from '../components/ui';

const severities = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];
const count = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
const statusLabel = (value: string) => value.toUpperCase() === 'NOT_APPLICABLE' ? 'Not Applicable' : value;

export function ComparisonCharts({before, after, validation = [], deploymentStatus}: {before: any, after: any, validation?: any[], deploymentStatus?: string}) {
  const categories = [...new Set([...severities, ...Object.keys(before?.vulnerabilities || {}), ...Object.keys(after?.vulnerabilities || {})])];
  const rows = categories.map(severity => ({severity, before: count(before?.vulnerabilities?.[severity]), after: count(after?.vulnerabilities?.[severity])}));
  const maximum = Math.max(1, ...rows.flatMap(row => [row.before ?? 0, row.after ?? 0]));
  return <div className="remediation-comparison">
    <section className="comparison-card" aria-label="Vulnerabilities before and after">
      <p className="eyebrow">VULNERABILITY DISTRIBUTION</p><h3>Findings by severity</h3>
      <p>Scan observations for each assessment. Missing evidence is not zero.</p>
      <div className="table-wrap"><table className="severity-comparison"><thead><tr><th scope="col">Severity</th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>
        {rows.map(row => <tr className="comparison-severity" key={row.severity} data-severity={row.severity}><th scope="row">{row.severity}</th>{(['before', 'after'] as const).map(period => <td key={period}><div className={`severity-value ${period}`}><b>{row[period] ?? 'Unavailable'}</b><div className="comparison-track" aria-hidden="true"><div style={{width: `${(row[period] ?? 0) / maximum * 100}%`}}/></div></div></td>)}</tr>)}
      </tbody></table></div>
    </section>
    <section className="comparison-card" aria-label="Assessment metric changes">
      <p className="eyebrow">BEFORE / AFTER</p><h3>Assessment changes</h3>
      <p>Counts describe each scan's coverage; reductions do not by themselves prove fixes.</p>
      <div className="table-wrap"><table className="metric-comparison"><thead><tr><th scope="col">Metric</th><th scope="col">Before</th><th scope="col">After</th><th scope="col">Change</th></tr></thead><tbody>
        {[['vulnerability_observations', 'Vulnerability observations'], ['patchable_vulnerabilities', 'Findings with a known fix'], ['configuration_findings', 'Configuration observations'], ['kev', 'Known exploited vulnerabilities'], ['images', 'Images assessed']].map(([key, label]) => {
          const original = count(before?.[key]), candidate = count(after?.[key]);
          const originalNA = key === 'configuration_findings' && before?.configuration_applicable === false;
          const candidateNA = key === 'configuration_findings' && after?.configuration_applicable === false;
          const delta = !originalNA && !candidateNA && original !== null && candidate !== null ? candidate - original : null;
          return <tr key={key}><th scope="row">{label}</th><td>{originalNA ? 'Not Applicable' : original ?? 'Unavailable'}</td><td>{candidateNA ? 'Not Applicable' : candidate ?? 'Unavailable'}</td><td><span className="comparison-delta neutral">{originalNA || candidateNA ? 'Not Applicable' : delta === null ? 'Comparison unavailable' : delta === 0 ? 'No count change' : `${Math.abs(delta)} ${delta < 0 ? 'fewer' : 'more'}`}</span></td></tr>;
        })}
      </tbody></table></div>
      {[...new Set([before?.comparison_note, after?.comparison_note].filter(Boolean))].map(note => <p key={note} className="comparison-note">{note}</p>)}
      <div className="comparison-epss"><strong>Highest EPSS score</strong><div>{(['before','after'] as const).map(period => {const value = count((period === 'before' ? before : after)?.epss_max);return <span key={period}>{period === 'before' ? 'Before' : 'After'} <b>{value === null ? 'Unavailable' : `${(value * 100).toFixed(2)}%`}</b></span>;})}</div><p>Highest estimated exploitation probability among assessed vulnerabilities.</p></div>
    </section>
    <section className="comparison-card comparison-checks" aria-label="Validation and risk"><p className="eyebrow">VALIDATION SCOPE</p><h3>Candidate checks</h3>
      <div className="table-wrap"><table><thead><tr><th scope="col">Check</th><th scope="col">Before</th><th scope="col">After</th><th scope="col">What it tells you</th></tr></thead><tbody>
        {[
          ['Helm rendering', 'Checks chart rendering when Helm charts are included.', before?.helm_render, after?.helm_render || validation.find(row => row.name === 'helm_template')?.status],
          ['Configuration policy', 'Reports configuration findings for applicable candidate manifests.', before?.policy_validation, after?.policy_validation],
          ['Deployment validation', 'Runtime verification is separate from image inspection and static scans.', undefined, deploymentStatus || 'NOT RUN'],
        ].map(([label,description,original,candidate]) => <tr key={label}><th scope="row">{label}</th><td><StatusBadge value={original || 'Unavailable'} label={statusLabel(original || 'Unavailable')}/></td><td><StatusBadge value={candidate || 'Unavailable'} label={statusLabel(candidate || 'Unavailable')}/></td><td>{description}</td></tr>)}
      </tbody></table></div>
    </section>
  </div>;
}
