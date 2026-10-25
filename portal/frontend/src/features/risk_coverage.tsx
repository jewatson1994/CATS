import {useState} from 'react';
import {requestJson} from '../api';

type Row = Record<string, any>;
const pretty = (value: unknown) => JSON.stringify(value, null, 2);
const humanize = (value: string) => value.replaceAll('_', ' ');
const coverageLabels: Record<string, string> = {
  authoritative_vex: 'Exact VEX candidate evidence',
  applicable_vex: 'Verified applicable VEX',
  advisory_only: 'Advisory-only evidence',
  kev: 'KEV enrichment',
  epss: 'EPSS enrichment',
  no_intelligence: 'No relevant intelligence',
  unresolved_identity: 'Unresolved identity',
  stale_or_conflicting: 'Stale or conflicting evidence',
};
const optionalCoverageLabels: Record<string, string> = {
  direct_vex_candidates: 'Candidates for the observed identity',
  resolved_identity: 'Authoritatively resolved package identities',
  resolved_vex_candidates: 'Candidates through resolved identities',
  direct_applicable_vex: 'Applicable VEX through observed identities',
  resolved_applicable_vex: 'Applicable VEX through resolved identities',
  exact_candidates: 'Exact VEX candidate evidence',
  rejected_identity: 'Rejected identity matches',
  missing_product_context: 'Missing product context',
  cve_absent: 'No matching CVE in VEX',
  identity_rejected: 'Rejected identity matches',
};
const vexLabels: Record<string, string> = {
  affected: 'Verified Affected', not_affected: 'Verified Not Affected', fixed: 'Verified Fixed',
  under_investigation: 'Under Investigation', no_vex: 'No VEX', unknown: 'No VEX evaluation',
  stale: 'Stale VEX', conflicting: 'Conflicting VEX', withdrawn: 'Withdrawn VEX',
  unverified: 'Unverified VEX', missing_product_context: 'Missing product context', missing_context: 'Unresolved product identity',
};
const advisoryMatchLabels: Record<string, string> = {
  explicit_version_list: 'CVE, package and explicitly listed version match',
  package_reference_ranges_not_evaluated: 'CVE and package reference match; affected version ranges have not been evaluated',
  package_reference_secdb_fix_not_evaluated: 'CVE, package and distribution reference match; the fixed-version comparison has not been evaluated',
};
function Json({value}: {value: unknown}) {return <pre className="risk-json">{pretty(value)}</pre>;}
function CoverageTable({report, caption}: {report: Row, caption: string}) {
  const denominator = report.total_findings;
  const categories = {...coverageLabels, ...Object.fromEntries(Object.entries(optionalCoverageLabels).filter(([key]) => report.counts?.[key] != null))};
  return <div className="risk-table"><table><caption>{caption} — {denominator.toLocaleString()} unique findings</caption>
    <thead><tr><th scope="col">Evidence category</th><th scope="col">Unique findings / total</th><th scope="col">Percent of total findings</th></tr></thead>
    <tbody>{Object.entries(categories).map(([key, label]) => {
      const count = report.counts?.[key];
      return <tr key={key}><th scope="row">{label}</th><td>{count == null ? 'Not recorded' : `${count.toLocaleString()} / ${denominator.toLocaleString()}`}</td><td>{count == null ? 'Not recorded' : denominator > 0 ? `${(100 * count / denominator).toFixed(1)}%` : 'Not applicable (no findings)'}</td></tr>;
    })}</tbody>
  </table></div>;
}
export function IntelligenceCoverage({assessment}: {assessment: Row}) {
  const coverage = assessment.summary?.coverage;
  if (!coverage) return <p className="risk-callout">Intelligence coverage was not recorded for this assessment. Reassess to generate the coverage report.</p>;
  return <section aria-label="Intelligence coverage" className="risk-coverage">
    <h3>Intelligence coverage</h3>
    <p>Each percentage uses the unique findings in its service or image as the denominator. A finding is counted once in each category, even when several sources or scanner observations support it. Categories overlap and must not be added together.</p>
    <p>Image totals must not be added to produce a service total: a finding may appear in more than one image. Advisory evidence does not establish VEX applicability or a Not Affected status.</p>
    <p>Candidate VEX evidence may still fail identity, trust or freshness checks. Only verified applicable VEX has passed those checks.</p>
    <CoverageTable report={coverage} caption="Service coverage"/>
    {(coverage.images || []).map((image: Row, index: number) => <details key={`${image.image}:${image.image_digest}:${index}`}>
      <summary>Image: {image.image || 'Image not identified'}{image.image_digest ? ` · ${image.image_digest}` : ' · digest not recorded'}</summary>
      <CoverageTable report={image} caption={`Coverage for ${image.image || 'unidentified image'}`}/>
    </details>)}
    {coverage.definitions && <details><summary>Coverage definitions</summary><Json value={coverage.definitions}/></details>}
    <details><summary>Reproducible coverage data</summary><p>Assessment #{assessment.id} · recorded {coverage.as_of || assessment.as_of}. Counts describe this saved assessment.</p><Json value={{assessment_id: assessment.id, as_of: coverage.as_of || assessment.as_of, source_execution_id: assessment.source_execution_id, coverage}}/></details>
  </section>;
}
function OriginalEvidence({url, label}: {url: string, label: string}) {
  const [value, setValue] = useState<Row | null>(null), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true); setError('');
    try {setValue(await requestJson<Row>(url));}
    catch (error) {setError(error instanceof Error ? error.message : 'Evidence could not be loaded.');}
    finally {setBusy(false);}
  }
  return <div><button type="button" disabled={busy} onClick={() => value ? setValue(null) : void load()}>{value ? `Close ${label}` : busy ? 'Loading original evidence…' : `Inspect ${label}`}</button>
    {error && <p role="alert">{error}</p>}{value && <Json value={value}/>}</div>;
}
function VexStatement({statement, assessmentId, rejected}: {statement: Row, assessmentId: number, rejected: boolean}) {
  const accepted = !statement.sample_only && !rejected && (statement.accepted === true || (statement.accepted == null && statement.reason === null));
  return <article className="risk-evidence"><h5>{statement.sample_only ? 'CVE presence sample' : accepted ? 'Accepted for applicability' : 'Not accepted for applicability'} · {statement.source || 'Source not recorded'}</h5>
    <p>Statement #{statement.id} · document #{statement.document_id}{statement.source_id != null ? ` · source #${statement.source_id}` : ''}. Publisher status: {humanize(statement.status || 'unknown')}.</p>
    {statement.sample_only && <p>This is one retained example showing that the CVE occurs in the VEX corpus. It does not establish applicability and does not represent all rejected candidates.</p>}
    <p>Reason: {statement.reason ? humanize(statement.reason) : accepted ? 'Exact identity and configured trust requirements satisfied' : 'Acceptance not established'}.</p>
    {statement.identity_kind && <p>Match method: {statement.identity_kind === 'exact_observed' ? 'Component identity used for exact lookup' : 'Authoritatively resolved identity'}{statement.relationship ? ` · ${humanize(statement.relationship)}` : ''}.</p>}
    {statement.matched_product_id && <p>Matched product: <code>{statement.matched_product_id}</code></p>}
    {statement.identity && <details><summary>Statement matching identifiers</summary><Json value={statement.identity}/></details>}
    {statement.justification && <p>Justification: {statement.justification}</p>}
    {statement.impact_statement && <p>Impact: {statement.impact_statement}</p>}
    {statement.action_statement && <p>Publisher action: {statement.action_statement}</p>}
    {statement.sha256 && <p className="risk-evidence-hash">Evidence SHA-256: <code>{statement.sha256}</code></p>}
    {statement.document_id != null && <OriginalEvidence url={`/api/risk/assessments/${assessmentId}/documents/${statement.document_id}`} label={`original VEX document #${statement.document_id}`}/>}
  </article>;
}
export function VexLookupSummary({vex}: {vex: Row}) {
  const applicable = typeof vex.direct_applicable_count === 'number' && typeof vex.resolved_applicable_count === 'number'
    ? vex.direct_applicable_count + vex.resolved_applicable_count : null;
  return <section aria-label="VEX lookup and applicability">
    <h4>VEX lookup and applicability</h4>
    <dl><dt>CVE or alias present in VEX</dt><dd>{vex.cve_present === true ? 'Present' : vex.cve_present === false ? 'Absent' : 'Not established'}</dd>
      <dt>Exact identity candidates</dt><dd>{vex.exact_candidate_count ?? 'Not recorded'}</dd>
      <dt>Statements passing applicability checks</dt><dd>{applicable ?? 'Not recorded'}</dd></dl>
    <p>CVE presence alone does not establish a package match. Exact candidates still require trusted, current evidence and matching product context. Accepted statements can conflict; the effective disposition controls exclusion.</p>
  </section>;
}
export function IdentityResolution({identity}: {identity: Row}) {
  const resolution = identity.resolution;
  const derived: Row[] = (resolution?.candidates || []).filter((candidate: Row) => candidate.kind === 'authoritative_resolved');
  const original = identity.scanner_identity || resolution?.observed_identity || identity;
  const binding = identity.sbom_binding;
  const provenance = binding?.provenance || {};
  const bindingLabels: Record<string, string> = {matched: 'Verified component binding', missing: 'No matching component',
    ambiguous: 'Multiple components match', conflict: 'Conflicting component evidence', scope_missing: 'Scan or image scope is missing'};
  return <section aria-label="Package identity resolution">
    <h4>Package identity resolution</h4>
    {resolution ? <p><strong>{humanize(resolution.outcome || 'insufficient_identity_evidence')}</strong></p>
      : <p>Package identity resolution was not recorded. Reassess to generate this evidence.</p>}
    <dl><dt>Original scanner identity</dt><dd><code>{original.raw_purl || original.context?.purl || 'Not recorded'}</code></dd>
      <dt>Installed version</dt><dd>{original.raw_installed_version || original.context?.version || 'Not recorded'}</dd>
      <dt>Resolver version</dt><dd>{resolution?.resolver_version || 'Not recorded'}</dd></dl>
    {binding && <section aria-label="SBOM component correlation">
      <h5>SBOM component correlation</h5><p><strong>{bindingLabels[binding.status] || humanize(binding.status || 'not recorded')}</strong></p>
      {binding.reasons?.length > 0 && <p className="risk-callout">Binding reasons: {binding.reasons.map(humanize).join('; ')}.</p>}
      {binding.status === 'matched' && <dl><dt>SBOM component identity used for lookup</dt><dd><code>{identity.context?.purl || identity.context?.product_id || 'Not recorded'}</code></dd>
        <dt>Correlated installed version</dt><dd>{identity.context?.version || identity.raw_installed_version || 'Not recorded'}</dd></dl>}
      <p>A verified SBOM binding supplies component identity. It does not establish VEX applicability or a Not Affected disposition.</p>
      <details><summary>SBOM binding provenance and original records</summary>
        <dl><dt>Scan execution</dt><dd>{provenance.execution_id ?? 'Not recorded'}</dd>
          <dt>Component record</dt><dd>{binding.component_id ?? 'Not recorded'}</dd>
          <dt>Component reference</dt><dd>{provenance.component_ref || 'Not recorded'}</dd>
          <dt>Binding method</dt><dd>{humanize(provenance.binding_kind || 'not recorded')}</dd>
          <dt>Image</dt><dd>{provenance.image || 'Not recorded'}</dd>
          <dt>Image digest</dt><dd><code>{provenance.digest || 'Not recorded'}</code></dd>
          <dt>Platform</dt><dd>{typeof provenance.platform === 'object' ? pretty(provenance.platform) : provenance.platform || 'Not recorded'}</dd>
          <dt>SBOM digest</dt><dd><code>{provenance.sbom_digest || 'Not recorded'}</code></dd></dl>
        <h6>Original scanner record</h6><Json value={original}/>
        <h6>Retained component record and binding</h6><Json value={{sbom_artifact: identity.sbom_artifact, binding}}/>
      </details>
    </section>}
    {resolution?.reasons?.length > 0 && <p className="risk-callout">Unresolved evidence: {resolution.reasons.map(humanize).join('; ')}.</p>}
    {resolution && !derived.length && <p>No additional authoritative identity is eligible for VEX matching.</p>}
    {derived.map((candidate, index) => <article className="risk-evidence" key={index}>
      <h5>Derived identity {index + 1}</h5><p><code>{candidate.context?.purl || candidate.context?.product_id}</code></p>
      <p>Method: {humanize(candidate.relationship || 'not recorded')}. {candidate.eligible ? 'Eligible for exact VEX lookup; applicability still requires trusted, current evidence.' : 'Not eligible for VEX matching.'}</p>
      <p>Evidence validity: {candidate.valid_until || 'Bound to the scanned image; assessment freshness checks still apply'}.</p>
      {(candidate.provenance_chain || []).map((step: Row, stepIndex: number) => <div key={stepIndex}>
        <p><strong>{humanize(step.relation || 'relationship')}</strong> · Source: {step.source || 'Not recorded'}</p>
        <p>Source version: {typeof step.source_version === 'object' ? [step.source_version?.name, step.source_version?.version].filter(Boolean).join(' ') || 'Not recorded' : step.source_version || 'Not recorded'} · Observed: {step.observed_at || 'Not recorded'}</p>
        <details><summary>Supporting evidence: {step.evidence_path || 'retained package record'}</summary><Json value={step.details || step}/></details>
      </div>)}
    </article>)}
    {resolution?.relationships?.length > 0 && <details><summary>Retained package relationships ({resolution.relationships.length})</summary><p>A recorded relationship alone does not establish an eligible vendor product identity.</p><Json value={resolution.relationships}/></details>}
  </section>;
}
export function ObservationIntelligence({observation, assessmentId}: {observation: Row, assessmentId: number}) {
  const vex = observation.vex || {}, advisory = observation.advisory || {};
  const statements: Row[] = vex.statements || [], rejected: Row[] = vex.rejected_candidates || [];
  return <div className="risk-observation-evidence">
    <p><strong>VEX: {vexLabels[vex.applicability_state] || vexLabels[vex.status] || humanize(vex.status || 'unknown')}</strong></p>
    {vex.status === 'fixed' && <p>A Fixed statement does not resolve the original scanner finding.</p>}
    {vex.reasons?.length > 0 && <ul>{vex.reasons.map((reason: string, index: number) => <li key={index}>{humanize(reason)}</li>)}</ul>}
    <VexLookupSummary vex={vex}/>
    {observation.identity && <IdentityResolution identity={observation.identity}/>}
    {observation.identity ? <details><summary>Observed component identity and scanner evidence</summary><Json value={observation.identity}/></details> : <p>Component identity detail was not recorded in this assessment.</p>}
    <details><summary>VEX acceptance and rejection evidence ({statements.length + rejected.length} retained)</summary>
      {vex.rejected_candidates_truncated && <p>Only a limited set of rejected candidates is retained. This list is incomplete.</p>}
      {!statements.length && !rejected.length && <p>No retained candidate statements for this observation. Review the evaluation reasons for missing identity or bounded lookup limits.</p>}
      {statements.map((statement, index) => <VexStatement key={`s:${statement.id}:${index}`} statement={statement} assessmentId={assessmentId} rejected={false}/>)}
      {rejected.map((statement, index) => <VexStatement key={`r:${statement.id}:${index}`} statement={statement} assessmentId={assessmentId} rejected={true}/>)}
    </details>
    <details><summary>Supplemental advisory evidence ({advisory.records?.length || 0})</summary>
      <p>Advisories enrich the existing scanner finding. They do not establish authoritative VEX applicability, a Not Affected exemption, or a resolved finding.</p>
      {advisory.truncated && <p>The advisory evidence list is limited. Additional records may not be displayed; review the lookup reasons and retained provenance.</p>}
      {advisory.reasons?.map((reason: string, index: number) => <p key={index}>{humanize(reason)}</p>)}
      {(advisory.records || []).map((record: Row, index: number) => <article className="risk-evidence" key={`${record.id}:${index}`}>
        <h5>{typeof record.source === 'object' ? record.source?.name : record.source || 'Source not recorded'} · record #{record.id}</h5>
        <p>{record.external_id || record.record_id} · {humanize(record.kind || 'advisory')}</p>
        <p>Correlation: {advisoryMatchLabels[record.match_reason] || humanize(record.match_reason || 'See retained evidence')}</p>
        {record.current != null && <p>{record.current ? 'Current source evidence' : 'Source evidence does not pass current trust and freshness checks'}{record.reason ? `: ${humanize(record.reason)}` : ''}.</p>}
        <details><summary>Advisory identifiers and provenance</summary><Json value={record}/></details>
        {record.id != null && <OriginalEvidence url={`/api/risk/records/${record.id}`} label={`original advisory record #${record.id}`}/>}
      </article>)}
      {!advisory.records?.length && <p>No supplemental advisory records retained for this observation.</p>}
    </details>
    <details><summary>Source statements and provenance</summary><Json value={{vex, advisory, identity: observation.identity}}/></details>
  </div>;
}
