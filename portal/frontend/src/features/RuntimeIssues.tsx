import {StatusBadge} from '../components/ui';
import type {RuntimeOverview} from './runtime';

type ScanAssessment = {status: 'compliant' | 'noncompliant' | 'unverified'; reason: string; execution_id?: number;
  source?: 'local_scan' | 'publisher_capture'; scanned_at?: string};
export type RuntimeCompliance = {status: 'approved' | 'excepted' | 'noncompliant' | 'unverified'; reason: string;
  service_id?: number; release_id?: number; approval_id?: number; scan_assessment?: ScanAssessment};

export type RuntimeIssue = {
  environment_id: number; agent_id?: string | null; namespace?: string; pod?: string; workload?: string;
  container?: string; uid?: string; image_ref?: string; image_id?: string; severity: string; code: string; reason: string;
  service_id?: number; release_id?: number; approval_id?: number; compliance?: RuntimeCompliance; codes?: string[];
};
export type IssueFilters = {environmentId: number | null; namespace: string; code: string};

const reasons: Record<string, string> = {
  approved: 'The observed digest matches a current Approved Release.',
  release_expired: 'The Cyber-approved release for this image has expired.',
  approval_window_elapsed: 'The approval window for this image has expired.',
  release_revoked: 'Cyber revoked the release for this image.',
  release_superseded: 'A newer release superseded the observed release.',
  release_suspended: 'The approved release is suspended.',
  approval_not_current: 'The approval for the observed image is no longer current.',
  image_outside_current_approved_release: 'This running image digest is outside the current approved release.',
  digest_not_approved: 'The observed digest is outside the approved inventory.',
  service_noncompliant: 'The identified service fails its required compliance policy.',
  service_inactive: 'The identified CATS service is inactive.',
  service_outside_environment_scope: 'The observed service falls outside this environment\'s approval scope.',
  ambiguous_service_membership: 'Several services match this image. CATS cannot establish which approval applies.',
  immutable_runtime_identity_unavailable: 'The report lacks a verified runtime image digest.',
  image_not_in_retained_release_evidence: 'CATS could not match this image to retained release evidence.',
  no_approved_release_match: 'No Approved Release in this environment matches the reported repository and digest.',
  scan_image_noncompliant: 'A finding in this assessment fails scan policy for the running image digest.',
  scan_image_compliant: 'This assessment records a compliant service and covers the running image digest.',
  scan_image_evidence_unavailable: 'CATS could not establish scan compliance for this service and running image digest.',
  repository_mapping_unavailable: 'CATS could not establish a repository mapping for this image.',
  requested_service_repository_mismatch: 'The reported repository does not belong to the identified service.',
  requested_digest_mismatch: 'The reference and runtime image report different digests.',
  platform_manifest_membership_unavailable: 'The approval evidence lacks the platform manifests needed to verify this running image.',
  service_unavailable: 'The identified CATS service is unavailable.',
  active_revision_unavailable: 'The active revision of the approval is unavailable.',
  current_release_evidence_unavailable: 'Current release evidence is unavailable.',
  environment_service_scope_unavailable: 'This environment has no eligible service scope.',
  container_not_running: 'The container was not running when the agent observed it.',
  coverage_unlinked: 'This environment has no linked agent.',
  coverage_never_reported: 'The agent has not sent its first report.',
  coverage_incomplete: 'The agent reported incomplete inventory.',
  coverage_stale: 'The latest report exceeded the freshness window.',
  coverage_revoked: 'This agent has been revoked.',
};
export function issueReason(reason: string) {return reasons[reason] || reason.replaceAll('_', ' ');}

const scanLabels = {compliant: 'Scan compliant', noncompliant: 'Scan noncompliant', unverified: 'Scan unverified'};
const scanTones = {compliant: 'success', noncompliant: 'danger', unverified: 'neutral'} as const;
const scanSources = {local_scan: 'Local scan', publisher_capture: 'Verified publisher capture'};
const scanTime = new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'long'});

export function ScanCompliance({assessment, current}: {assessment?: ScanAssessment; current: boolean}) {
  if (!assessment) return <span className="muted">Scan unverified</span>;
  const scannedAt = Date.parse(assessment.scanned_at ?? '');
  return <><StatusBadge value={assessment.status} label={current ? scanLabels[assessment.status] : 'Scan status unchecked'}
    tone={current ? scanTones[assessment.status] : 'neutral'}/>
    {current ? <span>{issueReason(assessment.reason)}</span> : <span>Last assessment was {assessment.status}.</span>}
    {assessment.source && <span>{scanSources[assessment.source]}</span>}
    {Number.isFinite(scannedAt) && <span>Scanned <time dateTime={assessment.scanned_at}>{scanTime.format(scannedAt)}</time></span>}
    {assessment.execution_id != null && <span>Assessment execution {assessment.execution_id}</span>}</>;
}

export function RuntimeIssues({overview, currentCoverage, filters, selectFilters, currentRead}: {
  overview: RuntimeOverview; currentCoverage: (id: string) => boolean; currentRead: boolean;
  filters: IssueFilters; selectFilters: (filters: IssueFilters) => void;
}) {
  const {environmentId, namespace, code} = filters;
  const issues = overview.issues || [];
  const names = new Map(overview.environments.map(env => [env.id, env.name]));
  const agents = new Map(overview.agents.map(agent => [agent.id, agent.name || agent.source_id]));
  const rows = environmentId === null ? issues : issues.filter(issue => issue.environment_id === environmentId);
  const namespaces = new Set(overview.namespaces?.filter(row => row.issue_count > 0 && (environmentId === null || environmentId === row.environment_id)).map(row => row.name));
  if (namespace) namespaces.add(namespace);
  function classification(issue: RuntimeIssue) {
    if (issue.code === 'coverage') return 'Coverage gap';
    if (!issue.agent_id || !currentRead || !currentCoverage(issue.agent_id)) return 'Coverage unchecked';
    return issue.severity === 'error' ? 'Confirmed policy failure' : 'Unverified observation';
  }
  const services = new Map(overview.services.map(service => [service.id, service.name]));
  const total = overview.total_issues ?? issues.length;
  const coverageAged = overview.agents.some(agent => agent.coverage === 'fresh' && currentRead && !currentCoverage(agent.id) && (environmentId === null || environmentId === agent.environment_id));
  return <section className="panel padded" aria-label="Runtime issues">
    <h2>Issues</h2>
    <div className="runtime-issue-filters">
      <label>Cluster or host<select value={environmentId ?? ''} onChange={event => {
        selectFilters({...filters, environmentId: event.target.value ? Number(event.target.value) : null, namespace: ''});
      }}><option value="">All clusters and hosts</option>{overview.environments.map(env => <option key={env.id} value={env.id}>{env.name}</option>)}</select></label>
      <label>Namespace<select value={namespace} onChange={event => selectFilters({...filters, namespace: event.target.value})}>
        <option value="">All namespaces</option>{[...namespaces].sort().map(name => <option key={name}>{name}</option>)}</select></label>
      <label>Issue type<select value={code} onChange={event => selectFilters({...filters, code: event.target.value})}>
        <option value="">All issue types</option><option value="noncompliant">Release policy failure</option>
        <option value="scan_noncompliant">Scan policy failure</option>
        <option value="unverified">Unverified observation</option><option value="coverage">Coverage gap</option></select></label>
    </div>
    {total > issues.length && <p className="runtime-notice">This page contains {issues.length} of {total} reported issues in this view.</p>}
    {coverageAged && <p className="runtime-notice">An agent report has expired since the last refresh. Its current coverage is unknown.</p>}
    {rows.length ? <div className="runtime-table"><table><caption>Reported issues ({rows.length})</caption>
      <thead><tr><th scope="col">Cluster / agent</th><th scope="col">Namespace / workload</th><th scope="col">Image / digest</th><th scope="col">Issue</th></tr></thead>
      <tbody>{rows.map((issue, index) => {
        const status = classification(issue);
        const decision = issue.compliance;
        const current = status !== 'Coverage unchecked';
        const workload = [issue.workload, issue.pod && issue.pod !== issue.workload ? 'Pod ' + issue.pod : '', issue.container && 'Container ' + issue.container].filter(Boolean);
        return <tr key={[issue.environment_id, issue.agent_id, issue.uid, issue.container, issue.code, index].join(':')}>
          <th scope="row">{names.get(issue.environment_id)}<span>{issue.agent_id && (agents.get(issue.agent_id) || issue.agent_id)}</span></th>
          <td>{issue.namespace || (issue.code === 'coverage' ? 'Environment' : 'Namespace unreported')}
            {workload.map(item => <span key={item}>{item}</span>)}</td>
          <td>{issue.image_ref && <code>{issue.image_ref}</code>}{issue.image_id && <code>{issue.image_id}</code>}
            {!issue.image_ref && !issue.image_id && (issue.code === 'coverage' ? 'Environment coverage' : 'Unreported')}</td>
          <td><StatusBadge value={issue.code} label={status} tone={status === 'Confirmed policy failure' ? 'danger' : 'warning'}/>
            {decision ? <><span>{current ? 'Release' : 'Last release status'} {decision.status}</span>
              <span>{issueReason(decision.reason)}</span><ScanCompliance assessment={decision.scan_assessment} current={current}/></>
              : <span>{issueReason(issue.reason)}</span>}
            {issue.service_id != null && <span>{services.get(issue.service_id) || `Service ${issue.service_id}`}</span>}
            {issue.approval_id != null && <span>Approval {issue.approval_id}</span>}{issue.release_id != null && <span>Release {issue.release_id}</span>}
            {status === 'Coverage unchecked' && <small>Reason from retained evidence.</small>}</td>
        </tr>;
      })}</tbody>
    </table></div> : !currentRead && !overview.issues ? null : <p>{!overview.issues ? 'Issue details are unavailable in this report.' : !currentRead
      ? 'Refresh to check current issues.' : 'No reported issues match this view.'}</p>}
  </section>;
}
