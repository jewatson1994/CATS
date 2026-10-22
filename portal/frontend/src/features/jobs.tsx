import {useEffect, useMemo, useState} from 'react';
import {requestJson, type PageData} from '../api';
import {DataGrid, type GridColumn} from '../components/DataGrid';
import {Callout, EmptyState, KeyValueGrid, PageHeader, StatusBadge} from '../components/ui';

interface Job {
  id: string; kind: string; service?: string; validator?: string; version?: string;
  requested_by: string; status: string; stage: string; progress?: number;
  elapsed_seconds: number; error?: string; correlation_id?: string;
  result_url?: string; download_url?: string; can_retry: boolean; can_cancel: boolean;
}
interface Snapshot {jobs: Job[]; counts: Record<string, number>; limit: number}
const labels: Record<string, string> = {export: 'Export', scan: 'Scan', 'remediation_plan': 'Remediation plan',
  'remediation_execute': 'Remediation', 'remediation_validate': 'Validation', 'remediation_deliver': 'Delivery'};
/** A result link worth showing: not one that only reopens this same job on the Jobs page (exports point there). */
function resultLink(job: Job): string | undefined {
  if (!job.result_url) return undefined;
  try {
    const url = new URL(job.result_url, window.location.origin);
    if (url.origin === window.location.origin && url.pathname === '/jobs' && url.searchParams.get('job') === job.id) return undefined;
  } catch {
    return job.result_url;
  }
  return job.result_url;
}
function duration(seconds: number) {return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;}
const kindLabel = (kind: string) => labels[kind] || kind;

export function Page({data}: {data: PageData}) {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [selected, setSelected] = useState<Job>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const selectedId = new URLSearchParams(window.location.search).get('job');
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const value = await requestJson<Snapshot>('/api/v1/jobs', {signal: controller.signal});
        if (!controller.signal.aborted) {setSnapshot(value); setError('');}
        if (selectedId) {
          const job = value.jobs.find(row => row.id === selectedId) ||
            await requestJson<Job>(`/api/v1/jobs/${encodeURIComponent(selectedId)}`, {signal: controller.signal});
          if (!controller.signal.aborted) setSelected(job);
        }
      } catch (failure) {
        if (!controller.signal.aborted) {setSelected(undefined); setError(failure instanceof Error ? failure.message : 'Unable to load jobs.');}
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(refresh, 5000);
      }
    }
    void refresh();
    return () => {controller.abort(); clearTimeout(timer);};
  }, [selectedId, busy]);
  async function act(job: Job, action: string) {
    setBusy(job.id);
    try {
      await requestJson(`/api/v1/jobs/${encodeURIComponent(job.id)}/${action}`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: data.csrf_token})});
    } catch (failure) {setError(failure instanceof Error ? failure.message : 'Unable to update job.');}
    finally {setBusy('');}
  }
  function actions(job: Job) {return <span className="row-actions">
    {job.download_url && job.status === 'completed' && <a className="secondary-button" href={job.download_url}>Download</a>}
    {resultLink(job) && <a className="secondary-button" href={resultLink(job)}>Open result</a>}
    {job.can_retry && <button disabled={!!busy} onClick={() => void act(job, 'retry')}>Retry</button>}
    {job.can_cancel && <button className="secondary-button" disabled={!!busy} onClick={() => void act(job, 'cancel')}>Cancel</button>}
    {!(job.download_url && job.status === 'completed') && !resultLink(job) && !job.can_retry && !job.can_cancel && <span className="muted">—</span>}
  </span>;}
  const columns = useMemo<GridColumn<Job>[]>(() => [
    {key: 'job', header: 'Job', identifier: true, hideable: false, value: job => kindLabel(job.kind),
      render: job => <span className="cell-stack"><a href={`/jobs?job=${encodeURIComponent(job.id)}`}>{kindLabel(job.kind)}</a>{job.correlation_id && <small className="mono">{job.correlation_id}</small>}</span>},
    {key: 'target', header: 'Service / validator', value: job => job.service || job.validator || 'Portfolio',
      render: job => <span className="cell-stack"><span>{job.service || job.validator || 'Portfolio'}</span>{job.version && <small>{job.version}</small>}</span>},
    {key: 'requested_by', header: 'Requested by', value: job => job.requested_by, render: job => job.requested_by},
    {key: 'status', header: 'State', hideable: false, value: job => job.status, render: job => <StatusBadge value={job.status} size="sm"/>},
    {key: 'stage', header: 'Stage', wrap: true, minWidth: 160, value: job => job.stage, render: job => <span className="cell-stack"><span>{job.stage}</span>
      {job.status === 'running' && job.progress != null && <progress max={100} value={job.progress} aria-label="Job progress"/>}
      {job.error && <span className="text-danger cell-error">{job.error}</span>}</span>},
    {key: 'elapsed', header: 'Elapsed', type: 'number', value: job => job.elapsed_seconds, render: job => duration(job.elapsed_seconds)},
    {key: 'actions', header: 'Actions', minWidth: 120, render: job => actions(job)},
    // actions() reads the latest busy state on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [busy, data.csrf_token]);
  const counts = Object.entries(snapshot?.counts || {});
  return <><PageHeader eyebrow="Operations" title="Jobs" description="Scans, remediation, exports, and validator provisioning. Updates every five seconds."/>
    {error && <Callout tone="danger" title="Jobs could not be refreshed">{error}</Callout>}
    {snapshot && <p className="status-summary" aria-label="Job counts">{counts.length ? counts.map(([state, count]) =>
      <StatusBadge key={state} value={state} label={`${state}: ${count}`} size="sm"/>) : <span className="muted">No jobs recorded.</span>}</p>}
    {selected && <section className="panel padded selected-job" aria-label="Selected job"><div className="selected-job-head"><h2>{kindLabel(selected.kind)} — {selected.status}</h2><StatusBadge value={selected.status}/></div>
      <KeyValueGrid columns={3} items={[['Stage', selected.stage], ['Elapsed', duration(selected.elapsed_seconds)], ['Requested by', selected.requested_by],
        ['Service / validator', selected.service || selected.validator || 'Portfolio'], ['Version', selected.version], ['Correlation ID', selected.correlation_id && <code>{selected.correlation_id}</code>]]}/>
      {selected.error && <p role="alert" className="text-danger">{selected.error}</p>}
      <div className="selected-job-actions">{actions(selected)}</div></section>}
    <section className="panel"><DataGrid<Job> id="jobs" label="Jobs" columns={columns} rows={snapshot?.jobs || []} rowKey={job => job.id}
      loading={!snapshot && !error} sort={{mode: 'client'}} rowClassName={job => job.id === selectedId ? 'dg-row-current' : undefined}
      empty={<EmptyState title="No jobs available." kind="empty"/>}
      footer={snapshot && <p className="muted grid-footnote">Showing the latest {snapshot.limit} jobs you can access. Counts include older jobs.</p>}/></section></>;
}
