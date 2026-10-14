import {useEffect, useState} from 'react';
import {requestJson, type PageData} from '../api';

interface Job {
  id: string; kind: string; service?: string; validator?: string; version?: string;
  requested_by: string; status: string; stage: string; progress?: number;
  elapsed_seconds: number; error?: string; correlation_id?: string;
  result_url?: string; download_url?: string; can_retry: boolean; can_cancel: boolean;
}
interface Snapshot {jobs: Job[]; counts: Record<string, number>; limit: number}
const labels: Record<string, string> = {export: 'Export', scan: 'Scan', 'remediation_plan': 'Remediation plan',
  'remediation_execute': 'Remediation', 'remediation_validate': 'Validation', 'remediation_deliver': 'Delivery'};
function duration(seconds: number) {return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;}

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
  function actions(job: Job) {return <>
    {job.download_url && job.status === 'completed' && <a className="secondary-button" href={job.download_url}>Download</a>}
    {job.result_url && <a href={job.result_url}>Open result</a>}
    {job.can_retry && <button disabled={!!busy} onClick={() => void act(job, 'retry')}>Retry</button>}
    {job.can_cancel && <button className="secondary-button" disabled={!!busy} onClick={() => void act(job, 'cancel')}>Cancel</button>}
  </>;}
  return <><div className="page-heading"><h1>Jobs</h1><p>Scans, remediation, exports, and validator provisioning. Updates every five seconds.</p></div>
    {error && <p role="alert">{error}</p>}
    {snapshot && <p aria-label="Job counts">{Object.entries(snapshot.counts).map(([state, count]) => `${state}: ${count}`).join(' · ')}</p>}
    {selected && <section className="panel padded" aria-label="Selected job"><h2>{labels[selected.kind] || selected.kind} — {selected.status}</h2>
      <p>{selected.stage} · {duration(selected.elapsed_seconds)}</p>{selected.error && <p role="alert">{selected.error}</p>}
      {actions(selected)}</section>}
    <section className="panel"><div className="table-wrap"><table><thead><tr>
      {['Job', 'Service / validator', 'Requested by', 'State', 'Stage / elapsed', 'Actions'].map(label => <th key={label}>{label}</th>)}
    </tr></thead><tbody>{snapshot?.jobs.map(job => <tr key={job.id}>
      <td><a href={`/jobs?job=${encodeURIComponent(job.id)}`}>{labels[job.kind] || job.kind}</a><small>{job.correlation_id}</small></td>
      <td>{job.service || job.validator || 'Portfolio'}{job.version && <small>{job.version}</small>}</td>
      <td>{job.requested_by}</td><td>{job.status}</td><td>{job.stage} · {duration(job.elapsed_seconds)}
        {job.status === 'running' && job.progress != null && <progress max={100} value={job.progress} aria-label="Job progress"/>}
        {job.error && <p>{job.error}</p>}</td><td>{actions(job)}</td>
    </tr>)}{!snapshot?.jobs.length && <tr><td colSpan={6}>{snapshot ? 'No jobs available.' : 'Loading jobs…'}</td></tr>}</tbody></table></div>
    {snapshot && <p className="muted">Showing the latest {snapshot.limit} jobs you can access. Counts include older jobs.</p>}</section></>;
}
