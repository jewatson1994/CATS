import { useEffect, useRef, useState } from 'react';
import { requestJson, type PageData } from '../api';
import { useJob, type JobState } from '../hooks/useJob';

interface ScanJob extends JobState {
  status: string; started_at?: string | null; finished_at?: string | null; phase?: string;
  skipped_charts?: string[];
  summary?: { skipped_images?: number; skipped_charts?: number; reports?: number; formats?: string[]; results?: number; configuration_findings?: number };
}
export interface SelfServiceData {
  mode: 'scan' | 'sbom'; description: string; image_list?: string; chart_url?: string;
  archive_names?: string[]; authenticated_ingest?: boolean;
  authenticated_services?: { service_key: string; name: string }[];
  service_version_options?: Record<string, string[]>; ingest_service_id?: string; ingest_service_version?: string;
  sbom_output_formats?: Record<string, string>; selected_sbom_formats?: string[];
  cyclonedx_spec_versions?: string[]; cyclonedx_spec_version?: string;
  job_id?: string; job?: ScanJob; status_message?: string;
  progress_phases: [string, string][]; progress_order: string[];
  current_user?: PageData['current_user']; csrf_token?: string;
}
const labels: Record<string, string> = { queued: 'Queued', running: 'Running', complete: 'Complete', incomplete: 'Incomplete', error: 'Error', cancelled: 'Cancelled' };
const phaseLabels: Record<string, string> = { queued: 'Queued', prepare_inputs: 'Prepare inputs', generate_sboms: 'SBOM generation', scan_sboms: 'SBOM scan', configuration_scan: 'Configuration scans', report_results: 'Report results', report_to_portal: 'Portal ingest' };
const ingestRequests = new Map<string, Promise<unknown>>();
const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Request failed. Please retry.';

export function Page({ data: pageData }: { data: PageData }) {
  const data = pageData as SelfServiceData;
  const scope = JSON.stringify([data.mode, data.job_id, data.ingest_service_id, data.ingest_service_version]);
  return <Workspace key={scope} data={data} scope={scope} />;
}
function Workspace({ data, scope }: { data: SelfServiceData; scope: string }) {
  const sbom = data.mode === 'sbom';
  const [service, setService] = useState(data.ingest_service_id || '');
  const [version, setVersion] = useState(data.ingest_service_version || '');
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState('');
  const [ingestState, setIngestState] = useState<'idle' | 'pending' | 'complete' | 'error'>('idle');
  const [ingestError, setIngestError] = useState('');
  const [ingestRetry, setIngestRetry] = useState(0);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const base = data.job_id ? `/api/public/jobs/${encodeURIComponent(data.job_id)}` : null;
  const { job: polledJob, error, retry, elapsedSeconds } = useJob<ScanJob>(base, scope);
  const job = polledJob || data.job;
  const status = job?.status || 'queued';
  const phase = job?.phase || 'queued';
  const terminal = ['complete', 'incomplete', 'error', 'cancelled'].includes(status);
  const resultsReady = ['complete', 'incomplete'].includes(status);
  const ingestTarget = data.ingest_service_id;
  useEffect(() => {
    if (sbom || !base || !resultsReady || !ingestTarget) return;
    let active = true;
    setIngestState('pending'); setIngestError('');
    let request = ingestRequests.get(scope);
    if (!request) {
      request = requestJson(`${base}/ingest?service_id=${encodeURIComponent(ingestTarget)}`, { method: 'POST' });
      ingestRequests.set(scope, request);
    }
    request.then(() => { if (active) setIngestState('complete'); }, reason => {
      if (active) { setIngestState('error'); setIngestError(errorMessage(reason)); }
    });
    return () => { active = false; };
  }, [sbom, base, resultsReady, ingestTarget, scope, ingestRetry]);
  async function cancel() {
    if (!base) return;
    setCancelling(true); setCancelError('');
    try { await requestJson(`${base}/cancel`, { method: 'POST' }); if (mounted.current) retry(); }
    catch (reason) { if (mounted.current) setCancelError(errorMessage(reason)); }
    finally { if (mounted.current) setCancelling(false); }
  }
  const summary = job?.summary || {};
  const skipped = (summary.skipped_images || 0) + (summary.skipped_charts || 0);
  const showCounts = terminal || phase === 'report_results';
  let statusText = job ? `${labels[status] || status} · ${phaseLabels[phase] || phase.replaceAll('_', ' ')}` : data.status_message || `Waiting for ${sbom ? 'SBOM' : 'scan'} worker…`;
  if (job && showCounts) statusText = sbom
    ? `${labels[status] || status} · ${summary.reports || 0} SBOM document(s) in ${(summary.formats || []).length} format(s)${summary.skipped_images ? `, ${summary.skipped_images} skipped image(s)` : ''}.`
    : `${statusText} · ${summary.results || 0} vulnerability result(s), ${summary.configuration_findings || 0} configuration finding(s)${skipped ? `, ${summary.skipped_images || 0} skipped image(s), ${summary.skipped_charts || 0} skipped chart(s)` : ''}.`;
  const download = (suffix: string, text: string, enabled = true) => <a className={`secondary-button${enabled ? '' : ' is-disabled'}`} href={enabled && base ? `${base}/${suffix}` : undefined} aria-disabled={!enabled || undefined} tabIndex={enabled ? undefined : -1}>{text}</a>;
  return <>
    <a className="back" href="/home">← CATS overview</a>
    <section className="heading"><div><p className="eyebrow">SELF-SERVICE WORKSPACE</p><h1>{sbom ? 'SBOM' : 'Scan'}</h1><p>{data.description}</p></div></section>
    <section className="self-service-panel panel">
      <h2>{sbom ? 'SBOM generator' : 'Public scan inputs'}</h2>
      <p className="muted">{sbom ? 'Provide public images or upload a Docker image archive. Generated documents are temporary and are not attached to a portal service.' : 'Provide public images, a Helm chart archive, or both. Results are temporary and are not attached to a portal service.'}</p>
      <form className="self-service-form" method="post" action={`/${data.mode}`} encType="multipart/form-data" onSubmit={() => setSubmitting(true)}>
        {data.csrf_token && <input type="hidden" name="csrf_token" value={data.csrf_token} />}
        <label htmlFor="image-list">Images</label><textarea id="image-list" name="image_list" rows={10} defaultValue={data.image_list || ''} placeholder={'docker.io/library/nginx:1.27\nghcr.io/example/app:latest'} />
        <label htmlFor="image-archive">Local Docker image archive <span className="muted">(optional .tar/.tar.gz/.tgz; may contain multiple tagged images)</span></label><input id="image-archive" name="image_archive" type="file" accept=".tar,.tar.gz,.tgz" />
        {!sbom && <>
          <label htmlFor="chart-url">Helm chart or repository URLs <span className="muted">(archive, Helm index/repository, or public OCI reference; one per line)</span></label><textarea id="chart-url" name="chart_url" rows={3} defaultValue={data.chart_url || ''} placeholder={'https://prometheus-community.github.io/helm-charts\nhttps://example.invalid/chart-two.tgz'} />
          <label htmlFor="chart-archive">Helm chart archives <span className="muted">(select one or more .tgz, .tar.gz, .tar, or .zip files)</span></label><input id="chart-archive" name="chart_archives" type="file" accept=".tgz,.tar.gz,.tar,.zip" multiple />
          {!!data.archive_names?.length && <p className="muted upload-summary">Submitted archives: {data.archive_names.join(', ')}. Select files again only if starting a new scan.</p>}
          <label htmlFor="service-definition">Service definition <span className="muted">(optional)</span></label><input id="service-definition" name="service_definition" type="file" accept=".yaml,.yml" aria-describedby="service-definition-help" /><small id="service-definition-help" className="muted">Upload a service-definition YAML/YML file. CATS will discover and assess every declared component.</small>
          {data.authenticated_ingest && <>
            <label htmlFor="ingest-service">Ingest completed scan into <span className="muted">(only services within your role, group, and service scope)</span></label><select id="ingest-service" name="ingest_service_id" value={service} onChange={event => { setService(event.target.value); setVersion(''); }}><option value="">Do not ingest (temporary results only)</option>{data.authenticated_services?.map(item => <option key={item.service_key} value={item.service_key}>{item.name} ({item.service_key})</option>)}</select>
            <label htmlFor="ingest-service-version">Service Version <span className="muted">(select an existing version or enter a new one)</span></label><input id="ingest-service-version" name="ingest_service_version" list="ingest-version-options" maxLength={120} value={version} onChange={event => setVersion(event.target.value)} autoComplete="off" disabled={!service} required={!!service} /><datalist id="ingest-version-options">{(data.service_version_options?.[service] || []).map(value => <option key={value} value={value} />)}</datalist>
          </>}
        </>}
        {sbom && <fieldset className="sbom-options"><legend>Output formats</legend><p className="muted">Select one or more. CATS inventories each image once, then serializes that inventory into every selected format.</p><div className="sbom-format-grid">{Object.entries(data.sbom_output_formats || {}).map(([value, label]) => <label key={value}><input type="checkbox" name="sbom_formats" value={value} defaultChecked={data.selected_sbom_formats?.includes(value)} /> <span>{label}</span></label>)}</div><label htmlFor="cyclonedx-spec-version">CycloneDX specification version<select id="cyclonedx-spec-version" name="cyclonedx_spec_version" defaultValue={data.cyclonedx_spec_version}>{data.cyclonedx_spec_versions?.map(value => <option key={value} value={value}>{value}</option>)}</select></label></fieldset>}
        <div className="self-service-actions"><button type="submit" disabled={submitting} aria-busy={submitting}>{submitting ? sbom ? 'Generating…' : 'Starting scan…' : sbom ? 'Generate SBOM' : 'Start scan'}</button>{data.current_user ? <span className="muted">Signed in as {data.current_user.display_name}</span> : !sbom && <a className="secondary-button" href="/login?next=/scan">Use authenticated mode</a>}</div>
      </form>
      {base ? <div className="scan-progress">
        <div className="scan-pipeline" aria-label={`${sbom ? 'SBOM generation' : 'Scan'} pipeline`}>{data.progress_phases.map(([step, label]) => {
          const index = data.progress_order.indexOf(step);
          const complete = (index >= 0 && data.progress_order.indexOf(phase) > index) || (status === 'complete' && index >= 0);
          const active = step === phase && status === 'running';
          const failed = ['error', 'incomplete'].includes(status) && step === phase;
          return <div key={step} className={`scan-pipeline-step${complete ? ' is-complete' : ''}${active ? ' is-active' : ''}${failed ? ' is-error' : ''}`}><span className="scan-pipeline-dot" /><strong>{label}</strong><small>{complete ? 'Complete' : active ? 'Running' : failed ? labels[status] : 'Waiting'}</small></div>;
        })}</div>
        <p className="muted self-service-status" role="status">{statusText}{elapsedSeconds != null && <span> · {Math.floor(elapsedSeconds / 60)}m {Math.floor(elapsedSeconds % 60)}s</span>}{ingestState === 'pending' && ' Ingesting into selected service…'}{ingestState === 'complete' && ' Ingested into selected service.'}</p>
        {error && <p role="alert">Unable to read scan status. {errorMessage(error)} <button type="button" onClick={retry}>Retry status</button></p>}
        {ingestState === 'error' && <p role="alert">Ingest failed. {ingestError} <button type="button" onClick={() => { ingestRequests.delete(scope); setIngestRetry(value => value + 1); }}>Retry ingestion</button></p>}
        {!sbom && !!job?.skipped_charts?.length && <details><summary>Charts not acquired</summary><ul>{job.skipped_charts.map((entry, index) => <li key={index}>{entry}</li>)}</ul></details>}
        {terminal && status !== 'cancelled' && <div className="scan-result-actions">{!sbom && <>{download('overview.html', 'Open HTML overview', resultsReady)}{download('results/view', 'Detailed results', resultsReady)}{download('export.xlsx', 'Download Excel', resultsReady)}</>}{download(sbom ? 'sboms' : 'artifacts', sbom ? 'Download SBOMs' : 'Download artifacts')}{download('logs', 'View debug log')}</div>}
        {['queued', 'running'].includes(status) && <div className="scan-result-actions"><button type="button" className="secondary-button" disabled={cancelling} onClick={cancel}>{cancelling ? 'Cancelling…' : 'Cancel scan'}</button></div>}
        {cancelError && <p role="alert">Unable to cancel scan. {cancelError}</p>}
      </div> : <p className="muted self-service-status">{data.status_message || (sbom ? 'Generated documents are temporary and are not attached to a portal service.' : 'Results are temporary and are not attached to a portal service.')}</p>}
    </section>
  </>;
}
