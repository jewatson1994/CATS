import {PageHeader} from '../components/ui';
import {WorkspaceGuide} from '../components/WorkspaceGuide';
import { useEffect, useRef, useState } from 'react';
import { PAGE_MEDIA_TYPE, requestJson, type PageData, type PageEnvelope } from '../api';
import { useJob, type JobState } from '../hooks/useJob';
import { ComposeInventory, type ComposeModel } from './compose_inventory';

interface ScanJob extends JobState {
  status: string; started_at?: string | null; finished_at?: string | null; phase?: string;
  skipped_charts?: string[]; compose_preview?: boolean;
  intelligence?: { status: string; databases: Record<string, { version?: string; built?: string; status?: string }> };
  summary?: { skipped_images?: number; skipped_charts?: number; reports?: number; formats?: string[]; results?: number; configuration_findings?: number; compose?: ComposeModel };
}
export interface SelfServiceData {
  mode: 'scan' | 'sbom'; description: string; image_list?: string; chart_url?: string;
  compose_files?: string; compose_profiles?: string; compose_preview?: boolean;
  archive_names?: string[]; authenticated_ingest?: boolean;
  authenticated_services?: { service_key: string; name: string }[];
  service_version_options?: Record<string, string[]>; ingest_service_id?: string; ingest_service_version?: string; ingest_scope?: 'auto' | 'service';
  sbom_output_formats?: Record<string, string>; selected_sbom_formats?: string[];
  cyclonedx_spec_versions?: string[]; cyclonedx_spec_version?: string;
  job_id?: string; job?: ScanJob; status_message?: string;
  progress_phases: [string, string][]; progress_order: string[];
  current_user?: PageData['current_user']; csrf_token?: string;
}
const labels: Record<string, string> = { preparing: 'Preparing', queued: 'Queued', running: 'Running', complete: 'Complete', incomplete: 'Incomplete', error: 'Error', cancelled: 'Cancelled' };
const phaseLabels: Record<string, string> = { preparing: 'Preparing submission', prepare: 'Preparing scan', transfer: 'Transferring evidence', ingest: 'Ingesting evidence', done: 'Finished', queued: 'Queued', prepare_inputs: 'Prepare inputs', compose_discovery: 'Discover Compose services', generate_sboms: 'SBOM generation', scan_sboms: 'SBOM scan', configuration_scan: 'Configuration scans', report_results: 'Report results', report_to_portal: 'Portal ingest' };
const ingestRequests = new Map<string, Promise<unknown>>();
const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Request failed. Please retry.';

export function Page({ data: pageData }: { data: PageData }) {
  return <Workspace initial={pageData as SelfServiceData} />;
}
function Workspace({ initial }: { initial: SelfServiceData }) {
  const [data, setData] = useState(initial);
  useEffect(() => { setData(initial); }, [initial]);
  const scope = JSON.stringify([data.mode, data.job_id, data.ingest_service_id, data.ingest_service_version, data.ingest_scope]);
  const sbom = data.mode === 'sbom';
  const [service, setService] = useState(data.ingest_service_id || '');
  const [version, setVersion] = useState(data.ingest_service_version || '');
  const [ingestScope, setIngestScope] = useState(data.ingest_scope || 'auto');
  const [submitting, setSubmitting] = useState(false);
  const [submittingPreview, setSubmittingPreview] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const submission = useRef<AbortController | null>(null);
  useEffect(() => () => submission.current?.abort(), []);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    submission.current?.abort();
    const controller = new AbortController();
    submission.current = controller;
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    setSubmittingPreview(submitter instanceof HTMLButtonElement && submitter.value === 'true');
    setSubmitting(true); setSubmitError('');
    try {
      const response = await requestJson<PageEnvelope>(`/${data.mode}`, {
        method: 'POST', body: new FormData(event.currentTarget, submitter), signal: controller.signal,
        headers: { Accept: PAGE_MEDIA_TYPE },
      });
      if (controller.signal.aborted) return;
      if (response.page !== 'self_service') throw new Error('Unable to start scan. Please retry.');
      setData(response.data as SelfServiceData);
    } catch (reason) {
      if (!controller.signal.aborted) setSubmitError(errorMessage(reason));
    } finally {
      if (!controller.signal.aborted) setSubmitting(false);
    }
  }
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState('');
  const [ingestState, setIngestState] = useState<'idle' | 'pending' | 'complete' | 'error'>('idle');
  const [ingestError, setIngestError] = useState('');
  const [ingestRetry, setIngestRetry] = useState(0);
  useEffect(() => { setIngestState('idle'); setIngestError(''); setCancelError(''); }, [scope]);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const base = data.job_id ? `/api/public/jobs/${encodeURIComponent(data.job_id)}` : null;
  const { job: polledJob, error, retry, elapsedSeconds } = useJob<ScanJob>(base, scope);
  const job = polledJob || data.job;
  const preview = job?.compose_preview ?? data.compose_preview ?? false;
  const progressPhases = preview ? data.progress_phases.filter(([step]) => ['prepare_inputs', 'compose_discovery'].includes(step)) : data.progress_phases;
  const status = job?.status || 'queued';
  const phase = job?.phase || 'queued';
  const terminal = ['complete', 'incomplete', 'error', 'cancelled'].includes(status);
  const resultsReady = ['complete', 'incomplete'].includes(status);
  const ingestTarget = data.ingest_service_id;
  useEffect(() => {
    if (sbom || !base || !terminal || submitting) return;
    const controller = new AbortController();
    requestJson<PageEnvelope>('/scan', {signal: controller.signal, headers: {Accept: PAGE_MEDIA_TYPE}})
      .then(response => {
        if (controller.signal.aborted || response.page !== 'self_service') return;
        setData(previous => ({...previous,
          authenticated_ingest: response.data.authenticated_ingest,
          authenticated_services: response.data.authenticated_services,
          service_version_options: response.data.service_version_options,
        }));
      }).catch(() => { /* Retain the last known targets if refresh is unavailable. */ });
    return () => controller.abort();
  }, [sbom, base, terminal, submitting]);
  useEffect(() => {
    if (sbom || preview || !base || !resultsReady || !ingestTarget) return;
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
  }, [sbom, preview, base, resultsReady, ingestTarget, scope, ingestRetry]);
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
  if (preview) statusText = `Compose preview · ${statusText}`;
  if (job && showCounts && !preview) statusText = sbom
    ? `${labels[status] || status} · ${summary.reports || 0} SBOM document(s) in ${(summary.formats || []).length} format(s)${summary.skipped_images ? `, ${summary.skipped_images} skipped image(s)` : ''}.`
    : `${statusText} · ${summary.results || 0} vulnerability result(s), ${summary.configuration_findings || 0} configuration finding(s)${skipped ? `, ${summary.skipped_images || 0} skipped image(s), ${summary.skipped_charts || 0} skipped chart(s)` : ''}.`;
  const download = (suffix: string, text: string, enabled = true) => <a className={`secondary-button${enabled ? '' : ' is-disabled'}`} href={enabled && base ? `${base}/${suffix}` : undefined} aria-disabled={!enabled || undefined} tabIndex={enabled ? undefined : -1}>{text}</a>;
  return <>
    <PageHeader eyebrow="Self-service workspace" title={sbom ? 'SBOM' : 'Scan'} description={data.description} back={data.current_user ? undefined : {href: '/home', label: 'CATS overview'}}/>
    <div className="workspace-split">
    <section className="self-service-panel panel">
      <h2>{sbom ? 'SBOM generator' : 'Public scan inputs'}</h2>
      <p className="muted">{sbom ? 'Provide public images or upload a Docker image archive. Generated documents are temporary and are not attached to a portal service.' : 'Provide public images, Helm charts, or Docker Compose files. Results are temporary and are not attached to a portal service.'}</p>
      <form className="self-service-form" method="post" action={`/${data.mode}`} encType="multipart/form-data" onSubmit={submit}>
        {data.csrf_token && <input type="hidden" name="csrf_token" value={data.csrf_token} />}
        <h3 className="form-group-title">Container images</h3><label htmlFor="image-list">Images</label><textarea id="image-list" name="image_list" rows={10} defaultValue={data.image_list || ''} placeholder={'docker.io/library/nginx:1.27\nghcr.io/example/app:latest'} />
        <label htmlFor="image-archive">Local Docker image archive <span className="muted">(optional .tar/.tar.gz/.tgz; may contain multiple tagged images)</span></label><input id="image-archive" name="image_archive" type="file" accept=".tar,.tar.gz,.tgz" />
        {!sbom && <>
          <h3 className="form-group-title">Helm charts</h3>
          <label htmlFor="chart-url">Helm chart or repository URLs <span className="muted">(archive, Helm index/repository, or public OCI reference; one per line)</span></label><textarea id="chart-url" name="chart_url" rows={3} defaultValue={data.chart_url || ''} placeholder={'https://prometheus-community.github.io/helm-charts\nhttps://example.invalid/chart-two.tgz'} />
          <label htmlFor="chart-archive">Helm chart archives <span className="muted">(select one or more .tgz, .tar.gz, .tar, or .zip files)</span></label><input id="chart-archive" name="chart_archives" type="file" accept=".tgz,.tar.gz,.tar,.zip" multiple />
          {!!data.archive_names?.length && <p className="muted upload-summary">Submitted archives: {data.archive_names.join(', ')}. Select files again only if starting a new scan.</p>}
          <h3 className="form-group-title">Docker Compose</h3>
          <label htmlFor="compose-uploads">Docker Compose files and companions <span className="muted">(optional; select YAML/YML, .env files, or .zip/.tar/.tar.gz/.tgz bundles)</span></label><input id="compose-uploads" name="compose_uploads" type="file" multiple aria-describedby="compose-help" />
          <small id="compose-help" className="muted">Preview discovers services and images without scanning. CATS never builds images or starts containers. Services declaring both image and build scan the declared image. Use a bundle to preserve folders and companion files.</small>
          <label htmlFor="compose-files">Compose file order <span className="muted">(optional; relative paths, one per line, base first then overrides)</span></label><textarea id="compose-files" name="compose_files" rows={3} defaultValue={data.compose_files || ''} placeholder={'compose.yaml\ncompose.production.yaml'} aria-describedby="compose-order-help" />
          <small id="compose-order-help" className="muted">Leave blank to select a single standard compose.yaml, compose.yml, docker-compose.yaml, or docker-compose.yml file. If more than one is present, specify the order explicitly.</small>
          <label htmlFor="compose-profiles">Compose profiles <span className="muted">(optional; comma or newline separated)</span></label><textarea id="compose-profiles" name="compose_profiles" rows={2} defaultValue={data.compose_profiles || ''} placeholder="production, monitoring" />
          <h3 className="form-group-title">Service definition</h3>
          <label htmlFor="service-definition">Service definition <span className="muted">(optional)</span></label><input id="service-definition" name="service_definition" type="file" accept=".yaml,.yml" aria-describedby="service-definition-help" /><small id="service-definition-help" className="muted">Upload a service-definition YAML/YML file. CATS will discover and assess every declared component.</small>
          {data.authenticated_ingest && <>
            <h3 className="form-group-title">Ingest into a service</h3>
            <label htmlFor="ingest-service">Ingest completed scan into <span className="muted">(only services within your role, group, and service scope)</span></label><select id="ingest-service" name="ingest_service_id" value={service} onChange={event => { setService(event.target.value); setVersion(''); }}><option value="">Do not ingest (temporary results only)</option>{data.authenticated_services?.map(item => <option key={item.service_key} value={item.service_key}>{item.name} ({item.service_key})</option>)}</select>
            <label htmlFor="ingest-service-version">Service Version <span className="muted">(select an existing version or enter a new one)</span></label><input id="ingest-service-version" name="ingest_service_version" list="ingest-version-options" maxLength={120} value={version} onChange={event => setVersion(event.target.value)} autoComplete="off" disabled={!service} required={!!service} /><datalist id="ingest-version-options">{(data.service_version_options?.[service] || []).map(value => <option key={value} value={value} />)}</datalist>
            <label htmlFor="ingest-scope">Assessment scope</label><select id="ingest-scope" name="ingest_scope" value={ingestScope} onChange={event => setIngestScope(event.target.value as 'auto' | 'service')} disabled={!service} aria-describedby="ingest-scope-help"><option value="auto">Automatic (a single image updates that image only)</option><option value="service">Full service assessment</option></select>
            <small id="ingest-scope-help" className="muted">Choose Full service assessment only when these inputs cover the whole service, including services made of one image. A newer assessment can become current and resolve findings absent from the scan. To replace an older image-only assessment, start a new scan with this choice.</small>
          </>}
        </>}
        {sbom && <fieldset className="sbom-options"><legend>Output formats</legend><p className="muted">Select one or more. CATS inventories each image once, then serializes that inventory into every selected format.</p><div className="sbom-format-grid">{Object.entries(data.sbom_output_formats || {}).map(([value, label]) => <label key={value}><input type="checkbox" name="sbom_formats" value={value} defaultChecked={data.selected_sbom_formats?.includes(value)} /> <span>{label}</span></label>)}</div><label htmlFor="cyclonedx-spec-version">CycloneDX specification version<select id="cyclonedx-spec-version" name="cyclonedx_spec_version" defaultValue={data.cyclonedx_spec_version}>{data.cyclonedx_spec_versions?.map(value => <option key={value} value={value}>{value}</option>)}</select></label></fieldset>}
        <div className="self-service-actions"><button type="submit" name="compose_preview" value="false" disabled={submitting} aria-busy={submitting && !submittingPreview}>{submitting && !submittingPreview ? sbom ? 'Generating…' : 'Starting scan…' : sbom ? 'Generate SBOM' : 'Start scan'}</button>{!sbom && <button type="submit" className="secondary-button" name="compose_preview" value="true" formNoValidate disabled={submitting} aria-busy={submitting && submittingPreview}>{submitting && submittingPreview ? 'Starting preview…' : 'Preview Compose'}</button>}{data.current_user ? <span className="muted">Signed in as {data.current_user.display_name}</span> : !sbom && <a className="secondary-button" href="/login?next=/scan">Use authenticated mode</a>}</div>
      </form>
      {submitError && <p role="alert">{submitError}</p>}
      {base ? <div className="scan-progress">
        <div className="scan-pipeline" aria-label={`${preview ? 'Compose preview' : sbom ? 'SBOM generation' : 'Scan'} pipeline`}>{progressPhases.map(([step, label]) => {
          const index = data.progress_order.indexOf(step);
          const complete = (index >= 0 && data.progress_order.indexOf(phase) > index) || (status === 'complete' && index >= 0);
          const active = step === phase && status === 'running';
          const failed = ['error', 'incomplete'].includes(status) && step === phase;
          return <div key={step} className={`scan-pipeline-step${complete ? ' is-complete' : ''}${active ? ' is-active' : ''}${failed ? ' is-error' : ''}`}><span className="scan-pipeline-dot" /><strong>{label}</strong><small>{complete ? 'Complete' : active ? 'Running' : failed ? labels[status] : 'Waiting'}</small></div>;
        })}</div>
        <p className="muted self-service-status" role="status">{statusText}{elapsedSeconds != null && <span> · {Math.floor(elapsedSeconds / 60)}m {Math.floor(elapsedSeconds % 60)}s</span>}{ingestState === 'pending' && ' Ingesting into selected service…'}{ingestState === 'complete' && ' Ingested into selected service.'}</p>
        {summary.compose && <ComposeInventory model={summary.compose} preview={preview} />}
        {job?.intelligence && !preview && <details open={job.intelligence.status !== 'current'}>
          <summary>Scan intelligence · {job.intelligence.status === 'current' ? 'Current' : 'Review database freshness'}</summary>
          <p className="muted">Each attempt uses a fixed database version. Importing newer intelligence does not change a scan already running; rescan to use the latest version.</p>
          <ul>{Object.entries(job.intelligence.databases).map(([scanner, database]) => <li key={scanner}>{scanner === 'grype' ? 'Grype' : 'Trivy'}: {database.status || 'unavailable'}{database.version && ` · version ${database.version}`}{database.built && ` · built ${database.built}`}</li>)}</ul>
        </details>}
        {error && <p role="alert">Unable to read scan status. {errorMessage(error)} <button type="button" onClick={retry}>Retry status</button></p>}
        {ingestState === 'error' && <p role="alert">Ingest failed. {ingestError} <button type="button" onClick={() => { ingestRequests.delete(scope); setIngestRetry(value => value + 1); }}>Retry ingestion</button></p>}
        {!sbom && !!job?.skipped_charts?.length && <details><summary>Charts not acquired</summary><ul>{job.skipped_charts.map((entry, index) => <li key={index}>{entry}</li>)}</ul></details>}
        {terminal && status !== 'cancelled' && <div className="scan-result-actions">{!sbom && !preview && <>{download('overview.html', 'Open HTML overview', resultsReady)}{download('results/view', 'Detailed results', resultsReady)}{download('export.xlsx', 'Download Excel', resultsReady)}</>}{download(sbom ? 'sboms' : 'artifacts', sbom ? 'Download SBOMs' : 'Download artifacts')}{download('logs', 'View debug log')}</div>}
        {['preparing', 'queued', 'running'].includes(status) && <div className="scan-result-actions"><button type="button" className="secondary-button" disabled={cancelling} onClick={cancel}>{cancelling ? 'Cancelling…' : preview ? 'Cancel preview' : 'Cancel scan'}</button></div>}
        {cancelError && <p role="alert">Unable to cancel scan. {cancelError}</p>}
      </div> : <p className="muted self-service-status">{data.status_message || (sbom ? 'Generated documents are temporary and are not attached to a portal service.' : 'Results are temporary and are not attached to a portal service.')}</p>}
        </section>
    <WorkspaceGuide title={sbom ? 'How SBOM generation works' : 'How scanning works'}
      steps={sbom ? [
        {title: 'Provide images', detail: 'Public image references, or a Docker image archive with one or more tagged images.'},
        {title: 'Inventory once', detail: 'CATS inventories each image a single time.'},
        {title: 'Download documents', detail: 'The inventory is written in every format you select. Documents are temporary.'},
      ] : [
        {title: 'Add inputs', detail: 'Images, Helm charts, Docker Compose files or a service definition, in any combination.'},
        {title: 'Acquire and inventory', detail: 'CATS resolves what to assess. It never builds images or starts containers.'},
        {title: 'Assess', detail: 'Vulnerability scanners run against a fixed intelligence version and report progress here.'},
        {title: 'Review or ingest', detail: data.authenticated_ingest ? 'Results are temporary unless you choose a service to ingest them into.' : 'Results are temporary and not attached to a portal service.'},
      ]}
      links={data.current_user ? [
        ...(sbom ? [] : [{href: '/discovery', label: 'Discover a whole deployment', icon: 'search' as const}]),
        {href: '/jobs', label: 'Track background jobs', icon: 'history' as const},
        {href: '/', label: 'Services', icon: 'layers' as const},
      ] : [{href: '/login', label: 'Sign in for service workflows', icon: 'key' as const}]}/>
    </div>
  </>;
}
