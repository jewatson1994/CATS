import {useState} from 'react';
import {requestJson, type PageData} from '../api';
import {useJob, TERMINAL, type JobState} from '../hooks/useJob';

interface PatchJob extends JobState {
  phase: string; failed_stage?: string; error?: string;
  stages?: Record<string, {status: string; reason?: string}>;
  result?: {artifact_available?: boolean};
}
const phases = [['queued','Queued'], ['acquiring_image','Acquiring image'], ['scanning_source','Scanning source image'],
  ['patching_image','Patching image'], ['scanning_patched','Scanning patched image'], ['preparing_output','Preparing output'],
  ['pushing_image','Pushing image'], ['signing_image','Signing and verifying image'], ['completed','Completed']];

function Progress({id}: {id: string}) {
  const {job, error, retry, elapsedSeconds} = useJob<PatchJob>(`/api/public/patch-jobs/${encodeURIComponent(id)}`, `patch:${id}`);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const terminal = job && TERMINAL.has(job.status.toLowerCase());
  const cancel = async () => {
    setCancelling(true); setCancelError(null);
    try {await requestJson(`/api/public/patch-jobs/${encodeURIComponent(id)}/cancel`, {method: 'POST'}); retry();}
    catch (cause) {setCancelError(cause instanceof Error ? cause.message : 'Unable to cancel patch.');}
    finally {setCancelling(false);}
  };
  const phase = phases.find(([key]) => key === (job?.failed_stage || job?.phase))?.[1] || job?.phase;
  return <div className="patch-progress"><div className="patch-pipeline">{phases.map(([key,label]) => {
    const stage = job?.stages?.[key]; const status = stage?.status;
    const state = status === 'success' ? 'is-complete' : status === 'running' ? 'is-active' : status === 'failed' ? 'is-error' : status === 'skipped' ? 'is-skipped' : '';
    const text = status === 'success' ? 'Completed' : status === 'running' ? 'Running' : status === 'failed' ? 'Failed' : status === 'skipped' ? stage?.reason === 'not_reached' ? 'Not reached' : 'Skipped' : terminal ? 'Not reached' : 'Waiting';
    return <div className={`patch-step ${state}`} key={key}><span className="scan-pipeline-dot"/><strong>{label}</strong><small>{text}</small></div>;
  })}</div><p className="muted" role="status">{job ? job.status === 'failed' ? `Failed during "${phase}"${job.error ? ` · ${job.error}` : ''}` : job.status === 'complete' ? 'Completed' : job.status === 'cancelled' ? 'Cancelled' : `${job.status} · ${phase}` : 'Reading patch status…'} · {elapsedSeconds}s</p>
    {(error || cancelError) && <p role="alert">{error || cancelError} <button type="button" onClick={retry}>Retry</button></p>}
    <div className="scan-result-actions">{job?.result && <a className="secondary-button" href={`/api/public/patch-jobs/${id}/results`}>View results</a>}
      {job?.result?.artifact_available && <a className="secondary-button" href={`/api/public/patch-jobs/${id}/patched-image.tar`}>Download patched image</a>}
      <a className="secondary-button" href={`/api/public/patch-jobs/${id}/logs`}>View sanitized log</a>
      {!terminal && <button type="button" className="secondary-button" disabled={cancelling} onClick={cancel}>{cancelling ? 'Cancelling…' : 'Cancel patch'}</button>}
    </div></div>;
}

export function Page({data}: {data: PageData}) {
  const [source, setSource] = useState('oci'); const [output, setOutput] = useState('download');
  const [registryId, setRegistryId] = useState(''); const [image, setImage] = useState(''); const [submitting,setSubmitting] = useState(false);
  const registry = data.configured_registries?.find((item: {id: number}) => String(item.id) === registryId);
  const destination = registry && image.trim() ? [String(registry.endpoint || '').replace(/^https?:\/\//,'').replace(/\/$/,''),
    String(registry.namespace || '').replace(/^\/+|\/+$/g,''), image.trim().replace(/^\/+/,'')].filter(Boolean).join('/') : '';
  return <><a className="back" href="/home">← CATS overview</a><section className="heading"><div><p className="eyebrow">SELF-SERVICE WORKSPACE</p>
    <h1>Patch</h1><p>Patch a public, private, or uploaded container image and verify the result with before-and-after vulnerability scans.</p></div></section>
    <section className="panel patch-panel"><h2>Container patch inputs</h2><p className="muted patch-helper">Patch a registry image or upload an image archive.<br/>Registry credentials are managed centrally by CATS.</p>
      {data.error && <div className="notice notice-error" role="alert">{data.error}</div>}
      <form method="post" action="/patch" encType="multipart/form-data" onSubmit={() => setSubmitting(true)}>
        <input type="hidden" name="csrf_token" value={data.csrf_token || ''}/>
        <section className="patch-input-section" aria-labelledby="patch-source-title"><h3 id="patch-source-title">Image source</h3>
          <div className="patch-choice-list" role="radiogroup" aria-label="Image source type">{[['oci','OCI Image'],['upload','Upload Image']].map(([value,label]) =>
            <label key={value}><input type="radio" name="source_mode" value={value} checked={source === value} onChange={() => setSource(value)}/>{label}</label>)}</div>
          {source === 'oci' ? <div className="patch-source-option"><label>OCI Image<input name="source_image" placeholder="docker.io/library/nginx:1.27"/></label><small className="muted">Enter a complete OCI image reference.<br/>Configured OCI Registry credentials are applied automatically when available.</small></div>
            : <div className="patch-source-option"><label>Container image archive (.tar)<input name="source_archive" type="file" accept=".tar"/></label></div>}
        </section><section className="patch-input-section" aria-labelledby="patch-output-title"><h3 id="patch-output-title">Patched image output</h3>
          <div className="patch-choice-list" role="radiogroup" aria-label="Patched image output">{[['download','Download patched image'],['push','Push patched image to OCI registry']].map(([value,label]) =>
            <label key={value}><input type="radio" name="output_mode" value={value} checked={output === value} onChange={() => setOutput(value)}/>{label}</label>)}</div>
          {output === 'push' && <div className="patch-source-option"><p>{data.signing?.enabled ? 'Signing is required. Sign in with image-signing permission to publish. CATS signs the pushed digest and verifies the signature before completing the job.' : 'Image signing is disabled in Configuration.'}</p>
            {!!data.configured_registries?.length && <label>Destination registry<select name="destination_registry_id" value={registryId} onChange={event => setRegistryId(event.target.value)}><option value="">Select a configured registry</option>{data.configured_registries.map((item: any) => <option key={item.id} value={item.id}>{item.display_name}</option>)}</select></label>}
            <label>Image / repository / tag<input name="destination_image" placeholder="nginx:1.27-patched" value={image} onChange={event => setImage(event.target.value)}/></label>
            <small className="muted">{destination && `Resolved destination: ${destination}`}</small></div>}
        </section>{data.current_user && !!data.authenticated_services?.length && <label className="patch-service-association">Associate completed patch with service <span className="muted">(optional)</span>
          <select name="service_id" defaultValue={data.selected_service_id || ''}><option value="">Do not retain this patch in a service</option>{data.authenticated_services.map((service: any) => <option key={service.service_key} value={service.service_key}>{service.name} ({service.service_key})</option>)}</select></label>}
        <button className="patch-start-button" disabled={submitting} aria-busy={submitting}>{submitting ? 'Queuing patch…' : 'Start patch'}</button>
      </form>{data.job_id && <Progress key={data.job_id} id={data.job_id}/>}</section></>;
}
