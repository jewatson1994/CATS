import {ArtifactEvidence, type VulnerabilityEvidence} from './artifact_evidence';
import {useEffect, useState, type FormEvent} from 'react';

import {requestJson, type PageData} from '../api';

import {useJob, type JobState} from '../hooks/useJob';

import {EmptyState, ErrorState, Loading, PageHeader, StatusBadge} from '../components/ui';

import './artifact_catalog.css';



type Image = {id: number; image_reference: string; image_digest?: string; lifecycle_status?: string};

type Campaign = {id: string | number; status: string; created_at?: string};

type Inventory = {images: Image[]; campaigns: Campaign[]; can_patch: boolean; max_images?: number};

interface CampaignDetail extends JobState {id: string | number; items: {id?: number; can_cancel?: boolean; can_retry?: boolean; cancel_requested?: boolean; image_id: number; image_reference: string; status: string; error?: string; job_id?: string; result?: {vulnerability_evidence?: VulnerabilityEvidence | null; patch_status?: string; signature_status?: string; immutable_destination?: string}}[]}

const hasDigest = (image: Image) => {
  const referenceDigest = image.image_reference.split('@')[1];
  const digest = image.image_digest || referenceDigest || '';
  return /^sha256:[a-f0-9]{64}$/.test(digest) && (!referenceDigest || referenceDigest === digest);
};
const message = (error: unknown) => error instanceof Error ? error.message : 'The request could not be completed.';

async function loadCampaign(url: string, signal: AbortSignal) {

  const value = await requestJson<CampaignDetail>(url, {signal});

  return {...value, status: ['completed', 'partial', 'partial_failure'].includes(value.status) ? value.status === 'completed' ? 'complete' : 'incomplete' : value.status};

}

function CampaignProgress({id, data}: {id: string; data: PageData}) {

  const {job, error, retry} = useJob<CampaignDetail>(`/api/patch-campaigns/${encodeURIComponent(id)}`, `campaign:${id}`, loadCampaign);

  const [busy, setBusy] = useState<number | null>(null), [actionError, setActionError] = useState(''), [notice, setNotice] = useState('');
  async function act(itemId: number, action: 'cancel' | 'retry') {
    if (busy !== null) return;
    setBusy(itemId); setActionError(''); setNotice('');
    try {
      await requestJson(`/api/patch-campaigns/${encodeURIComponent(id)}/items/${itemId}/${action}`, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: '{}'});
      setNotice(action === 'cancel' ? 'Cancellation requested. A running image may finish before cancellation is acknowledged.' : 'Image retry requested.'); retry();
    } catch (error) {setActionError(message(error));} finally {setBusy(null);}
  }
  return <section className="panel catalog-card" aria-label="Campaign progress">{actionError && <p role="alert">{actionError}</p>}{notice && <p role="status">{notice}</p>}<h2>Campaign {id}</h2>{error && <ErrorState title="Campaign status could not be loaded" onRetry={retry}>{error}</ErrorState>}{!job ? !error && <Loading label="Loading campaign status…"/> : <><p>Campaign status: <StatusBadge value={job.status}/></p><div className="catalog-grid">{job.items.map(item => <article key={item.image_id}><h3><code>{item.image_reference}</code></h3><StatusBadge value={item.status}/>{item.cancel_requested && <p>Cancellation pending worker acknowledgment.</p>}{item.id != null && <div className="catalog-actions">{item.can_cancel && <button disabled={busy !== null || item.cancel_requested} aria-label={`Cancel image ${item.image_reference}`} onClick={() => act(item.id!, 'cancel')}>Cancel image</button>}{item.can_retry && <button disabled={busy !== null} aria-label={`Retry image ${item.image_reference}`} onClick={() => act(item.id!, 'retry')}>Retry image</button>}</div>}{item.error && <p className="error">{item.error}</p>}{item.result && <dl className="catalog-identity"><dt>Patch result</dt><dd>{item.result.patch_status || 'Not reported'}</dd><dt>Signature</dt><dd>{item.result.signature_status || 'Not reported'}</dd><dt>Published artifact</dt><dd><code>{item.result.immutable_destination || 'Not reported'}</code></dd></dl>}<ArtifactEvidence value={item.result?.vulnerability_evidence}/>{item.job_id && <a href={`/api/public/patch-jobs/${encodeURIComponent(item.job_id)}/results`}>View image results</a>}</article>)}</div></>}</section>;

}

export function Page({data}: {data: PageData}) {

  const services = data.services || data.authenticated_services || [];

  const selected = new URLSearchParams(window.location.search).get('service_id') || '';

  const [service, setService] = useState(selected);

  return <><PageHeader title="Patch service images" description="Select service images to patch as one campaign. Each image retains its own result and verification status." back={{href: '/patch', label: 'Single-image Patch'}}/><label className="campaign-service-select">Service<select value={service} onChange={event => setService(event.target.value)}><option value="">Select a service</option>{services.map((item: {service_key: string; name: string}) => <option key={item.service_key} value={item.service_key}>{item.name} ({item.service_key})</option>)}</select></label>{service ? <ServiceCampaigns key={service} data={data} service={service}/> : <EmptyState title="Choose a service">Only services available to your account can be selected.</EmptyState>}</>;

}

function ServiceCampaigns({data, service}: {data: PageData; service: string}) {

  const root = `/api/services/${encodeURIComponent(service)}/patch-campaigns`;

  const [inventory, setInventory] = useState<Inventory | null>(null), [loadError, setLoadError] = useState(''), [revision, setRevision] = useState(0);

  const [selected, setSelected] = useState<number[]>([]), [registry, setRegistry] = useState(''), [prefix, setPrefix] = useState('');

  const [submitting, setSubmitting] = useState(false), [error, setError] = useState(''), [campaign, setCampaign] = useState('');

  useEffect(() => {

    const controller = new AbortController(); setLoadError('');

    requestJson<Inventory>(root, {signal: controller.signal}).then(value => {if (!controller.signal.aborted) {setInventory(value); setSelected(previous => previous.filter(id => value.images.some(image => image.id === id && hasDigest(image))));}}).catch(error => {if (!controller.signal.aborted) setLoadError(message(error));});

    return () => controller.abort();

  }, [root, revision]);

  const maximum = Math.min(inventory?.max_images || 20, 20);

  const images = inventory?.images || [];

  const eligibleImages = images.filter(hasDigest);
  const bounded = eligibleImages.slice(0, maximum).map(image => image.id);

  const registries = data.configured_registries || [];

  const canSubmit = inventory?.can_patch && selected.length > 0 && selected.length <= maximum && registry && !submitting;

  async function submit(event: FormEvent) {

    event.preventDefault(); if (!canSubmit) return;

    setSubmitting(true); setError('');

    try {

      const result = await requestJson<{id: string | number}>(root, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify({image_ids: selected, destination_registry_id: registry, destination_prefix: prefix.trim()})});

      setCampaign(String(result.id)); setSelected([]); setRevision(value => value + 1);

    } catch (error) {setError(message(error));} finally {setSubmitting(false);}

  }

  return <>{loadError && <ErrorState title="Service images could not be loaded" onRetry={() => setRevision(value => value + 1)}>{loadError}</ErrorState>}{!inventory ? !loadError && <Loading label="Loading service images…"/> : <><form className="panel catalog-card" onSubmit={submit}><h2>Select images</h2>{!inventory.can_patch && <p>You do not have permission to start patch campaigns for this service.</p>}{images.length ? <><p>{selected.length} selected · Up to {maximum} images per campaign.</p><button className="secondary-button" type="button" disabled={!inventory.can_patch || submitting || !bounded.length} onClick={() => setSelected(bounded.every(id => selected.includes(id)) ? [] : bounded)}>{bounded.every(id => selected.includes(id)) ? 'Clear selection' : eligibleImages.length > maximum ? `Select first ${maximum} images` : 'Select all eligible images'}</button><div className="campaign-image-list">{images.map(image => <label key={image.id}><input type="checkbox" checked={selected.includes(image.id)} disabled={!inventory.can_patch || !hasDigest(image) || submitting || (!selected.includes(image.id) && selected.length >= maximum)} onChange={event => setSelected(previous => event.target.checked ? [...previous, image.id] : previous.filter(id => id !== image.id))}/><span><code>{image.image_reference}</code>{image.image_digest && <small>{image.image_digest}</small>}{!hasDigest(image) && <small>A consistent immutable digest is required before patching.</small>}{image.lifecycle_status && <small>{image.lifecycle_status}</small>}</span></label>)}</div></> : <EmptyState title="No images available">Add service images before starting a campaign.</EmptyState>}<div className="catalog-filters"><label>Destination registry<select value={registry} disabled={!inventory.can_patch || submitting} onChange={event => setRegistry(event.target.value)} required><option value="">Select a configured registry</option>{registries.map((item: {id: string | number; display_name: string}) => <option key={item.id} value={item.id}>{item.display_name}</option>)}</select></label><label>Destination prefix<input value={prefix} disabled={!inventory.can_patch || submitting} onChange={event => setPrefix(event.target.value)} placeholder="team/patched (optional)" maxLength={200}/></label></div>{!registries.length && <p>No destination registries are configured for this account.</p>}{error && <p role="alert" className="error">{error}</p>}<button disabled={!canSubmit}>{submitting ? 'Starting campaign…' : 'Start patch campaign'}</button></form>{inventory.campaigns.length > 0 && <section className="panel catalog-card"><h2>Service campaigns</h2><div className="catalog-actions">{inventory.campaigns.map(item => <button className="secondary-button" key={item.id} aria-pressed={campaign === String(item.id)} onClick={() => setCampaign(String(item.id))}>Campaign {item.id} · {item.status}</button>)}</div></section>}</>}{campaign && <CampaignProgress key={campaign} id={campaign} data={data}/>}</>;

}
