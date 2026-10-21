import {ArtifactEvidence, type VulnerabilityEvidence} from './artifact_evidence';
import {useEffect, useState, type FormEvent} from 'react';

import {requestJson, type PageData} from '../api';

import {ServiceTabs} from '../components/ServiceHeader';

import {EmptyState, ErrorState, Loading, PageHeader, StatusBadge} from '../components/ui';

import {RequestApproval} from './cyber_approvals';
import './artifact_catalog.css';



type Artifact = {id: number; digest: string; media_type: string; platform: string; created_at?: string; eligibility?: {eligible: boolean; reasons: string[]}; services?: {service_key: string; name: string}[]};

type Recommendation = {vulnerability_evidence?: VulnerabilityEvidence | null; amendment_proposal_id?: number | null; id: number; status: string; source_artifact: Artifact; target_artifact: Artifact; eligibility?: {eligible: boolean; reasons: string[]}; can_adopt?: boolean};

type AssessmentReadiness = {status?: string; code?: string; message?: string; next_action?: string};
type ProposalReadiness = {ready_for_cyber_review: boolean; blockers?: AssessmentReadiness[]; artifacts?: {artifact_id: number; assigned: boolean; eligible: boolean; reasons: string[]}[]; required_steps?: string[]};

type CatalogResult = {items: Artifact[]; total: number; page_size?: number};

type RecommendationResult = {items: Recommendation[]; can_adopt?: boolean};

const errorText = (error: unknown) => error instanceof Error ? error.message : 'Unable to complete the request.';

function useCatalogResource<T>(url: string) {

  const [state, setState] = useState<{url: string; value?: T; error?: string}>({url});

  const [revision, setRevision] = useState(0);

  useEffect(() => {

    const controller = new AbortController();

    setState({url});

    requestJson<T>(url, {signal: controller.signal}).then(value => {if (!controller.signal.aborted) setState({url, value});}).catch(error => {if (!controller.signal.aborted) setState({url, error: errorText(error)});});

    return () => controller.abort();

  }, [url, revision]);

  return {...(state.url === url ? state : {url}), refresh: () => setRevision(value => value + 1)};

}

function Identity({artifact}: {artifact: Artifact}) {

  return <dl className="catalog-identity"><dt>Digest</dt><dd><code>{artifact.digest}</code></dd><dt>Media type</dt><dd>{artifact.media_type}</dd><dt>Platform</dt><dd>{artifact.platform}</dd></dl>;

}

function Eligibility({value}: {value?: Artifact['eligibility']}) {

  return <><StatusBadge value={value?.eligible ? 'eligible' : 'blocked'} label={value?.eligible ? 'Eligible for reuse' : 'Reuse blocked'} tone={value?.eligible ? 'success' : 'warning'}/>{!value?.eligible && <ul className="catalog-reasons">{(value?.reasons?.length ? value.reasons : ['Verification is not available.']).map((reason, index) => <li key={index}>{reason}</li>)}</ul>}</>;

}

export function Page({data}: {data: PageData}) {

  const [draft, setDraft] = useState(''), [search, setSearch] = useState(''), [page, setPage] = useState(1);

  const result = useCatalogResource<CatalogResult>(`/api/artifact-catalog?${new URLSearchParams({search, page: String(page)})}`);

  const submit = (event: FormEvent) => {event.preventDefault(); setSearch(draft.trim()); setPage(1);};

  const pageSize = result.value?.page_size || 25;

  return <><PageHeader title="Artifact catalog" description="Immutable artifact identities and verification status for services you can access."/><form className="catalog-filters" onSubmit={submit}><label>Search artifacts<input value={draft} onChange={event => setDraft(event.target.value)} placeholder="Digest, media type or platform"/></label><button>Search</button></form>

    {result.error ? <ErrorState title="Artifact catalog could not be loaded" onRetry={result.refresh}>{result.error}</ErrorState> : !result.value ? <Loading label="Loading artifact catalog…"/> : <>{!result.value.items.length ? <EmptyState title="No artifacts found">{search ? 'Try a different search.' : 'Artifacts appear here when digest-bound evidence is recorded for your services.'}</EmptyState> : <div className="catalog-grid">{result.value.items.map(artifact => <article className="panel catalog-card" key={artifact.id}><h2>Artifact {artifact.id}</h2><Identity artifact={artifact}/><Eligibility value={artifact.eligibility}/><div className="catalog-services">{artifact.services?.map(service => <a key={service.service_key} href={`/services/${encodeURIComponent(service.service_key)}/artifact-recommendations`}>{service.name}</a>)}</div></article>)}</div>}<nav className="catalog-pager" aria-label="Artifact catalog pages"><span>{result.value.total} artifacts · Page {page}</span><div><button className="secondary-button" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><button className="secondary-button" disabled={page * pageSize >= result.value.total} onClick={() => setPage(page + 1)}>Next</button></div></nav></>}

    {data.catalog_notice && <p>{data.catalog_notice}</p>}

  </>;

}

export function Recommendations({data}: {data: PageData}) {

  const service = data.service || data.view?.service;

  return service ? <ServiceRecommendations key={service.service_key} data={data} service={service}/> : <ErrorState title="Service context is unavailable">Return to the service and open artifact recommendations again.</ErrorState>;

}

function ServiceRecommendations({data, service}: {data: PageData; service: {service_key: string; name: string}}) {

  const root = `/api/services/${encodeURIComponent(service.service_key)}/artifact-recommendations`;

  const result = useCatalogResource<RecommendationResult>(root);

  const [reasons, setReasons] = useState<Record<number, string>>({});
  const [initialReadiness, setInitialReadiness] = useState<AssessmentReadiness | undefined>();
  const [amendment, setAmendment] = useState<number | null>(null);
  const [pending, setPending] = useState<number | null>(null), [error, setError] = useState(''), [notice, setNotice] = useState('');

  async function decide(id: number, action: 'defer' | 'dismiss' | 'reopen') {
    const reason = (reasons[id] || '').trim();
    if (pending !== null || (action === 'dismiss' && !reason)) return;
    setPending(id); setError(''); setNotice('');
    try {
      await requestJson(`${root}/${id}/decision`, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify({action, reason})});
      setNotice(action === 'defer' ? 'Recommendation deferred.' : action === 'dismiss' ? 'Recommendation dismissed.' : 'Recommendation reopened.'); result.refresh();
    } catch (error) {setError(errorText(error));} finally {setPending(null);}
  }

  async function adopt(id: number) {

    setPending(id); setError(''); setNotice('');

    try {

      const adopted = await requestJson<{amendment_proposal_id?: number | null; proposal?: {assessment_readiness?: AssessmentReadiness}}>(`${root}/${id}/adopt`, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: '{}'});

      setInitialReadiness(adopted.proposal?.assessment_readiness);
      setAmendment(adopted.amendment_proposal_id || null);
      setNotice('Adoption proposed for this service. Approval and release checks are still required.'); result.refresh();

    } catch (error) {setError(errorText(error));} finally {setPending(null);}

  }

  return <><PageHeader title="Artifact recommendations" eyebrow={service.name} description="Review verified replacements and propose adoption for this service. Proposals do not change the deployed artifact."/><ServiceTabs serviceKey={service.service_key} active="artifact-recommendations"/>

    <p><a href="/artifact-catalog">Browse artifact catalog</a></p>{error && <p role="alert" className="error">{error}</p>}{notice && <p role="status">{notice}</p>}{amendment && <AmendmentReview key={amendment} data={data} serviceKey={service.service_key} id={amendment} initial={initialReadiness}/>}

    {result.error ? <ErrorState title="Recommendations could not be loaded" onRetry={result.refresh}>{result.error}</ErrorState> : !result.value ? <Loading label="Loading recommendations…"/> : !result.value.items.length ? <EmptyState title="No artifact recommendations">No replacement recommendations are available for this service.</EmptyState> : <div className="catalog-grid">{result.value.items.map(item => {

      const eligibility = item.eligibility || item.target_artifact.eligibility;

      const adopted = ['adopted', 'proposed'].includes(item.status);

      const manageable = result.value?.can_adopt ?? item.can_adopt ?? false;
      const paused = ['deferred', 'dismissed'].includes(item.status);
      const permitted = item.can_adopt ?? result.value?.can_adopt ?? false;

      return <article className="panel catalog-card" key={item.id}><h2>Recommendation {item.id}</h2><StatusBadge value={item.status}/><h3>Current artifact</h3><Identity artifact={item.source_artifact}/><h3>Recommended artifact</h3><Identity artifact={item.target_artifact}/><Eligibility value={eligibility}/><ArtifactEvidence value={item.vulnerability_evidence}/>{!adopted && !paused && permitted && <div className="catalog-actions"><button disabled={!eligibility?.eligible || pending !== null} onClick={() => adopt(item.id)}>{pending === item.id ? 'Proposing…' : 'Propose adoption'}</button><span>This proposal applies only to this service.</span></div>}{!adopted && !manageable && <p className="muted">You do not have permission to adopt artifacts for this service.</p>}{adopted && item.amendment_proposal_id && manageable && <button disabled={pending !== null} onClick={() => {setInitialReadiness(undefined); setAmendment(item.amendment_proposal_id!);}}>Continue amendment review</button>}{!adopted && manageable && <fieldset disabled={pending !== null}><legend>Manage recommendation {item.id}</legend>{paused ? <button onClick={() => decide(item.id, 'reopen')}>Reopen recommendation</button> : <><label>Reason for recommendation {item.id}<textarea maxLength={2000} value={reasons[item.id] || ''} onChange={event => setReasons(previous => ({...previous, [item.id]: event.target.value}))}/></label><p>A reason is required to dismiss this recommendation.</p><button onClick={() => decide(item.id, 'defer')}>Defer recommendation</button><button disabled={!(reasons[item.id] || '').trim()} onClick={() => decide(item.id, 'dismiss')}>Dismiss recommendation</button></>}</fieldset>}</article>;

    })}</div>}

  </>;

}


function AmendmentReview({data, serviceKey, id, initial}: {data: PageData; serviceKey: string; id: number; initial?: AssessmentReadiness}) {
  const result = useCatalogResource<ProposalReadiness>(`/api/services/${encodeURIComponent(serviceKey)}/amendment-proposals/${id}/readiness`);
  const blockers = result.value?.blockers || (initial ? [initial] : []);
  return <section className="panel catalog-card" aria-label="Amendment assessment readiness"><h2>Amendment proposal #{id}</h2><p>Current service posture remains unchanged. A fresh assessment must cover the complete proposed inventory.</p>{result.error && <ErrorState title="Amendment readiness unavailable" onRetry={result.refresh}>{result.error}</ErrorState>}{!result.value && !result.error && <Loading label="Checking amendment evidence…"/>}{blockers.map((blocker,index) => <div key={index}><p>{blocker.message || blocker.code}</p>{blocker.next_action && <p>Next step: {blocker.next_action}</p>}</div>)}{result.value?.artifacts?.map(item => <div key={item.artifact_id}><h3>Artifact {item.artifact_id}</h3><p>{item.assigned ? 'Assigned to this service' : 'Service assignment missing'} · {item.eligible ? 'Evidence eligible' : 'Evidence incomplete'}</p><ul>{item.reasons.map((reason,index) => <li key={index}>{reason}</li>)}</ul></div>)}{result.value?.required_steps?.length ? <ol>{result.value.required_steps.map(step => <li key={step}>{step}</li>)}</ol> : null}<button className="secondary-button" onClick={result.refresh}>Refresh amendment readiness</button>{result.value?.ready_for_cyber_review === true ? <RequestApproval data={data} serviceKey={serviceKey} amendmentProposalId={id}/> : <p>Cyber submission is blocked until the proposed inventory evidence is ready.</p>}</section>;
}
