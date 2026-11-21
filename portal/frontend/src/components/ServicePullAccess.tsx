import {useEffect, useRef, useState, type FormEvent} from 'react';
import {can, requestJson, type PageData} from '../api';

import './service-controls.css';

interface PullAccess {service_id: number; public: boolean}

function checkedAccess(value: unknown, serviceId: number): PullAccess {
  const access = value as Partial<PullAccess> | null;
  if (!access || access.service_id !== serviceId || typeof access.public !== 'boolean') {
    throw new Error('CATS returned an unexpected pull-access setting. Refresh to try again.');
  }
  return {service_id: serviceId, public: access.public};
}

export function ServicePullAccess({data, serviceId}: {data: PageData; serviceId: number}) {
  const seed = data.service_pull_access?.service_id === serviceId && typeof data.service_pull_access?.public === 'boolean'
    ? data.service_pull_access as PullAccess : null;
  const [access, setAccess] = useState<PullAccess | null>(seed);
  const [selected, setSelected] = useState(seed?.public ? 'public' : 'private');
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [attempt, setAttempt] = useState(0);
  const currentService = useRef<number | null>(serviceId);
  currentService.current = serviceId;
  const editable = can(data, 'release.destination.manage');
  const url = `/api/oci/services/${serviceId}/pull-access`;
  const seededPublic = seed?.public;
  const visibleAccess = access?.service_id === serviceId ? access : null;

  useEffect(() => {
    currentService.current = serviceId;
    setError(''); setNotice(''); setBusy(false);
    if (seededPublic !== undefined && attempt === 0) {
      setAccess({service_id: serviceId, public: seededPublic});
      setSelected(seededPublic ? 'public' : 'private');
      return () => {currentService.current = null;};
    }
    const controller = new AbortController();
    setAccess(null);
    requestJson<unknown>(url, {signal: controller.signal}).then(value => {
      if (controller.signal.aborted) return;
      const current = checkedAccess(value, serviceId);
      setAccess(current); setSelected(current.public ? 'public' : 'private');
    }).catch(cause => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load pull access.');
    });
    return () => {controller.abort(); currentService.current = null;};
  }, [url, serviceId, seededPublic, attempt]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editable || !visibleAccess || busy) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await requestJson<unknown>(url, {method: 'PUT',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''},
        body: JSON.stringify({public: selected === 'public'})});
      if (currentService.current !== serviceId) return;
      const current = checkedAccess(result, serviceId);
      setAccess(current); setSelected(current.public ? 'public' : 'private');
      setNotice('Service pull access saved.');
    } catch (cause) {
      if (currentService.current === serviceId) setError(cause instanceof Error ? cause.message : 'Could not save pull access.');
    } finally {if (currentService.current === serviceId) setBusy(false);}
  }

  const savedSelection = visibleAccess?.public ? 'public' : 'private';
  const changed = Boolean(visibleAccess && selected !== savedSelection);
  return <section className="panel service-control-card service-setting" aria-label="Service pull access">
    <form onSubmit={save}>
      <div className="service-setting-row">
        <h2>Service pull access</h2>
        {visibleAccess && (editable ?
          <select aria-label="Service pull access" value={selected} disabled={busy} onChange={event => {
            setSelected(event.target.value); setNotice(''); setError('');
          }}>
            <option value="private">Private · sign-in required</option>
            <option value="public">Public · anonymous pulls</option>
          </select> : <span>{visibleAccess.public ? 'Public · anonymous pulls' : 'Private · sign-in required'}</span>)}
      </div>
      {changed && editable && <div className="service-control-editor">
        <p className="service-control-help">{selected === 'public'
          ? 'Anyone who can reach CATS can pull this service’s authorized artifacts without signing in.'
          : 'Pulls require authorized CATS registry credentials.'} The owning group’s OCI pull policy determines which artifacts are authorized.</p>
        <div className="service-control-actions">
          <button disabled={busy}>{busy ? 'Saving pull access…' : 'Save pull access'}</button>
          <button type="button" className="secondary-button" disabled={busy} onClick={() => {setSelected(savedSelection); setError('');}}>Cancel</button>
        </div>
      </div>}
    </form>
    {!visibleAccess && !error && <p role="status">Loading pull access.</p>}
    {error && <div role="alert"><p>{error}</p><button type="button" disabled={busy} onClick={() => setAttempt(value => value + 1)}>Refresh pull access</button></div>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
