import {useEffect, useId, useRef, useState, type FormEvent} from 'react';
import {can, requestJson, type PageData} from '../api';
import {StatusBadge} from './ui';
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
  const [editing, setEditing] = useState(false);
  const editorId = useId();
  const currentService = useRef<number | null>(serviceId);
  currentService.current = serviceId;
  const editable = can(data, 'release.destination.manage');
  const url = `/api/oci/services/${serviceId}/pull-access`;
  const seededPublic = seed?.public;
  const visibleAccess = access?.service_id === serviceId ? access : null;

  useEffect(() => {
    currentService.current = serviceId;
    setError(''); setNotice(''); setBusy(false); setEditing(false);
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
      setEditing(false);
    } catch (cause) {
      if (currentService.current === serviceId) setError(cause instanceof Error ? cause.message : 'Could not save pull access.');
    } finally {if (currentService.current === serviceId) setBusy(false);}
  }

  function cancel() {
    setSelected(visibleAccess?.public ? 'public' : 'private');
    setEditing(false); setError('');
  }

  return <section className="panel service-control-card" aria-label="Service pull access">
    <div className="service-control-heading">
      <div className="service-control-title"><h2>Service pull access</h2>
        {visibleAccess && <StatusBadge value={visibleAccess.public ? 'public' : 'private'} label={visibleAccess.public ? 'Public' : 'Private'} tone="neutral"/>}
      </div>
      {editable && visibleAccess && <button type="button" className="secondary-button" disabled={busy} aria-expanded={editing} aria-controls={editorId}
        onClick={() => {if (editing) cancel(); else {setEditing(true); setNotice('');}}}>Edit pull access</button>}
    </div>
    {!visibleAccess && !error && <p role="status">Loading pull access.</p>}
    {error && <div role="alert"><p>{error}</p><button type="button" disabled={busy} onClick={() => setAttempt(value => value + 1)}>Refresh pull access</button></div>}
    {visibleAccess && <>
      <p className="service-control-description">{visibleAccess.public ? 'Anyone who can reach CATS can pull approved artifacts without signing in.' : 'Pulls require authorized CATS registry credentials.'} Release approval is always required.</p>
      {editable && editing && <form id={editorId} className="service-control-editor" onSubmit={save}>
        <label>Pull access<select value={selected} disabled={busy} onChange={event => setSelected(event.target.value)}>
          <option value="private">Private — sign-in required</option><option value="public">Public — anonymous pulls</option>
        </select></label>
        <p className="service-control-help">{selected === 'public' ? 'Public access permits anonymous pulls of this service’s approved artifacts.' : 'Private access requires a CATS machine account with permission to pull.'}</p>
        <div className="service-control-actions"><button disabled={busy || selected === (visibleAccess.public ? 'public' : 'private')}>{busy ? 'Saving pull access…' : 'Save pull access'}</button>
          <button type="button" className="secondary-button" disabled={busy} onClick={cancel}>Cancel</button></div>
      </form>}
    </>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
