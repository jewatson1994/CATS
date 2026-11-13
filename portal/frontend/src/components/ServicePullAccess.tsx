import {useEffect, useRef, useState, type FormEvent} from 'react';
import {can, requestJson, type PageData} from '../api';

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

  return <section className="panel padded" aria-label="Service pull access">
    <h2>Service pull access</h2>
    {!visibleAccess && !error && <p role="status">Loading pull access.</p>}
    {error && <div role="alert"><p>{error}</p><button type="button" disabled={busy} onClick={() => setAttempt(value => value + 1)}>Refresh pull access</button></div>}
    {visibleAccess && <><p>Current access: <strong>{visibleAccess.public ? 'Public' : 'Private'}</strong></p>
      <p>{visibleAccess.public ? 'Anyone who can reach CATS can pull this service’s approved artifacts without signing in.' : 'Pulling this service’s artifacts requires authorized CATS registry credentials.'} CATS still checks approval and release validity on every pull.</p>
      {editable && <form onSubmit={save}>
        <label>Pull access<select value={selected} disabled={busy} onChange={event => setSelected(event.target.value)}>
          <option value="private">Private — sign-in required</option><option value="public">Public — anonymous pulls</option>
        </select></label>
        <p>Public access allows anyone with network access to pull approved artifacts for this service.</p>
        <button disabled={busy || selected === (visibleAccess.public ? 'public' : 'private')}>{busy ? 'Saving pull access…' : 'Save pull access'}</button>
      </form>}
    </>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
