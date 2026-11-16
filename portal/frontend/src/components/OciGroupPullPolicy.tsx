import {useEffect, useRef, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';

type Mode = 'approved_release' | 'compliance' | 'both';
type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'None';
interface PullPolicy {
  mode: Mode;
  blocked_severity: Severity;
  require_service_compliant: boolean;
  max_scan_age_days: number | null;
}
interface PolicyResponse {group_id: number; policy: PullPolicy; is_default: boolean}

const modes: {value: Mode; label: string; description: string}[] = [
  {value: 'approved_release', label: 'Approved releases', description: 'Require a current Cyber-approved release. New findings and scans do not override that approval.'},
  {value: 'compliance', label: 'Compliance rules', description: 'Require a complete scan bound to the exact image digest and passing the rules below. A Cyber approval is not required.'},
  {value: 'both', label: 'Approved releases and compliance', description: 'Require both a current Cyber-approved release and a complete assessment of the exact image that passes the rules below.'},
];

function checkedResponse(value: unknown, groupId: number): PolicyResponse {
  const response = value as Partial<PolicyResponse> | null;
  const policy = response?.policy;
  if (response?.group_id !== groupId || typeof response.is_default !== 'boolean' || !policy
      || !modes.some(mode => mode.value === policy.mode)
      || !['Critical', 'High', 'Medium', 'Low', 'None'].includes(policy.blocked_severity)
      || typeof policy.require_service_compliant !== 'boolean'
      || !(policy.max_scan_age_days === null || (Number.isInteger(policy.max_scan_age_days)
        && policy.max_scan_age_days >= 1 && policy.max_scan_age_days <= 3650))) {
    throw new Error('CATS returned an unexpected group pull policy. Reload to try again.');
  }
  return response as PolicyResponse;
}

function GroupEditor({data, groupId}: {data: PageData; groupId: number}) {
  const [saved, setSaved] = useState<PolicyResponse | null>(null);
  const [policy, setPolicy] = useState<PullPolicy | null>(null);
  const [age, setAge] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [attempt, setAttempt] = useState(0);
  const alive = useRef(false);
  const saveController = useRef<AbortController | null>(null);
  const url = `/api/oci/pull-policy?group_id=${groupId}`;

  useEffect(() => {
    alive.current = true;
    const controller = new AbortController();
    setPolicy(null); setSaved(null); setError(''); setNotice('');
    requestJson<unknown>(url, {signal: controller.signal}).then(value => {
      if (controller.signal.aborted) return;
      const result = checkedResponse(value, groupId);
      setSaved(result); setPolicy(result.policy); setAge(String(result.policy.max_scan_age_days ?? ''));
    }).catch(cause => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load the group pull policy.');
    });
    return () => {alive.current = false; controller.abort(); saveController.current?.abort();};
  }, [url, groupId, attempt]);

  function change(patch: Partial<PullPolicy>) {
    setPolicy(current => current ? {...current, ...patch} : current);
    setNotice('');
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!policy || busy) return;
    setError(''); setNotice('');
    const days = age.trim() ? Number(age) : null;
    if (days !== null && (!Number.isInteger(days) || days < 1 || days > 3650)) {
      setError('Maximum scan age must be blank or a whole number from 1 to 3650 days.'); return;
    }
    if (policy.mode !== 'approved_release' && policy.blocked_severity === 'None' && !policy.require_service_compliant) {
      setError('Choose a severity to block or require service compliance.'); return;
    }
    const controller = new AbortController();
    saveController.current = controller;
    setBusy(true);
    try {
      const value = await requestJson<unknown>(url, {method: 'PUT', signal: controller.signal,
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''},
        body: JSON.stringify({...policy, max_scan_age_days: days})});
      if (!alive.current || controller.signal.aborted) return;
      const result = checkedResponse(value, groupId);
      setSaved(result); setPolicy(result.policy); setAge(String(result.policy.max_scan_age_days ?? ''));
      setNotice('Group OCI pull policy saved. It applies to subsequent pulls, including cached content.');
    } catch (cause) {
      if (alive.current && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not save the group pull policy.');
    } finally {
      if (alive.current && !controller.signal.aborted) setBusy(false);
    }
  }

  return <>
    {!policy && !error && <p role="status">Loading group pull policy.</p>}
    {error && <div role="alert"><p>{error}</p><button type="button" className="button-secondary" disabled={busy}
      onClick={() => setAttempt(value => value + 1)}>Reload pull policy</button></div>}
    {policy && <form onSubmit={save}>
      <p>{saved?.is_default ? 'This group uses the default: approved releases.' : `Saved policy: ${modes.find(mode => mode.value === saved?.policy.mode)?.label}.`}</p>
      <label>OCI pull requirements<select value={policy.mode} disabled={busy} onChange={event => change({mode: event.target.value as Mode})}>
        {modes.map(mode => <option key={mode.value} value={mode.value}>{mode.label}</option>)}
      </select></label>
      <p>{modes.find(mode => mode.value === policy.mode)?.description}</p>
      {policy.mode !== 'approved_release' && <fieldset disabled={busy}>
        <legend>Compliance rules for pulls</legend>
        <div className="config-grid">
          <label>Block findings at or above<select value={policy.blocked_severity} onChange={event => change({blocked_severity: event.target.value as Severity})}>
            <option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="None">Do not apply a severity limit</option>
          </select></label>
          <label>Maximum scan age (days, optional)<input type="number" min="1" max="3650" step="1" value={age}
            onChange={event => {setAge(event.target.value); setNotice('');}}/></label>
        </div>
        <label className="policy-check"><input type="checkbox" checked={policy.require_service_compliant}
          onChange={event => change({require_service_compliant: event.target.checked})}/>Require service to be compliant</label>
        <p>Choosing Critical allows no Critical vulnerability findings for the image being pulled. Rules use findings retained by the scan; scan filters still apply. Missing or incomplete assessment evidence is denied.</p>
        <p className="muted">The optional service check also requires the service to pass its existing compliance policy. Imported services use verified publisher scan evidence and captured compliance status. Leave scan age blank to apply no additional age limit.</p>
      </fieldset>}
      <button disabled={busy}>{busy ? 'Saving pull policy.' : 'Save OCI pull policy'}</button>
    </form>}
    {notice && <p role="status">{notice}</p>}
  </>;
}

export function OciGroupPullPolicy({data, groupId}: {data: PageData; groupId?: number}) {
  return <section className="panel padded" aria-label="OCI pull policy">
    <h2>OCI pull policy</h2>
    <p>Choose what services owned by this group must satisfy before CATS allows their images to be pulled.</p>
    {groupId ? <GroupEditor key={groupId} data={data} groupId={groupId}/> : <p>Select an owning group to configure its OCI pull policy.</p>}
    <p className="muted">For example: Group A requires approval; Group B blocks Critical findings; Group C requires both. Public/private access and image integrity checks apply in every mode.</p>
  </section>;
}
