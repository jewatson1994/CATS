import {useEffect, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';

type AccessRequest = {
  user_id: number;
  username: string;
  display_name: string;
  service_id?: number;
  service_name?: string;
};
type Option = {id: number; name: string};
type Queue = {requests: AccessRequest[]; groups: Option[]; roles: Option[]};
const requestKey = (request: AccessRequest) => `${request.user_id}/${request.service_id ?? 'group'}`;

export function AccessRequests({data}: {data: PageData}) {
  const [queue, setQueue] = useState<Queue | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [claimed, setClaimed] = useState('');
  useEffect(() => {
    let active = true;
    requestJson<Queue>('/api/accounts/access-requests')
      .then(result => {if (active) setQueue(result);})
      .catch(error => {if (active) setError(error instanceof Error ? error.message : 'Unable to load access requests.');});
    return () => {active = false;};
  }, []);

  async function claim(event: FormEvent<HTMLFormElement>, request: AccessRequest) {
    event.preventDefault();
    const key = requestKey(request);
    const form = new FormData(event.currentTarget);
    const role = queue?.roles.find(item => item.id === Number(form.get('role_id')));
    const group = queue?.groups.find(item => item.id === Number(form.get('group_id')));
    if (!role || (!request.service_id && !group)) return;
    const scope = request.service_id ? {service_id: request.service_id} : {group_id: group?.id};
    const scopeName = request.service_name || group?.name;
    setBusy(key);
    setError('');
    setClaimed('');
    try {
      const result = await requestJson<{status: string; role?: string}>(`/api/accounts/access-requests/${request.user_id}/claim`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf_token: data.csrf_token, role_id: role.id, ...scope}),
      });
      setQueue(current => current ? {...current, requests: current.requests.filter(row => requestKey(row) !== key)} : current);
      setClaimed(result.status === 'already_granted'
        ? `${request.username} already has access to ${scopeName}.`
        : `Approved ${request.username} as ${result.role || role.name} for ${scopeName}.`);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to approve this request.');
    } finally {
      setBusy(null);
    }
  }

  return <section id="access-requests" className="panel padded admin-card">
    <h2>Pending access requests</h2>
    {error && <p role="alert">{error}</p>}
    {claimed && <p role="status">{claimed} <a href="/admin">Refresh accounts</a></p>}
    {!queue && !error && <p role="status">Loading access requests…</p>}
    {queue && !queue.requests.length && <p>No accounts are awaiting access.</p>}
    {queue && queue.requests.length > 0 && !queue.roles.length && <p>No roles are available to approve these requests.</p>}
    {queue?.requests.map(request => <form className="access-request-form" key={requestKey(request)} onSubmit={event => claim(event, request)}>
      <header>
        <h3>{request.display_name || request.username} {request.display_name && request.display_name !== request.username && <small>({request.username})</small>}</h3>
        {request.service_id && <p>Requested service <strong>{request.service_name}</strong></p>}
      </header>
      {!request.service_id && <label>Group for {request.username}
        <select name="group_id" required defaultValue={queue.groups.length === 1 ? queue.groups[0].id : ''}>
          <option value="">Choose a group</option>
          {queue.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}
        </select>
      </label>}
      <label>Role
        <select name="role_id" required defaultValue={queue.roles.find(role => role.name === 'Assessor')?.id ?? ''}
          aria-label={`Role for ${request.username}${request.service_name ? ' on ' + request.service_name : ''}`}>
          <option value="" disabled>Choose a role</option>
          {queue.roles.map(role => <option key={role.id} value={role.id}>{role.name}</option>)}
        </select>
      </label>
      <button type="submit" disabled={busy !== null || !queue.roles.length || (!request.service_id && !queue.groups.length)}>
        {busy === requestKey(request) ? 'Approving…' : 'Approve access'}
      </button>
    </form>)}
  </section>;
}
