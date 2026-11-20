import {useEffect, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';

type AccessRequest = {
  user_id: number;
  username: string;
  display_name: string;
  service_id?: number;
  service_name?: string;
};
type Queue = {requests: AccessRequest[]; groups: {id: number; name: string}[]};
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
    const groupId = new FormData(event.currentTarget).get('group_id');
    const scope = request.service_id ? {service_id: request.service_id} : {group_id: Number(groupId)};
    setBusy(key);
    setError('');
    setClaimed('');
    try {
      const result = await requestJson<{status: string}>(`/api/accounts/access-requests/${request.user_id}/claim`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf_token: data.csrf_token, ...scope}),
      });
      setQueue(current => current ? {...current, requests: current.requests.filter(row => requestKey(row) !== key)} : current);
      setClaimed(result.status === 'already_granted'
        ? `${request.username} already has access to ${request.service_name}.`
        : `Access request approved for ${request.username} (${request.service_name || 'selected group'}).`);
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
    {queue?.requests.map(request => <form key={requestKey(request)} onSubmit={event => claim(event, request)}>
      <h3>{request.display_name || request.username} <small>({request.username})</small></h3>
      {request.service_id
        ? <p>Requested service <strong>{request.service_name}</strong></p>
        : <label>Group for {request.username}
          <select name="group_id" required defaultValue={queue.groups.length === 1 ? queue.groups[0].id : ''}>
            <option value="">Choose a group</option>
            {queue.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}
          </select>
        </label>}
      <button disabled={busy !== null || (!request.service_id && !queue.groups.length)}>
        {busy === requestKey(request) ? 'Approving…' : request.service_id ? 'Approve service access as Assessor' : 'Claim as Assessor'}
      </button>
    </form>)}
  </section>;
}
