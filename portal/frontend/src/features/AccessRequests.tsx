import {useEffect, useState} from 'react';
import {requestJson, type PageData} from '../api';

type Queue = {requests: {user_id: number; username: string; display_name: string; created_at: string}[]; groups: {id: number; name: string}[]};
export function AccessRequests({data}: {data: PageData}) {
  const [queue, setQueue] = useState<Queue | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<number | null>(null);
  const [claimed, setClaimed] = useState('');
  useEffect(() => {let active = true; requestJson<Queue>('/api/accounts/access-requests').then(result => {if (active) setQueue(result);}).catch(error => {if (active) setError(error instanceof Error ? error.message : 'Unable to load access requests.');}); return () => {active = false;};}, []);
  async function claim(event: React.FormEvent<HTMLFormElement>, userId: number, username: string) {
    event.preventDefault(); setBusy(userId); setError(''); setClaimed('');
    const groupId = new FormData(event.currentTarget).get('group_id');
    try {
      await requestJson(`/api/accounts/access-requests/${userId}/claim`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: data.csrf_token, ...(groupId ? {group_id: Number(groupId)} : {})})});
      setQueue(current => current ? {...current, requests: current.requests.filter(row => row.user_id !== userId)} : current);
      setClaimed(`${username} now has Assessor access to the selected group.`);
    } catch (error) {setError(error instanceof Error ? error.message : 'Unable to claim account.');} finally {setBusy(null);}
  }
  return <section id="access-requests" className="panel padded admin-card"><h2>Pending access requests</h2><p>Claim an account into your service group to give it Assessor access. The account must still be awaiting access.</p>{error && <p role="alert">{error}</p>}{claimed && <p role="status">{claimed} <a href="/admin">Refresh accounts</a></p>}{!queue && !error && <p role="status">Loading access requests…</p>}{queue && (!queue.requests.length ? <p>No accounts are awaiting access.</p> : queue.requests.map(request => <form key={request.user_id} onSubmit={event => claim(event, request.user_id, request.username)}><h3>{request.display_name || request.username} <small>({request.username})</small></h3><label>Group for {request.username}<select name="group_id" required defaultValue={queue.groups.length === 1 ? queue.groups[0].id : ''}><option value="">Choose a group</option>{queue.groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label><button disabled={busy !== null || !queue.groups.length}>{busy === request.user_id ? 'Claiming…' : 'Claim as Assessor'}</button></form>))}</section>;
}
