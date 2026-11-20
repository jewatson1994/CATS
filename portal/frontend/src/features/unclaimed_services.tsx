import {useState, type FormEvent} from 'react';
import {ApiError, requestJson, type PageData} from '../api';
import {safeReference} from '../components/Form';
import {EmptyState, ErrorState, Loading, PageHeader, StatusBadge} from '../components/ui';
import {useReplicaResource} from '../hooks/useReplicaResource';

const queueApi = '/api/unclaimed-services';
type Group = {id: number; name: string};
type Candidate = {
  id: number; project_name: string; project_path: string; web_url?: string | null;
  commit_sha: string; status: string; scanned: boolean; execution_id?: number | null;
  scanned_at?: string | null; source_name?: string; claim_group_id: number; claim_group_ids: number[];
};
type Queue = {items: Candidate[]; groups: Group[]; page: number; pages: number; total: number};
type Claimed = {service_id: number; service_key: string};
const pageHref = (page: number) => '/unclaimed-services?page=' + page;

function CandidateRow({item, groups, data, claimed, reportError, refresh}: {
  item: Candidate; groups: Group[]; data: PageData;
  claimed: (id: number, result: Claimed) => void; reportError: (message: string) => void; refresh: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const allowed = groups.filter(group => item.claim_group_ids.includes(group.id));
  const groupId = allowed.find(group => group.id === item.claim_group_id)?.id || '';
  const project = safeReference(item.web_url);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || item.execution_id == null) return;
    const values = new FormData(event.currentTarget);
    setBusy(true); reportError('');
    try {
      const result = await requestJson<Claimed>(queueApi + '/' + item.id + '/claim', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''},
        body: JSON.stringify({group_id: Number(values.get('group_id')), execution_id: item.execution_id, csrf_token: data.csrf_token}),
      });
      claimed(item.id, result);
    } catch (cause) {
      reportError(item.project_path + ' — ' + (cause instanceof Error ? cause.message : 'Could not claim this project.'));
      if (cause instanceof ApiError && [403, 404, 409].includes(cause.status)) refresh();
    } finally {setBusy(false);}
  }
  return <tr>
    <td><strong>{item.project_name || item.project_path}</strong>
      <div>{project ? <a href={project} rel="noreferrer" target="_blank">{item.project_path}</a> : item.project_path}</div>
      {item.source_name && <small>{item.source_name}</small>}</td>
    <td><code className="wrap-text">{item.commit_sha || 'Unavailable'}</code></td>
    <td><StatusBadge value={item.status}/>{item.execution_id != null && <div>Scan #{item.execution_id}</div>}
      {item.scanned_at && <time dateTime={item.scanned_at}>{new Date(item.scanned_at).toLocaleString()}</time>}</td>
    <td>{allowed.length > 0 ? <form onSubmit={submit}>
      <label>Claim group<select name="group_id" aria-label={'Claim group for ' + item.project_path} required defaultValue={groupId}>
        {!groupId && <option value="" disabled>Select a group</option>}{allowed.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}
      </select></label><button disabled={busy}>{busy ? 'Claiming…' : 'Claim service'}</button></form> :
      <span>No authorized claim group</span>}</td>
  </tr>;
}

export function Page({data}: {data: PageData}) {
  const enabled = data.cats_mode !== 'replica' && data.may_view_unclaimed === true;
  const requested = Number(new URLSearchParams(window.location.search).get('page'));
  const page = Number.isSafeInteger(requested) && requested > 0 ? requested : 1;
  const queue = useReplicaResource<Queue>(enabled ? queueApi + '?page=' + page : null);
  const [lastClaim, setLastClaim] = useState<{id: number; result: Claimed} | null>(null);
  const [claimError, setClaimError] = useState('');
  if (!enabled) return <ErrorState title="Unclaimed Services is unavailable"/>;
  const list = queue.value;
  const items = list?.items.filter(item => item.scanned && item.execution_id != null && item.id !== lastClaim?.id);
  return <><PageHeader title="Unclaimed Services" description="Review projects found by topic polling and claim scanned evidence for your group."
    actions={<button className="secondary-button" onClick={queue.reload}>Refresh queue</button>}/>
    {lastClaim && <p role="status">Service claimed. <a href={'/services/' + encodeURIComponent(lastClaim.result.service_key)}>Open service evidence</a></p>}
    {claimError && <p role="alert">{claimError}</p>}
    {queue.error ? <ErrorState title="Could not load unclaimed services" onRetry={queue.reload}>{queue.error}</ErrorState> :
     !list ? <Loading label="Loading unclaimed services…"/> : <section className="panel padded">
      {!items?.length ? <EmptyState title="No unclaimed services on this page">Projects appear here after CATS scans and ingests their latest revision.</EmptyState> :
        <div className="table-wrap"><table><thead><tr>{['Project', 'Source revision', 'Scan evidence', 'Claim'].map(column => <th key={column}>{column}</th>)}</tr></thead>
          <tbody>{items.map(item => <CandidateRow key={item.id + ':' + item.execution_id} item={item} groups={list.groups} data={data} reportError={setClaimError} refresh={queue.reload}
            claimed={(id, result) => {setLastClaim({id, result}); queue.reload();}}/>)}</tbody></table></div>}
      {list.pages > 1 && <nav className="pager" aria-label="Unclaimed services pages">
        {list.page > 1 && <a href={pageHref(list.page - 1)}>Previous page</a>}<span>Page {list.page} of {list.pages} · {list.total} projects</span>
        {list.page < list.pages && <a href={pageHref(list.page + 1)}>Next page</a>}</nav>}
    </section>}
  </>;
}
