import {useEffect, useState} from 'react';
import {requestJson} from '../api';

const api = '/api/admin/log-forwarding/components';
interface Source {source_id: string; source_name: string; last_received_at: string}
interface EventRow {id: number; event_id: string; timestamp: string; received_at: string; data: Record<string, unknown>}
interface EventPage {events: EventRow[]; next_before_id: number | null}

function useReceiptQuery<T>(url: string, revision: number) {
  const [result, setResult] = useState<{url: string; revision: number; data?: T; error?: string}>();
  useEffect(() => {
    const controller = new AbortController();
    requestJson<T>(url, {signal: controller.signal}).then(data => {
      if (!controller.signal.aborted) setResult({url, revision, data});
    }).catch((error: Error) => {
      if (!controller.signal.aborted) setResult({url, revision, error: error.message});
    });
    return () => controller.abort();
  }, [url, revision]);
  return result?.url === url && result.revision === revision ? result : undefined;
}

function ReceivedEvents({source, revision}: {source: Source; revision: number}) {
  const [before, setBefore] = useState<number | null>(null);
  const params = new URLSearchParams({source_id: source.source_id, limit: '25'});
  if (before !== null) params.set('before_id', String(before));
  const result = useReceiptQuery<EventPage>(api + '/events?' + params, revision);
  const page = result?.data;
  return <section aria-label={'Events from ' + source.source_name}><h4>{source.source_name}</h4>
    {result?.error && <p role="alert">{result.error}</p>}
    {!result && <p role="status">Loading events.</p>}
    {page && <>
      {page.events.length === 0 && <p>No retained operational events for this source.</p>}
      {page.events.map(event => <details key={event.id}><summary>
        <time dateTime={event.received_at}>{new Date(event.received_at).toLocaleString()}</time> · <code>{event.event_id}</code>
      </summary><p>Source time <time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time></p>
        <pre className="audit-detail">{JSON.stringify(event.data, null, 2)}</pre>
      </details>)}
      <div className="config-actions">
        {before !== null && <button type="button" onClick={() => setBefore(null)}>Newest events</button>}
        {page.next_before_id !== null && <button type="button" onClick={() => setBefore(page.next_before_id)}>Older events</button>}
      </div>
    </>}
  </section>;
}

function ReceiptList() {
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<Source | null>(null);
  const result = useReceiptQuery<{components: Source[]}>(api, revision);
  const sources = result?.data?.components;
  return <>
    <p>Sources with operational events stored at HQ, ordered by last receipt.</p>
    <button type="button" onClick={() => setRevision(value => value + 1)}>Refresh receipts</button>
    {result?.error && <p role="alert">{result.error}</p>}
    {!result && <p role="status">Loading reporting sources.</p>}
    {sources?.length === 0 && <p>HQ has no retained operational events.</p>}
    {!!sources?.length && <table><thead><tr><th>Reporting source</th><th>Last received at HQ</th></tr></thead>
      <tbody>{sources.map(source => <tr key={source.source_id}><td><button type="button" className="secondary-button"
        onClick={() => setSelected(source)}>{source.source_name}</button></td>
        <td><time dateTime={source.last_received_at}>{new Date(source.last_received_at).toLocaleString()}</time></td></tr>)}</tbody>
    </table>}
    {selected && <ReceivedEvents key={selected.source_id + ':' + revision} source={selected} revision={revision}/>}
  </>;
}

export function ReceivedByHQ() {
  const [open, setOpen] = useState(false);
  return <section className="panel padded configuration-panel" aria-label="Received by HQ">
    <h3><button type="button" className="secondary-button" aria-expanded={open} onClick={() => setOpen(!open)}>Received by HQ</button></h3>
    {open && <ReceiptList/>}
  </section>;
}
