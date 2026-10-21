import {useEffect, useState} from 'react';
import {ApiError, can, requestJson, type PageData} from '../api';
import {ErrorState, Loading, StatusBadge} from '../components/ui';

type Revision = {id: number; decision: string; suspended: boolean; revoked: boolean; version: number; pointer_version: number | null; active_revision_id: number | null; manifest_digest: string; manifest: unknown};
export function ReleaseRevision({data, approvalId, serviceId}: {data: PageData; approvalId: string; serviceId: number}) {
  const url = `/api/approved-releases/${encodeURIComponent(approvalId)}/revision`;
  const [revision, setRevision] = useState<Revision | null>(null), [missing, setMissing] = useState(false), [error, setError] = useState(''), [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false), [reason, setReason] = useState(''), [notice, setNotice] = useState('');
  useEffect(() => {
    const controller = new AbortController(); setError('');
    requestJson<Revision>(url, {signal: controller.signal}).then(value => {if (!controller.signal.aborted) {setRevision(value); setMissing(false);}}).catch(error => {if (!controller.signal.aborted) {if (error instanceof ApiError && error.status === 404) setMissing(true); else setError(error instanceof Error ? error.message : 'Revision could not be loaded.');}});
    return () => controller.abort();
  }, [url, reload]);
  async function act(action: 'activate' | 'suspend' | 'revoke') {
    if (!revision || busy) return;
    setBusy(true); setError(''); setNotice('');
    try {
      setRevision(await requestJson<Revision>(`${url}/${action}`, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify({expected_version: action === 'activate' ? revision.pointer_version : revision.version, ...(action !== 'activate' ? {reason: reason.trim()} : {})})}));
      setNotice(action === 'activate' ? 'Release revision activated.' : action === 'suspend' ? 'Release revision suspended.' : 'Release revision revoked.'); setReason('');
    } catch (error) {setError(error instanceof Error ? error.message : 'Revision action failed.');} finally {setBusy(false);}
  }
  if (missing) return <section className="panel padded"><h2>Release revision</h2><p>This release has no governed revision record.</p></section>;
  return <section className="panel padded" aria-label="Release revision"><h2>Release revision</h2>{error && <ErrorState title="Revision request failed" onRetry={() => setReload(value => value + 1)}>{error}</ErrorState>}{notice && <p role="status">{notice}</p>}{!revision ? !error && <Loading label="Loading revision…"/> : <><p>Revision {revision.id} · <StatusBadge value={revision.decision}/> · {revision.active_revision_id === revision.id ? 'Selected active revision' : 'Not selected'}</p>{revision.suspended && <p>Suspended</p>}{revision.revoked && <p>Revoked</p>}<p>Manifest digest: <code>{revision.manifest_digest}</code></p><details><summary>Review frozen revision manifest</summary><pre className="approval-json">{JSON.stringify(revision.manifest, null, 2)}</pre></details><p>Activation rechecks current approval, expiry, artifact eligibility, and the signed manifest. A selected pointer alone does not authorize distribution.</p>{can(data, 'approval.decide', serviceId) && <div className="approval-form"><button disabled={busy || revision.decision !== 'approved' || revision.suspended || revision.revoked || revision.pointer_version === null || revision.active_revision_id === revision.id} onClick={() => act('activate')}>Activate revision</button><label>Restriction reason<textarea value={reason} onChange={event => setReason(event.target.value)} disabled={busy}/></label><button disabled={busy || revision.suspended || revision.revoked || !reason.trim()} onClick={() => act('suspend')}>Suspend revision</button><button disabled={busy || revision.revoked || !reason.trim()} onClick={() => act('revoke')}>Revoke revision</button></div>}</>}</section>;
}
