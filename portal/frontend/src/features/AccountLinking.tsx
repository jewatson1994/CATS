import {useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';

export function AccountLinking({data}: {data: PageData}) {
  const [preview, setPreview] = useState<any>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const users = data.users || [];
  async function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(''); setPreview(null); setDone(false);
    const form = new FormData(event.currentTarget);
    try {
      const result = await requestJson<any>('/api/admin/accounts/preview', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: data.csrf_token, survivor_id: Number(form.get('survivor')), source_id: form.get('source') ? Number(form.get('source')) : null, issuer: form.get('issuer'), subject: form.get('subject'), identity_verified: form.get('verified') === 'on'})});
      setPreview(result);
      setSelected(result.survivor.roles.filter((r: any) => r.selectable).map((r: any) => r.id));
    } catch (e) {setError(e instanceof Error ? e.message : 'Unable to preview accounts');} finally {setBusy(false);}
  }
  async function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const confirmation = new FormData(event.currentTarget).get('confirmation');
    try {
      await requestJson('/api/admin/accounts/apply', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: data.csrf_token, preview_token: preview.preview_token, selected_assignment_ids: selected, confirmation})});
      setPreview(null); setDone(true);
    } catch (e) {setError(e instanceof Error ? e.message : 'Unable to apply change');} finally {setBusy(false);}
  }
  return <section className="panel padded admin-card"><h2>Link or merge OIDC accounts</h2>
    <p>Use the exact issuer and subject (sub) verified in your identity provider. Names and email addresses do not establish identity. Another administrator must make changes to your own account.</p>
    <form onSubmit={inspect}>
      <label>Surviving account (select the local account to retain its password)<select name="survivor" required>{users.map((u: any) => <option key={u.id} value={u.id}>{u.username}</option>)}</select></label>
      <label>Duplicate OIDC account to retire (optional)<select name="source"><option value="">Link an identity without merging</option>{users.map((u: any) => <option key={u.id} value={u.id}>{u.username}</option>)}</select></label>
      <label>Verified issuer URL<input name="issuer" type="url" required maxLength={2048}/></label>
      <label>Verified subject (sub)<input name="subject" required maxLength={1024} autoComplete="off"/></label>
      <label><input name="verified" type="checkbox" required/>I verified this issuer and subject in the identity provider, independently of the account name or email.</label>
      <button disabled={busy}>Preview account change</button>
    </form>
    {error && <p role="alert">{error}</p>}{done && <p role="status">Account change saved. Affected sessions were revoked. <a href="/admin">Refresh accounts</a>.</p>}
    {preview && <form onSubmit={apply}><h3>Review identities and access</h3>
      <p>Identity: <code>{preview.identity.issuer}</code> / <code>{preview.identity.subject}</code></p>
      {[preview.survivor, preview.source].filter(Boolean).map((account: any) => <article key={account.id}>
        <h4>{account.id === preview.survivor.id ? 'Surviving' : 'Retiring'}: {account.username} — {account.enabled ? 'Enabled' : 'Disabled'}</h4>
        <p>{account.local_credentials ? 'Local password is retained on the survivor.' : 'No local password.'} {account.scan_ownership.length} owned scans.</p>
        <ul>{account.identities.map((identity: any) => <li key={identity.identity_key}>{identity.issuer} / {identity.subject}</li>)}</ul>
        {!!account.external_subject && !account.identities.length && <p>Legacy identity: {account.external_subject}</p>}
        <p>Historical references remain attributed to this account: {Object.entries(account.historical_references).map(([name, count]) => `${name}: ${count}`).join(', ') || 'None'}.</p>
        {account.roles.map((role: any) => <label key={role.id}><input type="checkbox" disabled={!role.selectable} checked={selected.includes(role.id)} onChange={e => setSelected(old => e.target.checked ? [...old, role.id] : old.filter(id => id !== role.id))}/>{role.role} · {role.source} · {role.service || role.group || role.scope}<small> Permissions: {role.permissions.join(', ')}</small>{!role.selectable && <small>Re-evaluated at next OIDC login</small>}</label>)}
      </article>)}
      <ul>{preview.conflicts.map((item: string) => <li key={item}>{item}</li>)}</ul>
      <label>Type <strong>{preview.confirmation}</strong> to approve these exact changes<input name="confirmation" required autoComplete="off"/></label>
      <button disabled={busy}>Confirm account change</button>
    </form>}
  </section>;
}
