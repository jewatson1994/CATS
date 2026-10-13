import {useState} from 'react';
import {requestJson, type PageData} from '../api';

export interface OidcCandidate {
  kind: 'group' | 'realm_role' | 'client_role';
  label: string;
  claim_path: string;
  expected_value: string;
}
interface Directory {provider: string; candidates: OidcCandidate[]; warnings: string[]}
const names = {group: 'Group', realm_role: 'Realm role', client_role: 'Client role'};

export function OidcDiscovery({data, onSelect}: {data: PageData; onSelect: (candidate: OidcCandidate) => void}) {
  const [directory, setDirectory] = useState<Directory | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [query, setQuery] = useState('');
  async function discover() {
    setBusy(true); setError(''); setDirectory(null);
    const body = new FormData();
    body.set('csrf_token', data.csrf_token || '');
    try {
      setDirectory(await requestJson<Directory>('/admin/configuration/oidc-mappings/discover', {method: 'POST', body}));
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'Unable to discover provider groups and roles.');
    } finally {setBusy(false);}
  }
  const candidates = directory?.candidates.filter(row => `${row.label} ${names[row.kind]} ${row.expected_value}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())) || [];
  return <div className="config-edit-card">
    <h3>Available provider groups and roles</h3>
    <p>Discover memberships from your saved Keycloak connection, then choose their CATS role and scope. Save any OIDC connection changes first.</p>
    <p className="muted">Keycloak requires service accounts enabled for this client and permission to read groups, roles, clients, and client scopes. Membership mappers must include claims in the ID token.</p>
    <button type="button" disabled={busy} onClick={discover}>{busy ? 'Discovering…' : directory ? 'Refresh groups and roles' : 'Discover groups and roles'}</button>
    {busy && <p role="status">Reading available groups and roles…</p>}
    {error && <p role="alert">{error}</p>}
    {directory && <>
      {directory.warnings.map((warning, index) => <p role="status" key={index}>{warning}</p>)}
      <p role="status">{directory.candidates.length} available mappings found. Selecting one opens the mapping editor; access changes only when you save the mapping.</p>
      {!!directory.candidates.length && <label>Filter provider groups and roles<input type="search" value={query} onChange={event => setQuery(event.target.value)}/></label>}
      {!!candidates.length && <div className="table-wrap"><table><thead><tr><th>Provider membership</th><th>Type</th><th>Action</th></tr></thead><tbody>{candidates.map((row, index) => <tr key={`${row.claim_path}:${row.expected_value}:${index}`}><td>{row.label}</td><td>{names[row.kind]}</td><td><button type="button" className="button-secondary" onClick={() => onSelect(row)} aria-label={`Map ${names[row.kind].toLowerCase()} ${row.label}`}>Map to CATS</button></td></tr>)}</tbody></table></div>}
      {!candidates.length && <p>{directory.candidates.length ? 'No memberships match your filter.' : 'No memberships are available with the current ID token settings.'}</p>}
    </>}
  </div>;
}
