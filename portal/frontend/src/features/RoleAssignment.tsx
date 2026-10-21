import {useState} from 'react';
import {can, type PageData} from '../api';
import {Post} from './admin_shared';

export function signInMethods(user: any): string[] {
  return Array.isArray(user.sign_in_methods) ? user.sign_in_methods : [user.auth_source].filter(Boolean);
}
export function signInLabel(user: any): string {
  const methods = signInMethods(user);
  return methods.includes('local') && methods.includes('oidc') ? 'Local + OIDC' : methods.includes('oidc') ? 'OIDC' : methods.includes('local') ? 'Local' : 'No sign-in method';
}

export function RoleAssignment({data, userId}: {data: PageData; userId?: number}) {
  const [accountId, setAccountId] = useState(String(userId || ''));
  const [roleId, setRoleId] = useState('');
  const [mode, setMode] = useState('');
  const [scope, setScope] = useState(can(data, 'role.manage') ? 'services' : 'group');
  const [services, setServices] = useState<string[]>([]);
  const [serviceSearch, setServiceSearch] = useState('');
  const role = (data.roles || []).find((item: any) => String(item.id) === roleId);
  const account = (data.user_rows || []).find((row: any) => String(row.user.id) === accountId);
  const methods = signInMethods(account?.user || {});
  const grantMode = mode || 'local';
  const oidcEligible = methods.includes('oidc') && account?.eligibility?.some((entry: any) => entry.role === role?.name && entry.mode === 'cats_managed' && entry.active);
  const globalAllowed = can(data, 'role.manage');
  return <Post data={data} action="/admin/assignments" className="role-assignment-form">
    {userId ? <input type="hidden" name="user_id" value={userId}/> : <label>Account<select name="user_id" required value={accountId} onChange={event => {setAccountId(event.target.value); setMode('');}}><option value="">Choose an account</option>{(data.users || []).map((user: any) => <option key={user.id} value={user.id}>{user.display_name || user.username} ({user.username})</option>)}</select></label>}
    <label>Role<select name="role_id" required value={roleId} onChange={event => {setRoleId(event.target.value); setMode(''); if (!globalAllowed) setScope('group');}}><option value="">Choose a role</option>{(data.roles || []).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
    {role && <p className="muted">{role.description || role.name}</p>}
    <label>Grant source<select name="assignment_mode" value={grantMode} onChange={event => setMode(event.target.value)}><option value="local">Independent role grant</option>{oidcEligible && <option value="cats_scope">OIDC role with CATS-managed scope</option>}</select></label>
    <p className="muted">{grantMode === 'cats_scope' ? 'Access is active only while this account has the matching OIDC role. Assigning scope does not grant OIDC eligibility.' : 'This role stays active independently of identity-provider claims and applies to every sign-in method on the account.'}</p>
    <label>Access scope<select value={scope} onChange={event => setScope(event.target.value)}>{(globalAllowed || role?.name === 'Service Manager') && <option value="services">Selected services</option>}<option value="group">One service group</option>{globalAllowed && <option value="global">Global access</option>}</select></label>
    {scope === 'services' && <fieldset><legend>Services ({services.length} selected)</legend><label>Find a service<input type="search" value={serviceSearch} onChange={event => setServiceSearch(event.target.value)}/></label><div className="assignment-service-list">{(data.services || []).map((service: any) => <label key={service.id} hidden={!service.name.toLowerCase().includes(serviceSearch.toLowerCase())}><input type="checkbox" name="service_ids" value={service.id} checked={services.includes(String(service.id))} onChange={event => setServices(current => event.target.checked ? [...current, String(service.id)] : current.filter(id => id !== String(service.id)))}/>{service.name}</label>)}</div>{!(data.services || []).some((service: any) => service.name.toLowerCase().includes(serviceSearch.toLowerCase())) && <p>No services match your search.</p>}</fieldset>}
    {(scope === 'group' || !globalAllowed) && <label>Service group<select name="group_id" required defaultValue=""><option value="">Choose a group</option>{(data.groups || []).map((group: any) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>}
    {scope === 'global' && <label><input type="checkbox" name="explicit_global" value="true" required/>Grant this role globally, including its application-wide permissions.</label>}
    <button disabled={!accountId || !roleId || (scope === 'services' && !services.length)}>Assign role</button>
  </Post>;
}

