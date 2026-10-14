import {useState, type ReactNode} from 'react';
import {Csrf} from '../components/Form';
import type {PageData} from '../api';

interface Access {application_permissions: string[]; services: {id:number;name:string;permissions:string[]}[]}
interface Preview {token:string;note:string;users:{user_id:number;username:string;before:Access;after:Access}[]}
function AccessSummary({access}:{access:Access}) {
  return <><p>Application-wide: {access.application_permissions.join(', ') || 'None'}</p>{access.services.length ? access.services.map(service => <p key={service.id}><strong>{service.name}</strong>: {service.permissions.join(', ')}</p>) : <p>No service access</p>}</>;
}
export function MappingReviewForm({data, children, existing}:{data:PageData;children:ReactNode;existing:boolean}) {
  const [preview,setPreview] = useState<Preview|null>(null), [error,setError] = useState('');
  const [busy,setBusy] = useState(false);
  return <form method="post" action="/admin/configuration/oidc-mappings" onChange={() => setPreview(null)}
    onSubmit={async event => {
      const action = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement|null;
      if (action?.value !== 'preview') return;
      event.preventDefault(); setBusy(true); setError('');
      try {const body = new FormData(event.currentTarget); body.set('action','preview');
        const response = await fetch('/admin/configuration/oidc-mappings', {method:'POST',body,credentials:'same-origin'});
        const result = await response.json(); if (!response.ok) throw new Error(result.detail || 'Preview failed'); setPreview(result);
      } catch (error) {setError(error instanceof Error ? error.message : 'Preview failed');} finally {setBusy(false);}
    }}><Csrf data={data}/>{children}<input type="hidden" name="preview_token" value={preview?.token || ''}/>
    <button name="action" value="preview" disabled={busy}>Preview resulting access</button>
    {error && <p role="alert">{error}</p>}{preview && <section aria-label="Resulting access preview"><p>{preview.note}</p>{preview.users.map(user => <details key={user.user_id} open><summary>{user.username}</summary><h4>Current access</h4><AccessSummary access={user.before}/><h4>After saving</h4><AccessSummary access={user.after}/></details>)}</section>}
    <button name="action" value="save" disabled={busy || (existing && !preview)}>Confirm and save mapping</button>
  </form>;
}
