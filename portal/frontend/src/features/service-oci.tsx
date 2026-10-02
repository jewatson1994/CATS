import {useState} from 'react';
import {can, requestJson, type PageData} from '../api';
import {Dialog} from '../components/Form';

export function ServiceOCIDestinations({data}: {data: PageData}) {
  const [rows,setRows] = useState<any[]>((data.oci_destinations || []).filter((row:any) => row.scope === 'service'));
  const [selected,setSelected] = useState(''), [error,setError] = useState(''), [result,setResult] = useState<any>(null);
  const [busy,setBusy] = useState(false);
  const root = `/api/services/${encodeURIComponent(data.service.service_key)}/oci-destinations`;
  if (!can(data,'service.edit',data.service.id)) return null;
  const mutate = async (method:string, suffix:string, body?:any) => {
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await requestJson<any>(root+suffix, {method,headers:{'Content-Type':'application/json','X-CSRF-Token':data.csrf_token || ''}, ...(body ? {body:JSON.stringify(body)} : {})});
      if (suffix.endsWith('/test')) setResult(response);
      else {const destinations = await requestJson<any[]>(root);setRows(destinations);setSelected('');window.dispatchEvent(new CustomEvent('cats:oci-destinations-changed',{detail:destinations}));}
    } catch (err) {setError(err instanceof Error ? err.message : 'Destination operation failed');}
    finally {setBusy(false);}
  };
  const current = rows.find(row => row.id === selected);
  return <Dialog button="OCI destinations" title="Service OCI destinations"><p>These destinations and their CA trust belong to this service. Credentials can be replaced without displaying stored values.</p>
    {error && <p role="alert" className="error">{error}</p>}
    <label>Destination<select value={selected} onChange={event => {setSelected(event.target.value);setResult(null);}}><option value="">New destination</option>{rows.map(row => <option key={row.id} value={row.id}>{row.name}{row.is_default ? ' (default)' : ''}</option>)}</select></label>
    <form key={selected + rows.map(row => row.endpoint).join()} onSubmit={event => {event.preventDefault(); const fields = new FormData(event.currentTarget);const body:any = {name:fields.get('name'),endpoint:fields.get('endpoint'),namespace:fields.get('namespace'),is_default:fields.get('is_default') === 'on'};for(const key of ['username','password','ca_pem']) if(fields.get(key)) body[key] = fields.get(key);if(fields.get('clear_credentials')) {body.username='';body.password='';}if(fields.get('clear_ca')) body.ca_pem='';void mutate(selected ? 'PATCH' : 'POST',selected ? `/${selected}` : '',body);event.currentTarget.reset();}}>
      <label>Name<input name="name" required maxLength={160} defaultValue={current?.name || ''}/></label>
      <label>HTTPS registry endpoint<input name="endpoint" required placeholder="https://registry.example" defaultValue={current?.endpoint || ''}/></label>
      <label>Repository namespace<input name="namespace" placeholder="team/service" defaultValue={current?.namespace || ''}/></label>
      <label>Replacement username<input name="username" autoComplete="off"/></label>
      <label>Replacement password or token<input name="password" type="password" autoComplete="new-password"/></label>
      <p>{current?.credentials_configured ? 'Credentials stored. Leave blank to retain them.' : 'No credentials stored.'}</p>
      <label><input type="checkbox" name="clear_credentials"/> Remove stored credentials</label>
      <label>Destination CA certificates (PEM)<textarea name="ca_pem" placeholder="Leave blank to retain configured CA trust"/></label>
      <p>{current?.ca_configured ? 'Destination CA trust configured.' : 'System CA trust only.'}</p>
      <label><input type="checkbox" name="clear_ca"/> Remove destination CA trust</label>
      <label><input type="checkbox" name="is_default" defaultChecked={current?.is_default || false}/> Default for this service</label>
      <button disabled={busy} type="submit">{selected ? 'Save destination' : 'Create destination'}</button>
    </form>
    {selected && <><button disabled={busy} type="button" onClick={() => void mutate('POST',`/${selected}/test`)}>Test connection</button><button disabled={busy} type="button" onClick={() => void mutate('DELETE',`/${selected}`)}>Delete destination</button></>}
    {result && <section aria-label="Connection test results">{Object.entries(result).map(([key,value]) => <p key={key}>{key.replaceAll('_',' ')}: {String(value)}</p>)}</section>}
  </Dialog>;
}
