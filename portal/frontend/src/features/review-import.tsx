import {useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';
import {Csrf, Dialog} from '../components/Form';
import './review-import.css';

const kindLabels: Record<string, string> = {poams: 'POA&Ms', mitigations: 'Mitigations', exceptions: 'Exceptions'};
const fieldLabels: Record<string, string> = {
  title: 'Title', description: 'Description', remediation: 'Remediation', due_date: 'Due date',
  finding_id: 'Vulnerability finding ID', policy_finding_id: 'Policy finding ID',
  justification: 'Justification', expires_at: 'Expiration', ticket: 'Ticket',
};
interface Preview {
  token?: string;
  recognized: number;
  rows: {row: number; values: Record<string, unknown>}[];
  errors: {row?: number; field?: string; message: string}[];
}
interface ImportResult {batch_id: number; count: number; href: string}

/** A confirmed file becomes one Cyber review request with independently reviewed rows. */
export function ReviewImport({data}: {data: PageData}) {
  const kinds: string[] = (data.review_import_kinds || []).filter((value: string) => kindLabels[value]);
  const [kind, setKind] = useState(kinds[0] || 'poams');
  const [preview, setPreview] = useState<Preview | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  if (!kinds.length || !data.service) return null;
  const root = `/services/${encodeURIComponent(data.service.service_key)}/review-imports`;
  const reset = () => {setPreview(null); setResult(null); setError('');};
  const validate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const body = new FormData(event.currentTarget);
    reset(); setBusy(true);
    try {setPreview(await requestJson<Preview>(`${root}/${kind}/preview`, {method: 'POST', body}));}
    catch (reason) {setError(reason instanceof Error ? reason.message : 'Unable to validate this file.');}
    finally {setBusy(false);}
  };
  const confirm = async () => {
    if (!preview?.token || preview.errors.length || busy) return;
    setBusy(true); setError('');
    const body = new FormData(); body.set('csrf_token', data.csrf_token || '');
    try {setResult(await requestJson<ImportResult>(`${root}/confirm/${encodeURIComponent(preview.token)}`, {method: 'POST', body}));}
    catch (reason) {setError(reason instanceof Error ? reason.message : 'Unable to submit this import.');}
    finally {setBusy(false);}
  };
  const fields = preview ? [...new Set(preview.rows.flatMap(row => Object.keys(row.values)))] : [];
  return <Dialog button="Import for Cyber review" title={`Import for ${data.service.name}`} className="review-dialog review-import-dialog" buttonClass="secondary-button">
    <p>Each line creates a separate entry awaiting Cyber approval. The import sends one request containing all rows, which Cyber can approve or deny individually.</p>
    {result ? <div role="status"><p>Submitted {result.count} {result.count === 1 ? 'entry' : 'entries'} in one Cyber review request.</p><a className="primary-button" href={result.href}>Open review request</a><button type="button" className="secondary-button" onClick={reset}>Import another file</button></div> : <>
      <form onSubmit={validate}>
        <Csrf data={data}/>
        <label>Entry type<select value={kind} disabled={busy} onChange={event => {setKind(event.target.value); reset();}}>{kinds.map(value => <option key={value} value={value}>{kindLabels[value]}</option>)}</select></label>
        <p><a href={`${root}/${kind}/template.csv`}>Download {kindLabels[kind]} template</a>. Use the template headers in a CSV or Excel workbook. Dates use ISO format, for example 2026-12-31.</p>
        {kind === 'exceptions' && <p>Each exception must identify a vulnerability finding or a policy finding belonging to this service.</p>}
        <label>Import file<input name="upload" type="file" accept=".csv,.xlsx" required disabled={busy} onChange={reset}/></label>
        <button disabled={busy}>{busy ? 'Processing…' : 'Validate and preview'}</button>
      </form>
      {preview && <section aria-label="Import preview" aria-busy={busy}>
        <h4>{preview.recognized} {preview.recognized === 1 ? 'row' : 'rows'} found</h4>
        {!!preview.errors.length && <div role="alert"><p>Correct these errors and upload the file again. No entries have been created.</p><ul>{preview.errors.map((issue, index) => <li key={index}>{issue.row != null && `Row ${issue.row}: `}{issue.field && `${fieldLabels[issue.field] || issue.field} — `}{issue.message}</li>)}</ul></div>}
        {!!preview.rows.length && <div className="table-wrap review-import-preview"><table><thead><tr><th>Row</th>{fields.map(field => <th key={field}>{fieldLabels[field] || field.replaceAll('_', ' ')}</th>)}</tr></thead><tbody>{preview.rows.map(row => <tr key={row.row}><th scope="row">{row.row}</th>{fields.map(field => <td key={field}>{row.values[field] == null || row.values[field] === '' ? '—' : String(row.values[field])}</td>)}</tr>)}</tbody></table></div>}
        <button type="button" disabled={busy || !!preview.errors.length || !preview.token || !preview.rows.length} onClick={confirm}>Submit {preview.recognized} {preview.recognized === 1 ? 'entry' : 'entries'} for Cyber review</button>
      </section>}
    </>}
    {error && <p role="alert" className="error">{error}</p>}
  </Dialog>;
}
