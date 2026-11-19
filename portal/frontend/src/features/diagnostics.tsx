import {useEffect, useState} from 'react';
import {ApiError, requestJson, type PageData} from '../api';
import {diagnosticReport, sanitizeDiagnostic, type Diagnostic} from '../diagnostics';
import {ErrorDetails} from '../components/ErrorDetails';
import {AdminTabs, Heading} from './admin_shared';

interface Results {items: Diagnostic[]; total: number; retention_days: number}
interface Recurrence {code: string; component: string; summary: string; count: number; last_seen: string}
const filterNames = ['q', 'component', 'service_id', 'job_id', 'severity', 'since', 'until', 'correlation_id'] as const;
const labels: Record<typeof filterNames[number], string> = {q: 'Search errors', component: 'Component', service_id: 'Service ID', job_id: 'Job ID', severity: 'Severity', since: 'From', until: 'Until', correlation_id: 'Correlation ID'};

function inputValue(name: typeof filterNames[number], query: string) {
  const value = new URLSearchParams(query).get(name) || '';
  if (!value || (name !== 'since' && name !== 'until')) return value;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  // datetime-local displays local wall time; submission converts it back to UTC.
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, -1);
}

export function Page({data}: {data: PageData}) {
  const allowed = data.may_view_diagnostics === true;
  const [query, setQuery] = useState(() => {
    const initial = new URLSearchParams(window.location.search);
    const clean = new URLSearchParams();
    for (const name of filterNames) if (initial.get(name)) clean.set(name, initial.get(name)!);
    return clean.toString();
  });
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [results, setResults] = useState<Results>();
  const [groups, setGroups] = useState<Recurrence[]>([]);
  const [selectedId, setSelectedId] = useState(new URLSearchParams(window.location.search).get('error_id') || '');
  const [selected, setSelected] = useState<Diagnostic>();
  const [failure, setFailure] = useState<Error>();
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!allowed) return;
    const controller = new AbortController();
    setLoading(true); setFailure(undefined);
    const params = new URLSearchParams(query); params.set('limit', '50'); params.set('offset', String(offset));
    void Promise.all([
      requestJson<Results>(`/api/diagnostics?${params}`, {signal: controller.signal}),
      requestJson<{items: Recurrence[]}>('/api/diagnostics/summary', {signal: controller.signal}),
    ]).then(([rows, summary]) => {if (!controller.signal.aborted) {setResults(rows); setGroups(summary.items);}})
      .catch(error => {if (!controller.signal.aborted) setFailure(error);})
      .finally(() => {if (!controller.signal.aborted) setLoading(false);});
    return () => controller.abort();
  }, [allowed, query, offset, revision]);
  useEffect(() => {
    if (!allowed || !selectedId) {setSelected(undefined); return;}
    const controller = new AbortController(); setSelected(undefined);
    void requestJson<Diagnostic>(`/api/diagnostics/${encodeURIComponent(selectedId)}`, {signal: controller.signal})
      .then(value => {if (!controller.signal.aborted) setSelected(value);})
      .catch(error => {if (!controller.signal.aborted) setFailure(error);});
    return () => controller.abort();
  }, [allowed, selectedId, revision]);
  function exportRows() {
    if (!results) return;
    const blob = new Blob([JSON.stringify({exported_at: new Date().toISOString(), total_matching: results.total,
      exported_count: results.items.length, offset, items: results.items.map(item => JSON.parse(diagnosticReport(item)))}, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob); const link = document.createElement('a');
    link.href = url; link.download = 'cats-diagnostics.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  if (!allowed) return <section className="panel padded" role="alert"><h1>Diagnostics Center</h1><p>Administrator access is required.</p></section>;
  return <><AdminTabs data={data} selected="diagnostics"/><Heading title="Diagnostics Center" description="Find operational failures, inspect resolution guidance, and share sanitized reports."/>
    <section className="panel padded"><form onSubmit={event => {
      event.preventDefault(); const form = new FormData(event.currentTarget); const params = new URLSearchParams();
      for (const name of filterNames) {const value = String(form.get(name) || '').trim(); if (value) params.set(name, name === 'since' || name === 'until' ? new Date(value).toISOString() : value);}
      setOffset(0); setQuery(params.toString()); setRevision(value => value + 1);
    }}><div className="diagnostic-filters">{filterNames.map(name => <label key={name}>{labels[name]}{name === 'severity'
      ? <select name={name} defaultValue={new URLSearchParams(query).get(name) || ''}><option value="">All severities</option>{['error', 'warning', 'critical', 'info'].map(value => <option key={value}>{value}</option>)}</select>
      : <input name={name} type={name === 'since' || name === 'until' ? 'datetime-local' : 'search'} step={name === 'since' || name === 'until' ? 'any' : undefined} defaultValue={inputValue(name, query)}/>}</label>)}</div>
      <div className="diagnostic-actions"><button type="submit">Search diagnostics</button><button type="button" className="secondary-button" onClick={() => setRevision(value => value + 1)}>Refresh</button>
        <button type="button" className="secondary-button" disabled={!results?.items.length || loading || !!failure} onClick={exportRows}>Export displayed reports</button></div></form>
      <p className="muted">Reports redact request bodies and credentials. Export includes the displayed page, up to 50 records.{results && ` Retention: ${results.retention_days} days.`}</p>
    </section>
    {failure && <ErrorDetails diagnostic={failure instanceof ApiError ? failure.diagnostic : undefined} message={failure.message} admin/>}
    {selected && <section className="panel padded" aria-label="Selected diagnostic"><div className="diagnostic-actions"><h2>Diagnostic report</h2><button type="button" className="secondary-button" onClick={() => setSelectedId('')}>Close report</button></div><ErrorDetails diagnostic={selected} admin expanded/></section>}
    <section className="panel padded" aria-busy={loading}><h2>Recorded errors</h2>{loading && <p role="status">Loading diagnostics…</p>}
      {!loading && !failure && results?.items.length === 0 && <p>No diagnostics match these filters.</p>}
      <div className="diagnostic-table-scroll"><table className="diagnostic-results"><thead><tr><th>Time</th><th>Component / code</th><th>Summary</th><th>Severity</th><th>Details</th></tr></thead><tbody>
        {(results?.items || []).map(raw => {const item = sanitizeDiagnostic(raw) as Diagnostic; return <tr key={item.error_id}><td>{item.timestamp}</td><td>{item.component}<br/><code>{item.code}</code></td><td>{item.summary}</td><td>{item.severity}</td><td><button type="button" className="secondary-button" onClick={() => setSelectedId(item.error_id)}>Inspect</button></td></tr>;})}
      </tbody></table></div>
      {results && <div className="diagnostic-actions"><span>{results.total ? `${offset + 1}–${offset + results.items.length}` : '0'} of {results.total} matching records</span><button type="button" className="secondary-button" disabled={!offset || loading} onClick={() => setOffset(value => Math.max(0, value - 50))}>Previous</button><button type="button" className="secondary-button" disabled={offset + 50 >= results.total || loading} onClick={() => setOffset(value => value + 50)}>Next</button></div>}
    </section>
    <section className="panel padded"><h2>Recurring failures</h2><p className="muted">Counts across retained diagnostics, independent of the filters above.</p>{!groups.length && !loading && <p>No recurring failures recorded.</p>}
      <div className="diagnostic-table-scroll"><table className="diagnostic-results"><thead><tr><th>Component / code</th><th>Summary</th><th>Occurrences</th><th>Last seen</th></tr></thead><tbody>{groups.map(group => <tr key={`${group.component}:${group.code}`}><td>{group.component} / <code>{group.code}</code></td><td>{sanitizeDiagnostic(group.summary)}</td><td>{group.count}</td><td>{group.last_seen}</td></tr>)}</tbody></table></div>
    </section></>;
}
