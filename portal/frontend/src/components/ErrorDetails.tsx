import {useState, useSyncExternalStore} from 'react';
import {diagnosticNotices, diagnosticReport, localDiagnostic, sanitizeDiagnostic, type Diagnostic} from '../diagnostics';
import './diagnostics.css';

function fieldText(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : '';
}

function originatingSourceFrame(technical?: Record<string, unknown>): string {
  const exceptions = technical?.exceptions;
  if (!Array.isArray(exceptions)) return '';
  // The server records the outer exception first, followed by its causes.
  // Each traceback runs from the caller to the frame that raised the error.
  for (const exception of [...exceptions].reverse()) {
    if (!Array.isArray(exception?.frames)) continue;
    for (const frame of [...exception.frames].reverse()) {
      if (!frame || typeof frame !== 'object') continue;
      const file = fieldText(frame.file), line = fieldText(frame.line), name = fieldText(frame.function);
      if (file || line || name) return [file, line && `line ${line}`, name && `function ${name}`].filter(Boolean).join(' · ');
    }
  }
  return '';
}

export function DiagnosticLinks({diagnostic, admin = false}: {diagnostic: Diagnostic; admin?: boolean}) {
  const resource = diagnostic.resource || {};
  const service = typeof resource.service_key === 'string' ? resource.service_key.trim() : '';
  const rawJob = typeof resource.job_id === 'string' ? resource.job_id.trim() : '';
  // Jobs projects scan and provisioning IDs with prefixes; other resource IDs
  // (for example deployment validation runs) do not identify Jobs records.
  let job = typeof resource.jobs_view_id === 'string' ? resource.jobs_view_id.trim() : '';
  if (!job && /^(scan|validator):.+$/.test(rawJob)) job = rawJob;
  if (!job && rawJob && diagnostic.component === 'scanner') job = `scan:${rawJob}`;
  if (!job && rawJob && diagnostic.component === 'worker') job = rawJob;
  if (!job && diagnostic.component === 'provisioning' && typeof resource.operation_id === 'string' && resource.operation_id.trim()) {
    job = `validator:${resource.operation_id.trim()}`;
  }
  return <nav className="diagnostic-actions" aria-label="Related diagnostic resources">
    {service && <a href={`/services/${encodeURIComponent(service)}`}>Open service</a>}
    {job && <a href={`/jobs?job=${encodeURIComponent(job)}`}>Open job</a>}
    {admin && diagnostic.error_id && <a href={`/admin/diagnostics?error_id=${encodeURIComponent(diagnostic.error_id)}`}>Inspect in Diagnostics Center</a>}
    {admin && diagnostic.correlation_id && <a href={`/admin/diagnostics?correlation_id=${encodeURIComponent(diagnostic.correlation_id)}`}>Related events</a>}
  </nav>;
}

export function ErrorDetails({diagnostic, message, admin = false, expanded = false}: {
  diagnostic?: Diagnostic; message?: string; admin?: boolean; expanded?: boolean;
}) {
  const value = sanitizeDiagnostic(diagnostic || localDiagnostic(message || 'The operation could not be completed.')) as Diagnostic;
  const context = value.context || {};
  const affected = Object.entries(value.resource || {}).map(([key, item]) => {
    const text = fieldText(item);
    return text ? `${key.replaceAll('_', ' ')}: ${text}` : '';
  }).filter(Boolean).join(' · ');
  const evidence = [
    ['Affected resource', affected],
    ['Failed stage', fieldText(context.failed_stage) || fieldText(context.stage)],
    ['Last successful stage', fieldText(context.last_successful_stage)],
    ['Worker identity', fieldText(context.worker_id)],
    ['Tool', fieldText(context.tool)],
    ['Tool exit code', fieldText(context.exit_code)],
    ['Source', originatingSourceFrame(value.technical)],
  ];
  const [copyStatus, setCopyStatus] = useState('');
  async function copy() {
    try {await navigator.clipboard.writeText(diagnosticReport(value)); setCopyStatus('Report copied.');}
    catch {setCopyStatus('Clipboard unavailable. Select and copy the report below.');}
  }
  return <section className="diagnostic-error" aria-label="Error details">
    <p className="diagnostic-summary">{value.summary}</p>
    <details open={expanded || undefined}><summary>View error details</summary>
      <dl className="diagnostic-fields">
        <div><dt>Known cause</dt><dd>{value.cause || 'The cause has not been confirmed.'}</dd></div>
        <div><dt>Component / operation</dt><dd>{value.component} / {value.operation}</dd></div>
        {evidence.filter(([, text]) => text).map(([label, text]) => <div key={label}><dt>{label}</dt><dd>{text}</dd></div>)}
        <div><dt>Error code / status</dt><dd><code>{value.code}</code> · {value.status || 'No HTTP response'} · {value.severity}</dd></div>
        <div><dt>Time</dt><dd>{value.timestamp}</dd></div>
        <div><dt>Error ID</dt><dd><code>{value.error_id || 'Not recorded on the server'}</code></dd></div>
        <div><dt>Correlation ID</dt><dd><code>{value.correlation_id || 'Not available'}</code></dd></div>
        <div><dt>Retry guidance</dt><dd>{value.retryable ? 'Retry may succeed after the issue is resolved.' : 'Review the resolution steps before retrying.'}</dd></div>
      </dl>
      <strong>How to resolve</strong><ul>{(value.resolution?.length ? value.resolution : ['Share the error and correlation IDs with an administrator for investigation.']).map((step, index) => <li key={index}>{step}</li>)}</ul>
      <DiagnosticLinks diagnostic={value} admin={admin}/>
      <div className="diagnostic-actions"><button type="button" className="secondary-button" onClick={() => void copy()}>Copy sanitized report</button><span role="status">{copyStatus}</span></div>
      <details><summary>Sanitized technical report</summary><pre className="diagnostic-report" tabIndex={0}>{diagnosticReport(value)}</pre></details>
    </details>
  </section>;
}

export function ErrorNotifications({admin = false}: {admin?: boolean}) {
  const notices = useSyncExternalStore(diagnosticNotices.subscribe, diagnosticNotices.snapshot);
  if (!notices.length) return null;
  return <aside className="diagnostic-notifications" aria-label="Recent request errors">
    {notices.map(item => <div className="panel padded diagnostic-notice" key={item.key}>
      <div className="diagnostic-actions"><strong role="status">Request failed{item.count > 1 ? ` (${item.count} occurrences)` : ''}</strong>
        <button type="button" className="secondary-button" aria-label="Dismiss error" onClick={() => diagnosticNotices.dismiss(item.key)}>Dismiss</button></div>
      <ErrorDetails diagnostic={item.diagnostic} admin={admin}/>
    </div>)}
  </aside>;
}
