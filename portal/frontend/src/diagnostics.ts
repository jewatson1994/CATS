export interface Diagnostic {
  error_id: string; correlation_id: string; timestamp: string; component: string; operation: string;
  code: string; category: string; severity: string; status: number | string; summary: string;
  cause?: string | null; resolution: string[]; resource: Record<string, unknown>; retryable: boolean;
  technical?: Record<string, unknown>; context?: Record<string, unknown>;
}

const secretKey = /password|passwd|secret|token|authorization|cookie|credential|api[-_]?key|private[-_]?key|csrf|session|^(?:body|request_body|request_headers|headers|environment|env|payload)$/i;
/** Defense in depth for copied/exported reports; request bodies and headers are never collected. */
export function sanitizeDiagnostic(value: unknown, depth = 0): any {
  if (depth > 8) return '[omitted]';
  if (typeof value === 'string') return value.slice(0, 12000)
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, '[redacted]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [redacted]')
    .replace(/\b(?:https?:\/\/)[^\s"<>]+/gi, raw => {
      try {const url = new URL(raw); url.username = ''; url.password = ''; url.search = ''; url.hash = ''; return url.href;} catch {return '[redacted URL]';}
    })
    .replace(/((?:password|passwd|secret|token|authorization|cookie|api[_-]?key|csrf)[\w-]*["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1[redacted]');
  if (Array.isArray(value)) return value.slice(0, 100).map(item => sanitizeDiagnostic(item, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100)
    .map(([key, item]) => [key, secretKey.test(key) ? '[redacted]' : sanitizeDiagnostic(item, depth + 1)]));
  return value;
}

export function diagnosticReport(diagnostic: Diagnostic): string {
  return JSON.stringify(sanitizeDiagnostic(diagnostic), null, 2);
}

export function localDiagnostic(summary: string, status = 0, operation = 'request', code = 'CLIENT_REQUEST_FAILED'): Diagnostic {
  return {error_id: '', correlation_id: '', timestamp: new Date().toISOString(), component: 'browser', operation,
    code, category: status ? 'http' : 'network', severity: 'error', status, summary, cause: null,
    resolution: [status === 401 ? 'Sign in again, then retry the operation.' : 'Review the details and retry when the issue is resolved. If it continues, share this report with an administrator.'],
    resource: {}, retryable: status === 0 || status >= 500};
}

export interface DiagnosticNotice {key: number; diagnostic: Diagnostic; count: number}
let notices: DiagnosticNotice[] = [];
let sequence = 0;
const listeners = new Set<() => void>();
const emit = () => {for (const listener of listeners) listener();};
export const diagnosticNotices = {
  subscribe(listener: () => void) {listeners.add(listener); return () => {listeners.delete(listener);};},
  snapshot: () => notices,
  dismiss(key: number) {notices = notices.filter(item => item.key !== key); emit();},
  clear() {notices = []; emit();},
};
export function publishDiagnostic(diagnostic: Diagnostic) {
  const safe = sanitizeDiagnostic(diagnostic) as Diagnostic;
  const signature = (item: Diagnostic) => JSON.stringify([item.code, item.component, item.operation, item.status, item.summary, item.resource]);
  const previous = notices.find(item => signature(item.diagnostic) === signature(safe));
  notices = [...notices.filter(item => item !== previous), {key: previous?.key ?? ++sequence, diagnostic: safe, count: (previous?.count || 0) + 1}].slice(-3);
  emit();
}
