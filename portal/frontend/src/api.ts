import {diagnosticNotices, localDiagnostic, publishDiagnostic, sanitizeDiagnostic, type Diagnostic} from './diagnostics';
export const PAGE_MEDIA_TYPE = 'application/vnd.cats.page+json';

export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly diagnostic?: Diagnostic, readonly detail?: unknown) {super(message); this.name = 'ApiError';}
}

type MutationListener = () => void;
const mutationListeners = new Set<MutationListener>();
/** Notified after every non-GET request (answered or not), so cached reads can be discarded. */
export function onMutation(listener: MutationListener): () => void {
  mutationListeners.add(listener);
  return () => {mutationListeners.delete(listener);};
}
const sessionListeners = new Set<() => void>();
/** Notified when the server reports that the session has ended (401 or redirect to sign-in). */
export function onSessionEnded(listener: () => void): () => void {
  sessionListeners.add(listener);
  return () => {sessionListeners.delete(listener);};
}
export function sessionEnded() {diagnosticNotices.clear(); for (const listener of [...sessionListeners]) listener();}

export function detailMessage(detail: unknown): string | undefined {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map(detailMessage).filter(Boolean).join('; ') || undefined;
  if (detail && typeof detail === 'object') {
    const value = detail as Record<string, unknown>;
    return detailMessage(value.message ?? value.reason ?? value.detail ?? value.msg ?? value.error ?? value.summary);
  }
}

/** Cookies stay HttpOnly. FormData preserves backend-owned validation and CSRF. */
export async function requestJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const target = new URL(url, window.location.origin);
  if (target.origin !== window.location.origin) throw new ApiError('External API URLs are not allowed.', 0);
  const headers = new Headers(options.headers);
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  const mutation = (options.method || 'GET').toUpperCase() !== 'GET';
  const fail = (message: string, status: number, detail?: unknown, diagnostic?: Diagnostic): never => {
    const safe = sanitizeDiagnostic(diagnostic || localDiagnostic(message, status, `${options.method || 'GET'} ${target.pathname}`)) as Diagnostic;
    publishDiagnostic(safe);
    throw new ApiError(sanitizeDiagnostic(message), status, safe, sanitizeDiagnostic(detail));
  };
  let response: Response;
  try {
    response = await fetch(target.href, {
      ...options, credentials: 'same-origin', cache: 'no-store',
      headers,
    });
  } catch (error) {
    if (options.signal?.aborted || (error instanceof Error && error.name === 'AbortError')) throw error;
    return fail(error instanceof Error && !(error instanceof TypeError) && error.message
      ? error.message : 'Unable to reach the server. Check your connection and try again.', 0);
  } finally {
    // Any mutation may have changed server state, including one whose
    // response was lost: discard cached reads either way.
    if (mutation) for (const listener of mutationListeners) listener();
  }
  if (response.redirected && new URL(response.url).pathname === '/login') {
    sessionEnded();
    window.location.assign(response.url);
    return fail('Your session has expired. Please sign in again.', 401);
  }
  if (response.status === 401) sessionEnded();
  if (!response.headers.get('content-type')?.includes('json')) {
    return fail('The server returned an unexpected response.', response.status);
  }
  let data: unknown;
  try {data = await response.json();} catch {return fail('The server returned invalid JSON.', response.status);}
  if (!response.ok) {
    const detail = (data as {detail?: unknown})?.detail;
    const diagnostic = (data as {diagnostic?: Diagnostic})?.diagnostic;
    return fail(detailMessage(detail) || diagnostic?.summary || 'The request could not be completed.', response.status, detail, diagnostic);
  }
  return data as T;
}

export interface PageData {
  current_user?: {display_name: string; theme: string} | null;
  csrf_token?: string;
  themes?: Record<string, string>;
  can?: Record<string, Record<string, boolean>>;
  next_path?: string;
  pending_request_count?: number;
  actionable_notifications?: {label: string; service: string; href?: string}[];
  cats_deployed_version?: string;
  [key: string]: any;
}
export interface PageEnvelope {schemaVersion: 1; page: string; data: PageData; cacheScope?: string; sessionIdentity?: string}

export function can(data: PageData, permission: string, serviceId?: number): boolean {
  return data.can?.[permission]?.[serviceId == null ? '*' : String(serviceId)] === true;
}
