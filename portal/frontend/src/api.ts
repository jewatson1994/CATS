export const PAGE_MEDIA_TYPE = 'application/vnd.cats.page+json';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {super(message);}
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
export function sessionEnded() {for (const listener of [...sessionListeners]) listener();}

/** Cookies stay HttpOnly. FormData preserves backend-owned validation and CSRF. */
export async function requestJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const target = new URL(url, window.location.origin);
  if (target.origin !== window.location.origin) throw new ApiError('External API URLs are not allowed.', 0);
  const headers = new Headers(options.headers);
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  const mutation = (options.method || 'GET').toUpperCase() !== 'GET';
  let response: Response;
  try {
    response = await fetch(target.href, {
      ...options, credentials: 'same-origin', cache: 'no-store',
      headers,
    });
  } finally {
    // Any mutation may have changed server state, including one whose
    // response was lost: discard cached reads either way.
    if (mutation) for (const listener of mutationListeners) listener();
  }
  if (response.redirected && new URL(response.url).pathname === '/login') {
    sessionEnded();
    window.location.assign(response.url);
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  if (response.status === 401) sessionEnded();
  if (!response.headers.get('content-type')?.includes('json')) {
    throw new ApiError('The server returned an unexpected response.', response.status);
  }
  const data: unknown = await response.json();
  if (!response.ok) {
    const detail = (data as {detail?: unknown})?.detail;
    throw new ApiError(typeof detail === 'string' ? detail : 'The request could not be completed.', response.status);
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
  actionable_notifications?: {label: string; service: string}[];
  cats_deployed_version?: string;
  [key: string]: any;
}
export interface PageEnvelope {schemaVersion: 1; page: string; data: PageData; cacheScope?: string}

export function can(data: PageData, permission: string, serviceId?: number): boolean {
  return data.can?.[permission]?.[serviceId == null ? '*' : String(serviceId)] === true;
}
