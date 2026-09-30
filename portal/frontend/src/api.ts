export const PAGE_MEDIA_TYPE = 'application/vnd.cats.page+json';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {super(message);}
}

/** Cookies stay HttpOnly. FormData preserves backend-owned validation and CSRF. */
export async function requestJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const target = new URL(url, window.location.origin);
  if (target.origin !== window.location.origin) throw new ApiError('External API URLs are not allowed.', 0);
  const headers = new Headers(options.headers);
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  const response = await fetch(target.href, {
    ...options, credentials: 'same-origin', cache: 'no-store',
    headers,
  });
  if (response.redirected && new URL(response.url).pathname === '/login') {
    window.location.assign(response.url);
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
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
export interface PageEnvelope {schemaVersion: 1; page: string; data: PageData}

export function can(data: PageData, permission: string, serviceId?: number): boolean {
  return data.can?.[permission]?.[serviceId == null ? '*' : String(serviceId)] === true;
}
