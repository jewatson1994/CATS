import {ApiError, PAGE_MEDIA_TYPE, type PageEnvelope} from './api';

/**
 * In-memory page workspace. A UX optimization only: never an authorization
 * source, never persisted (no localStorage/sessionStorage), and discarded with
 * the document, which is replaced on every login, logout or session expiry.
 *
 * Entries are partitioned by the server's `cacheScope` (session + user +
 * authorization revision). Any envelope with a different scope, or with none
 * (anonymous pages), discards the whole store before it is used again.
 */
export interface CachedPage {
  envelope: PageEnvelope;
  bytes: number;
  digest: string;
  fetchedAt: number;
}

interface Inflight {promise: Promise<CachedPage>; controller: AbortController; consumers: number}

export const LIMITS = {entries: 24, bytes: 24 * 1024 * 1024, entryBytes: 4 * 1024 * 1024};

/** FNV-1a: cheap content identity, so unchanged revalidations do not re-render. */
export function digestText(text: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index++) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return `${text.length}:${(hash >>> 0).toString(16)}`;
}

async function fetchPage(location: string, signal: AbortSignal): Promise<CachedPage> {
  const target = new URL(location, window.location.origin);
  if (target.origin !== window.location.origin) throw new ApiError('External page URLs are not allowed.', 0);
  const response = await fetch(target.href, {credentials: 'same-origin', cache: 'no-store', signal,
    headers: {Accept: PAGE_MEDIA_TYPE}});
  if (response.redirected && new URL(response.url).pathname === '/login') {
    window.location.assign(response.url);
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  if (!response.headers.get('content-type')?.includes('json')) throw new ApiError('The server returned an unexpected response.', response.status);
  const text = await response.text();
  const data: any = JSON.parse(text);
  if (!response.ok) {
    const detail = data?.detail;
    throw new ApiError(typeof detail === 'string' ? detail : 'The request could not be completed.', response.status);
  }
  return {envelope: data as PageEnvelope, bytes: text.length, digest: digestText(text), fetchedAt: Date.now()};
}

export class PageStore {
  private entries = new Map<string, CachedPage>();
  private inflight = new Map<string, Inflight>();
  private scope = '';
  private totalBytes = 0;
  private epoch = 0;
  constructor(private loader: (location: string, signal: AbortSignal) => Promise<CachedPage> = fetchPage) {}

  get size() {return this.entries.size;}
  get bytes() {return this.totalBytes;}

  /** Cached page for the current scope, refreshed in LRU order. */
  get(location: string): CachedPage | undefined {
    const entry = this.entries.get(location);
    if (!entry) return undefined;
    this.entries.delete(location);
    this.entries.set(location, entry);
    return entry;
  }

  peek(location: string): CachedPage | undefined {return this.entries.get(location);}

  delete(location: string) {
    const entry = this.entries.get(location);
    if (entry) {this.totalBytes -= entry.bytes; this.entries.delete(location);}
  }

  /**
   * After a mutation: drop cached pages, and refuse to store reads that were
   * already in flight (they may describe pre-mutation state). In-flight
   * requests still resolve for their current consumer.
   */
  invalidate() {
    this.entries.clear();
    this.totalBytes = 0;
    this.epoch += 1;
  }

  clear() {
    this.entries.clear();
    this.totalBytes = 0;
    for (const item of this.inflight.values()) item.controller.abort();
    this.inflight.clear();
  }

  /** Accept a fresh envelope; a scope change discards everything first. */
  put(location: string, page: CachedPage) {
    const scope = page.envelope.cacheScope || '';
    if (!scope || scope !== this.scope) {
      // A different session, user or authorization revision (or an anonymous
      // page, e.g. after expiry) must never see previously cached content.
      this.entries.clear();
      this.totalBytes = 0;
      this.scope = scope;
    }
    if (!scope || page.bytes > LIMITS.entryBytes) return;
    this.delete(location);
    this.entries.set(location, page);
    this.totalBytes += page.bytes;
    for (const [key, entry] of this.entries) {
      if (this.entries.size <= LIMITS.entries && this.totalBytes <= LIMITS.bytes) break;
      if (key === location) continue;
      this.totalBytes -= entry.bytes;
      this.entries.delete(key);
    }
  }

  /**
   * Fetch (deduplicated per location) and store. Each consumer may abort; the
   * shared request is cancelled only when no consumer still wants it.
   */
  load(location: string, signal?: AbortSignal): Promise<CachedPage> {
    let item = this.inflight.get(location);
    if (!item) {
      const controller = new AbortController();
      const epoch = this.epoch;
      const promise = this.loader(location, controller.signal).then(page => {
        if (this.inflight.get(location)?.promise === promise && epoch === this.epoch) this.put(location, page);
        return page;
      }).finally(() => {if (this.inflight.get(location)?.promise === promise) this.inflight.delete(location);});
      item = {promise, controller, consumers: 0};
      this.inflight.set(location, item);
    }
    const shared = item;
    shared.consumers += 1;
    if (!signal) return shared.promise;
    return new Promise<CachedPage>((resolve, reject) => {
      let settled = false;
      const abort = () => {
        if (settled) return;
        settled = true;
        shared.consumers -= 1;
        if (shared.consumers <= 0) shared.controller.abort();
        reject(new DOMException('Aborted', 'AbortError'));
      };
      if (signal.aborted) {abort(); return;}
      signal.addEventListener('abort', abort, {once: true});
      shared.promise.then(value => {if (!settled) {settled = true; signal.removeEventListener('abort', abort); resolve(value);}},
        error => {if (!settled) {settled = true; signal.removeEventListener('abort', abort); reject(error);}});
    });
  }

  isLoading(location: string) {return this.inflight.has(location);}
}

export const pageStore = new PageStore();
