import {ApiError, PAGE_MEDIA_TYPE, sessionEnded, type PageEnvelope} from './api';

/**
 * In-memory page workspace. A UX optimization only: never an authorization
 * source and never persisted (no localStorage/sessionStorage).
 *
 * Entries are partitioned by the server's `cacheScope` (session + user +
 * authorization revision). Any envelope with a different scope, or with none
 * (anonymous pages), discards the whole store and every read in flight. A
 * mutation or the end of the session (401, or a session change announced by
 * another tab) does the same. Saved pages older than MAX_DISPLAY_AGE_MS are
 * fetched again rather than shown.
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
    sessionEnded();
    window.location.assign(response.url);
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  if (response.status === 401) sessionEnded();
  if (!response.headers.get('content-type')?.includes('json')) throw new ApiError('The server returned an unexpected response.', response.status);
  const text = await response.text();
  const data: any = JSON.parse(text);
  if (!response.ok) {
    const detail = data?.detail;
    throw new ApiError(typeof detail === 'string' ? detail : 'The request could not be completed.', response.status);
  }
  return {envelope: data as PageEnvelope, bytes: text.length, digest: digestText(text), fetchedAt: Date.now()};
}

/** A response that belongs to an earlier generation (scope change, mutation, session end). */
export class SupersededError extends Error {
  constructor() {super('The page changed while it was loading. Please retry.'); this.name = 'SupersededError';}
}

/** Longest a saved page may be shown before it must be fetched again. */
export const MAX_DISPLAY_AGE_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 3;

export class PageStore {
  private entries = new Map<string, CachedPage>();
  private inflight = new Map<string, Inflight & {generation: number}>();
  private scope = '';
  private session = '';
  private totalBytes = 0;
  /**
   * Request generation. It advances on every boundary after which earlier
   * reads must not be shown: a different authorization scope, a mutation, or
   * the end of the session. A response from an older generation is neither
   * stored nor delivered; its consumers transparently receive a fresh read.
   */
  private generation = 0;
  private scopeListeners = new Set<(scope: string, previous: string) => void>();
  constructor(private loader: (location: string, signal: AbortSignal) => Promise<CachedPage> = fetchPage,
              private clock: () => number = () => Date.now()) {}

  get size() {return this.entries.size;}
  get bytes() {return this.totalBytes;}
  get currentScope() {return this.scope;}
  /** Opaque signed-in session identity of the latest page ('' when none). */
  get currentSession() {return this.session;}

  /** Notified when a response establishes a different non-empty scope than a previous non-empty one. */
  onScopeChange(listener: (scope: string, previous: string) => void): () => void {
    this.scopeListeners.add(listener);
    return () => {this.scopeListeners.delete(listener);};
  }

  /** Cached page for the current scope, refreshed in LRU order; too-old copies are discarded. */
  get(location: string): CachedPage | undefined {
    const entry = this.entries.get(location);
    if (!entry) return undefined;
    if (this.clock() - entry.fetchedAt > MAX_DISPLAY_AGE_MS) {this.delete(location); return undefined;}
    this.entries.delete(location);
    this.entries.set(location, entry);
    return entry;
  }

  peek(location: string): CachedPage | undefined {return this.entries.get(location);}

  delete(location: string) {
    const entry = this.entries.get(location);
    if (entry) {this.totalBytes -= entry.bytes; this.entries.delete(location);}
  }

  /** Start a new generation: drop saved pages and detach (abort) every read in flight. */
  private advance() {
    this.generation += 1;
    this.entries.clear();
    this.totalBytes = 0;
    const pending = [...this.inflight.values()];
    this.inflight.clear();
    for (const item of pending) item.controller.abort();
  }

  /** After a mutation: no earlier read may be stored or shown. */
  invalidate() {this.advance();}

  /** Session ended or changed: forget everything, including the scope. */
  clear() {
    this.advance();
    this.scope = '';
    this.session = '';
  }

  private adoptScope(scope: string) {
    if (scope === this.scope) return;
    const previous = this.scope;
    // A different session, user or authorization revision (or an anonymous
    // page): nothing loaded under the previous scope may be reused or shown.
    this.advance();
    this.scope = scope;
    if (previous && scope) for (const listener of this.scopeListeners) listener(scope, previous);
  }

  /** Accept a fresh envelope; a scope change discards everything first. */
  put(location: string, page: CachedPage) {
    const scope = page.envelope.cacheScope || '';
    if (page.envelope.sessionIdentity !== undefined) this.session = page.envelope.sessionIdentity || '';
    this.adoptScope(scope);
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

  private start(location: string) {
    const controller = new AbortController();
    const generation = this.generation;
    const current = () => generation === this.generation;
    const promise = this.loader(location, controller.signal).then(page => {
      if (!current()) throw new SupersededError();
      if (this.inflight.get(location)?.promise === promise) this.inflight.delete(location);
      this.put(location, page);  // may adopt a new scope (and advance the generation)
      return page;
    }, error => {
      if (error instanceof ApiError && error.status === 401) {
        // The session has ended: never retried, whatever else happened meanwhile.
        this.clear();
        throw error;
      }
      if (!current()) throw new SupersededError();
      throw error;
    }).finally(() => {if (this.inflight.get(location)?.promise === promise) this.inflight.delete(location);});
    // Consumers attach their own handlers; this one only prevents an
    // unhandled rejection when every consumer has gone.
    promise.catch(() => {});
    const item = {promise, controller, consumers: 0, generation};
    this.inflight.set(location, item);
    return item;
  }

  /**
   * Fetch (deduplicated per location within a generation) and store. Each
   * consumer may abort; the shared request is cancelled only when no consumer
   * still wants it. A superseded read is retried for its consumers.
   */
  load(location: string, signal?: AbortSignal, attempt = 1): Promise<CachedPage> {
    const shared = this.inflight.get(location) || this.start(location);
    shared.consumers += 1;
    return new Promise<CachedPage>((resolve, reject) => {
      let settled = false;
      const finish = () => {settled = true; signal?.removeEventListener('abort', abort);};
      const abort = () => {
        if (settled) return;
        finish();
        shared.consumers -= 1;
        if (shared.consumers <= 0) shared.controller.abort();
        reject(new DOMException('Aborted', 'AbortError'));
      };
      if (signal?.aborted) {abort(); return;}
      signal?.addEventListener('abort', abort, {once: true});
      shared.promise.then(value => {
        if (settled) return;
        finish();
        if (shared.generation !== this.generation && value.envelope.cacheScope !== this.scope) {
          // Delivered after a newer boundary under a different scope: never show it.
          if (attempt < MAX_ATTEMPTS) this.load(location, signal, attempt + 1).then(resolve, reject);
          else reject(new SupersededError());
          return;
        }
        resolve(value);
      }, error => {
        if (settled) return;
        finish();
        if (error instanceof SupersededError && attempt < MAX_ATTEMPTS && !signal?.aborted) {
          this.load(location, signal, attempt + 1).then(resolve, reject);
          return;
        }
        reject(error);
      });
    });
  }

  isLoading(location: string) {return this.inflight.has(location);}
}

export const pageStore = new PageStore();
