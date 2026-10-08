import {describe, expect, it, vi} from 'vitest';
import {ApiError} from './api';
import {LIMITS, MAX_DISPLAY_AGE_MS, PageStore, digestText, type CachedPage} from './pageStore';

const page = (scope: string | undefined, label = 'x', bytes = 10): CachedPage => ({
  envelope: {schemaVersion: 1, page: 'home', data: {label}, cacheScope: scope}, bytes, digest: digestText(label), fetchedAt: Date.now(),
});

describe('PageStore', () => {
  it('partitions by cache scope and never caches anonymous pages', () => {
    const store = new PageStore();
    store.put('/a', page('scope-1', 'a'));
    store.put('/b', page('scope-1', 'b'));
    expect(store.size).toBe(2);
    // A new session/user/authorization revision discards everything first.
    store.put('/c', page('scope-2', 'c'));
    expect(store.peek('/a')).toBeUndefined();
    expect(store.peek('/b')).toBeUndefined();
    expect(store.peek('/c')?.envelope.data.label).toBe('c');
    // An anonymous envelope (e.g. login after expiry) clears and is not stored.
    store.put('/login', page(undefined, 'login'));
    expect(store.size).toBe(0);
    store.put('/d', page('', 'd'));
    expect(store.size).toBe(0);
  });

  it('bounds entries and bytes with least-recently-used eviction', () => {
    const store = new PageStore();
    for (let index = 0; index < LIMITS.entries + 5; index++) store.put(`/p${index}`, page('s', String(index)));
    expect(store.size).toBe(LIMITS.entries);
    expect(store.peek('/p0')).toBeUndefined();
    store.get(`/p5`); // touch: now most recent
    store.put('/new', page('s', 'new'));
    expect(store.peek('/p5')).toBeDefined();
    store.put('/huge', page('s', 'huge', LIMITS.entryBytes + 1));
    expect(store.peek('/huge')).toBeUndefined();
    store.put('/big1', page('s', 'b1', LIMITS.bytes - 100));
    store.put('/big2', page('s', 'b2', 200));
    expect(store.bytes).toBeLessThanOrEqual(LIMITS.bytes);
    expect(store.peek('/big2')).toBeDefined();
  });

  it('deduplicates concurrent loads and cancels only when no consumer remains', async () => {
    let resolve: (value: CachedPage) => void = () => {};
    let signal: AbortSignal | undefined;
    const loader = vi.fn((_location: string, abort: AbortSignal) => {signal = abort; return new Promise<CachedPage>(done => {resolve = done;});});
    const store = new PageStore(loader);
    const first = new AbortController();
    const one = store.load('/x', first.signal);
    const two = store.load('/x');
    expect(loader).toHaveBeenCalledTimes(1);
    first.abort();
    await expect(one).rejects.toThrow();
    expect(signal?.aborted).toBe(false); // the second consumer still wants it
    resolve(page('s', 'x'));
    expect((await two).envelope.data.label).toBe('x');
    expect(store.peek('/x')).toBeDefined();
    const lone = new AbortController();
    const three = store.load('/y', lone.signal);
    lone.abort();
    await expect(three).rejects.toThrow();
    expect(signal?.aborted).toBe(true);
  });

  it('never stores or delivers a read that was in flight across a mutation', async () => {
    const resolvers: ((value: CachedPage) => void)[] = [];
    const loader = vi.fn(() => new Promise<CachedPage>(done => {resolvers.push(done);}));
    const store = new PageStore(loader);
    store.put('/cached', page('s', 'cached'));
    const pending = store.load('/x');
    store.invalidate();
    expect(store.peek('/cached')).toBeUndefined();
    resolvers[0](page('s', 'pre-mutation'));  // the old response arrives late
    await vi.waitFor(() => expect(loader).toHaveBeenCalledTimes(2));
    resolvers[1](page('s', 'post-mutation'));
    // The consumer receives a fresh read, never the pre-mutation one.
    expect((await pending).envelope.data.label).toBe('post-mutation');
    expect(store.peek('/x')?.envelope.data.label).toBe('post-mutation');
  });

  it('never delivers or stores a response from an earlier authorization scope', async () => {
    const resolvers = new Map<string, ((value: CachedPage) => void)[]>();
    const loader = vi.fn((location: string) => new Promise<CachedPage>(done => {
      resolvers.set(location, [...(resolvers.get(location) || []), done]);
    }));
    const store = new PageStore(loader);
    store.put('/old', page('admin-scope', 'admin data'));
    const oldRead = store.load('/report');      // requested while still admin
    const newRead = store.load('/services');
    // The newer response arrives first and establishes the restricted scope.
    resolvers.get('/services')![0](page('restricted-scope', 'restricted services'));
    expect((await newRead).envelope.data.label).toBe('restricted services');
    expect(store.peek('/old')).toBeUndefined();
    // The admin-scope response that arrives afterwards is discarded and re-read.
    resolvers.get('/report')![0](page('admin-scope', 'admin report'));
    await vi.waitFor(() => expect(resolvers.get('/report')!.length).toBe(2));
    resolvers.get('/report')![1](page('restricted-scope', 'restricted report'));
    expect((await oldRead).envelope.data.label).toBe('restricted report');
    expect(store.peek('/report')?.envelope.cacheScope).toBe('restricted-scope');
  });

  it('forgets every saved page when the session ends', async () => {
    const store = new PageStore(() => Promise.reject(new ApiError('Your session has expired.', 401)));
    store.put('/a', page('s', 'a'));
    store.put('/b', page('s', 'b'));
    await expect(store.load('/c')).rejects.toThrow('expired');
    expect(store.size).toBe(0);
    expect(store.currentScope).toBe('');
  });

  it('does not show a saved page older than the display limit', () => {
    let time = 1_000_000;
    const store = new PageStore(undefined, () => time);
    store.put('/a', {...page('s', 'a'), fetchedAt: time});
    time += MAX_DISPLAY_AGE_MS - 1;
    expect(store.get('/a')).toBeDefined();
    time += 2;
    expect(store.get('/a')).toBeUndefined();
    expect(store.size).toBe(0);
  });

  it('announces a change between two non-empty scopes only', () => {
    const store = new PageStore();
    const seen: string[] = [];
    store.onScopeChange((scope, previous) => seen.push(`${previous}->${scope}`));
    store.put('/a', page('one', 'a'));
    store.put('/b', page('two', 'b'));
    store.put('/login', page(undefined, 'login'));
    store.put('/c', page('three', 'c'));
    expect(seen).toEqual(['one->two']);
  });
});
