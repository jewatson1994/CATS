import {describe, expect, it, vi} from 'vitest';
import {LIMITS, PageStore, digestText, type CachedPage} from './pageStore';

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

  it('never stores reads that were in flight across a mutation', async () => {
    let resolve: (value: CachedPage) => void = () => {};
    const store = new PageStore(() => new Promise<CachedPage>(done => {resolve = done;}));
    store.put('/cached', page('s', 'cached'));
    const pending = store.load('/x');
    store.invalidate();
    expect(store.peek('/cached')).toBeUndefined();
    resolve(page('s', 'pre-mutation'));
    expect((await pending).envelope.data.label).toBe('pre-mutation'); // the consumer still gets it
    expect(store.peek('/x')).toBeUndefined(); // but it is not reused
  });
});
