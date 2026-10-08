import {afterEach, expect, it, vi} from 'vitest';
import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {App, FRESH_MS} from './App';
import {PAGE_MEDIA_TYPE, requestJson} from './api';
import {PageStore} from './pageStore';

const envelope = (detail: string, scope = 'scope-1') => ({schemaVersion: 1, page: 'request_error', data: {detail}, cacheScope: scope});
const respond = (body: unknown, status = 200) => new Response(JSON.stringify(body), {status, headers: {'content-type': PAGE_MEDIA_TYPE}});

afterEach(() => {vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); window.history.replaceState(null, '', '/');});

function navigate(path: string) {
  act(() => {window.history.pushState(null, '', path); window.dispatchEvent(new PopStateEvent('popstate'));});
}

async function visitTwoPages(fetch: ReturnType<typeof vi.fn>, store: PageStore) {
  window.history.replaceState(null, '', '/home');
  vi.stubGlobal('fetch', fetch); vi.stubGlobal('scrollTo', vi.fn());
  render(<App initial={envelope('Page A') as any} store={store}/>);
  navigate('/scan');
  await screen.findByText('Page B');
}

it('returns to a cached page immediately and refreshes it quietly', async () => {
  const store = new PageStore();
  const fetch = vi.fn().mockResolvedValueOnce(respond(envelope('Page B')));
  await visitTwoPages(fetch, store);
  let finish: (response: Response) => void = () => {};
  fetch.mockImplementationOnce(() => new Promise<Response>(resolve => {finish = resolve;}));
  const realNow = Date.now;
  vi.spyOn(Date, 'now').mockImplementation(() => realNow() + FRESH_MS + 1);
  navigate('/home');
  // Rendered from memory before the refresh resolves: no loading state.
  expect(screen.getByText('Page A')).toBeInTheDocument();
  expect(document.querySelector('.page-navigating')).toBeNull();
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  await act(async () => {finish(respond(envelope('Page A, refreshed')));});
  await screen.findByText('Page A, refreshed');
});

it('discards a cached page when the refresh reports access was revoked', async () => {
  const store = new PageStore();
  const fetch = vi.fn().mockResolvedValueOnce(respond(envelope('Page B')));
  await visitTwoPages(fetch, store);
  fetch.mockResolvedValueOnce(respond({detail: 'Permission denied'}, 403));
  const realNow = Date.now;
  vi.spyOn(Date, 'now').mockImplementation(() => realNow() + FRESH_MS + 1);
  navigate('/home');
  await screen.findByText('Permission denied');
  expect(screen.queryByText('Page A')).not.toBeInTheDocument();
  expect(store.peek('/home')).toBeUndefined();
});

it('purges every cached page when the authorization scope changes', async () => {
  const store = new PageStore();
  const fetch = vi.fn().mockResolvedValueOnce(respond(envelope('Page B', 'scope-2')));
  await visitTwoPages(fetch, store);
  // Page A was cached under scope-1; scope-2 arrived, so A is gone.
  expect(store.peek('/home')).toBeUndefined();
  fetch.mockResolvedValueOnce(respond(envelope('Page A again', 'scope-2')));
  navigate('/home');
  await screen.findByText('Page A again');
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('mutations invalidate cached reads', async () => {
  const store = new PageStore();
  const fetch = vi.fn().mockResolvedValueOnce(respond(envelope('Page B')));
  await visitTwoPages(fetch, store);
  expect(store.peek('/home')).toBeDefined();
  fetch.mockResolvedValueOnce(new Response('{}', {headers: {'content-type': 'application/json'}}));
  await requestJson('/api/public/patch-jobs/x/cancel', {method: 'POST'});
  expect(store.peek('/home')).toBeUndefined();
  expect(store.peek('/scan')).toBeUndefined();
});

it('prefetches a deliberately hovered service tab once, without navigating', async () => {
  vi.useFakeTimers({shouldAdvanceTime: true});
  const store = new PageStore();
  window.history.replaceState(null, '', '/home');
  const fetch = vi.fn().mockResolvedValue(respond(envelope('Prefetched')));
  vi.stubGlobal('fetch', fetch); vi.stubGlobal('scrollTo', vi.fn());
  render(<App initial={envelope('Page A') as any} store={store}/>);
  const link = document.createElement('a');
  link.href = '/services/payments?overview=true'; link.dataset.prefetch = 'true'; link.textContent = 'Overview';
  document.body.appendChild(link);
  fireEvent.pointerOver(link);
  fireEvent.pointerOut(link); // abandoned intent: nothing fetched
  await act(async () => {vi.advanceTimersByTime(500);});
  expect(fetch).not.toHaveBeenCalled();
  fireEvent.pointerOver(link);
  await act(async () => {vi.advanceTimersByTime(500);});
  await waitFor(() => expect(store.peek('/services/payments?overview=true')).toBeDefined());
  fireEvent.pointerOver(link);
  await act(async () => {vi.advanceTimersByTime(500);});
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(screen.getByText('Page A')).toBeInTheDocument();
  link.remove();
});

it('renders an already-loaded lazy page synchronously, without the Suspense fallback', async () => {
  const {lazyComponent} = await import('./App');
  const {Suspense} = await import('react');
  let resolve: (module: Record<string, unknown>) => void = () => {};
  const loader = () => new Promise<Record<string, unknown>>(done => {resolve = done;});
  const Page = lazyComponent<{label: string}>('./test-module', 'Page', loader);
  const first = render(<Suspense fallback={<p>Loading page…</p>}><Page label="one"/></Suspense>);
  expect(screen.getByText('Loading page…')).toBeInTheDocument();
  await act(async () => {resolve({Page: ({label}: {label: string}) => <p>Ready {label}</p>});});
  await screen.findByText('Ready one');
  first.unmount();
  render(<Suspense fallback={<p>Loading page…</p>}><Page label="two"/></Suspense>);
  // Same tick: no fallback, no throttled reveal.
  expect(screen.getByText('Ready two')).toBeInTheDocument();
  expect(screen.queryByText('Loading page…')).toBeNull();
});

it('prepares the chunk of the initially served page before the first render', async () => {
  const {preparePage} = await import('./App');
  await expect(preparePage(null)).resolves.toBeUndefined();
  await expect(preparePage({schemaVersion: 1, page: 'request_error', data: {}} as any)).resolves.toBeUndefined();
  // A lazily split page: its module is loaded, so the first render cannot suspend.
  const loaded = await preparePage({schemaVersion: 1, page: 'audit', data: {}} as any) as Record<string, unknown>;
  expect(typeof loaded.Page).toBe('function');
});

it('forgets every saved page when a refresh reports the session ended', async () => {
  const store = new PageStore();
  const fetch = vi.fn().mockResolvedValueOnce(respond(envelope('Page B')));
  await visitTwoPages(fetch, store);
  expect(store.size).toBe(2);
  fetch.mockResolvedValueOnce(respond({detail: 'Your session has expired.'}, 401));
  const realNow = Date.now;
  vi.spyOn(Date, 'now').mockImplementation(() => realNow() + FRESH_MS + 1);
  navigate('/home');
  await screen.findByText('Your session has expired.');
  expect(screen.queryByText('Page A')).toBeNull();
  // Page B (and everything else) is gone too, not only the page that failed.
  expect(store.size).toBe(0);
  expect(store.peek('/scan')).toBeUndefined();
});

function fakeChannels() {
  const channels: any[] = [];
  vi.stubGlobal('BroadcastChannel', class {
    onmessage: ((event: MessageEvent) => void) | null = null;
    posted: unknown[] = [];
    constructor(readonly name: string) {channels.push(this);}
    postMessage(message: unknown) {this.posted.push(message);}
    close() {}
  });
  return channels;
}
const withSession = (detail: string, scope: string, session: string) => ({...envelope(detail, scope), sessionIdentity: session});

it('another tab of the same session with a new authorization only drops saved pages; the shown page stays', async () => {
  const channels = fakeChannels();
  const store = new PageStore();
  window.history.replaceState(null, '', '/home');
  const fetch = vi.fn().mockResolvedValueOnce(respond(withSession('Page B', 'scope-1', 'session-1')));
  vi.stubGlobal('fetch', fetch); vi.stubGlobal('scrollTo', vi.fn());
  render(<App initial={withSession('Page A', 'scope-1', 'session-1') as any} store={store}/>);
  navigate('/scan');
  await screen.findByText('Page B');
  const channel = channels.find(item => item.name === 'cats-session');
  expect(channel.posted).toContainEqual({type: 'session', session: 'session-1', scope: 'scope-1', signedOut: false});
  // Same session, same scope (another tab opened): nothing happens.
  act(() => channel.onmessage({data: {type: 'session', session: 'session-1', scope: 'scope-1'}} as MessageEvent));
  expect(store.size).toBe(2);
  // Same session, authorization changed elsewhere: saved pages go, the page shown (and its input) stays.
  act(() => channel.onmessage({data: {type: 'session', session: 'session-1', scope: 'scope-2'}} as MessageEvent));
  expect(store.size).toBe(0);
  expect(screen.getByText('Page B')).toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);  // no reload
});

it('hides and reloads when another tab signs in as someone else or finishes signing out', async () => {
  const channels = fakeChannels();
  const store = new PageStore();
  window.history.replaceState(null, '', '/home');
  const fetch = vi.fn().mockResolvedValueOnce(respond(withSession('Page B', 'scope-1', 'session-1')));
  vi.stubGlobal('fetch', fetch); vi.stubGlobal('scrollTo', vi.fn());
  render(<App initial={withSession('Page A', 'scope-1', 'session-1') as any} store={store}/>);
  navigate('/scan');
  await screen.findByText('Page B');
  const channel = channels.find(item => item.name === 'cats-session');
  let finish: (response: Response) => void = () => {};
  fetch.mockImplementationOnce(() => new Promise<Response>(resolve => {finish = resolve;}));
  act(() => channel.onmessage({data: {type: 'session', session: 'session-2', scope: 'scope-9'}} as MessageEvent));
  expect(store.size).toBe(0);
  expect(screen.queryByText('Page B')).toBeNull();  // nothing from the old session stays visible
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  await act(async () => {finish(respond(withSession('Page B as the new session', 'scope-9', 'session-2')));});
  await screen.findByText('Page B as the new session');
  // A sign-in page announced after sign-out completed.
  fetch.mockImplementationOnce(() => new Promise<Response>(() => {}));
  act(() => channel.onmessage({data: {type: 'session', session: '', scope: '', signedOut: true}} as MessageEvent));
  expect(screen.queryByText('Page B as the new session')).toBeNull();
  // An anonymous page that is not the sign-in page says nothing about sessions.
});

it('signing out forgets saved pages locally and leaves the announcement to the sign-in page', async () => {
  const channels = fakeChannels();
  const store = new PageStore();
  await visitTwoPages(vi.fn().mockResolvedValueOnce(respond(envelope('Page B'))), store);
  const posted = channels[0].posted.length;
  act(() => {window.dispatchEvent(new Event('cats:session-ending'));});
  expect(store.size).toBe(0);
  expect(channels[0].posted.length).toBe(posted);  // no announcement racing the logout request
});

it('the sign-in page reached after sign-out tells other tabs', () => {
  const channels = fakeChannels();
  window.history.replaceState(null, '', '/login');
  vi.stubGlobal('fetch', vi.fn()); vi.stubGlobal('scrollTo', vi.fn());
  render(<App initial={{schemaVersion: 1, page: 'login', data: {}, cacheScope: '', sessionIdentity: ''} as any} store={new PageStore()}/>);
  expect(channels[0].posted).toContainEqual({type: 'session', session: '', scope: '', signedOut: true});
});
