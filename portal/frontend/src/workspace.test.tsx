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
