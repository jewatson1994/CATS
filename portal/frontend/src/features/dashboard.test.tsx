import {act, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Page} from './dashboard';

afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals();});
const response = (body: object) => new Response(JSON.stringify(body), {headers: {'content-type': 'application/json'}});
const pending = {posture_preparing: 1, posture_assessed: 0, total_count: 1,
  rows: [{service: {service_key: 'demo', name: 'Demo'}, posture_pending: true}]};
const loaded = {posture_preparing: 0, total_count: 1,
  rows: [{service: {service_key: 'demo', name: 'Demo'}, status: 'GREEN', kind: 'VERIFIED'}], compliant_count: 1};
const shell = {dashboard_url: '/api/dashboard/services?lifecycle=active'};
it('loads the Services dashboard asynchronously after rendering its heading', async () => {
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({views:[], compliant_count:4, noncompliant_count:2}), {headers:{'content-type':'application/json'}})));
  render(<Page data={{dashboard_url:'/api/dashboard/services?lifecycle=active'}}/>);
  expect(screen.getByRole('heading', {name:'Services'})).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Loading dashboard data');
  await screen.findByRole('heading', {name:'Service Snapshot'});
  expect(screen.getByText('4')).toBeInTheDocument();
});

it('polls a pending dashboard with backoff and only one request in flight, stopping once ready', async () => {
  vi.useFakeTimers();
  let finish!: (value: Response) => void;
  const fetch = vi.fn()
    .mockResolvedValueOnce(response(pending))
    .mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; }))
    .mockResolvedValueOnce(response(loaded));
  vi.stubGlobal('fetch', fetch);
  await act(async () => {render(<Page data={shell}/>);});
  expect(screen.getByRole('link', {name: 'Demo'})).toBeVisible();
  await act(async () => {await vi.advanceTimersByTimeAsync(3000);});
  await act(async () => {await vi.advanceTimersByTimeAsync(60000);});
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => {finish(response(pending));});
  await act(async () => {await vi.advanceTimersByTimeAsync(5999);});
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => {await vi.advanceTimersByTimeAsync(1);});
  expect(screen.queryByText('Posture pending')).not.toBeInTheDocument();
  await act(async () => {await vi.advanceTimersByTimeAsync(60000);});
  expect(fetch).toHaveBeenCalledTimes(3);
});

it('retains the service after a refresh fails and lets the user retry', async () => {
  vi.useFakeTimers();
  const fetch = vi.fn().mockResolvedValueOnce(response(pending)).mockRejectedValueOnce(new TypeError('failed'))
    .mockResolvedValueOnce(response(loaded));
  vi.stubGlobal('fetch', fetch);
  await act(async () => {render(<Page data={shell}/>);});
  await act(async () => {await vi.advanceTimersByTimeAsync(3000);});
  expect(screen.getByRole('link', {name: 'Demo'})).toBeVisible();
  expect(screen.getByRole('alert')).toHaveTextContent('Unable to refresh the dashboard');
  await act(async () => {await vi.advanceTimersByTimeAsync(60000);});
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => {fireEvent.click(screen.getByRole('button', {name: 'Retry dashboard'}));});
  expect(screen.queryByRole('button', {name: 'Retry dashboard'})).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(3);
});

it('cancels the pending refresh when filters change or the dashboard unmounts', async () => {
  vi.useFakeTimers();
  const fetch = vi.fn().mockImplementation(async () => response(pending));
  vi.stubGlobal('fetch', fetch);
  const page = render(<Page data={shell}/>);
  await act(async () => {});
  const first = fetch.mock.calls[0][1].signal as AbortSignal;
  await act(async () => {page.rerender(<Page data={{dashboard_url: shell.dashboard_url + '&q=demo'}}/>);});
  expect(first.aborted).toBe(true);
  const second = fetch.mock.calls[1][1].signal as AbortSignal;
  page.unmount();
  expect(second.aborted).toBe(true);
  await act(async () => {await vi.advanceTimersByTimeAsync(60000);});
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('waits for a visible tab before retrying and resumes only once with the existing backoff', async () => {
  vi.useFakeTimers();
  const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  let finish!: (value: Response) => void;
  const fetch = vi.fn()
    .mockResolvedValueOnce(response(pending))
    .mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; }))
    .mockResolvedValueOnce(response(loaded));
  vi.stubGlobal('fetch', fetch);
  await act(async () => {render(<Page data={shell}/>);});
  visibility.mockReturnValue('hidden');
  document.dispatchEvent(new Event('visibilitychange'));
  await act(async () => {await vi.advanceTimersByTimeAsync(60000);});
  expect(fetch).toHaveBeenCalledTimes(1);
  visibility.mockReturnValue('visible');
  await act(async () => {
    document.dispatchEvent(new Event('visibilitychange'));
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(30000);
  });
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => {finish(response(pending));});
  await act(async () => {await vi.advanceTimersByTimeAsync(5999);});
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => {await vi.advanceTimersByTimeAsync(1);});
  expect(fetch).toHaveBeenCalledTimes(3);
});

it('removes the deferred visibility retry when the dashboard unmounts', async () => {
  vi.useFakeTimers();
  const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  const fetch = vi.fn().mockImplementation(async () => response(pending));
  vi.stubGlobal('fetch', fetch);
  const page = render(<Page data={shell}/>);
  await act(async () => {});
  visibility.mockReturnValue('hidden');
  document.dispatchEvent(new Event('visibilitychange'));
  await act(async () => {await vi.advanceTimersByTimeAsync(3000);});
  page.unmount();
  visibility.mockReturnValue('visible');
  await act(async () => {
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(60000);
  });
  expect(fetch).toHaveBeenCalledTimes(1);
});
