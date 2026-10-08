import {afterEach, expect, it} from 'vitest';
import {cleanup, render, screen} from '@testing-library/react';
import {Page} from './service-validation';

afterEach(cleanup);
it('shows the observed failure and actionable guidance outside technical diagnostics', () => {
  render(<Page data={{view:{service:{id:1,service_key:'demo'}},validation:{status:'FAILED',phase:'COMPLETE',cleanup_status:'COMPLETE',failure_details:[{resource:'demo / nginx',reason:'CreateContainerConfigError',message:'image will run as root',guidance:'Set securityContext.runAsUser to a non-root UID.'}]}} as any} />);
  expect(screen.getByText('What failed and how to fix it')).toBeTruthy();
  expect(screen.getByText(/image will run as root/)).toBeTruthy();
  expect(screen.getByText(/Set securityContext.runAsUser/)).toBeTruthy();
});
it('pages validation history without loading every run', () => {
  render(<Page data={{view:{service:{id:1,service_key:'demo'}},validation:{status:'VERIFIED',phase:'COMPLETE',cleanup_status:'COMPLETE',terminal:true},
    validation_runs:[{run_key:'run-51',artifact_type:'ORIGINAL',status:'VERIFIED'}],
    validation_history:{page:2,pages:3,total:120,page_size:50}} as any} />);
  expect(screen.getByText('Page 2 of 3 · 120 runs')).toBeTruthy();
  expect(screen.getByRole('link',{name:'Previous'}).getAttribute('href')).toBe('/services/demo?validation=true&validation_page=1');
  expect(screen.getByRole('link',{name:'Next'}).getAttribute('href')).toBe('/services/demo?validation=true&validation_page=3');
});

it('polls validation status, not evidence, and loads evidence once at terminal', async () => {
  const {vi, expect: assert} = await import('vitest');
  const {act, waitFor} = await import('@testing-library/react');
  vi.useFakeTimers({shouldAdvanceTime: true});
  const urls: string[] = [];
  const statuses = [
    {run_key: 'run-1', status: 'RUNNING', phase: 'INSTALLING', cleanup_status: 'PENDING', revision: 'v1', terminal: false},
    {run_key: 'run-1', status: 'RUNNING', phase: 'INSTALLING', cleanup_status: 'PENDING', revision: 'v1', terminal: false},
    {run_key: 'run-1', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE', revision: 'v2', terminal: true},
  ];
  const json = (body: unknown) => new Response(JSON.stringify(body), {headers: {'content-type': 'application/json'}});
  vi.stubGlobal('fetch', vi.fn((url: string) => {
    urls.push(url);
    return Promise.resolve(json(url.endsWith('/status') ? statuses.shift() || statuses[0]
      : {run_key: 'run-1', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE', terminal: true, revision: 'v2', reason: 'All workloads ready'}));
  }));
  try {
    render(<Page data={{view: {service: {id: 1, service_key: 'demo'}}, validation: {run_key: 'run-1', status: 'RUNNING', phase: 'INSTALLING', cleanup_status: 'PENDING', revision: 'v1'}} as any}/>);
    for (let step = 0; step < 6; step++) await act(async () => {vi.advanceTimersByTime(4000);});
    await waitFor(() => assert(urls.filter(url => !url.endsWith('/status'))).toHaveLength(1));
    assert(urls.filter(url => url.endsWith('/status'))).toHaveLength(3);
    const count = urls.length;
    await act(async () => {vi.advanceTimersByTime(60000);});
    assert(urls.length).toBe(count);
  } finally {
    vi.unstubAllGlobals(); vi.useRealTimers();
  }
});

it('a delayed detail response for an earlier run never replaces a newly started run', async () => {
  const {vi, expect: assert} = await import('vitest');
  const {act, fireEvent, waitFor} = await import('@testing-library/react');
  vi.useFakeTimers({shouldAdvanceTime: true});
  let releaseOld: (response: Response) => void = () => {};
  const json = (body: unknown) => new Response(JSON.stringify(body), {headers: {'content-type': 'application/json'}});
  const fetch = vi.fn((url: string, options?: RequestInit) => {
    if (options?.method === 'POST') return Promise.resolve(json({run_id: 'run-2', run: {run_key: 'run-2', status: 'QUEUED', phase: 'QUEUED', cleanup_status: 'PENDING'}}));
    if (url.includes('/run-1/status')) return Promise.resolve(json({run_key: 'run-1', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE', revision: 'v9', terminal: true}));
    if (url.endsWith('/run-1')) return new Promise<Response>(resolve => {
      releaseOld = resolve;
      options?.signal?.addEventListener('abort', () => resolve(json({run_key: 'run-1', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE', terminal: true, reason: 'OLD RUN EVIDENCE'})));
    });
    return Promise.resolve(json({run_key: 'run-2', status: 'RUNNING', phase: 'INSTALLING', cleanup_status: 'PENDING', revision: 'n1', terminal: false}));
  });
  vi.stubGlobal('fetch', fetch);
  try {
    render(<Page data={{view: {service: {id: 1, service_key: 'demo'}}, can_validate: true, can: {'remediation.execute': {'1': true}}, csrf_token: 't',
      validation: {run_key: 'run-1', status: 'RUNNING', phase: 'INSTALLING', cleanup_status: 'PENDING', revision: 'v1'}} as any}/>);
    await act(async () => {vi.advanceTimersByTime(3000);});
    await waitFor(() => assert(fetch.mock.calls.some(call => String(call[0]).endsWith('/run-1'))));  // old detail pending
    await act(async () => {fireEvent.submit(screen.getByRole('button', {name: 'Re-run Validation'}).closest('form')!);});
    await waitFor(() => assert(screen.getAllByText(/Queued|Installing|Running/i).length).toBeGreaterThan(0));
    // The earlier run's detail now arrives.
    await act(async () => {releaseOld(json({run_key: 'run-1', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE', terminal: true, reason: 'OLD RUN EVIDENCE'}));});
    await act(async () => {vi.advanceTimersByTime(3000);});
    assert(screen.queryByText(/OLD RUN EVIDENCE/)).toBeNull();
  } finally {vi.unstubAllGlobals(); vi.useRealTimers();}
});
