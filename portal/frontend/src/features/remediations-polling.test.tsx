import {act, cleanup, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {PAGE_MEDIA_TYPE} from '../api';
import {Report} from './remediations';

vi.mock('../components/ServiceHeader', () => ({ServiceHeader: () => null, ServiceTabs: () => null}));
afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.useRealTimers();});

const job = (status: string, extra = {}) => ({job_key: 'R-1', status, revision_number: 1, original_revision: 'V1', remediation_status: 'partial',
  delivery_status: 'not_requested', verification_status: 'not_run', signing_status: 'not_requested', before_snapshot: {vulnerabilities: {}},
  after_snapshot: {vulnerabilities: {}}, validation: [], changed_artifacts: [], patched_images: [], configuration_changes: [], stages: [],
  logs: [], output_mode: 'bundle', started_at: new Date().toISOString(), ...extra});
const data = (status: string, revision: string, extra = {}) => ({service: {id: 7, service_key: 'example', name: 'Example'}, can: {}, job: job(status, extra), status_revision: revision});
const json = (body: unknown, type = 'application/json') => new Response(JSON.stringify(body), {headers: {'content-type': type}});

it('polls only the lightweight status and fetches the report when its revision changes', async () => {
  vi.useFakeTimers({shouldAdvanceTime: true});
  const urls: string[] = [];
  const statuses = [
    {status: 'running', phase: 'patch_images', revision: 'r1', terminal: false},   // unchanged since render
    {status: 'running', phase: 'patch_images', revision: 'r1', terminal: false},
    {status: 'complete', phase: 'output', revision: 'r2', terminal: true},         // final
  ];
  const fetch = vi.fn((url: string) => {
    urls.push(url);
    if (url.endsWith('/status')) return Promise.resolve(json(statuses.shift() || statuses[statuses.length - 1]));
    return Promise.resolve(json({schemaVersion: 1, page: 'remediation_report', data: data('complete', 'r2', {logs: ['Final evidence']})}, PAGE_MEDIA_TYPE));
  });
  vi.stubGlobal('fetch', fetch);
  render(<Report data={data('running', 'r1')}/>);
  for (let step = 0; step < 6; step++) await act(async () => {vi.advanceTimersByTime(4000);});
  await waitFor(() => expect(urls.filter(url => !url.endsWith('/status'))).toHaveLength(1));
  expect(urls.filter(url => url.endsWith('/status'))).toHaveLength(3);
  expect(urls[0]).toContain('/api/v1/services/example/remediations/R-1/status');
  // Polling stopped at the terminal status; no further requests are made.
  const count = urls.length;
  await act(async () => {vi.advanceTimersByTime(60000);});
  expect(urls.length).toBe(count);
  expect(screen.getByText(/Final evidence/)).toBeInTheDocument();
});

it('does not poll a remediation that is already finished', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  render(<Report data={data('complete', 'r9')}/>);
  await new Promise(resolve => setTimeout(resolve, 50));
  expect(fetch).not.toHaveBeenCalled();
});

it('pauses while the document is hidden and resumes when visible', async () => {
  vi.useFakeTimers({shouldAdvanceTime: true});
  let visibility = 'hidden';
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility as DocumentVisibilityState);
  const fetch = vi.fn(() => Promise.resolve(json({status: 'running', revision: 'r1', terminal: false})));
  vi.stubGlobal('fetch', fetch);
  render(<Report data={data('running', 'r1')}/>);
  await act(async () => {vi.advanceTimersByTime(20000);});
  expect(fetch).not.toHaveBeenCalled();
  visibility = 'visible';
  await act(async () => {document.dispatchEvent(new Event('visibilitychange'));});
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
});


it('keeps polling at a terminal status until the final report has loaded', async () => {
  vi.useFakeTimers({shouldAdvanceTime: true});
  const urls: string[] = [];
  let reportAttempts = 0;
  const fetch = vi.fn((url: string) => {
    urls.push(url);
    if (url.endsWith('/status')) return Promise.resolve(json({status: 'complete', phase: 'output', revision: 'r2', terminal: true}));
    reportAttempts += 1;
    if (reportAttempts === 1) return Promise.reject(new TypeError('network down'));
    return Promise.resolve(json({schemaVersion: 1, page: 'remediation_report', data: data('complete', 'r2', {logs: ['Final evidence']})}, PAGE_MEDIA_TYPE));
  });
  vi.stubGlobal('fetch', fetch);
  render(<Report data={data('running', 'r1')}/>);
  for (let step = 0; step < 8; step++) await act(async () => {vi.advanceTimersByTime(5000);});
  await waitFor(() => expect(reportAttempts).toBe(2));
  // The first final-report request failed; polling did not stop until it loaded.
  expect(screen.getByText(/Final evidence/)).toBeInTheDocument();
  const count = urls.length;
  await act(async () => {vi.advanceTimersByTime(60000);});
  expect(urls.length).toBe(count);  // and stopped once it had
});
