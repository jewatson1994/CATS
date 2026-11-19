import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {Page} from './jobs';
import {requestJson} from '../api';
import {localDiagnostic} from '../diagnostics';
vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.clearAllMocks();});
const row = {id: 'job-1', kind: 'export', service: 'Payments', requested_by: 'Alice', status: 'queued', stage: 'Queued', elapsed_seconds: 12, can_cancel: true, can_retry: false};
it('shows queued exports and submits only the authorized action with CSRF', async () => {
  vi.mocked(requestJson).mockResolvedValue({jobs: [row], counts: {queued: 1}, limit: 100});
  render(<Page data={{csrf_token: 'csrf'}}/>);
  await screen.findByText('Payments');
  expect(screen.queryByRole('button', {name: 'Retry'})).toBeNull();
  fireEvent.click(screen.getByRole('button', {name: 'Cancel'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/v1/jobs/job-1/cancel', expect.objectContaining({method: 'POST', body: '{"csrf_token":"csrf"}'})));
});
it('shows completed download and failed diagnostics without unsupported controls', async () => {
  vi.mocked(requestJson).mockResolvedValue({jobs: [{...row, status: 'completed', can_cancel: false, download_url: '/api/v1/exports/job-1/download'},
    {...row, id: 'provision', kind: 'validator.provision', status: 'failed', can_cancel: false, error: 'Pinned Kind image is missing.'}], counts: {completed: 1, failed: 1}, limit: 100});
  render(<Page data={{}}/>);
  expect(await screen.findByRole('link', {name: 'Download'})).toHaveAttribute('href', '/api/v1/exports/job-1/download');
  expect(screen.getByText('Pinned Kind image is missing.')).toBeTruthy();
  expect(screen.queryByRole('button', {name: 'Cancel'})).toBeNull();
});
it('hides an Open result link that only points back to the same job, keeping real result links', async () => {
  vi.mocked(requestJson).mockResolvedValue({jobs: [
    {...row, status: 'completed', can_cancel: false, download_url: '/api/v1/exports/job-1/download', result_url: '/jobs?job=job-1'},
    {...row, id: 'scan-1', kind: 'scan', status: 'completed', can_cancel: false, result_url: '/api/public/jobs/scan-1/results/view'}], counts: {completed: 2}, limit: 100});
  render(<Page data={{}}/>);
  expect(await screen.findByRole('link', {name: 'Download'})).toHaveAttribute('href', '/api/v1/exports/job-1/download');
  const results = screen.getAllByRole('link', {name: 'Open result'});
  expect(results).toHaveLength(1);
  expect(results[0]).toHaveAttribute('href', '/api/public/jobs/scan-1/results/view');
});
it('renders the selected job diagnostic and worker recovery context', async () => {
  window.history.replaceState({}, '', '/jobs?job=job-1');
  const diagnostic = {...localDiagnostic('Worker heartbeat expired.'), error_id: 'err-1', cause: 'The worker stopped reporting progress.', resolution: ['Check the worker before retrying.'], resource: {job_id: 'job-1'}};
  vi.mocked(requestJson).mockResolvedValue({jobs: [{...row, status: 'failed', diagnostic, attempts: 2, max_attempts: 3, worker_id: 'worker-a', heartbeat_at: '2026-11-16T12:00:00Z'}], counts: {failed: 1}, limit: 100});
  render(<Page data={{may_view_diagnostics: true}}/>);
  await screen.findByRole('region', {name: 'Selected job'});
  expect(screen.getByText('2 / 3')).toBeInTheDocument();
  expect(screen.getByText('worker-a')).toBeInTheDocument();
  expect(screen.getAllByRole('link', {name: 'Inspect in Diagnostics Center', hidden: true})[0]).toHaveAttribute('href', '/admin/diagnostics?error_id=err-1');
  expect(screen.getAllByText('Check the worker before retrying.')).toHaveLength(2);
  window.history.replaceState({}, '', '/');
});
