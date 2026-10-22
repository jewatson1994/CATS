import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {Page} from './jobs';
import {requestJson} from '../api';
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
