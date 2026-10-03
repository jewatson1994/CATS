import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Page, type SelfServiceData } from './self_service';
const mocks = vi.hoisted(() => ({ request: vi.fn(), retry: vi.fn(), job: null as any }));
vi.mock('../api', () => ({ requestJson: mocks.request, PAGE_MEDIA_TYPE: 'application/vnd.cats.page+json' }));
vi.mock('../hooks/useJob', () => ({ useJob: () => ({ job: mocks.job, error: null, retry: mocks.retry, elapsedSeconds: 2 }) }));
const data: SelfServiceData = {
  mode: 'scan', description: 'Scan images', progress_phases: [['prepare_inputs', 'Prepare inputs']], progress_order: ['prepare_inputs'],
  authenticated_ingest: true, authenticated_services: [{ service_key: 'a', name: 'A' }, { service_key: 'b', name: 'B' }],
  service_version_options: { a: ['1'], b: ['2'] }, ingest_service_id: 'a', ingest_service_version: '1',
};
describe('self service workspace', () => {
  afterEach(cleanup);
  beforeEach(() => { mocks.job = null; mocks.request.mockReset().mockResolvedValue({page: 'self_service', data}); mocks.retry.mockReset(); });
  it('preserves submission failures and permits destination changes and repeated retries without remounting', async () => {
    mocks.request.mockResolvedValueOnce({page: 'self_service', data: {...data, status_message: 'Acquisition failed'}})
      .mockRejectedValueOnce(new Error('Worker unavailable'))
      .mockResolvedValueOnce({page: 'self_service', data: {...data, job_id: 'retry-success', ingest_service_id: ''}});
    render(<Page data={data} />);
    const selector = screen.getByLabelText(/Ingest completed scan into/);
    const form = screen.getByRole('button', {name: 'Start scan'}).closest('form')!;
    fireEvent.submit(form);
    await screen.findByText('Acquisition failed');
    expect(selector).toBeEnabled();
    fireEvent.change(selector, {target: {value: 'b'}});
    fireEvent.change(screen.getByLabelText(/Service Version/), {target: {value: '2'}});
    fireEvent.submit(form);
    await screen.findByRole('alert');
    expect(screen.getByRole('alert')).toHaveTextContent('Worker unavailable');
    expect(selector).toHaveValue('b');
    expect(screen.getByRole('button', {name: 'Start scan'})).toBeEnabled();
    fireEvent.submit(form);
    await waitFor(() => expect(screen.getByRole('button', {name: 'Start scan'})).toBeEnabled());
    expect(mocks.request).toHaveBeenCalledTimes(3);
    expect((mocks.request.mock.calls[1][1].body as FormData).get('ingest_service_id')).toBe('b');
  });
  it('retains multipart inputs and resets version when target changes', () => {
    render(<Page data={data} />);
    expect(screen.getByRole('button', { name: 'Start scan' }).closest('form')).toHaveAttribute('enctype', 'multipart/form-data');
    fireEvent.change(screen.getByLabelText(/Ingest completed scan into/), { target: { value: 'b' } });
    expect(screen.getByLabelText(/Service Version/)).toHaveValue('');
    expect(document.querySelector('#ingest-version-options option')).toHaveAttribute('value', '2');
    fireEvent.change(screen.getByLabelText(/Ingest completed scan into/), { target: { value: '' } });
    expect(screen.getByLabelText(/Service Version/)).toBeDisabled();
  });
  it('ignores an older submission resolving after a newer failure', async () => {
    let resolveOld!: (value: unknown) => void;
    mocks.request.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve; }))
      .mockRejectedValueOnce(new Error('New attempt failed'));
    render(<Page data={data} />);
    const form = screen.getByRole('button', {name: 'Start scan'}).closest('form')!;
    fireEvent.submit(form);
    fireEvent.submit(form);
    await screen.findByText('New attempt failed');
    resolveOld({page: 'self_service', data: {...data, status_message: 'Stale failure'}});
    await waitFor(() => expect(screen.getByRole('button', {name: 'Start scan'})).toBeEnabled());
    expect(screen.queryByText('Stale failure')).not.toBeInTheDocument();
    expect(screen.getByText('New attempt failed')).toBeInTheDocument();
  });
  it.each(['complete', 'incomplete', 'error', 'cancelled'])('refreshes targets after %s without losing the job outcome', async status => {
    mocks.job = {status, phase: 'prepare_inputs'};
    mocks.request.mockResolvedValue({page: 'self_service', data: {...data,
      authenticated_services: [{service_key: 'c', name: 'Current'}]}});
    render(<Page data={{...data, job_id: `terminal-${status}`, ingest_service_id: ''}} />);
    await screen.findByRole('option', {name: 'Current (c)'});
    fireEvent.change(screen.getByLabelText(/Ingest completed scan into/), {target: {value: 'c'}});
    expect(screen.getByLabelText(/Ingest completed scan into/)).toHaveValue('c');
    expect(screen.getByRole('status')).toHaveTextContent(status === 'error' ? 'Error' : status[0].toUpperCase() + status.slice(1));
    expect(screen.getByRole('button', {name: 'Start scan'})).toBeEnabled();
  });
  it('exposes logs and artifacts on error but disables unavailable results', () => {
    mocks.job = { status: 'error', phase: 'prepare_inputs' };
    render(<Page data={{ ...data, job_id: 'error-test', ingest_service_id: '' }} />);
    expect(screen.getByRole('link', { name: 'View debug log' })).toHaveAttribute('href', '/api/public/jobs/error-test/logs');
    expect(screen.getByText('Detailed results')).toHaveAttribute('aria-disabled', 'true');
    expect(screen.queryByRole('button', { name: 'Cancel scan' })).not.toBeInTheDocument();
  });
  it('ingests once per job scope and allows an explicit retry after failure', async () => {
    mocks.job = { status: 'complete', phase: 'report_results' };
    mocks.request.mockImplementation((url: string) => url === '/scan'
      ? Promise.resolve({page: 'self_service', data})
      : mocks.request.mock.calls.filter(([path]) => path.includes('/ingest?')).length === 1
        ? Promise.reject(new Error('Unavailable')) : Promise.resolve({}));
    const view = render(<Page data={{ ...data, job_id: 'ingest-test' }} />);
    await screen.findByRole('button', { name: 'Retry ingestion' });
    view.rerender(<Page data={{ ...data, job_id: 'ingest-test' }} />);
    expect(mocks.request.mock.calls.filter(([path]) => path.includes('/ingest?'))).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'Retry ingestion' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Ingested into selected service.'));
    expect(mocks.request.mock.calls.filter(([path]) => path.includes('/ingest?'))).toHaveLength(2);
  });
});
