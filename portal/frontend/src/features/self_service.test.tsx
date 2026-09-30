import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Page, type SelfServiceData } from './self_service';
const mocks = vi.hoisted(() => ({ request: vi.fn(), retry: vi.fn(), job: null as any }));
vi.mock('../api', () => ({ requestJson: mocks.request }));
vi.mock('../hooks/useJob', () => ({ useJob: () => ({ job: mocks.job, error: null, retry: mocks.retry, elapsedSeconds: 2 }) }));
const data: SelfServiceData = {
  mode: 'scan', description: 'Scan images', progress_phases: [['prepare_inputs', 'Prepare inputs']], progress_order: ['prepare_inputs'],
  authenticated_ingest: true, authenticated_services: [{ service_key: 'a', name: 'A' }, { service_key: 'b', name: 'B' }],
  service_version_options: { a: ['1'], b: ['2'] }, ingest_service_id: 'a', ingest_service_version: '1',
};
describe('self service workspace', () => {
  afterEach(cleanup);
  beforeEach(() => { mocks.job = null; mocks.request.mockReset(); mocks.retry.mockReset(); });
  it('retains multipart inputs and resets version when target changes', () => {
    render(<Page data={data} />);
    expect(screen.getByRole('button', { name: 'Start scan' }).closest('form')).toHaveAttribute('enctype', 'multipart/form-data');
    fireEvent.change(screen.getByLabelText(/Ingest completed scan into/), { target: { value: 'b' } });
    expect(screen.getByLabelText(/Service Version/)).toHaveValue('');
    expect(document.querySelector('#ingest-version-options option')).toHaveAttribute('value', '2');
    fireEvent.change(screen.getByLabelText(/Ingest completed scan into/), { target: { value: '' } });
    expect(screen.getByLabelText(/Service Version/)).toBeDisabled();
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
    mocks.request.mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValue({});
    const view = render(<Page data={{ ...data, job_id: 'ingest-test' }} />);
    await screen.findByRole('button', { name: 'Retry ingestion' });
    view.rerender(<Page data={{ ...data, job_id: 'ingest-test' }} />);
    expect(mocks.request).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Retry ingestion' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Ingested into selected service.'));
    expect(mocks.request).toHaveBeenCalledTimes(2);
  });
});
