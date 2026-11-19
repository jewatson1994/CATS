import {fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Page} from './diagnostics';
import {requestJson} from '../api';
import {localDiagnostic} from '../diagnostics';
vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
afterEach(() => {vi.clearAllMocks(); vi.restoreAllMocks(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/');});
const record = {...localDiagnostic('Import failed', 409, 'import', 'OWNERSHIP'), error_id: 'err-1', correlation_id: 'corr-1'};
function setup() {
  vi.mocked(requestJson).mockImplementation(async url => {
    if (url === '/api/diagnostics/summary') return {items: [{code: 'OWNERSHIP', component: 'ingestion', summary: 'Ownership conflict', count: 8, last_seen: '2026-11-16'}], total: 8};
    if (url === '/api/diagnostics/err-1') return record;
    return {items: [record], total: 55, retention_days: 30};
  });
}
it('requires the server admin flag before requesting diagnostics', () => {
  render(<Page data={{can: {'config.manage': {'*': true}}}}/>);
  expect(screen.getByText('Administrator access is required.')).toBeInTheDocument();
  expect(requestJson).not.toHaveBeenCalled();
});
it('searches and pages errors, inspects a report, and shows recurrence', async () => {
  setup(); render(<Page data={{may_view_diagnostics: true}}/>);
  expect(await screen.findByText('Import failed')).toBeInTheDocument();
  expect(screen.getByText('Ownership conflict')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Component'), {target: {value: 'ingestion'}});
  fireEvent.change(screen.getByLabelText('Search errors'), {target: {value: 'ownership'}});
  fireEvent.click(screen.getByRole('button', {name: 'Search diagnostics'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/diagnostics?q=ownership&component=ingestion&limit=50&offset=0', expect.anything()));
  fireEvent.click(screen.getByRole('button', {name: 'Next'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/diagnostics?q=ownership&component=ingestion&limit=50&offset=50', expect.anything()));
  fireEvent.click(screen.getByRole('button', {name: 'Inspect'}));
  await screen.findByRole('region', {name: 'Selected diagnostic'});
  expect(screen.getByRole('button', {name: 'Copy sanitized report'})).toBeVisible();
  expect(screen.getByRole('link', {name: 'Diagnostics Center'})).toHaveAttribute('aria-current', 'page');
});
it('opens a linked diagnostic and correlation filter', async () => {
  setup(); window.history.replaceState(null, '', '/admin/diagnostics?error_id=err-1&correlation_id=corr-1');
  render(<Page data={{may_view_diagnostics: true}}/>);
  await screen.findByRole('region', {name: 'Selected diagnostic'});
  expect(requestJson).toHaveBeenCalledWith('/api/diagnostics?correlation_id=corr-1&limit=50&offset=0', expect.anything());
});

it('displays linked date bounds in local time and preserves them on search', async () => {
  setup();
  const since = '2026-11-15T14:12:34.567Z';
  const until = '2026-11-16T18:45:56.789Z';
  window.history.replaceState(null, '', `/admin/diagnostics?${new URLSearchParams({since, until})}`);
  render(<Page data={{may_view_diagnostics: true}}/>);
  await screen.findByText('Import failed');
  expect(new Date((screen.getByLabelText('From') as HTMLInputElement).value).toISOString()).toBe(since);
  expect(new Date((screen.getByLabelText('Until') as HTMLInputElement).value).toISOString()).toBe(until);
  vi.mocked(requestJson).mockClear();
  fireEvent.click(screen.getByRole('button', {name: 'Search diagnostics'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith(`/api/diagnostics?${new URLSearchParams({since, until, limit: '50', offset: '0'})}`, expect.anything()));
});

it('exports only displayed sanitized records and states the matching total', async () => {
  let exported = '';
  const NativeBlob = Blob;
  vi.stubGlobal('Blob', class extends NativeBlob {constructor(parts: BlobPart[], options?: BlobPropertyBag) {super(parts, options); exported = String(parts[0]);}});
  vi.stubGlobal('URL', Object.assign(URL, {createObjectURL: vi.fn().mockReturnValue('blob:report'), revokeObjectURL: vi.fn()}));
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  vi.mocked(requestJson).mockImplementation(async url => url === '/api/diagnostics/summary' ? {items: []} : {
    items: [{...record, technical: {password: 'do-not-export', request_body: 'private body'}}], total: 65, retention_days: 30});
  render(<Page data={{may_view_diagnostics: true}}/>);
  await screen.findByText('Import failed');
  fireEvent.click(screen.getByRole('button', {name: 'Export displayed reports'}));
  expect(JSON.parse(exported)).toMatchObject({total_matching: 65, exported_count: 1, offset: 0, items: [{error_id: 'err-1'}]});
  expect(exported).not.toContain('do-not-export'); expect(exported).not.toContain('private body');
});
