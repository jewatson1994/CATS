import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson, sessionEnded} from './api';
import {diagnosticNotices, diagnosticReport, localDiagnostic, publishDiagnostic} from './diagnostics';
import {DiagnosticLinks, ErrorDetails, ErrorNotifications} from './components/ErrorDetails';

afterEach(() => {act(() => diagnosticNotices.clear()); vi.unstubAllGlobals(); vi.restoreAllMocks();});
const diagnostic = {...localDiagnostic('Artifact belongs to another service.', 409, 'ingest', 'ARTIFACT_OWNERSHIP_CONFLICT'),
  error_id: 'err-123', correlation_id: 'corr-456', resource: {service_key: 'payments', job_id: 'job-7'},
  resolution: ['Choose the owning service or explicitly transfer ownership.']};

it.each([
  ['scanner', {job_id: 'scan-7'}, 'scan:scan-7'],
  ['worker', {job_id: 'durable-7'}, 'durable-7'],
  ['risk worker', {job_id: 'other-7', jobs_view_id: 'durable-7'}, 'durable-7'],
  ['provisioning', {operation_id: 'attempt-7'}, 'validator:attempt-7'],
  ['browser', {job_id: 'validator:attempt-7'}, 'validator:attempt-7'],
] as const)('links %s failures to the Jobs projection ID', (component, resource, jobId) => {
  render(<DiagnosticLinks diagnostic={{...diagnostic, component, resource}}/>);
  expect(screen.getByRole('link', {name: 'Open job'})).toHaveAttribute('href', `/jobs?job=${encodeURIComponent(jobId)}`);
});

it('omits links for numeric service IDs and unknown job families', () => {
  render(<DiagnosticLinks diagnostic={{...diagnostic, component: 'Validation', resource: {service_id: 42, job_id: '123'}}}/>);
  expect(screen.queryByRole('link', {name: 'Open service'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link', {name: 'Open job'})).not.toBeInTheDocument();
});

it('shows supplied failure evidence and authorized source frames outside the JSON report', () => {
  render(<ErrorDetails diagnostic={{...diagnostic, status: 'failed',
    context: {failed_stage: 'push artifact', stage: 'delivery', last_successful_stage: 'package verified', worker_id: 'delivery-worker-2', tool: 'registry-client', exit_code: 0},
    technical: {exceptions: [{frames: [{file: 'delivery.py', line: 87, function: 'upload'}]}]},
  }} expanded/>);
  for (const text of ['push artifact', 'package verified', 'delivery-worker-2', 'registry-client', '0', 'delivery.py · line 87 · function upload']) {
    expect(screen.getByText(text, {selector: 'dd'})).toBeVisible();
  }
  expect(screen.getByText('service key: payments · job id: job-7', {selector: 'dd'})).toBeVisible();
  expect(screen.queryByText('delivery', {selector: 'dd'})).not.toBeInTheDocument();
});

it('omits unavailable evidence fields and uses a recorded stage when no failed stage is supplied', () => {
  render(<ErrorDetails diagnostic={{...diagnostic, resource: {}, context: {stage: 'scan dependencies'}}} expanded/>);
  expect(screen.getByText('scan dependencies', {selector: 'dd'})).toBeVisible();
  for (const label of ['Affected resource', 'Last successful stage', 'Worker identity', 'Tool', 'Tool exit code', 'Source']) {
    expect(screen.queryByText(label, {selector: 'dt'})).not.toBeInTheDocument();
  }
});

it('shows the originating frame of the deepest cause instead of HTTP middleware', () => {
  const exceptions = [
    {type: 'HTTPException', frames: [{file: '_exception_handler.py', line: 42, function: 'wrapped_app'}, {file: 'main.py', line: 100, function: 'ingest'}]},
    {type: 'ValueError', frames: [{file: 'main.py', line: 90, function: 'ingest'}, {file: 'service_ownership.py', line: 10, function: 'require_owner'}]},
  ];
  render(<ErrorDetails diagnostic={{...diagnostic, technical: {exceptions}}} expanded/>);
  expect(screen.getByText('Source', {selector: 'dt'})).toBeVisible();
  expect(screen.getByText('service_ownership.py · line 10 · function require_owner', {selector: 'dd'})).toBeVisible();
  expect(screen.queryByText(/wrapped_app/, {selector: 'dd'})).not.toBeInTheDocument();
  expect(exceptions[0].type).toBe('HTTPException');
  expect(exceptions[1].frames[0].function).toBe('ingest');
});

it('preserves structured ownership reasons and publishes failures even when a caller swallows them', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({detail: {reason: 'Artifact belongs to another service.', owner_service_id: 7}, diagnostic}), {status: 409, headers: {'content-type': 'application/json'}})));
  render(<ErrorNotifications admin/>);
  let failure: any;
  await act(async () => {await requestJson('/api/ingest', {method: 'POST'}).catch(error => {failure = error;});});
  expect(failure).toMatchObject({status: 409, message: diagnostic.summary, detail: {owner_service_id: 7}, diagnostic: {error_id: 'err-123'}});
  expect(screen.getByText(diagnostic.summary, {selector: 'p'})).toBeInTheDocument();
  fireEvent.click(screen.getByText('View error details'));
  expect(screen.getByText('Choose the owning service or explicitly transfer ownership.')).toBeVisible();
  expect(screen.getByRole('link', {name: 'Open service'})).toHaveAttribute('href', '/services/payments');
  expect(screen.getByRole('link', {name: 'Related events'})).toHaveAttribute('href', '/admin/diagnostics?correlation_id=corr-456');
});

it('bounds repeated polling failures and clears reports at session end', () => {
  for (let index = 0; index < 10; index++) publishDiagnostic(diagnostic);
  expect(diagnosticNotices.snapshot()).toHaveLength(1);
  expect(diagnosticNotices.snapshot()[0].count).toBe(10);
  for (let index = 0; index < 5; index++) publishDiagnostic({...diagnostic, code: `OTHER_${index}`});
  expect(diagnosticNotices.snapshot()).toHaveLength(3);
  sessionEnded(); expect(diagnosticNotices.snapshot()).toEqual([]);
});

it('redacts nested credentials and URL queries in copied reports without losing IDs or guidance', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', {clipboard: {writeText}});
  const value = {...diagnostic, technical: {authorization: 'private-header', nested: {api_key: 'private-key'},
    output: 'Bearer abc.def.ghi password=hunter2 https://user:pass@example.test/path?secret=hidden', request_url: 'https://example.test/?safe=still-private'}};
  render(<ErrorDetails diagnostic={value} expanded admin/>);
  fireEvent.click(screen.getByRole('button', {name: 'Copy sanitized report'}));
  await waitFor(() => expect(writeText).toHaveBeenCalled());
  const report = writeText.mock.calls[0][0];
  for (const secret of ['private-header', 'private-key', 'abc.def.ghi', 'hunter2', 'user:pass', 'secret=hidden', 'still-private']) expect(report).not.toContain(secret);
  expect(report).toContain('err-123'); expect(report).toContain(diagnostic.resolution[0]);
  expect(JSON.parse(diagnosticReport(value)).technical.authorization).toBe('[redacted]');
});

it('does not publish cancelled requests but gives network and invalid JSON errors useful details', async () => {
  const controller = new AbortController(); controller.abort();
  vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new DOMException('Aborted', 'AbortError'))
    .mockRejectedValueOnce(new TypeError('Failed to fetch'))
    .mockResolvedValueOnce(new Response('{broken', {headers: {'content-type': 'application/json'}})));
  await expect(requestJson('/api/jobs', {signal: controller.signal})).rejects.toMatchObject({name: 'AbortError'});
  expect(diagnosticNotices.snapshot()).toEqual([]);
  await expect(requestJson('/api/jobs')).rejects.toMatchObject({status: 0, diagnostic: {component: 'browser', retryable: true}});
  await expect(requestJson('/api/jobs')).rejects.toMatchObject({message: 'The server returned invalid JSON.'});
});

it('offers a selectable report when clipboard access fails and does not show admin destinations to ordinary users', async () => {
  vi.stubGlobal('navigator', {clipboard: {writeText: vi.fn().mockRejectedValue(new Error('Denied'))}});
  render(<ErrorDetails diagnostic={diagnostic} expanded/>);
  fireEvent.click(screen.getByRole('button', {name: 'Copy sanitized report'}));
  expect(await screen.findByText('Clipboard unavailable. Select and copy the report below.')).toBeVisible();
  expect(screen.queryByRole('link', {name: 'Inspect in Diagnostics Center'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByText('Sanitized technical report'));
  expect(screen.getByText(/"error_id": "err-123"/)).toBeVisible();
});
