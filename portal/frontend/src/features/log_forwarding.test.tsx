import {fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {LogForwarding} from './log_forwarding';

vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
const api = vi.mocked(requestJson);
const url = '/api/admin/log-forwarding/destinations';
const admin = {may_manage_log_forwarding: true, csrf_token: 'csrf'};
const splunk = {id: 7, name: 'Security Operations', kind: 'splunk', enabled: true, audit: true,
  diagnostics: false, config: {url: 'https://siem.example:8088', index: 'main'}, has_secret: true,
  pending: 3, last_sent_at: '2026-11-23T13:00:00Z', last_error: null};
afterEach(() => {vi.resetAllMocks(); vi.restoreAllMocks();});

it('requires the explicit forwarding capability before loading receiver information', () => {
  render(<LogForwarding data={{can: {'config.manage': {'*': true}}}}/>);
  expect(screen.queryByRole('region', {name: 'Log forwarding'})).toBeNull();
  expect(api).not.toHaveBeenCalled();
});

it('creates a syslog destination with the selected source and listener details', async () => {
  api.mockResolvedValue({destinations: []});
  render(<LogForwarding data={admin}/>);
  await screen.findByText('No forwarding destinations configured.');
  fireEvent.click(screen.getByRole('button', {name: 'Add destination'}));
  fireEvent.change(screen.getByLabelText('Destination name'), {target: {value: 'Enclave'}});
  fireEvent.change(screen.getByLabelText('Collector IP or hostname'), {target: {value: '10.0.0.8'}});
  expect(screen.getByLabelText('Port')).toHaveValue(6514);
  fireEvent.change(screen.getByLabelText('Transport'), {target: {value: 'tcp'}});
  expect(screen.getByLabelText('Port')).toHaveValue(514);
  fireEvent.change(screen.getByLabelText('Port'), {target: {value: '1514'}});
  fireEvent.click(screen.getByLabelText('Security audit trail'));
  fireEvent.click(screen.getByRole('button', {name: 'Save destination'}));
  expect(screen.getByRole('alert')).toHaveTextContent('Select at least one event source.');
  fireEvent.click(screen.getByLabelText('Operational diagnostics'));
  fireEvent.click(screen.getByRole('button', {name: 'Save destination'}));
  await screen.findByText('Destination saved.');
  const mutation = api.mock.calls.find(([, opts]) => opts?.method === 'POST');
  expect(mutation?.[0]).toBe(url);
  expect(mutation?.[1]?.headers).toMatchObject({'X-CSRF-Token': 'csrf'});
  expect(JSON.parse(String(mutation?.[1]?.body))).toEqual({name: 'Enclave', kind: 'syslog', enabled: true,
    audit: false, diagnostics: true, operational: false, config: {host: '10.0.0.8', port: 1514, transport: 'tcp'}});
});

it('edits Splunk settings without exposing or replacing a stored credential', async () => {
  api.mockResolvedValue({destinations: [splunk]});
  render(<LogForwarding data={admin}/>);
  fireEvent.click(await screen.findByRole('button', {name: 'Edit'}));
  expect(screen.getByLabelText('Destination type')).toBeDisabled();
  expect(screen.getByLabelText('HEC URL')).toHaveAttribute('readonly');
  expect(screen.getByLabelText('HEC token', {exact: false})).toHaveValue('');
  fireEvent.click(screen.getByLabelText('Operational diagnostics'));
  fireEvent.click(screen.getByRole('button', {name: 'Save destination'}));
  await screen.findByText('Destination saved.');
  const mutation = api.mock.calls.find(([, opts]) => opts?.method === 'PUT');
  expect(mutation?.[0]).toBe(url + '/7');
  expect(JSON.parse(String(mutation?.[1]?.body))).toEqual({name: splunk.name, kind: 'splunk', enabled: true,
    diagnostics: true, operational: false, audit: true, config: splunk.config});
});

it('sends a test event to a paused receiver and shows a searchable event ID', async () => {
  api.mockImplementation(async (path) => path.endsWith('/test') ? {event_id: 'test-123456'}
    : {destinations: [{...splunk, enabled: false, last_error: 'HEC returned HTTP 403'}]});
  render(<LogForwarding data={admin}/>);
  fireEvent.click(await screen.findByRole('button', {name: 'Send test event'}));
  await screen.findByText(/Search the receiver for test-123456/);
  expect(api).toHaveBeenCalledWith(url + '/7/test', expect.objectContaining({method: 'POST', headers: expect.objectContaining({'X-CSRF-Token': 'csrf'})}));
  expect(screen.getByText('Last error: HEC returned HTTP 403')).toBeVisible();
  expect(screen.queryByRole('button', {name: 'Replay all stored audit events'})).toBeNull();
});

it('shows Azure workspace routing fields only for Azure and sends the chosen cloud', async () => {
  api.mockResolvedValue({destinations: []});
  render(<LogForwarding data={admin}/>);
  fireEvent.click(await screen.findByRole('button', {name: 'Add destination'}));
  fireEvent.change(screen.getByLabelText('Destination type'), {target: {value: 'azure'}});
  const values: Record<string, string> = {'Destination name': 'Workspace', 'Logs ingestion endpoint': 'https://example.ingest.monitor.azure.us',
    'Data collection rule immutable ID': 'dcr-abc', 'Stream name': 'Custom-CatsAudit', 'Microsoft Entra tenant ID': 'tenant',
    'Application (client) ID': 'client', 'Azure cloud': 'government', 'Client secret': 'test-secret'};
  for (const [name, value] of Object.entries(values)) fireEvent.change(screen.getByLabelText(name), {target: {value}});
  fireEvent.click(screen.getByRole('button', {name: 'Save destination'}));
  await screen.findByText('Destination saved.');
  const body = JSON.parse(String(api.mock.calls.find(([, opts]) => opts?.method === 'POST')?.[1]?.body));
  expect(body).toMatchObject({kind: 'azure', secret: 'test-secret', config: {cloud: 'government', rule_id: 'dcr-abc', stream: 'Custom-CatsAudit'}});
  expect(body.config).not.toHaveProperty('secret');
  expect(screen.queryByText('test-secret')).toBeNull();
});

it('requires confirmation of the exact pending count before discarding queued deliveries', async () => {
  api.mockResolvedValue({destinations: [{...splunk, enabled: false}]});
  const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
  render(<LogForwarding data={admin}/>);
  const remove = await screen.findByRole('button', {name: 'Remove'});
  fireEvent.click(remove);
  expect(confirm).toHaveBeenCalledWith(expect.stringContaining('3 pending delivery copies'));
  expect(api.mock.calls.some(([, opts]) => opts?.method === 'DELETE')).toBe(false);
  fireEvent.click(remove);
  await screen.findByText('Destination removed.');
  expect(api).toHaveBeenCalledWith(url + '/7?discard_count=3', expect.objectContaining({method: 'DELETE'}));
});

it('renders only the relay status on replicas, including an outage and dropped operational copies', async () => {
  api.mockResolvedValue({state: 'retrying', pending: 24, last_sent_at: null, last_error: 'HQ unavailable', dropped_operational: 7});
  render(<LogForwarding data={{...admin, cats_mode: 'replica', may_view_log_relay: true}}/>);
  await screen.findByText('Retrying delivery');
  expect(screen.getByText(/24 queued/)).toBeVisible();
  expect(screen.getByText('Operational copies dropped: 7')).toBeVisible();
  expect(screen.getByText('Last error: HQ unavailable')).toBeVisible();
  expect(screen.queryByRole('button', {name: 'Add destination'})).toBeNull();
  expect(screen.queryByRole('button', {name: 'Manage reporters'})).toBeNull();
  expect(api.mock.calls.map(([path]) => path)).toEqual(['/api/admin/log-forwarding/relay']);
});

it('enrolls a scoped component reporter and clears the token after the operator saves it', async () => {
  const source = {id: 'guid-1', name: 'Site B', allow_audit: true, allow_diagnostics: true, revoked: false, last_received_at: null};
  let saved = false;
  api.mockImplementation(async (path, options) => {
    if (path === url) return {destinations: []};
    if (options?.method === 'POST') {saved = true; return {source, token: 'test-one-time-value'};}
    return {sources: saved ? [source] : []};
  });
  render(<LogForwarding data={admin}/>);
  await screen.findByText('No forwarding destinations configured.');
  expect(api.mock.calls.map(([path]) => path)).toEqual([url]);
  fireEvent.click(screen.getByRole('button', {name: 'Manage reporters'}));
  fireEvent.click(await screen.findByRole('button', {name: 'Enroll reporter'}));
  fireEvent.change(screen.getByLabelText('Reporter name'), {target: {value: 'Site B'}});
  fireEvent.click(screen.getByRole('button', {name: 'Generate reporter token'}));
  expect(await screen.findByLabelText('One-time reporter token')).toHaveValue('test-one-time-value');
  expect(api).toHaveBeenCalledWith('/api/admin/log-forwarding/sources', expect.objectContaining({method: 'POST',
    headers: expect.objectContaining({'X-CSRF-Token': 'csrf'}), body: JSON.stringify({name: 'Site B', allow_audit: true, allow_diagnostics: true})}));
  fireEvent.click(screen.getByRole('button', {name: 'I saved the token'}));
  expect(screen.queryByDisplayValue('test-one-time-value')).toBeNull();
  await screen.findByText('No events received yet.');
});

it('rotates credentials only after confirmation and revokes enrolled reporters', async () => {
  let revoked = false;
  const source = {id: 'guid-2', name: 'Site C', allow_audit: false, allow_diagnostics: true, last_received_at: '2026-11-23T13:00:00Z'};
  api.mockImplementation(async (path) => {
    if (path === url) return {destinations: []};
    if (path.endsWith('/rotate')) return {source, token: 'rotated-token'};
    if (path.endsWith('/revoke')) {revoked = true; return {source};}
    return {sources: [{...source, revoked}]};
  });
  vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValue(true);
  render(<LogForwarding data={admin}/>);
  fireEvent.click(screen.getByRole('button', {name: 'Manage reporters'}));
  const rotate = await screen.findByRole('button', {name: 'Rotate token'});
  fireEvent.click(rotate);
  expect(api.mock.calls.some(([path]) => path.endsWith('/rotate'))).toBe(false);
  fireEvent.click(rotate);
  expect(await screen.findByLabelText('One-time reporter token')).toHaveValue('rotated-token');
  fireEvent.click(screen.getByRole('button', {name: 'I saved the token'}));
  fireEvent.click(screen.getByRole('button', {name: 'Revoke token'}));
  await screen.findByText('Revoked');
  expect(screen.queryByRole('button', {name: 'Rotate token'})).toBeNull();
});

it('lets HQ administrators forward only component operations and displays the overflow count', async () => {
  api.mockResolvedValue({destinations: [{...splunk, audit: false, operational: true, dropped_operational: 11}]});
  render(<LogForwarding data={admin}/>);
  await screen.findByText('Operational copies dropped: 11');
  fireEvent.click(screen.getByRole('button', {name: 'Edit'}));
  expect(screen.getByLabelText('Component operational logs')).toBeChecked();
  fireEvent.click(screen.getByRole('button', {name: 'Save destination'}));
  await screen.findByText('Destination saved.');
  const body = JSON.parse(String(api.mock.calls.find(([, opts]) => opts?.method === 'PUT')?.[1]?.body));
  expect(body).toMatchObject({audit: false, diagnostics: false, operational: true});
});
