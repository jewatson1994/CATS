import {fireEvent, render, screen, waitFor} from '@testing-library/react';
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
    audit: false, diagnostics: true, config: {host: '10.0.0.8', port: 1514, transport: 'tcp'}});
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
    diagnostics: true, audit: true, config: splunk.config});
});

it('sends a test event to a paused receiver and shows a searchable event ID', async () => {
  api.mockImplementation(async (path) => path.endsWith('/test') ? {event_id: 'test-123456'}
    : {destinations: [{...splunk, enabled: false, last_error: 'HEC returned HTTP 403'}]});
  render(<LogForwarding data={admin}/>);
  fireEvent.click(await screen.findByRole('button', {name: 'Send test event'}));
  await screen.findByText(/Search the receiver for test-123456/);
  expect(api).toHaveBeenCalledWith(url + '/7/test', expect.objectContaining({method: 'POST', headers: expect.objectContaining({'X-CSRF-Token': 'csrf'})}));
  expect(screen.getByText('Last error: HEC returned HTTP 403')).toBeVisible();
  expect(screen.queryByRole('button', {name: 'Replay retained audit'})).toBeNull();
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
  await waitFor(() => expect(api).toHaveBeenCalledWith(url + '/7?discard_count=3', expect.objectContaining({method: 'DELETE'})));
});
