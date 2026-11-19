import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {ApiError, requestJson} from '../api';
import {ApprovalDetail, ReleaseDetail, RequestApproval} from './cyber_approvals';

vi.mock('../api', async original => ({...await original<typeof import('../api')>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const data = {csrf_token: 'csrf'};
const cyber = {id: 11, name: 'Cyber registry', endpoint: 'https://cyber.test', namespace: 'approved', is_default: true};
const additional = {id: 'service-dest-1', name: 'Operations', endpoint: 'https://ops.test', namespace: 'deploy'};
const ready = {can_request: true, ready: true, service_id: 22, destinations: [
  {id: 1, name: 'Fallback registry', endpoint: 'https://other.test', namespace: 'review'}, cyber],
  can_select_additional_destination: true, additional_destinations: [additional]};

it('keeps the Cyber default and sends the selected service-owned registry with the approval request', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce(ready).mockResolvedValueOnce({id: 15});
  render(<RequestApproval data={data} serviceKey="payments"/>);
  const choices = within(await screen.findByRole('group', {name: 'Release destinations'}));
  expect(choices.getByText('Cyber registry')).toBeVisible();
  const select = choices.getByRole('combobox', {name: /Additional service destination/});
  expect(select).toHaveValue('');
  expect(choices.queryByRole('option', {name: /Fallback registry/})).not.toBeInTheDocument();
  fireEvent.change(select, {target: {value: additional.id}});
  expect(choices.getByText(/body of evidence to both registries/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', {name: 'Request Cyber Approval'}));
  await screen.findByText('Review request #15');
  expect(requestJson).toHaveBeenCalledWith('/api/cyber-approvals', expect.objectContaining({
    body: JSON.stringify({service_key: 'payments', variant: 'current_service', additional_destination_id: additional.id}),
    headers: expect.objectContaining({'X-CSRF-Token': 'csrf'}),
  }));
});

it.each([true, false])('shows registry setup only to a manager when no service destination exists (manager=%s)', async allowed => {
  vi.mocked(requestJson).mockResolvedValue({...ready, additional_destinations: [], can_select_additional_destination: allowed});
  render(<RequestApproval data={data} serviceKey="payments"/>);
  const choices = within(await screen.findByRole('group', {name: 'Release destinations'}));
  expect(choices.queryByRole('combobox')).not.toBeInTheDocument();
  expect(screen.getByRole('button', {name: 'Request Cyber Approval'})).toBeEnabled();
  if (allowed) expect(choices.getByRole('link', {name: /Manage OCI destinations/})).toHaveAttribute('href', '/services/payments?remediations=true');
  else expect(choices.queryByRole('link')).not.toBeInTheDocument();
});

it('shows the effective publication namespace when a registered endpoint has a blank namespace', async () => {
  vi.mocked(requestJson).mockResolvedValue({...ready, destinations: [{...cyber, namespace: ''}],
    additional_destinations: [{...additional, namespace: ''}]});
  render(<RequestApproval data={data} serviceKey="payments"/>);
  const choices = within(await screen.findByRole('group', {name: 'Release destinations'}));
  expect(choices.getByText('https://cyber.test/cyber-approved')).toBeVisible();
  expect(choices.getByRole('option', {name: 'Operations (https://ops.test/cyber-approved)'})).toBeInTheDocument();
});

it('requires an explicit choice when a selected registry disappears during a request', async () => {
  vi.mocked(requestJson)
    .mockResolvedValueOnce(ready)
    .mockRejectedValueOnce(new Error('Destination changed before submission.'))
    .mockResolvedValueOnce({...ready, additional_destinations: []})
    .mockResolvedValueOnce({id: 19});
  render(<RequestApproval data={data} serviceKey="payments"/>);
  fireEvent.change(await screen.findByRole('combobox', {name: /Additional service destination/}), {target: {value: additional.id}});
  const submit = screen.getByRole('button', {name: 'Request Cyber Approval'});
  fireEvent.click(submit);
  await screen.findByText(/selected service destination is no longer available/);
  expect(submit).toBeDisabled();
  fireEvent.click(screen.getByRole('button', {name: 'Clear selection'}));
  fireEvent.click(submit);
  await screen.findByText('Review request #19');
  expect(requestJson).toHaveBeenLastCalledWith('/api/cyber-approvals', expect.objectContaining({
    body: JSON.stringify({service_key: 'payments', variant: 'current_service'}),
  }));
});

it('shows both bound registries to the reviewer before the Cyber decision', async () => {
  vi.mocked(requestJson).mockResolvedValue({id: 15, status: 'pending', can_decide: true, destination: cyber, additional_destination: additional});
  render(<ApprovalDetail data={data} id="15"/>);
  const targets = within(await screen.findByRole('region', {name: 'Requested release destinations'}));
  expect(targets.getByText('https://cyber.test/approved')).toBeVisible();
  expect(targets.getByText('https://ops.test/deploy')).toBeVisible();
});

it.each(['release', 'revocation'])('retries only the additional %s delivery and refreshes its receipt', async kind => {
  const row = {id: 15, destination: cyber, status: 'approved', publish_status: 'published', validity_status: 'valid',
    revoked: kind === 'revocation', additional_destination: additional,
    additional_deliveries: [{kind, status: 'failed', error: 'Service registry unavailable', can_retry: true}]};
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (url.endsWith('/revision')) throw new ApiError('No governed revision', 404);
    if (options?.method === 'POST') return {...row, additional_deliveries: [{kind, status: 'queued', can_retry: false}]};
    return row;
  });
  render(<ReleaseDetail data={data} id="15"/>);
  const additionalDelivery = within(await screen.findByRole('region', {name: 'Additional service delivery'}));
  expect(additionalDelivery.getByRole('alert')).toHaveTextContent('Service registry unavailable');
  expect(screen.queryByRole('button', {name: 'Retry publication'})).not.toBeInTheDocument();
  fireEvent.click(additionalDelivery.getByRole('button', {name: `Retry additional ${kind} delivery`}));
  await waitFor(() => expect(additionalDelivery.getByText('Queued')).toBeVisible());
  expect(requestJson).toHaveBeenCalledWith(`/api/approved-releases/15/additional-deliveries/${kind}/retry`, expect.objectContaining({
    method: 'POST', headers: expect.objectContaining({'X-CSRF-Token': 'csrf'}),
  }));
});
