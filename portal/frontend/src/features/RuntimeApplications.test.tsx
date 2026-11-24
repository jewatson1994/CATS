import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {RuntimeApplications} from './RuntimeApplications';
import {requestJson} from '../api';

vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks(); window.history.replaceState(null, '', '/');});
const app = {id: 6, name: 'payments', namespace: 'checkout', environment: 'Test west', environment_id: 1,
  cluster_role: 'validation', fingerprint: 'b'.repeat(64), present: true, service: null, service_id: null,
  discovered_at: '2026-11-20T01:00:00Z', last_observed_at: '2026-11-20T02:00:00Z',
  components: [{workload_kind: 'Deployment', workload: 'api', container: 'web', image_id: 'registry/pay@sha256:test'}],
  services: [{id: 8,name: 'Checkout'}], can_assign: true, can_create: true,
  suggestions: [{service_id: 8, confidence: 'medium', evidence: ['Kubernetes application label']}]};
const sample = {applications: [app], candidates: [], next_offset: null};

it('shows observed components before submitting the reviewed fingerprint and refreshes the association', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce(sample).mockResolvedValueOnce({id: 6, service_id: 8})
    .mockResolvedValueOnce({...sample, applications: [{...app, service_id: 8, service: 'Checkout'}]});
  render(<RuntimeApplications csrf="token"/>);
  expect(requestJson).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', {name: /Discovered applications/}));
  fireEvent.click(await screen.findByText('payments', {selector: 'strong'}));
  expect(screen.getByText('Deployment api')).toBeVisible();
  expect(screen.getByText(/medium confidence/)).toHaveTextContent('Kubernetes application label');
  fireEvent.change(screen.getByLabelText('Assign to service'), {target: {value: '8'}});
  fireEvent.click(screen.getByRole('button', {name: 'Assign application'}));
  expect(await screen.findByRole('heading', {name: 'Service associations'})).toBeVisible();
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/applications/6/assignment', {
    method: 'POST', headers: {'X-CSRF-Token': 'token', 'Content-Type': 'application/json'},
    body: JSON.stringify({expected_fingerprint: app.fingerprint, expected_service_id: null, service_id: 8})});
});

it('opens a notification deep link and preserves the new-service form when assignment conflicts', async () => {
  window.history.replaceState(null, '', '/?runtime_applications=1');
  vi.mocked(requestJson).mockResolvedValueOnce(sample).mockRejectedValueOnce(new Error('Inventory changed. Refresh and review it.'));
  render(<RuntimeApplications csrf="csrf"/>);
  fireEvent.click(await screen.findByText('payments'));
  fireEvent.change(screen.getByLabelText('Assign to service'), {target: {value: 'new'}});
  fireEvent.change(screen.getByLabelText('New service key'), {target: {value: 'payments'}});
  fireEvent.click(screen.getByRole('button', {name: 'Create service and assign'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Inventory changed');
  expect(screen.getByLabelText('New service key')).toHaveValue('payments');
  expect(JSON.parse(String(vi.mocked(requestJson).mock.calls[1][1]?.body))).toMatchObject({new_service_key: 'payments'});
});

it('shows a prior submitted revision after source drift and hides assignment from read-only viewers', async () => {
  vi.mocked(requestJson).mockResolvedValue({...sample, applications: [{...app, can_assign: false, service: 'Checkout', service_id: 8}],
    candidates: [{id: 11, service: 'Checkout', environment: 'Test west', namespace: 'checkout', version: 1, proposed_version: '1.2',
      current: false, status: 'submitted', approval_id: 43, assessment_status: 'ready', href: '/cyber-approvals?id=43'}]});
  render(<RuntimeApplications csrf="csrf"/>);
  fireEvent.click(screen.getByRole('button', {name: /Discovered applications/}));
  expect(await screen.findByRole('link', {name: /Revision 1/})).toHaveAttribute('href', '/cyber-approvals?id=43');
  fireEvent.click(screen.getByText('payments'));
  await waitFor(() => expect(screen.queryByLabelText('Assign to service')).toBeNull());
});
