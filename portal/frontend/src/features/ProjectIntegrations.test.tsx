import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {requestJson} from '../api';
import {Page} from './service_overview';

vi.mock('../api', async actual => ({...await actual<typeof import('../api')>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks(); window.history.replaceState({}, '', '/');});
const service = {id: 12, service_key: 'payments', name: 'Payments', groups: [{id: 1, name: 'Ops'}], lifecycle_status: 'active'};
const data = {view: {service}, can: {'service.edit': {'12': true}, 'scan.ingest': {'12': true}},
  service_pull_access: {service_id: 12, public: false}, csrf_token: 'csrf'};
const root = '/api/services/payments/project-credentials';
const credential = {id: 42, project_label: 'Nightly build', service_key: 'payments', status: 'active', scopes: ['artifacts.submit'],
  expires_at: '2026-12-01T01:00:00Z', created_at: '2026-11-01T01:00:00Z', revoked_at: null};
const secret = 'sample-token-shown-once';
async function openPanel() {
  const region = within(screen.getByRole('region', {name: 'Project integrations'}));
  fireEvent.click(region.getByRole('button', {name: 'Manage credentials'}));
  await waitFor(() => expect(region.queryByText('Loading CI credentials.')).not.toBeInTheDocument());
  return region;
}

it('issues a service-bound project credential and dismisses its token permanently', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({credentials: []}).mockResolvedValueOnce({credential, token: secret})
    .mockResolvedValueOnce({credentials: [credential]});
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText}});
  render(<Page data={data}/>);
  expect(requestJson).not.toHaveBeenCalled();
  const panel = await openPanel();
  expect(panel.getByText('payments')).toBeVisible();
  fireEvent.click(panel.getByRole('button', {name: 'New credential'}));
  expect(panel.getByRole('button', {name: 'Issue credential'})).toBeDisabled();
  fireEvent.change(panel.getByLabelText('Project label'), {target: {value: '  Nightly build  '}});
  fireEvent.click(panel.getByLabelText(/Write scan evidence/));
  fireEvent.change(panel.getByLabelText('Expires in days'), {target: {value: '7'}});
  fireEvent.click(panel.getByRole('button', {name: 'Issue credential'}));
  await panel.findByText(secret);
  expect(requestJson).toHaveBeenCalledWith(root, expect.objectContaining({
    method: 'POST', headers: expect.objectContaining({'X-CSRF-Token': 'csrf'}),
    body: JSON.stringify({csrf_token: 'csrf', project_label: 'Nightly build', scopes: ['artifacts.submit', 'evidence.write'], expires_in_days: 7}),
  }));
  fireEvent.click(panel.getByRole('button', {name: 'Copy token'}));
  expect(writeText).toHaveBeenCalledWith(secret);
  fireEvent.click(panel.getByRole('button', {name: 'Dismiss token'}));
  expect(panel.queryByText(secret)).not.toBeInTheDocument();
  fireEvent.click(panel.getByText('CI submission example'));
  fireEvent.click(panel.getByRole('button', {name: 'Copy submission example'}));
  const snippet = writeText.mock.calls.at(-1)?.[0];
  expect(snippet).toContain('/api/v1/artifact-submissions');
  expect(snippet).toContain('Bearer $CATS_PROJECT_TOKEN');
  expect(snippet).toContain('Idempotency-Key: $CATS_SUBMISSION_KEY');
  expect(snippet).not.toContain(secret);
  fireEvent.click(panel.getByRole('button', {name: 'Close credentials'}));
  await openPanel();
  expect(panel.queryByText(secret)).not.toBeInTheDocument();
  expect(panel.getByText('Nightly build')).toBeVisible();
  expect(window.location.href).not.toContain(secret);
  expect([JSON.stringify(localStorage), JSON.stringify(sessionStorage)].join('')).not.toContain(secret);
});

it.each(['active', 'inactive'])('lets a service editor revoke an %s credential without issuing a new one', async status => {
  vi.mocked(requestJson).mockResolvedValueOnce({credentials: [{...credential, status}]}).mockResolvedValueOnce({credential: {...credential, status: 'revoked'}});
  render(<Page data={{...data, can: {'service.edit': {'12': true}}}}/>);
  const panel = await openPanel();
  expect(panel.queryByRole('button', {name: 'New credential'})).not.toBeInTheDocument();
  fireEvent.click(panel.getByRole('button', {name: 'Revoke Nightly build'}));
  expect(requestJson).toHaveBeenCalledTimes(1);
  fireEvent.click(panel.getByRole('button', {name: 'Confirm revocation'}));
  expect(await panel.findByText('Revoked credential for Nightly build.')).toBeVisible();
  expect(requestJson).toHaveBeenCalledWith(root + '/42/revoke', expect.objectContaining({
    method: 'POST', body: JSON.stringify({csrf_token: 'csrf'}),
  }));
  expect(panel.queryByRole('button', {name: 'Revoke Nightly build'})).not.toBeInTheDocument();
});

it.each([
  {imported_service: true}, {read_only: true}, {can: {}},
])('hides credential management when the service is read-only or the user lacks service.edit', extra => {
  render(<Page data={{...data, ...extra}}/>);
  expect(screen.queryByRole('region', {name: 'Project integrations'})).not.toBeInTheDocument();
  expect(requestJson).not.toHaveBeenCalledWith(root, expect.anything());
});

it.each([
  [{...service, lifecycle_status: 'archived'}, /active service/],
  [{...service, groups: []}, /one owning group/],
] as const)('allows reviewing credentials while issuance is unavailable', async (blocked, reason) => {
  vi.mocked(requestJson).mockResolvedValue({credentials: []});
  render(<Page data={{...data, view: {service: blocked}}}/>);
  const panel = await openPanel();
  expect(panel.getByText(reason)).toBeVisible();
  expect(panel.queryByRole('button', {name: 'New credential'})).not.toBeInTheDocument();
});

it('does not display an old token after navigating to a different service', async () => {
  let complete!: (value: unknown) => void;
  vi.mocked(requestJson).mockResolvedValueOnce({credentials: []})
    .mockImplementationOnce(() => new Promise(resolve => {complete = resolve;}));
  const page = render(<Page data={data}/>);
  const panel = await openPanel();
  fireEvent.click(panel.getByRole('button', {name: 'New credential'}));
  fireEvent.change(panel.getByLabelText('Project label'), {target: {value: credential.project_label}});
  fireEvent.click(panel.getByRole('button', {name: 'Issue credential'}));
  page.rerender(<Page data={{...data, can: {'service.edit': {'99': true}},
    service_pull_access: {service_id: 99, public: false}, view: {service: {...service, id: 99, service_key: 'invoices'}}}}/>);
  complete({credential, token: secret});
  await waitFor(() => expect(screen.queryByText(secret)).not.toBeInTheDocument());
  expect(within(screen.getByRole('region', {name: 'Project integrations'})).getByText('invoices')).toBeVisible();
});
