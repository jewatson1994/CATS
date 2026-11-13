import {afterEach, expect, it, vi} from 'vitest';
import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {requestJson, type PageData} from '../api';
import {ServicePullAccess} from './ServicePullAccess';

vi.mock('../api', async original => ({...await original<object>(), requestJson: vi.fn()}));
const request = vi.mocked(requestJson);
const privateAccess = {service_id: 42, public: false};
const admin: PageData = {csrf_token: 'csrf-proof', can: {'release.destination.manage': {'*': true}}, service_pull_access: privateAccess};
afterEach(() => vi.resetAllMocks());

it('loads service visibility for a viewer without showing a setting control', async () => {
  request.mockResolvedValue({service_id: 42, public: true});
  render(<ServicePullAccess data={{}} serviceId={42}/>);
  expect(await screen.findByText('Public')).toBeInTheDocument();
  expect(screen.getByText(/Anyone who can reach CATS/)).toBeInTheDocument();
  expect(screen.queryByRole('combobox', {name: 'Pull access'})).not.toBeInTheDocument();
  expect(request).toHaveBeenCalledWith('/api/oci/services/42/pull-access', expect.objectContaining({signal: expect.any(AbortSignal)}));
});

it('uses the persisted page setting without an extra request or assuming public access', () => {
  render(<ServicePullAccess data={admin} serviceId={42}/>);
  expect(screen.getByText('Private')).toBeInTheDocument();
  expect(screen.getByRole('combobox', {name: 'Pull access'})).toHaveValue('private');
  expect(screen.getByRole('button', {name: 'Save pull access'})).toBeDisabled();
  expect(request).not.toHaveBeenCalled();
});

it.each([false, true])('saves a service public setting with CSRF, including imported read-only pages: %s', async imported => {
  request.mockResolvedValue({service_id: 42, public: true});
  render(<ServicePullAccess data={{...admin, imported_service: imported, read_only: imported}} serviceId={42}/>);
  fireEvent.change(screen.getByRole('combobox', {name: 'Pull access'}), {target: {value: 'public'}});
  expect(screen.getByText('Private')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  expect(await screen.findByText('Service pull access saved.')).toBeInTheDocument();
  expect(screen.getByText('Public')).toBeInTheDocument();
  expect(request).toHaveBeenCalledWith('/api/oci/services/42/pull-access', {
    method: 'PUT', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-proof'}, body: JSON.stringify({public: true}),
  });
});

it('can return a public service to private access', async () => {
  request.mockResolvedValue(privateAccess);
  render(<ServicePullAccess data={{...admin, service_pull_access: {service_id: 42, public: true}}} serviceId={42}/>);
  fireEvent.change(screen.getByRole('combobox', {name: 'Pull access'}), {target: {value: 'private'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  await screen.findByText('Service pull access saved.');
  expect(screen.getByText('Private')).toBeInTheDocument();
  expect(JSON.parse(String(request.mock.calls[0][1]?.body))).toEqual({public: false});
});

it('does not claim a failed change succeeded and can reload the actual setting', async () => {
  request.mockRejectedValueOnce(new Error('Permission denied')).mockResolvedValue(privateAccess);
  render(<ServicePullAccess data={admin} serviceId={42}/>);
  fireEvent.change(screen.getByRole('combobox', {name: 'Pull access'}), {target: {value: 'public'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Permission denied');
  expect(screen.queryByText('Service pull access saved.')).not.toBeInTheDocument();
  expect(screen.getByText('Private')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Refresh pull access'}));
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  expect(await screen.findByText('Private')).toBeInTheDocument();
  expect(screen.getByRole('combobox', {name: 'Pull access'})).toHaveValue('private');
});

it('rejects a response belonging to another service rather than showing its visibility', async () => {
  request.mockResolvedValue({service_id: 43, public: true});
  render(<ServicePullAccess data={{}} serviceId={42}/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('unexpected pull-access setting');
  expect(screen.queryByText('Public')).not.toBeInTheDocument();
});

it('does not apply a completed save to a different service after navigation', async () => {
  let finishSave!: (value: unknown) => void;
  request.mockImplementation(() => new Promise(resolve => {finishSave = resolve;}));
  const {rerender} = render(<ServicePullAccess data={admin} serviceId={42}/>);
  fireEvent.change(screen.getByRole('combobox', {name: 'Pull access'}), {target: {value: 'public'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  expect(screen.getByRole('button', {name: 'Saving pull access…'})).toBeDisabled();
  rerender(<ServicePullAccess data={{...admin, service_pull_access: {service_id: 43, public: false}}} serviceId={43}/>);
  await act(async () => finishSave({service_id: 42, public: true}));
  expect(screen.getByText('Private')).toBeInTheDocument();
  expect(screen.getByRole('combobox', {name: 'Pull access'})).toHaveValue('private');
  expect(screen.queryByText('Service pull access saved.')).not.toBeInTheDocument();
});
