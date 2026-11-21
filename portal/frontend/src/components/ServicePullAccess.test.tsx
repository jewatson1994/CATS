import {afterEach, expect, it, vi} from 'vitest';
import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {requestJson, type PageData} from '../api';
import {ServicePullAccess} from './ServicePullAccess';

vi.mock('../api', async original => ({...await original<object>(), requestJson: vi.fn()}));
const request = vi.mocked(requestJson);
const privateAccess = {service_id: 42, public: false};
const admin: PageData = {csrf_token: 'csrf-proof', can: {'release.destination.manage': {'*': true}}, service_pull_access: privateAccess};
const selectAccess = () => screen.getByRole('combobox', {name: 'Service pull access'});
const choose = (value: string) => fireEvent.change(selectAccess(), {target: {value}});
afterEach(() => vi.resetAllMocks());

it('loads the current visibility for a viewer without a setting control', async () => {
  request.mockResolvedValue({service_id: 42, public: true});
  render(<ServicePullAccess data={{}} serviceId={42}/>);
  expect(await screen.findByText('Public · anonymous pulls')).toBeInTheDocument();
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  expect(request).toHaveBeenCalledWith('/api/oci/services/42/pull-access', expect.objectContaining({signal: expect.any(AbortSignal)}));
});

it('shows the saved setting directly in the dropdown without an extra request', () => {
  render(<ServicePullAccess data={admin} serviceId={42}/>);
  expect(selectAccess()).toHaveValue('private');
  expect(screen.queryByRole('button', {name: 'Save pull access'})).not.toBeInTheDocument();
  expect(request).not.toHaveBeenCalled();
});

it.each([false, true])('saves a public selection with CSRF, including imported service pages: %s', async imported => {
  request.mockResolvedValue({service_id: 42, public: true});
  render(<ServicePullAccess data={{...admin, imported_service: imported, read_only: imported}} serviceId={42}/>);
  choose('public');
  expect(screen.getByText(/Anyone who can reach CATS/)).toHaveTextContent('owning group');
  expect(request).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  expect(await screen.findByText('Service pull access saved.')).toBeInTheDocument();
  expect(selectAccess()).toHaveValue('public');
  expect(request).toHaveBeenCalledWith('/api/oci/services/42/pull-access', {
    method: 'PUT', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-proof'}, body: JSON.stringify({public: true}),
  });
});

it('can return a public service to private access', async () => {
  request.mockResolvedValue(privateAccess);
  render(<ServicePullAccess data={{...admin, service_pull_access: {service_id: 42, public: true}}} serviceId={42}/>);
  choose('private');
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  await screen.findByText('Service pull access saved.');
  expect(selectAccess()).toHaveValue('private');
  expect(JSON.parse(String(request.mock.calls[0][1]?.body))).toEqual({public: false});
});

it('keeps a failed change unsaved and reloads the actual setting on request', async () => {
  request.mockRejectedValueOnce(new Error('Permission denied')).mockResolvedValue(privateAccess);
  render(<ServicePullAccess data={admin} serviceId={42}/>);
  choose('public');
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Permission denied');
  expect(screen.queryByText('Service pull access saved.')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Refresh pull access'}));
  await waitFor(() => expect(selectAccess()).toHaveValue('private'));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('rejects another service’s visibility response', async () => {
  request.mockResolvedValue({service_id: 43, public: true});
  render(<ServicePullAccess data={{}} serviceId={42}/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('unexpected pull-access setting');
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
});

it('ignores a completed save after navigation to a different service', async () => {
  let finishSave!: (value: unknown) => void;
  request.mockImplementation(() => new Promise(resolve => {finishSave = resolve;}));
  const {rerender} = render(<ServicePullAccess data={admin} serviceId={42}/>);
  choose('public');
  fireEvent.click(screen.getByRole('button', {name: 'Save pull access'}));
  expect(selectAccess()).toBeDisabled();
  rerender(<ServicePullAccess data={{...admin, service_pull_access: {service_id: 43, public: false}}} serviceId={43}/>);
  await act(async () => finishSave({service_id: 42, public: true}));
  expect(selectAccess()).toHaveValue('private');
  expect(screen.queryByText('Service pull access saved.')).not.toBeInTheDocument();
});

it('restores the saved selection on cancel without a request', () => {
  render(<ServicePullAccess data={admin} serviceId={42}/>);
  choose('public');
  fireEvent.click(screen.getByRole('button', {name: 'Cancel'}));
  expect(selectAccess()).toHaveValue('private');
  expect(screen.queryByRole('button', {name: 'Save pull access'})).not.toBeInTheDocument();
  expect(request).not.toHaveBeenCalled();
});
