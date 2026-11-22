import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {AccessRequests} from './AccessRequests';
import {requestJson} from '../api';

vi.mock('../api', () => ({requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});

const assessor = {id: 12, name: 'Assessor'};
const manager = {id: 14, name: 'Service Manager'};
const cyber = {id: 19, name: 'Cybersecurity'};
const data = {csrf_token: 'csrf'};

it.each([manager, cyber])('approves the chosen $name role for one requested service', async role => {
  vi.mocked(requestJson).mockResolvedValueOnce({requests: [
    {user_id: 3, username: 'new-user', service_id: 20, service_name: 'Alpha'},
    {user_id: 3, username: 'new-user', service_id: 21, service_name: 'Beta'},
  ], groups: [], roles: [assessor, manager, cyber]}).mockResolvedValueOnce({status: 'claimed', role: role.name});
  render(<AccessRequests data={data}/>);
  const select = await screen.findByRole('combobox', {name: 'Role for new-user on Alpha'});
  expect(select).toHaveValue(String(assessor.id));
  expect(screen.queryByLabelText('Group for new-user')).toBeNull();
  fireEvent.change(select, {target: {value: String(role.id)}});
  expect(screen.getByRole('combobox', {name: 'Role for new-user on Beta'})).toHaveValue(String(assessor.id));
  fireEvent.click(within(select.closest('form')!).getByRole('button', {name: 'Approve access'}));
  expect(await screen.findByRole('status')).toHaveTextContent(`Approved new-user as ${role.name} for Alpha.`);
  expect(vi.mocked(requestJson).mock.calls[1][0]).toBe('/api/accounts/access-requests/3/claim');
  expect(JSON.parse(vi.mocked(requestJson).mock.calls[1][1]?.body as string)).toEqual({
    csrf_token: 'csrf', service_id: 20, role_id: role.id,
  });
  expect(screen.queryByText('Alpha')).toBeNull();
  expect(screen.getByText('Beta')).toBeInTheDocument();
});

it('requires a group and uses the default Assessor role when approving the account', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({
    requests: [{user_id: 3, username: 'new-user', display_name: 'New user'}],
    groups: [{id: 4, name: 'Finance'}, {id: 5, name: 'Operations'}], roles: [assessor, manager],
  }).mockResolvedValueOnce({status: 'claimed', role: assessor.name});
  render(<AccessRequests data={data}/>);
  const group = await screen.findByLabelText('Group for new-user');
  expect(group).toBeRequired();
  expect(group).toHaveValue('');
  expect(screen.queryByRole('option', {name: 'Cybersecurity'})).toBeNull();
  fireEvent.click(screen.getByRole('button', {name: 'Approve access'}));
  expect(requestJson).toHaveBeenCalledTimes(1);
  fireEvent.change(group, {target: {value: '5'}});
  fireEvent.click(screen.getByRole('button', {name: 'Approve access'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledTimes(2));
  expect(JSON.parse(vi.mocked(requestJson).mock.calls[1][1]?.body as string)).toEqual({
    csrf_token: 'csrf', group_id: 5, role_id: assessor.id,
  });
  expect(await screen.findByRole('status')).toHaveTextContent('Approved new-user as Assessor for Operations.');
});

it('keeps the role selected after an approval fails', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({
    requests: [{user_id: 3, username: 'new-user'}], groups: [{id: 4, name: 'Finance'}], roles: [assessor, manager],
  }).mockRejectedValueOnce(new Error('Account is no longer pending'));
  render(<AccessRequests data={data}/>);
  const role = await screen.findByLabelText('Role for new-user');
  fireEvent.change(role, {target: {value: String(manager.id)}});
  const button = screen.getByRole('button', {name: 'Approve access'});
  fireEvent.click(button);
  expect(await screen.findByRole('alert')).toHaveTextContent('Account is no longer pending');
  expect(role).toHaveValue(String(manager.id));
  expect(button).toBeEnabled();
});

it('requires an explicit choice when Assessor is unavailable', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({
    requests: [{user_id: 3, username: 'new-user', service_id: 20, service_name: 'Alpha'}],
    groups: [], roles: [manager, cyber],
  });
  render(<AccessRequests data={data}/>);
  const role = await screen.findByLabelText('Role for new-user on Alpha');
  expect(role).toHaveValue('');
  fireEvent.click(screen.getByRole('button', {name: 'Approve access'}));
  expect(requestJson).toHaveBeenCalledTimes(1);
});

it('disables approval when the reviewer has no available roles', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({
    requests: [{user_id: 3, username: 'new-user', service_id: 20, service_name: 'Alpha'}], groups: [], roles: [],
  });
  render(<AccessRequests data={data}/>);
  expect(await screen.findByRole('button', {name: 'Approve access'})).toBeDisabled();
  expect(screen.getByText('No roles are available to approve these requests.')).toBeInTheDocument();
});
