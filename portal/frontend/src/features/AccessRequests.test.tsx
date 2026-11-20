import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {AccessRequests} from './AccessRequests';
import {requestJson} from '../api';
vi.mock('../api', () => ({requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
it('approves only the selected service and keeps the other request for the same account', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({requests: [
    {user_id: 3, username: 'new-user', service_id: 20, service_name: 'Alpha'},
    {user_id: 3, username: 'new-user', service_id: 21, service_name: 'Beta'},
  ], groups: []}).mockResolvedValueOnce({status: 'claimed'});
  render(<AccessRequests data={{csrf_token: 'csrf'}}/>);
  const form = (await screen.findByText('Alpha')).closest('form')!;
  expect(form.querySelector('select')).toBeNull();
  fireEvent.submit(form);
  await waitFor(() => expect(screen.queryByText('Alpha')).toBeNull());
  expect(JSON.parse(vi.mocked(requestJson).mock.calls[1][1]?.body as string)).toEqual({csrf_token: 'csrf', service_id: 20});
  expect(screen.getByText('Beta')).toBeInTheDocument();
});
it('requires a group and claims the exact pending account with CSRF', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({requests: [{user_id: 3, username: 'new-user', display_name: 'New user'}], groups: [{id: 4, name: 'Finance'}, {id: 5, name: 'Operations'}]}).mockResolvedValueOnce({status: 'claimed'});
  render(<AccessRequests data={{csrf_token: 'csrf'}}/>);
  const select = await screen.findByLabelText('Group for new-user');
  expect(select).toBeRequired();
  expect(select).toHaveValue('');
  fireEvent.change(select, {target: {value: '5'}});
  fireEvent.submit(screen.getByRole('button', {name: 'Claim as Assessor'}).closest('form')!);
  await waitFor(() => expect(requestJson).toHaveBeenCalledTimes(2));
  expect(vi.mocked(requestJson).mock.calls[1][0]).toBe('/api/accounts/access-requests/3/claim');
  expect(JSON.parse(vi.mocked(requestJson).mock.calls[1][1]?.body as string)).toEqual({csrf_token: 'csrf', group_id: 5});
  await screen.findByText('No accounts are awaiting access.');
});
it('keeps a failed request visible and reports the server error', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({requests: [{user_id: 3, username: 'new-user'}], groups: [{id: 4, name: 'Finance'}]}).mockRejectedValueOnce(new Error('Account is no longer pending'));
  render(<AccessRequests data={{csrf_token: 'csrf'}}/>);
  const button = await screen.findByRole('button', {name: 'Claim as Assessor'});
  fireEvent.submit(button.closest('form')!);
  expect(await screen.findByRole('alert')).toHaveTextContent('Account is no longer pending');
  expect(screen.getByRole('button', {name: 'Claim as Assessor'})).toBeEnabled();
});
