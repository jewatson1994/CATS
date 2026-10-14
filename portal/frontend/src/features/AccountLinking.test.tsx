import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {AccountLinking} from './AccountLinking';
import {requestJson} from '../api';

vi.mock('../api', () => ({requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});

it('previews exact identity and only retains deliberately selected permissions', async () => {
  const account = {id: 1, username: 'local', enabled: true, local_credentials: true,
    scan_ownership: [], historical_references: {}, identities: [], roles: [
      {id: 7, selectable: true, role: 'Viewer', source: 'local', scope: 'global', permissions: ['service.view']}]};
  vi.mocked(requestJson).mockResolvedValueOnce({survivor: account,
    source: {...account, id: 2, username: 'duplicate', roles: [
      {id: 8, selectable: true, role: 'Admin', source: 'local', scope: 'global', permissions: ['user.manage']},
      {id: 9, selectable: false, role: 'OIDC Admin', source: 'oidc', scope: 'global', permissions: ['user.manage']}]},
    identity: {issuer: 'https://id.example', subject: 'sub'}, preview_token: 'preview', confirmation: 'LINK local', conflicts: ['Review access']
  }).mockResolvedValueOnce({survivor_id: 1});
  render(<AccountLinking data={{csrf_token: 'csrf', users: [{id: 1, username: 'local'}, {id: 2, username: 'duplicate'}]}}/>);
  fireEvent.change(screen.getByLabelText(/Duplicate OIDC/), {target: {value: '2'}});
  fireEvent.change(screen.getByLabelText('Verified issuer URL'), {target: {value: 'https://id.example'}});
  fireEvent.change(screen.getByLabelText('Verified subject (sub)'), {target: {value: 'sub'}});
  fireEvent.click(screen.getByLabelText(/I verified/));
  fireEvent.submit(screen.getByRole('button', {name: 'Preview account change'}).closest('form')!);
  await screen.findByText('Review identities and access');
  expect(JSON.parse(vi.mocked(requestJson).mock.calls[0][1]?.body as string)).toMatchObject({survivor_id: 1, source_id: 2, issuer: 'https://id.example', subject: 'sub', identity_verified: true});
  expect(screen.getByLabelText(/Viewer · local/)).toBeChecked();
  expect(screen.getByLabelText(/^Admin · local/)).not.toBeChecked();
  expect(screen.getByLabelText(/OIDC Admin · oidc/)).toBeDisabled();
  fireEvent.change(screen.getByLabelText(/Type/), {target: {value: 'LINK local'}});
  fireEvent.submit(screen.getByRole('button', {name: 'Confirm account change'}).closest('form')!);
  await waitFor(() => expect(requestJson).toHaveBeenCalledTimes(2));
  expect(JSON.parse(vi.mocked(requestJson).mock.calls[1][1]?.body as string)).toMatchObject({selected_assignment_ids: [7], preview_token: 'preview', confirmation: 'LINK local', csrf_token: 'csrf'});
  await screen.findByRole('status');
});
