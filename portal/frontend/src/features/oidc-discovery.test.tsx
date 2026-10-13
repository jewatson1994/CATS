import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Page} from './configuration';

afterEach(() => {cleanup(); vi.restoreAllMocks(); window.history.replaceState({}, '', '/'); sessionStorage.clear();});
const data = {csrf_token: 'csrf', can: {'config.manage': {'*': true}}, oidc_roles: [{id: 2, name: 'Assessor'}], oidc_groups: [{id: 4, name: 'Security'}]};
function openSettings() {
  window.history.replaceState({}, '', '/admin/configuration#identity-access');
  return render(<Page data={data}/>);
}

it('discovers and filters memberships, then prefills an editable scoped mapping without saving', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({provider: 'keycloak', warnings: [], candidates: [
    {kind: 'group', label: '/Engineering', claim_path: 'groups', expected_value: '/Engineering'},
    {kind: 'realm_role', label: 'reviewer', claim_path: 'realm_access.roles', expected_value: 'reviewer'},
  ]}), {headers: {'Content-Type': 'application/json'}}));
  const {container} = openSettings();
  fireEvent.click(screen.getByRole('button', {name: 'Discover groups and roles'}));
  fireEvent.click(await screen.findByRole('button', {name: 'Map group /Engineering'}));
  expect(screen.getByLabelText('Claim path')).toHaveValue('groups');
  expect(screen.getByLabelText('Expected value')).toHaveValue('/Engineering');
  fireEvent.click(screen.getByRole('button', {name: 'Map realm role reviewer'}));
  expect(screen.getByLabelText('Claim path')).toHaveValue('realm_access.roles');
  expect(screen.getByLabelText('Expected value')).toHaveValue('reviewer');
  fireEvent.change(screen.getByLabelText('Scope'), {target: {value: 'group'}});
  fireEvent.change(screen.getByLabelText('Group'), {target: {value: '4'}});
  const form = container.querySelector('form[action="/admin/configuration/oidc-mappings"]') as HTMLFormElement;
  expect(new FormData(form).get('scope_id')).toBe('4');
  expect(new FormData(form).get('role_id')).toBe('2');
  fireEvent.change(screen.getByLabelText('Filter provider groups and roles'), {target: {value: 'reviewer'}});
  expect(screen.queryByRole('button', {name: 'Map group /Engineering'})).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0][0]).toContain('/admin/configuration/oidc-mappings/discover');
  expect((fetcher.mock.calls[0][1]?.body as FormData).get('csrf_token')).toBe('csrf');
});

it('shows setup failures and allows retry without retaining stale candidates', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({detail: 'Enable service accounts in Keycloak.'}), {status: 422, headers: {'Content-Type': 'application/json'}}))
    .mockResolvedValueOnce(new Response(JSON.stringify({provider: 'keycloak', candidates: [], warnings: ['Add groups to the ID token.']}), {headers: {'Content-Type': 'application/json'}}));
  openSettings();
  fireEvent.click(screen.getByRole('button', {name: 'Discover groups and roles'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Enable service accounts in Keycloak.');
  fireEvent.click(screen.getByRole('button', {name: 'Discover groups and roles'}));
  expect(await screen.findByText('Add groups to the ID token.')).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
});
