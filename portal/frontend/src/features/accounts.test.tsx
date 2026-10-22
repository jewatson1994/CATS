import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it} from 'vitest';
import {Page} from './admin';
import {RoleAssignment} from './RoleAssignment';

afterEach(cleanup);
const user = (id: number, username: string, methods: string[]) => ({user: {id, username, display_name: username, auth_source: 'local', sign_in_methods: methods, enabled: true}, assignments: [], permissions: []});
const data = {csrf_token: 'csrf', user_rows: [user(1, 'password-user', ['local']), user(2, 'provider-user', ['oidc']), user(3, 'linked-user', ['local', 'oidc'])], users: [{id: 1, username: 'password-user'}, {id: 2, username: 'provider-user'}], roles: [{id: 1, name: 'Assessor', description: 'Review service evidence'}], services: [{id: 7, name: 'Payments'}, {id: 8, name: 'Inventory'}], groups: [{id: 2, name: 'Operations'}], can: {}};
it('separates sign-in methods using real credentials instead of account origin', () => {
  render(<Page data={data}/>);
  expect(screen.getByRole('button', {name: 'password-user'})).toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'provider-user'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'OIDC (1)'}));
  expect(screen.getByRole('button', {name: 'provider-user'})).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Both (local + OIDC) (1)'}));
  expect(screen.getByRole('button', {name: 'linked-user'})).toBeInTheDocument();
  expect(screen.getByText('Local + OIDC', {selector: 'td .dg-cell'})).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Find an account'), {target: {value: 'missing'}});
  expect(screen.getByText('No accounts match this sign-in method and search.')).toBeInTheDocument();
});
it('requires deliberate account, role and scope; submits only the chosen scope', () => {
  render(<RoleAssignment data={{...data, can: {'role.manage': {'*': true}}}}/>);
  const button = screen.getByRole('button', {name: 'Assign role'});
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Account'), {target: {value: '1'}});
  fireEvent.change(screen.getByLabelText('Role'), {target: {value: '1'}});
  expect(screen.getByLabelText('Grant source')).toHaveValue('local');
  fireEvent.click(screen.getByLabelText('Payments'));
  expect(button).not.toBeDisabled();
  expect(new FormData(button.closest('form')!).getAll('service_ids')).toEqual(['7']);
  fireEvent.change(screen.getByLabelText('Access scope'), {target: {value: 'group'}});
  fireEvent.change(screen.getByLabelText('Service group'), {target: {value: '2'}});
  const payload = new FormData(button.closest('form')!);
  expect(payload.getAll('service_ids')).toEqual([]);
  expect(payload.get('group_id')).toBe('2');
  expect(payload.get('csrf_token')).toBe('csrf');

});
it('requires deliberate OIDC grants and confirmation of global access', () => {
  render(<RoleAssignment data={{...data, can: {'role.manage': {'*': true}}}} userId={2}/>);
  expect(screen.getByLabelText('Grant source')).toHaveValue('local');
  fireEvent.change(screen.getByLabelText('Access scope'), {target: {value: 'global'}});
  expect(screen.getByLabelText(/Grant this role globally/)).toBeRequired();
  expect(screen.getByLabelText(/Grant this role globally/)).not.toBeChecked();
});
it('does not expose account administration to scoped role managers', () => {
  render(<Page data={{...data, may_assign_roles: true}}/>);
  expect(screen.getByRole('button', {name: 'Assign role'})).toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Create account'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Create custom role'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Preview account change'})).not.toBeInTheDocument();
});

it('limits scoped managers to a required group for Assessor grants', () => {
  render(<RoleAssignment data={data} userId={1}/>);
  fireEvent.change(screen.getByLabelText('Role'), {target: {value: '1'}});
  expect(screen.getByLabelText('Access scope')).toHaveValue('group');
  expect(screen.getByLabelText('Service group')).toBeRequired();
  expect(screen.queryByRole('option', {name: 'Global access'})).not.toBeInTheDocument();
  expect(screen.queryByRole('option', {name: 'Selected services'})).not.toBeInTheDocument();
});
