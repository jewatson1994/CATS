import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {Page as Admin} from './admin';
import {Page as Settings} from './configuration';
import {Page as Staging} from './staging';
import {Page as Audit} from './audit';

beforeEach(() => {
  HTMLDialogElement.prototype.showModal = vi.fn(function(this: HTMLDialogElement) {this.setAttribute('open', '');});
});
afterEach(() => {cleanup(); vi.restoreAllMocks(); window.history.replaceState({}, '', '/'); sessionStorage.clear();});
const permissions = {can: {'user.manage': {'*': true}, 'role.manage': {'*': true}, 'config.manage': {'*': true}, 'audit.view': {'*': true}}, csrf_token: 'csrf'};
describe('native administration workflows', () => {
  it('keeps staging out of administration and exposes global settings', () => {
    render(<Admin data={{...permissions, users: [], roles: [], services: [], groups: [], permission_catalog: {}, user_rows: []}}/>);
    expect(screen.queryByRole('link', {name: 'Service staging'})).not.toBeInTheDocument();
    expect(screen.getByRole('link', {name: 'Settings'})).toHaveAttribute('href', '/admin/configuration');
  });
  it('lists accounts in a compact table and opens access details from the username', () => {
    const {container} = render(<Admin data={{...permissions, users: [], roles: [], services: [], groups: [], permission_catalog: {'audit.view': 'Review events'}, user_rows: [
      {user: {id: 1, display_name: 'Jane', username: 'jane', auth_source: 'local', enabled: true, is_self: true}, assignments: [{id: 7, role: 'Reviewer', group: 'Team', service: 'All services in group'}], permissions: ['audit.view']},
      {user: {id: 2, display_name: 'Pat', username: 'pat', auth_source: 'oidc', enabled: false}, assignments: [], permissions: []}]}}/>);
    expect(screen.getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['Username', 'Enabled', 'Source', 'Last login']);
    expect(screen.queryByText('Reviewer')).not.toBeVisible();
    fireEvent.click(screen.getByRole('button', {name: 'jane'}));
    const account = screen.getByRole('dialog', {name: 'Account: jane'});
    expect(within(account).getByText('Reviewer')).toBeVisible();
    expect(within(account).getByText('Team')).toBeVisible();
    expect(account.querySelector('form[action="/admin/assignments"] input[name="user_id"]')).toHaveValue('1');
    expect(account.querySelector('form[action="/admin/assignments"] input[name="csrf_token"]')).toHaveValue('csrf');
    expect(container.querySelectorAll('.account-record')).toHaveLength(2);
    for (const action of ['/admin/users', '/admin/roles', '/admin/assignments', '/admin/groups']) {
      const form = container.querySelector(`form[action="${action}"]`);
      expect(form?.closest('dialog')).not.toBeNull();
      expect(form?.querySelector('input[name="csrf_token"]')).toHaveValue('csrf');
    }
    expect(container.querySelector('.account-assignment')).toHaveTextContent('ReviewerTeamAll services in group');
    fireEvent.change(screen.getByRole('searchbox'), {target: {value: 'PAT'}});
    expect(container.querySelectorAll('.account-record')).toHaveLength(1);
    expect(container.querySelector('.account-record')).toHaveTextContent('Pat');
    expect(Array.from(container.querySelectorAll('tbody tr > td')).slice(1).map(cell => cell.textContent)).toEqual(['Disabled', 'OIDC', 'Never']);
    fireEvent.change(screen.getByRole('searchbox'), {target: {value: 'missing'}});
    expect(screen.getByText('No accounts match your search.')).toBeInTheDocument();
  });
  it('preserves account actions while preventing self-disable/delete and nonlocal reset', () => {
    const {container} = render(<Admin data={{...permissions, users: [], roles: [], services: [], groups: [], permission_catalog: {'audit.view': 'Review events'}, user_rows: [
      {user: {id: 1, display_name: '<script>Jane</script>', username: 'jane', auth_source: 'local', enabled: true, is_self: true}, assignments: [], permissions: ['audit.view']},
      {user: {id: 2, display_name: 'Pat', username: 'pat', auth_source: 'oidc', enabled: false, is_self: false}, assignments: [], permissions: []}]}}/>);
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('form[action="/admin/users/1/toggle"]')).toBeNull();
    expect(container.querySelector('form[action="/admin/users/1/delete"]')).toBeNull();
    expect(container.querySelector('form[action="/admin/users/1/reset-password"] input[name="temporary_password"]')).toHaveAttribute('minlength', '14');
    expect(container.querySelector('form[action="/admin/users/2/reset-password"]')).toBeNull();
    expect(container.querySelector('form[action="/admin/users/2/delete"] input[name="csrf_token"]')).toHaveValue('csrf');
    fireEvent.click(screen.getByRole('button', {name: 'pat'}));
    expect(screen.getByRole('button', {name: 'Enable'})).toBeVisible();
  });
  it('preserves staging redirect and single eligible group', () => {
    const {container} = render(<Staging data={{...permissions, next_path: '/admin/staging?saved=1', stage_groups: [{id: 4, name: 'Team'}]}}/>);
    expect(container.querySelector('input[name="group_id"]')).toHaveValue('4');
    expect(container.querySelector('input[name="next_path"]')).toHaveValue('/admin/staging?saved=1');
    expect(screen.getByRole('button', {name: 'Stage service'}).closest('form')).toHaveAttribute('action', '/admin/services/stage');
  });
  it('renders audit scope, formatted dates and older/collapse links', () => {
    render(<Audit data={{...permissions, configuration: {audit_retention_days: 30, log_level: 'WARNING'}, groups: [{id: 4, name: 'Team'}], selected_group_id: 4,
      shown_count: 20, retained_count: 70, next_show: 70, events: [{id: 1, created_at: 'Display date', actor: 'jane', action: 'user.created', target_type: 'user', target_id: 2, detail: {username: 'pat'}}]}}/>);
    expect(screen.getByRole('button', {name: 'Save audit policy'}).closest('form')).toHaveAttribute('action', '/admin/audit-policy?group_id=4');
    expect(screen.getByRole('link', {name: 'Show older events'})).toHaveAttribute('href', '/admin/audit?show=70&group_id=4');
    expect(screen.getByRole('link', {name: 'Collapse to latest 10'})).toHaveAttribute('href', '/admin/audit?group_id=4');
    expect(screen.getByText('Display date')).toBeInTheDocument();
  });
  it('keeps editor credentials blank and preserves forms and unsaved inputs through search', () => {
    const {container} = render(<Settings data={{...permissions, configuration: {display_timezone: 'UTC', date_format: '%Y-%m-%d', time_format: '%H:%M UTC', identity_mode: 'both'}, timezones: ['UTC'], date_formats: [['%Y-%m-%d', 'ISO']], time_formats: [['%H:%M UTC', 'UTC']],
      oidc: {provider_name: 'Org', client_id: 'client', issuer: 'https://id', client_secret_configured: true}, signing: {configured: true}, validator: {client_key_configured: true},
      registries: [{id: 'prod', display_name: 'Production', endpoint: 'https://registry', username: 'scanner', auth_mode: 'credentials', secret_configured: true}], oidc_mappings: [], package_managers: ['apt'],
      os_definitions: {linux: {name: 'Linux', package_manager: 'apt'}}, repository_policies: {linux: {verify_tls: false, verify_packages: true}}, custom_os: [], edit_os_id: 'linux'}}/>);
    expect(container.querySelector('input[name="client_secret"]')).toHaveValue('');
    expect(container.querySelector('textarea[name="client_key"]')).toHaveValue('');
    fireEvent.click(screen.getByRole('button', {name: 'Edit'}));
    expect(container.querySelector('input[name="registry_id"]')).toHaveValue('prod');
    expect(container.querySelector('input[name="password"]')).toHaveValue('');
    expect(container.querySelector('input[name="username"]')).toHaveValue('scanner');
    fireEvent.change(container.querySelector('input[name="display_name"]')!, {target: {value: 'Unsaved name'}});
    fireEvent.change(screen.getByRole('searchbox'), {target: {value: 'registry'}});
    expect(container.querySelector('input[name="display_name"]')).toHaveValue('Unsaved name');
    expect(screen.getByRole('button', {name: 'Save registry'}).closest('form')?.querySelector('input[name="csrf_token"]')).toHaveValue('csrf');
    fireEvent.change(screen.getByRole('searchbox'), {target: {value: 'no-such-setting'}});
    expect(screen.getByText('No matching settings found.')).toBeInTheDocument();
    const signingForm = container.querySelector('form[action="/admin/configuration/signing"]');
    expect(signingForm).toHaveAttribute('enctype', 'multipart/form-data');
    expect(signingForm?.querySelector('input[name="private_key"]')).toHaveAttribute('type', 'file');
    expect(container.querySelector('form[action="/admin/configuration/repositories"] input[name="verify_tls"][type="hidden"]')).toHaveValue('false');
  });
});
