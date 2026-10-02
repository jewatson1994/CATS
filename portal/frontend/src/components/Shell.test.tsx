import {cleanup, render, screen, within} from '@testing-library/react';
import {afterEach, describe, expect, it} from 'vitest';
import {Shell} from './Shell';
import {AdminTabs} from '../features/admin_shared';

afterEach(cleanup);
const current_user = {display_name: 'Jane', theme: 'cats'};
describe('unified administration navigation', () => {
  it.each([
    [['user.manage', 'config.manage', 'audit.view'], '/admin', ['Accounts & roles', 'Settings', 'General Policy', 'Hardening Policy', 'Vulnerability Policy', 'Dependency Watchlist']],
    [['config.manage'], '/admin/configuration', ['Settings', 'General Policy', 'Hardening Policy', 'Vulnerability Policy', 'Dependency Watchlist']],
    [['audit.view'], '/admin/general-policy', ['General Policy']],
    [['user.manage'], '/admin', ['Accounts & roles']],
  ])('opens the first allowed section for %j', (permissions, href, sections) => {
    const data = {current_user, can: Object.fromEntries((permissions as string[]).map(permission => [permission, {'*': true}]))};
    render(<Shell data={data}><AdminTabs data={data} selected="accounts"/></Shell>);
    const entry = screen.getByRole('link', {name: 'Administration'});
    expect(entry).toHaveAttribute('href', href);
    expect(entry.querySelector('span')).toHaveTextContent('⚙');
    expect(screen.queryByRole('link', {name: 'Configuration'})).not.toBeInTheDocument();
    expect(within(screen.getByRole('navigation', {name: 'Administration sections'})).getAllByRole('link').map(link => link.textContent)).toEqual(sections);
  });
  it('hides administration when no administrative permissions are granted', () => {
    render(<Shell data={{current_user, can: {'service.view': {'*': true}}}}>Services</Shell>);
    expect(screen.queryByRole('link', {name: 'Administration'})).not.toBeInTheDocument();
  });
  it('does not expose global administration for service-scoped permissions', () => {
    render(<Shell data={{current_user, can: {'config.manage': {'7': true}, 'user.manage': {'7': true}}}}>Services</Shell>);
    expect(screen.queryByRole('link', {name: 'Administration'})).not.toBeInTheDocument();
  });
});
