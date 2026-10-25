import {render, screen, within} from '@testing-library/react';
import {expect, it} from 'vitest';
import {AdminTabs} from './admin_shared';
import {PolicyPage} from './policies';

it('groups administration destinations and keeps every permission check', () => {
  const all = {can: {'user.manage': {'*': true}, 'config.manage': {'*': true}, 'release.destination.manage': {'*': true}}, selected_group_id: 4};
  const {unmount} = render(<AdminTabs data={all} selected="vulnerability"/>);
  const nav = screen.getByRole('navigation', {name: 'Administration sections'});
  expect(within(nav).getAllByRole('group').map(group => group.getAttribute('aria-label'))).toEqual(['Access', 'Platform', 'Policy', 'Delivery']);
  expect(within(nav).getByRole('link', {name: 'Vulnerability Policy'})).toHaveAttribute('aria-current', 'page');
  expect(within(nav).getByRole('link', {name: 'Vulnerability Policy'})).toHaveAttribute('href', '/admin/compliance?group_id=4');
  expect(within(nav).getByRole('link', {name: 'Release Destinations'})).toHaveAttribute('href', '/admin/approved-release-destinations');
  unmount();
  // Only audit permission: General Policy alone, no empty sections.
  render(<AdminTabs data={{can: {'audit.view': {'*': true}}}} selected="general"/>);
  const limited = screen.getByRole('navigation', {name: 'Administration sections'});
  expect(within(limited).getAllByRole('link').map(link => link.textContent)).toEqual(['General Policy']);
  expect(within(limited).getAllByRole('group').map(group => group.getAttribute('aria-label'))).toEqual(['Policy']);
});

it('policy pages use the same grouped navigation with their own permission flags', () => {
  render(<PolicyPage kind="watchlist" data={{configuration: {}, groups: [], may_manage: true, may_audit: true, may_manage_users: false, export_templates: [], events: [], shown_count: 0, retained_count: 0, raw_due_rules: [], epss_rules: [], entries: []}}/>);
  const nav = screen.getByRole('navigation', {name: 'Administration sections'});
  expect(within(nav).queryByRole('link', {name: 'Accounts & roles'})).not.toBeInTheDocument();
  expect(within(nav).getByRole('link', {name: 'Dependency Watchlist'})).toHaveAttribute('aria-current', 'page');
  expect(within(nav).getByRole('link', {name: 'Hardening Policy'})).toHaveAttribute('href', '/admin/compliance-frameworks');
});
