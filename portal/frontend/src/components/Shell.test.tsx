import {afterEach, expect, it} from 'vitest';
import {fireEvent, render, screen, within} from '@testing-library/react';
import {Shell} from './Shell';

const data = {current_user: {display_name: 'Tester', theme: 'cats'}};
afterEach(() => window.history.replaceState(null, '', '/'));

it('groups existing destinations and marks the active child and group', () => {
  window.history.replaceState(null, '', '/approved-releases');
  render(<Shell data={data}>Content</Shell>);
  const nav = screen.getByRole('navigation', {name: 'Primary navigation'});
  expect(Array.from(nav.children).filter(child => child.tagName === 'A').map(child => child.textContent)).toEqual(['Services', 'Discovery', 'Scan', 'Patch']);
  const summary = screen.getByText('Cybersecurity', {selector: 'summary'});
  expect(summary.parentElement).toHaveAttribute('data-active', 'true');
  fireEvent.click(summary);
  expect(screen.getByRole('link', {name: 'Approved Releases'})).toHaveAttribute('aria-current', 'page');
  expect(screen.getByRole('link', {name: 'Approvals'})).toHaveAttribute('href', '/cyber-approvals');
  fireEvent.click(screen.getByText('More', {selector: 'summary'}));
  for (const name of ['Remediate', 'SBOM', 'Jobs', 'Requests']) expect(within(nav).getByRole('link', {name})).toBeInTheDocument();
  expect(screen.queryByRole('link', {name: 'Administration'})).not.toBeInTheDocument();
});

it('closes disclosures on Escape, outside click and navigation, restoring Escape focus', () => {
  render(<Shell data={data}>Content</Shell>);
  const summary = screen.getByText('More', {selector: 'summary'});
  fireEvent.click(summary);
  const link = screen.getByRole('link', {name: 'Jobs'});
  link.focus();
  fireEvent.keyDown(link, {key: 'Escape'});
  expect(summary.parentElement).not.toHaveAttribute('open');
  expect(summary).toHaveFocus();
  fireEvent.click(summary);
  fireEvent.click(document.body);
  expect(summary.parentElement).not.toHaveAttribute('open');
  fireEvent.click(summary);
  fireEvent.click(screen.getByRole('link', {name: 'Services'}));
  expect(summary.parentElement).not.toHaveAttribute('open');
});

it('preserves administration permissions, notification counts and public navigation', () => {
  const {unmount} = render(<Shell data={{...data, may_manage_accounts: true, pending_request_count: 2}}>Content</Shell>);
  expect(screen.getByRole('link', {name: 'Administration'})).toHaveAttribute('href', '/admin');
  expect(screen.getByLabelText('Notifications (2 pending)')).toBeInTheDocument();
  unmount();
  render(<Shell data={{}}>Content</Shell>);
  expect(screen.getByRole('link', {name: 'Login'})).toHaveAttribute('href', '/login');
  expect(screen.queryByText('More', {selector: 'summary'})).not.toBeInTheDocument();
});
