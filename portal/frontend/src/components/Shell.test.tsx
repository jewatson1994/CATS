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

it('shows a compact brand with the full product name and version available without wrapping the header', () => {
  render(<Shell data={{...data, cats_deployed_version: '2.4.1'}}>Content</Shell>);
  const brand = screen.getByRole('link', {name: /^CATS.*Continuous Assessment & Tracking System/});
  expect(brand).toHaveAttribute('title', 'CATS — Continuous Assessment & Tracking System · 2.4.1');
  expect(within(brand).getByText('2.4.1')).toHaveClass('cats-version');
  expect(screen.getByRole('link', {name: 'Skip to main content'})).toHaveAttribute('href', '#main-content');
  expect(screen.getByRole('main')).toHaveAttribute('id', 'main-content');
  fireEvent.click(screen.getByText('Tester', {selector: '.user-name'}));
  fireEvent.click(screen.getByRole('button', {name: 'About CATS'}));
  const about = screen.getByRole('dialog', {name: 'CATS'});
  expect(about).toHaveTextContent('Continuous Assessment & Tracking System');
  expect(about).toHaveTextContent('2.4.1');
});

it('groups secondary destinations into labelled sections and supports arrow-key movement', () => {
  render(<Shell data={data}>Content</Shell>);
  const more = screen.getByText('More', {selector: 'summary'});
  fireEvent.click(more);
  const menu = more.parentElement!;
  expect(within(menu).getAllByRole('group').map(group => group.getAttribute('aria-label'))).toEqual(['Governance', 'Inventory', 'Operations']);
  const links = within(menu).getAllByRole('link');
  // Each link keeps the destination as its accessible name and carries a short description.
  expect(links.map(link => link.querySelector('.menu-item-label')?.textContent)).toEqual(['Remediate', 'Requests', 'Artifact catalog', 'SBOM', 'Jobs']);
  expect(within(menu).getByRole('link', {name: 'Jobs'})).toHaveAccessibleDescription('Scans, exports and background work');
  links[0].focus();
  fireEvent.keyDown(links[0], {key: 'ArrowDown'});
  expect(links[1]).toHaveFocus();
  fireEvent.keyDown(links[1], {key: 'End'});
  expect(links[4]).toHaveFocus();
  fireEvent.keyDown(links[4], {key: 'ArrowDown'});
  expect(links[0]).toHaveFocus();
  fireEvent.keyDown(links[0], {key: 'ArrowUp'});
  expect(links[4]).toHaveFocus();
  fireEvent.keyDown(links[4], {key: 'Home'});
  expect(links[0]).toHaveFocus();
});

it('keeps only one header menu open at a time', () => {
  render(<Shell data={data}>Content</Shell>);
  const cyber = screen.getByText('Cybersecurity', {selector: 'summary'}).parentElement as HTMLDetailsElement;
  const more = screen.getByText('More', {selector: 'summary'}).parentElement as HTMLDetailsElement;
  cyber.open = true;
  fireEvent(cyber, new Event('toggle'));
  more.open = true;
  fireEvent(more, new Event('toggle'));
  expect(more.open).toBe(true);
  expect(cyber.open).toBe(false);
});

it('shows user initials while keeping the account name accessible', () => {
  render(<Shell data={{current_user: {display_name: 'Ada Lovelace', theme: 'cats'}}}>Content</Shell>);
  const summary = screen.getByTitle('Ada Lovelace');
  expect(within(summary).getByText('AL')).toHaveAttribute('aria-hidden', 'true');
  expect(summary).toHaveTextContent('Ada Lovelace');
});
