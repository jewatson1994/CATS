import {afterEach, expect, it, vi} from 'vitest';
import {fireEvent, render, screen, waitFor} from '@testing-library/react';
import {NotificationBell} from './NotificationBell';

const announcement = {id: 9, title: 'Scheduled outage', message: 'Offline at 14:00 UTC.', expires_at: null, unread: true};
afterEach(() => vi.unstubAllGlobals());

it('keeps requests and announcements distinct and marks only the notice as read', async () => {
  const fetch = vi.fn(async (_url: string, init: RequestInit) =>
    new Response(JSON.stringify(init.method === 'POST' ? {...announcement, unread: false} : announcement),
      {headers: {'Content-Type': 'application/json'}}));
  vi.stubGlobal('fetch', fetch);
  render(<NotificationBell data={{announcement, csrf_token: 'nonce', pending_request_count: 2,
    actionable_notifications: [{label: 'Access requested', service: 'Example', href: '/admin#access-requests'}]}}/>);
  const summary = screen.getByLabelText('Notifications (2 pending, 1 unread announcement)');
  expect(summary).toHaveTextContent('3');
  fireEvent.click(summary);
  expect(screen.getByRole('region', {name: 'Portal announcement'})).toHaveTextContent('Offline at 14:00 UTC.');
  fireEvent.click(screen.getByRole('button', {name: 'Mark as read'}));
  await waitFor(() => expect(screen.getByLabelText('Notifications (2 pending)')).toHaveTextContent('2'));
  expect(screen.getByText('Scheduled outage')).toBeInTheDocument();
  expect(screen.getByRole('link', {name: /Access requested/})).toHaveAttribute('href', '/admin#access-requests');
  expect(fetch.mock.calls.some(([url, init]) => url.endsWith('/account/announcements/9/read')
    && init.method === 'POST' && String(init.body) === 'csrf_token=nonce')).toBe(true);
});

it('retrieves a newly published announcement when the bell opens', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(announcement),
    {headers: {'Content-Type': 'application/json'}})));
  render(<NotificationBell data={{}}/>);
  fireEvent.click(screen.getByLabelText('Notifications'));
  expect(await screen.findByText('Scheduled outage')).toBeInTheDocument();
  expect(screen.getByLabelText('Notifications (1 unread announcement)')).toHaveTextContent('1');
  expect(screen.queryByRole('link', {name: /requests/i})).not.toBeInTheDocument();
});
