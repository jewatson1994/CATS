import {render, screen, cleanup} from '@testing-library/react';
import {afterEach, expect, it} from 'vitest';
import {Service} from './poam';

afterEach(cleanup);
it('preserves filters and size on page links and resets page when filters change', () => {
  const base = '/services/key?poam=true&status_filter=active&sort_by=due&page_size=25';
  render(<Service data={{service: {id: 7, service_key: 'key', name: 'Service', groups: []},
    embedded: true, view: {}, entries: [], overdue_entry_ids: [], status_filter: 'active',
    sort_by: 'due', page: 2, page_size: 25, page_count: 4, total_items: 80,
    pagination_base: base}}/>);
  expect(screen.getByRole('link', {name: 'Previous'})).toHaveAttribute('href', `${base}&page=1`);
  expect(screen.getByRole('link', {name: 'Next'})).toHaveAttribute('href', `${base}&page=3`);
  expect(screen.getByText('Page 2 of 4 · 80 entries')).toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Overdue'})).toHaveAttribute('href',
    '/services/key?poam=true&status_filter=overdue&sort_by=due&page_size=25');
});

it('links exception rows to their source and preserves lifecycle states', () => {
  render(<Service data={{service: {id: 7, service_key: 'key', name: 'Service', groups: []}, view: {},
    entries: [{id: 'exception:vulnerability:19', item_type: 'exception', title: 'Accepted library risk',
      description: 'An expired exception', remediation: 'Replace library', status: 'expired', detail_url: '/findings/19'}],
    overdue_entry_ids: [], status_filter: 'all', sort_by: 'newest', page_count: 1}}/>);
  expect(screen.getByRole('link', {name: 'Accepted library risk'})).toHaveAttribute('href', '/findings/19');
  expect(screen.getByText('expired')).toBeInTheDocument();
  expect(screen.queryByText('Cybersecurity review required')).not.toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Expired'})).toHaveAttribute('href', '/poam/services/key?status_filter=expired&sort_by=newest&page_size=50');
});
