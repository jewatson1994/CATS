import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {Page} from './dashboard';
afterEach(cleanup);
beforeEach(() => window.localStorage.clear());

const row = (key: string, name: string, critical: number, extra: Record<string, unknown> = {}) => ({
  service: { service_key: key, name }, status: 'GREEN', warning_reasons: [], critical, high: 0, medium: 0, low: 0, kev: 0, watchlist: 0,
  patchable: 0, poam: 0, poam_overdue: 0, missing: false, sbom: true, kind: 'VERIFIED', last_scan: null, last_scan_display: '—', ...extra,
});

describe('Services security matrix', () => {
  it('shows pending posture without empty-service or zero-compliance claims, then displays refreshed results', () => {
    const initial = {rows: [], total_count: 0, compliant_count: 0, noncompliant_count: 0, poam_active_count: 0, posture_preparing: 7};
    const {rerender} = render(<Page data={initial}/>);
    const summary = screen.getByRole('region', {name: 'Service summary'});
    expect(within(summary).getAllByText('Pending')).toHaveLength(4);
    expect(within(summary).queryByText('0')).not.toBeInTheDocument();
    expect(screen.getByText('Service posture is being prepared.')).toBeInTheDocument();
    expect(screen.queryByText('No active services.')).not.toBeInTheDocument();
    expect(screen.queryByRole('navigation', {name: 'Service pages'})).not.toBeInTheDocument();
    rerender(<Page data={{...initial, posture_preparing: 0, rows: [row('a', 'Alpha', 0)], total_count: 1, compliant_count: 1}}/>);
    expect(screen.queryByText('Pending')).not.toBeInTheDocument();
    expect(screen.getByRole('link', {name: 'Alpha'})).toBeInTheDocument();
    expect(screen.getByRole('navigation', {name: 'Service pages'})).toHaveTextContent('1–1 of 1 services');
  });

  it('retains real totals while some posture is still being prepared', () => {
    render(<Page data={{rows: [row('a', 'Alpha', 0)], total_count: 1, compliant_count: 1, noncompliant_count: 0, posture_preparing: 7}}/>);
    expect(screen.queryByText('Pending')).not.toBeInTheDocument();
    expect(screen.getByRole('link', {name: 'Alpha'})).toBeInTheDocument();
  });

  it('preserves submitted filters and server portfolio totals independent of filtered rows', () => {
    render(<Page data={{ q: 'payments', cve: 'CVE-2026-12345', component: 'openssl', since: '2026-09-01', status: 'RED', severity: 'High', attention: 'kev', rows: [], total_count: 20,
      pagination_base: '/?lifecycle=active&q=payments&status=RED&attention=kev&severity=High&component=openssl&cve=CVE-2026-12345&since=2026-09-01&page_size=50' }} />);
    expect(screen.getByLabelText('CVE')).toHaveValue('CVE-2026-12345');
    expect(screen.getByLabelText('CVE')).toHaveAttribute('name', 'cve');
    expect(screen.getByLabelText('Search')).toHaveValue('payments');
    expect(screen.getByLabelText('Component / image')).toHaveValue('openssl');
    expect(screen.getByLabelText('Scanned since')).toHaveValue('2026-09-01');
    expect(screen.getByLabelText('Status')).toHaveValue('RED');
    expect(screen.getByLabelText('Severity')).toHaveValue('High');
    expect(screen.getByLabelText('Attention')).toHaveValue('kev');
    // One GET form to "/" carries every field, including the toolbar search.
    fireEvent.click(screen.getByRole('button', { name: /Filters/ }));
    expect(screen.getByRole('dialog', { name: 'Filter services' })).toBeInTheDocument();
    const form = screen.getByRole('button', { name: 'Apply filters' }).closest('form')!;
    expect(form).toHaveAttribute('action', '/');
    expect(form).toHaveAttribute('method', 'get');
    expect(screen.getByLabelText('Search')).toHaveAttribute('form', form.id);
    expect(within(form).getByDisplayValue('active')).toHaveAttribute('name', 'lifecycle');
    expect(screen.getByText('20')).toBeInTheDocument();
    const empty = screen.getByText('No services match these filters.');
    expect(empty.closest('td')).toHaveAttribute('colspan', '15');
  });

  it('shows active filters as removable chips and counts drawer filters on the Filters button', () => {
    render(<Page data={{ q: 'payments', cve: 'CVE-2026-1', status: 'all', severity: 'High', attention: 'all', rows: [], total_count: 0,
      pagination_base: '/?lifecycle=active&q=payments&status=all&attention=all&severity=High&cve=CVE-2026-1&page_size=50' }} />);
    const chips = screen.getByRole('list', { name: 'Active filters' });
    expect(within(chips).getAllByRole('listitem').map(item => item.textContent)).toEqual(['Search: payments', 'CVE: CVE-2026-1', 'Severity: High']);
    const removeSeverity = within(chips).getByRole('link', { name: 'Remove filter Severity: High' });
    const target = new URL(removeSeverity.getAttribute('href')!, 'http://cats.invalid');
    expect(target.pathname).toBe('/');
    expect(target.searchParams.get('severity')).toBeNull();
    expect(target.searchParams.get('q')).toBe('payments');
    expect(target.searchParams.get('cve')).toBe('CVE-2026-1');
    expect(target.searchParams.get('page_size')).toBe('50');
    expect(screen.getByRole('link', { name: 'Clear all' })).toHaveAttribute('href', '/?lifecycle=active');
    // Search has its own visible field; the badge counts the two drawer filters.
    expect(screen.getByRole('button', { name: /Filters/ })).toHaveTextContent('2');
    fireEvent.click(screen.getByRole('button', { name: /Filters/ }));
    expect(screen.getByRole('link', { name: 'Reset' })).toHaveAttribute('href', '/?lifecycle=active');
  });

  it('retains governance links, posture colors and backend-formatted scan dates', () => {
    render(<Page data={{ metrics: {}, rows: [{ service: { service_key: 'api', name: 'Payments' }, status: 'YELLOW', warning_reasons: ['4 dependency watchlist matches'], critical: 1, high: 2, kev: 3, watchlist: 4, patchable: 5, poam: 6, poam_overdue: 7, missing: true, sbom: false, kind: 'FAILED', last_scan_display: '28 Sep 2026' }] }} />);
    const row = screen.getByRole('link', { name: 'Payments' }).closest('tr')!;
    expect(within(row).getByText('Compliant').closest('.badge')).toHaveClass('badge-success');
    expect(within(row).getByText('Compliant').closest('.badge')).toHaveAttribute('data-value', 'YELLOW');
    expect(within(row).getByRole('img', { name: 'Warnings present' })).toBeInTheDocument();
    expect(within(row).getByRole('link', { name: /Warnings for Payments/ })).toHaveAttribute('title', '4 dependency watchlist matches');
    expect(within(row).queryByText('Warnings')).not.toBeInTheDocument();
    expect(within(row).getByRole('link', { name: '4' })).toHaveAttribute('href', '/services/api?finding_state=warnings');
    expect(within(row).getByRole('link', { name: '6' })).toHaveAttribute('href', '/poam/services/api');
    const kind = within(row).getByRole('link', { name: 'Failed' });
    expect(kind).toHaveAttribute('href', '/services/api?validation=true');
    expect(within(kind).getByText('Failed').closest('.badge')).toHaveAttribute('data-value', 'FAILED');
    expect(within(row).getByText('28 Sep 2026')).toBeInTheDocument();
    expect(within(row).getByText('Yes')).toBeInTheDocument();
    expect(within(row).getByText('No')).toBeInTheDocument();
  });

  it('sorts the whole dataset only when every matching service is on the page', () => {
    const rows = [row('a', 'Alpha', 1), row('b', 'Bravo', 5), row('c', 'Charlie', 3)];
    const {unmount} = render(<Page data={{ rows, total_count: 3, total_pages: 1, page: 1, page_size: 50 }} />);
    const critical = () => screen.getByRole('columnheader', { name: /Critical/ });
    expect(critical()).toHaveAttribute('aria-sort', 'none');
    fireEvent.click(within(critical()).getByRole('button'));
    expect(critical()).toHaveAttribute('aria-sort', 'descending');
    const names = () => screen.getAllByRole('row').slice(1).map(item => within(item).getAllByRole('cell')[0].textContent);
    expect(names()).toEqual(['Bravo', 'Charlie', 'Alpha']);
    fireEvent.click(within(critical()).getByRole('button'));
    expect(critical()).toHaveAttribute('aria-sort', 'ascending');
    expect(names()).toEqual(['Alpha', 'Charlie', 'Bravo']);
    fireEvent.click(within(critical()).getByRole('button'));
    expect(names()).toEqual(['Alpha', 'Bravo', 'Charlie']);
    unmount();
    // A paginated result is ordered by the server: one page must not be re-sorted as if it were the dataset.
    render(<Page data={{ rows, total_count: 120, total_pages: 3, page: 1, page_size: 50, pagination_base: '/?lifecycle=active&page_size=50' }} />);
    expect(critical()).not.toHaveAttribute('aria-sort');
    expect(within(critical()).queryByRole('button')).not.toBeInTheDocument();
    const pager = screen.getByRole('navigation', { name: 'Service pages' });
    expect(pager).toHaveTextContent('1–50 of 120 services');
    expect(within(pager).getByRole('link', { name: 'Next page' })).toHaveAttribute('href', '/?lifecycle=active&page_size=50&page=2');
    expect(within(pager).getByLabelText('Rows')).toHaveValue('50');
  });

  it('keeps the lifecycle switch, export and security-critical columns available', () => {
    render(<Page data={{ rows: [row('a', 'Alpha', 0)], lifecycle: 'staged', lifecycle_counts: { active: 4, staged: 1, archived: 2 } }} />);
    const lifecycle = screen.getByRole('navigation', { name: 'Service lifecycle' });
    expect(within(lifecycle).getByRole('link', { name: /Staged/ })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Export Excel' })).toHaveAttribute('href', '/exports/services.xlsx');
    fireEvent.click(screen.getByRole('button', { name: /Columns/ }));
    for (const name of ['Service', 'Status', 'Critical', 'High', 'KEV']) expect(screen.getByRole('checkbox', { name: new RegExp(`^${name}`) })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: /^Patchable/ })).toBeEnabled();
  });
});
