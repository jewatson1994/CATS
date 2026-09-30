import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { Page } from './cybersecurity';
afterEach(cleanup);
describe('cybersecurity portfolio', () => {
  it('preserves submitted filters and server portfolio totals independent of filtered rows', () => {
    render(<Page data={{ q: 'payments', component: 'openssl', since: '2026-09-01', status: 'RED', severity: 'High', attention: 'kev', rows: [], metrics: { services: 20, scanned: 17 } }} />);
    expect(screen.getByLabelText('Search')).toHaveValue('payments');
    expect(screen.getByLabelText('Component / image')).toHaveValue('openssl');
    expect(screen.getByLabelText('Scanned since')).toHaveValue('2026-09-01');
    expect(screen.getByLabelText('Status')).toHaveValue('RED');
    expect(screen.getByLabelText('Severity')).toHaveValue('High');
    expect(screen.getByLabelText('Attention')).toHaveValue('kev');
    expect(screen.getByRole('button', { name: 'Filter' }).closest('form')).toHaveAttribute('action', '/cybersecurity');
    expect(screen.getByText('20 / 17')).toBeInTheDocument();
    expect(screen.getByText('No services match these filters.')).toHaveAttribute('colspan', '13');
  });
  it('retains governance links, posture colors and backend-formatted scan dates', () => {
    render(<Page data={{ metrics: {}, rows: [{ service: { service_key: 'api', name: 'Payments' }, status: 'YELLOW', critical: 1, high: 2, kev: 3, watchlist: 4, patchable: 5, poam: 6, poam_overdue: 7, missing: true, sbom: false, kind: 'FAILED', last_scan_display: '28 Sep 2026' }] }} />);
    const row = screen.getByRole('link', { name: 'Payments' }).closest('tr')!;
    expect(within(row).getByText('YELLOW')).toHaveClass('excepted');
    expect(within(row).getByRole('link', { name: '4' })).toHaveAttribute('href', '/services/api?finding_state=warnings');
    expect(within(row).getByRole('link', { name: '6' })).toHaveAttribute('href', '/poam/services/api');
    expect(within(row).getByRole('link', { name: 'FAILED' })).toHaveAttribute('href', '/services/api?validation=true');
    expect(within(row).getByText('28 Sep 2026')).toBeInTheDocument();
    expect(within(row).getByText('Yes')).toBeInTheDocument();
    expect(within(row).getByText('No')).toBeInTheDocument();
  });
});
