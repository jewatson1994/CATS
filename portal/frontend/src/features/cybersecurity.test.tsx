import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
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
    expect(screen.getByText('No services match these filters.')).toHaveAttribute('colspan', '14');
  });
  it('compares saved versions, flags partial scans and switches services', () => {
    const scan = (id: number, version: string, high: number, complete = true) => ({ execution_id: id, version, scanned_at: '2026-10-01T12:00:00Z', counts: { High: high }, total: high, complete });
    render(<Page data={{ rows: [], metrics: { services: 2, green: 1, red: 1 }, history: [
      { service_key: 'api', name: 'API', versions: [scan(2, '2.0', 3, false), scan(1, '1.0', 7)], trend: [scan(1, '1.0', 7), scan(2, '2.0', 3, false)] },
      { service_key: 'db', name: 'Database', versions: [scan(3, '3.0', 0)], trend: [scan(3, '3.0', 0)] },
    ] }} />);
    expect(screen.getAllByText('-4')).toHaveLength(2);
    expect(screen.getByRole('note')).toHaveTextContent('does not establish');
    expect(screen.getByRole('img')).toHaveAccessibleName('Service posture: 1 compliant, 0 warnings, 1 non-compliant');
    fireEvent.change(screen.getByLabelText('Compare service'), { target: { value: 'db' } });
    expect(screen.getByText('Two distinct versioned service scans are needed for a version comparison.')).toBeInTheDocument();
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
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
