import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Page } from './cybersecurity';
afterEach(() => {cleanup(); vi.unstubAllGlobals();});
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
const json = (value: unknown) => new Response(JSON.stringify(value), {headers:{'content-type':'application/json'}});
it('loads portfolio before independent selected history and retains metrics when history fails', async () => {
  let finishPortfolio: (response: Response) => void = () => {};
  let finishHistory: (response: Response) => void = () => {};
  const fetch = vi.fn().mockImplementationOnce(() => new Promise<Response>(resolve => {finishPortfolio = resolve;}))
    .mockImplementationOnce(() => new Promise<Response>(resolve => {finishHistory = resolve;}))
    .mockRejectedValueOnce(new Error('History unavailable'));
  vi.stubGlobal('fetch', fetch);
  render(<Page data={{dashboard_url:'/api/dashboard/cybersecurity?q=api'}}/>);
  expect(screen.getByRole('status')).toHaveTextContent('Loading dashboard data');
  expect(fetch).toHaveBeenCalledTimes(1);
  await act(async () => {finishPortfolio(json({metrics:{services:20, scanned:17}, rows:[], services:[{service_key:'api', name:'API'}, {service_key:'db', name:'Database'}]}));});
  expect(screen.getByText('20 / 17')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Loading service history');
  expect(fetch.mock.calls[1][0]).toContain('/api/dashboard/cybersecurity/services/api/history');
  fireEvent.change(screen.getByLabelText('Compare service'), {target:{value:'db'}});
  await screen.findByText('History unavailable');
  expect(fetch.mock.calls[2][0]).toContain('/api/dashboard/cybersecurity/services/db/history');
  expect(fetch.mock.calls[1][1].signal.aborted).toBe(true);
  await act(async () => {finishHistory(json({service_key:'api', name:'API', trend:[], versions:[]}));});
  expect(screen.getByLabelText('Compare service')).toHaveValue('db');
  expect(screen.getByText('History unavailable')).toBeInTheDocument();
  expect(screen.getByText('20 / 17')).toBeInTheDocument();
});
it('renders an independent portfolio error with its page heading and retry', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Portfolio unavailable')));
  render(<Page data={{dashboard_url:'/api/dashboard/cybersecurity'}}/>);
  await screen.findByText('Portfolio unavailable');
  expect(screen.getByRole('heading', {name:'Cybersecurity'})).toBeInTheDocument();
  expect(screen.getByRole('button', {name:'Retry dashboard'})).toBeInTheDocument();
});
it('populates a selected history response independently and does not request history for an empty portfolio', async () => {
  const fetch = vi.fn().mockResolvedValueOnce(json({metrics:{services:1}, rows:[], services:[{service_key:'api',name:'API'}]}))
    .mockResolvedValueOnce(json({service_key:'api',name:'API',versions:[],trend:[{execution_id:1,version:'1.0',scanned_at:'2026-10-01T12:00:00Z',complete:true,counts:{High:3},total:3}]}));
  vi.stubGlobal('fetch',fetch);
  const {unmount} = render(<Page data={{dashboard_url:'/api/dashboard/cybersecurity'}}/>);
  expect(await screen.findByRole('list', {name:'Recent service scans'})).toHaveTextContent('1.0');
  unmount();
  fetch.mockResolvedValueOnce(json({metrics:{services:0},rows:[],services:[]}));
  render(<Page data={{dashboard_url:'/api/dashboard/cybersecurity'}}/>);
  await screen.findByText('No service scan history is available yet.');
  expect(fetch).toHaveBeenCalledTimes(3);
});
