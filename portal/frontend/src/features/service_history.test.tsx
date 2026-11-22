import {afterEach, expect, it} from 'vitest';
import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {Page} from './service_history';
import type {PageData} from '../api';

afterEach(cleanup);
const snapshot = {scan_id: 'scan-7', key: 'run-v1', at: 'Nov 4, 2026', scope: 'service', complete: true,
  summary: {severity: {Critical: 0, High: 1, Medium: 0, Low: 0, Unknown: 0}, posture: 'warning',
    sbom_covered_images: 1, total_images: 2, kev: 0, watchlist: null, open_poams: null, overdue_poams: null,
    validation_failures: 0, artifacts: 1, sbom_components: 28, vulnerability_findings: 1, policy_findings: 0},
  source_files: ['Chart.yaml'], data: {service: {name: 'Captured service'}, service_overview: {
    artifacts: [{type: 'Image', artifact: 'worker', version: '1.0'}]},
    findings: [{cve: 'CVE-OLD', severity: 'High'}], policy_findings: [],
    sbom_components: Array.from({length: 28}, (_, i) => ({name: 'pkg-' + i, version: '0.8'}))}};
const page = (tab: string, extra: Partial<PageData> = {}): PageData => ({
  service: {service_key: 'payments', name: 'Renamed service'}, version: '1 beta', versions: ['2', '1 beta'],
  snapshots: [snapshot], imported_snapshots: [], selected_scan: 'scan-7', history_tab: tab,
  scan_options: [{...snapshot, source: 'native'}, {scan_id: 'import-2-0', key: 'old-import', source: 'imported'}],
  page: 2, total_pages: 2, imported_page: 1, page_size: 10, ...extra,
});

it('shows exactly the historical views and keeps the version and selected scan in every tab', () => {
  render(<Page data={page('overview')}/>);
  expect(screen.getByRole('heading', {name: 'Captured service'})).toBeInTheDocument();
  const nav = screen.getByRole('navigation', {name: 'Historical service views'});
  const links = within(nav).getAllByRole('link') as HTMLAnchorElement[];
  expect(links.map(link => link.textContent)).toEqual(['Overview', 'Dependencies', 'Findings', 'Releases']);
  for (const link of links) {
    const url = new URL(link.href);
    expect(url.pathname).toBe('/services/payments/history');
    expect(url.searchParams.get('version')).toBe('1 beta');
    expect(url.searchParams.get('scan')).toBe('scan-7');
    expect(url.searchParams.get('page')).toBe('2');
  }
  expect(screen.getByText('worker')).toBeInTheDocument();
  expect(screen.queryByText('Renamed service')).not.toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Current service workspace'})).toHaveAttribute('href', '/services/payments?overview=true');
  expect(screen.getByLabelText('Retained scan')).toHaveValue('scan-7');
  expect(screen.queryByRole('button', {name: /edit|approve|submit|configure/i})).not.toBeInTheDocument();
});

it('shows and searches retained dependencies without rendering other evidence', () => {
  render(<Page data={page('dependencies')}/>);
  expect(screen.queryByText('CVE-OLD')).not.toBeInTheDocument();
  expect(screen.queryByText('pkg-27')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Search sbom components'), {target: {value: 'pkg-27'}});
  expect(screen.getByText('pkg-27')).toBeInTheDocument();
  expect(screen.queryByText('pkg-1')).not.toBeInTheDocument();
});

it('shows severity and posture for the selected scan first and distinguishes zero from unrecorded evidence', () => {
  const imported = {...snapshot, scan_id: 'import-2-0', summary: {...snapshot.summary,
    severity: {Critical: 3, High: 0, Medium: 0, Low: 0, Unknown: 2}, posture: null, artifacts: null}};
  render(<Page data={page('overview', {imported_snapshots: [imported], selected_scan: imported.scan_id})}/>);
  const severity = screen.getByRole('region', {name: 'Findings by severity'});
  const posture = screen.getByRole('region', {name: 'Service posture'});
  const metrics = screen.getByRole('region', {name: 'Captured inventory'});
  expect(severity.compareDocumentPosition(metrics) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(posture.compareDocumentPosition(metrics) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(within(severity).getByText('Critical').parentElement).toHaveTextContent('Critical3');
  expect(within(severity).getByText('High').parentElement).toHaveTextContent('High0');
  expect(within(severity).getByText('Unknown').parentElement).toHaveTextContent('Unknown2');
  expect(within(posture).getByRole('img')).toHaveAccessibleName('Service posture: Not recorded');
  expect(within(posture).getByText('SBOM coverage (images)').nextElementSibling).toHaveTextContent('1 / 2');
  expect(within(posture).getByText('KEV / watchlist').nextElementSibling).toHaveTextContent('0 / Not recorded');
  expect(within(posture).getByText('Validation failures').nextElementSibling).toHaveTextContent(/^0$/);
  expect(within(metrics).getByRole('link', {name: 'Artifacts Not recorded'})).toBeInTheDocument();
  expect(within(metrics).getByRole('link', {name: 'Policy findings 0'})).toBeInTheDocument();
});

it('deep-links all four metrics to their evidence tables for the selected imported scan', () => {
  const imported = {...snapshot, scan_id: 'import-2-0'};
  const data = page('overview', {imported_snapshots: [imported], selected_scan: imported.scan_id});
  const {rerender} = render(<Page data={data}/>);
  const metrics = screen.getByRole('region', {name: 'Captured inventory'});
  const targets = within(metrics).getAllByRole('link').map(link => new URL((link as HTMLAnchorElement).href));
  expect(targets.map(url => [url.searchParams.get('tab'), url.hash])).toEqual([
    ['overview', '#artifact-inventory'], ['dependencies', '#sbom-components'],
    ['findings', '#vulnerability-findings'], ['findings', '#policy-findings'],
  ]);
  for (const target of targets) {
    expect(target.pathname).toBe('/services/payments/history');
    expect(Object.fromEntries(target.searchParams)).toMatchObject({version: '1 beta', scan: imported.scan_id,
      page: '2', imported_page: '1', page_size: '10'});
    rerender(<Page data={{...data, history_tab: target.searchParams.get('tab')}}/>);
    expect(document.getElementById(target.hash.slice(1))?.tagName).toBe('H3');
  }
});

it('focuses a directly opened historical evidence fragment after its table mounts', () => {
  const previousURL = window.location.href;
  window.history.replaceState(null, '', '#policy-findings');
  try {
    render(<Page data={page('findings')}/>);
    expect(screen.getByRole('heading', {name: 'Policy findings'})).toHaveFocus();
  } finally {window.history.replaceState(null, '', previousURL);}
});

it('keeps findings and version-bound releases read only', () => {
  const {rerender} = render(<Page data={page('findings', {snapshots: [], imported_snapshots: [snapshot]})}/>);
  expect(screen.getByText('CVE-OLD')).toBeInTheDocument();
  expect(screen.getByText('Imported evidence')).toBeInTheDocument();
  rerender(<Page data={page('releases', {snapshots: [], releases: [
    {release_key: 'approved-v1', source: 'Local', scan: 'run-v1', digest: 'sha256:old'}]})}/>);
  expect(screen.getByText('approved-v1')).toBeInTheDocument();
  expect(screen.queryByText('CVE-OLD')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: /revoke|approve|request|publish/i})).not.toBeInTheDocument();
});
