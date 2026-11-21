import {afterEach, expect, it} from 'vitest';
import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {Page} from './service_history';
import type {PageData} from '../api';

afterEach(cleanup);
const snapshot = {scan_id: 'scan-7', key: 'run-v1', at: 'Nov 4, 2026', scope: 'service', complete: true,
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
