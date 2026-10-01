import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, render, screen} from '@testing-library/react';
import {Page} from './service_overview';
import type {PageData} from '../api';

afterEach(() => {cleanup(); vi.useRealTimers(); vi.unstubAllGlobals();});
const fixture = (extra: Partial<PageData> = {}): PageData => ({
  view: {service: {id: 1, service_key: 'sample', name: 'Sample', groups: []}, version: '1.0'},
  overview_data: {}, deployment_validation: {status: 'QUEUED', static_scan_complete: true},
  architecture_verification: {state: 'VERIFIED', label: 'Verified'},
  can: {'service.export': {'1': true}}, ...extra,
});
it('renders separate static and runtime statuses, scoped exports and stale evidence notice', () => {
  render(<Page data={fixture({evidence_notice: 'stale'})}/>);
  expect(screen.getByText('IN PROGRESS')).toBeInTheDocument();
  expect(screen.getByText('Complete')).toBeInTheDocument();
  expect(screen.getByText('Verified')).toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent('evidence changed');
  expect(screen.getByRole('link', {name: 'POA&M'})).toHaveAttribute('href', '/services/sample/exports/poam.xlsx');
  expect(screen.getByRole('link', {name: 'PPSM'})).toHaveAttribute('href', '/services/sample/exports/ppsm.xlsx');
  expect(screen.getByRole('link', {name: 'Asset List'})).toHaveAttribute('href', '/services/sample/exports/asset_list.xlsx');
});
it('keeps unattempted deployment validation independent of completed static scanning', () => {
  render(<Page data={fixture({deployment_validation: {status: 'NOT_ATTEMPTED', static_scan_complete: true}})}/>);
  expect(screen.getByText('Complete')).toBeInTheDocument();
  expect(screen.getAllByText('NOT ATTEMPTED').length).toBeGreaterThan(0);
});
it('scopes evidence polling to the selected release and aborts when leaving', async () => {
  vi.useFakeTimers();
  const fetch = vi.fn().mockImplementation(() => new Promise(() => {}));
  vi.stubGlobal('fetch', fetch);
  const {unmount} = render(<Page data={fixture({view_version: '2.0 beta'})}/>);
  await vi.advanceTimersByTimeAsync(5000);
  expect(fetch.mock.calls[0][0]).toBe(`${window.location.origin}/api/v1/services/sample/architecture-evidence?view_version=2.0%20beta`);
  unmount();
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
});
