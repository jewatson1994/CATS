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
  expect(screen.queryByRole('link', {name: 'Service definitions / chart catalogs'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link', {name: 'Versions & spreadsheet exchange'})).not.toBeInTheDocument();
  expect(screen.getByLabelText('View historical versions for Sample')).toHaveTextContent('1.0');
});
it('keeps unattempted deployment validation independent of completed static scanning', () => {
  render(<Page data={fixture({deployment_validation: {status: 'NOT_ATTEMPTED', static_scan_complete: true}})}/>);
  expect(screen.getByText('Complete')).toBeInTheDocument();
  expect(screen.getAllByText('NOT ATTEMPTED').length).toBeGreaterThan(0);
});
it('labels modern validation and distinguishes missing runtime counts from measured zero', () => {
  render(<Page data={fixture({deployment_validation: {status: 'COULD_NOT_VALIDATE', diagnostics: {schrodinger: {schema_version: 'cats.validation/v2'}}, resource_summary: {pods: {ready: 0, expected: 1}}}})}/>);
  expect(screen.getByText('CATSchrödinger’s')).toBeInTheDocument();
  expect(screen.getByText('0 / 1')).toBeInTheDocument();
  expect(screen.getAllByText('Unavailable / Unavailable')).toHaveLength(2);
});
it('shows immutable artifact matches with independent producer evidence and no whole release claim', () => {
  const digest = 'sha256:' + 'a'.repeat(64);
  render(<Page data={fixture({artifact_provenance: [{artifact_kind: 'image', digest,
    identity_type: 'oci_manifest', source_version: '1.5', revision_number: 1,
    post_remediation_scan: 'PASS', runtime_verification: 'not_verified', signature: 'failed'}]})}/>);
  const section = screen.getByRole('region', {name: 'Known Artifacts'});
  expect(section).toHaveTextContent('Service 1.5 / Remediation R1');
  expect(section).toHaveTextContent(digest);
  expect(section).toHaveTextContent('PASS');
  expect(section).toHaveTextContent('NOT VERIFIED');
  expect(section).toHaveTextContent('FAILED');
  expect(section).toHaveTextContent('do not establish verification or lineage for the complete release');
});
it('scopes evidence polling to the selected release and aborts when leaving', async () => {
  vi.useFakeTimers();
  const fetch = vi.fn().mockImplementation(() => new Promise(() => {}));
  vi.stubGlobal('fetch', fetch);
  const {unmount} = render(<Page data={fixture({view_version: '2.0 beta', architecture_polling: true})}/>);
  await vi.advanceTimersByTimeAsync(5000);
  expect(fetch.mock.calls[0][0]).toBe(`${window.location.origin}/api/v1/services/sample/architecture-evidence?view_version=2.0%20beta&summary=true`);
  unmount();
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
});

const response = (body: any) => ({ok: true, status: 200, headers: new Headers({'content-type': 'application/json'}), json: async () => body});
it('does not poll architecture evidence without an active validation', async () => {
  vi.useFakeTimers();
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  render(<Page data={fixture({architecture_polling: false})}/>);
  await vi.advanceTimersByTimeAsync(30000);
  expect(fetch).not.toHaveBeenCalled();
});
it('polls the summary while validation runs and stops at a terminal state', async () => {
  vi.useFakeTimers();
  const fetch = vi.fn()
    .mockResolvedValueOnce(response({architecture: {state: 'DECLARED', label: 'Declared'}, graph: {summary: {declared: 2}}, active_validation: {run_key: 'r1'}}))
    .mockResolvedValueOnce(response({architecture: {state: 'VERIFIED', label: 'Verified'}, graph: {summary: {declared: 2}}, active_validation: null}));
  vi.stubGlobal('fetch', fetch);
  render(<Page data={fixture({architecture_polling: true})}/>);
  await vi.advanceTimersByTimeAsync(5000);
  await vi.advanceTimersByTimeAsync(5000);
  await vi.advanceTimersByTimeAsync(30000);
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(new URL(fetch.mock.calls[0][0]).searchParams.get('summary')).toBe('true');
});
