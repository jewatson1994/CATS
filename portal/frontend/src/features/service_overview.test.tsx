import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {Page} from './service_overview';
import type {PageData} from '../api';

afterEach(() => {cleanup(); vi.useRealTimers(); vi.unstubAllGlobals();});
const fixture = (extra: Partial<PageData> = {}): PageData => ({
  view: {service: {id: 1, service_key: 'sample', name: 'Sample', groups: []}, version: '1.0'},
  service_pull_access: {service_id: 1, public: false},
  overview_data: {}, deployment_validation: {status: 'QUEUED', static_scan_complete: true},
  architecture_verification: {state: 'VERIFIED', label: 'Verified'},
  can: {'service.export': {'1': true}}, ...extra,
});
it('places the schedule and pull access directly after the owning group in the overview header', () => {
  render(<Page data={fixture({can_schedule_scans: true, scan_schedule: {cadence: 'off'},
    can: {'release.destination.manage': {'*': true}}})}/>);
  const group = screen.getByText(/Owning group:/);
  const schedule = screen.getByRole('region', {name: 'Scan schedule'});
  const access = screen.getByRole('region', {name: 'Service pull access'});
  expect(group.nextElementSibling).toBe(schedule);
  expect(schedule.nextElementSibling).toBe(access);
  expect(group.closest('section')).toContainElement(screen.getByRole('heading', {name: 'Sample'}));
  expect(schedule).toContainElement(screen.getByRole('button', {name: /Scan schedule: Off/}));
  expect(access).toContainElement(screen.getByRole('combobox', {name: 'Service pull access'}));
});

it('updates a legacy overnight schedule to a weekly local time on multiple days', () => {
  render(<Page data={fixture({can_schedule_scans: true, csrf_token: 'token', scan_schedule: {
    cadence: 'daily', weekday: 4, timezone: 'America/New_York', next_run_at: '2026-11-07T02:00:00Z',
  }})}/>);
  fireEvent.click(screen.getByRole('button', {name: /Scan schedule: Daily · 21:00–05:00/}));
  expect(screen.getByText(/Next scheduled start/)).toHaveTextContent(/9:00\s?PM/i);
  fireEvent.change(screen.getByLabelText('Frequency'), {target: {value: 'weekly'}});
  expect(screen.getByRole('checkbox', {name: 'Friday'})).toBeChecked();
  fireEvent.click(screen.getByRole('checkbox', {name: 'Tuesday'}));
  const start = screen.getByLabelText('Start time');
  expect(start).toBeRequired();
  expect(start).toHaveValue('');
  fireEvent.change(start, {target: {value: '16:42'}});
  const form = screen.getByRole('button', {name: 'Save schedule'}).closest('form')!;
  const posted = new FormData(form);
  expect(form).toHaveAttribute('action', '/services/sample/scan-schedule');
  expect(posted.getAll('weekdays')).toEqual(['1', '4']);
  expect(Object.fromEntries(posted)).toMatchObject({timezone: 'America/New_York', time_of_day: '16:42', csrf_token: 'token'});
});
it('renders separate static and runtime statuses, scoped exports and stale evidence notice', () => {
  render(<Page data={fixture({evidence_notice: 'stale'})}/>);
  expect(screen.getByText('In progress')).toBeInTheDocument();
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
  expect(screen.getAllByText('Not attempted').length).toBeGreaterThan(0);
});
it('labels modern validation and distinguishes missing runtime counts from measured zero', () => {
  render(<Page data={fixture({deployment_validation: {status: 'COULD_NOT_VALIDATE', diagnostics: {schrodinger: {schema_version: 'cats.validation/v2'}}, resource_summary: {pods: {ready: 0, expected: 1}}}})}/>);
  expect(screen.getByText('CATSchrödinger’s')).toBeInTheDocument();
  expect(screen.getByText('0 / 1')).toBeInTheDocument();
  // Unmeasured Deployments/StatefulSets and both unreported conditions are labelled, never shown as zero.
  expect(screen.getAllByText('Not reported')).toHaveLength(4);
});
it('shows immutable artifact matches with independent producer evidence and no whole release claim', () => {
  const digest = 'sha256:' + 'a'.repeat(64);
  render(<Page data={fixture({artifact_provenance: [{artifact_kind: 'image', digest,
    identity_type: 'oci_manifest', source_version: '1.5', revision_number: 1,
    post_remediation_scan: 'PASS', runtime_verification: 'not_verified', signature: 'failed'}]})}/>);
  const section = screen.getByRole('region', {name: 'Known Artifacts'});
  expect(section).toHaveTextContent('Service 1.5 / Remediation R1');
  expect(section).toHaveTextContent(digest);
  expect(section).toHaveTextContent('Pass');
  expect(section).toHaveTextContent('Not verified');
  expect(section).toHaveTextContent('Failed');
  expect(section).toHaveTextContent('do not establish verification or lineage for the complete release');
});
it('shows per-image patch actions independently from removal permissions and keeps history beside the image', () => {
  render(<Page data={fixture({can_patch_images: true, service_images: [{id: 8, image_reference: 'registry/app:v2', image_digest: `sha256:${'b'.repeat(64)}`, lifecycle_status: 'active', patch_history: [{original_image: 'registry/app:v1', result_image: 'registry/app:v2', patched_at: '2026-10-25T12:00:00Z', job_id: 'patch-1'}]}]})}/>);
  expect(screen.getByRole('link', {name: 'Patch registry/app:v2'})).toHaveAttribute('href', '/patch-campaigns?service_id=sample&image_id=8');
  expect(screen.getByLabelText('Patch history for registry/app:v2')).toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Request Removal'})).not.toBeInTheDocument();
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

it('shows persisted Compose services and declared configuration safely', () => {
  render(<Page data={fixture({overview_data: {compose: {complete: true, images: ['nginx:stable'], services: [{name: 'web', image: 'nginx:stable', status: 'image_declared', source_files: ['compose.yaml'], configuration: {command: '<script>hello</script>', environment: {TOKEN: '[REDACTED]'}}}], issues: []}}})}/>);
  const inventory = screen.getByRole('region', {name: 'Compose inventory'});
  expect(inventory).toHaveTextContent('web');
  expect(inventory).toHaveTextContent('compose.yaml');
  expect(inventory).toHaveTextContent('[REDACTED]');
  expect(inventory).toHaveTextContent('<script>hello</script>');
  expect(inventory.querySelector('script')).toBeNull();
});

it('shows Risk Profile as a card without VEX evidence on Overview', () => {
  render(<Page data={fixture()}/>);
  expect(screen.getByRole('heading', {name: 'Risk Profile'}).closest('article')).toHaveClass('overview-dashboard-card');
  expect(screen.getByRole('button', {name: 'View assessment'})).toHaveAttribute('aria-expanded', 'false');
  expect(screen.queryByText('Automatic VEX disposition and evidence')).not.toBeInTheDocument();
});

it('cancels an edited schedule without changing its saved summary or posting', () => {
  render(<Page data={fixture({can_schedule_scans: true, scan_schedule: {cadence: 'off', timezone: 'UTC'}})}/>);
  expect(screen.queryByLabelText('Frequency')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Scan schedule: Off'}));
  fireEvent.change(screen.getByLabelText('Frequency'), {target: {value: 'weekly'}});
  fireEvent.click(screen.getByRole('button', {name: 'Cancel'}));
  expect(screen.queryByLabelText('Frequency')).not.toBeInTheDocument();
  expect(screen.getByRole('button', {name: 'Scan schedule: Off'})).toHaveFocus();
  fireEvent.click(screen.getByRole('button', {name: 'Scan schedule: Off'}));
  expect(screen.getByLabelText('Frequency')).toHaveValue('off');
});

it('keeps disable-only scan permission without exposing the schedule editor', () => {
  render(<Page data={fixture({csrf_token: 'disable-token', can_disable_scan_schedule: true,
    scan_schedule: {cadence: 'daily', timezone: 'UTC'}})}/>);
  fireEvent.click(screen.getByRole('button', {name: /Scan schedule: Daily/}));
  expect(screen.queryByLabelText('Frequency')).not.toBeInTheDocument();
  const form = screen.getByRole('button', {name: 'Turn off scheduled scans'}).closest('form')!;
  expect(form).toHaveAttribute('action', '/services/sample/scan-schedule');
  expect(Object.fromEntries(new FormData(form))).toEqual({csrf_token: 'disable-token', cadence: 'off'});
});
