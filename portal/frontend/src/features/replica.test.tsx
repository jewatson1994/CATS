import {afterEach, expect, it, vi} from 'vitest';
import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {Overrides, Page, Releases} from './replica';
import {Shell} from '../components/Shell';
import {ServiceHeader, ServiceTabs} from '../components/ServiceHeader';
import {OverrideIndicator} from '../components/OverrideIndicator';
import {ReplicaReleaseIndicator} from '../components/ReplicaReleaseIndicator';
import {OperatingMode} from '../operatingMode';
import {requestJson} from '../api';
import {Page as PublicHome} from './home';

vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson: vi.fn()}));
const request = vi.mocked(requestJson);
const data = {cats_mode: 'replica', current_user: {display_name: 'Local operator', theme: 'cats'}, csrf_token: 'token',
  service: {id: 7, service_key: 'mission', name: 'Mission service'}, can: {'local_override.create': {'7': true}}};
afterEach(() => {vi.useRealTimers(); vi.clearAllMocks(); window.history.replaceState(null, '', '/');});

it('shows replica navigation with local administration and read-only service views', () => {
  render(<Shell data={{...data, can: {'replica.admin': {'*': true}}}}><ServiceTabs serviceKey="mission"/></Shell>);
  expect(screen.getByText('Read-only replica')).toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Administration'})).toHaveAttribute('href', '/admin/replica');
  expect(screen.getByRole('link', {name: 'Cyber Overrides'})).toHaveAttribute('href', '/services/mission/cyber-overrides');
  for (const name of ['Scan', 'Patch', 'Discovery', 'Approvals', 'Recommendations']) expect(screen.queryByRole('link', {name})).not.toBeInTheDocument();
});

it('preserves exact denial scope and supports an indefinite explicit risk acceptance', async () => {
  const digest = 'sha256:' + 'a'.repeat(64);
  window.history.replaceState(null, '', `/services/mission/cyber-overrides?release_id=3&digest=${digest}&denial_condition=revoked`);
  request.mockImplementation(async url => String(url).includes('/releases') ? {releases: [{id: 3, sequence: 4, status: 'revoked'}]} : {overrides: []});
  render(<OperatingMode.Provider value="replica"><Overrides data={data}/></OperatingMode.Provider>);
  await screen.findByRole('option', {name: 'Release 4 · revoked'});
  fireEvent.change(screen.getByLabelText('Imported release'), {target: {value: '3'}});
  fireEvent.change(screen.getByLabelText('Mission impact'), {target: {value: 'Critical operations unavailable'}});
  fireEvent.change(screen.getByLabelText('Justification'), {target: {value: 'Mitigations in place'}});
  fireEvent.change(screen.getByLabelText('Explicit risk acceptance'), {target: {value: 'Cyber accepts documented mission risk'}});
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', {name: 'Create local Cyber override'}));
  await waitFor(() => expect(request).toHaveBeenCalledWith('/api/services/mission/local-overrides', expect.objectContaining({method: 'POST'})));
  const [, init] = request.mock.calls.find(([, init]) => init?.method === 'POST')!;
  expect(JSON.parse(String(init?.body))).toEqual({release_id: 3, digest, denial_condition: 'revoked', mission_impact: 'Critical operations unavailable',
    justification: 'Mitigations in place', risk_acceptance: 'Cyber accepts documented mission risk', expires_at: null, review_at: null, elevated_risk_acknowledged: true});
  expect(init?.headers).toEqual(expect.objectContaining({'X-CSRF-Token': 'token'}));
  expect(await screen.findByText(/Local Cyber override created/)).toBeInTheDocument();
});

it('keeps active exceptions distinct and does not offer mutation to a viewer', async () => {
  request.mockImplementation(async url => String(url).includes('/releases') ? {releases: []} : {overrides: [{id: 1, release_id: 3, status: 'active',
    denial_condition: 'expired', expires_at: null, created_by_display_name: 'Cyber approver', digests: []}]});
  render(<Overrides data={{...data, can: {}}}/>);
  expect(await screen.findByText('Indefinite — explicit revocation required')).toBeInTheDocument();
  expect(screen.getByText(/normal approval remains expired/)).toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Create local Cyber override'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Revoke immediately'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'View usage history'})).not.toBeInTheDocument();
});

it('shows active override status prominently on service views', async () => {
  request.mockResolvedValue({overrides: [{status: 'active'}, {status: 'revoked'}]});
  render(<OverrideIndicator serviceKey="mission"/>);
  expect(await screen.findByText('Mission-continuity exception active')).toBeInTheDocument();
  expect(screen.getByText(/1 local Cyber override recorded/)).toBeInTheDocument();
});

it('uses immutable captured evidence and preserves release expiration', async () => {
  request.mockImplementation(async url => String(url).includes('local-overrides') ? {overrides: [{release_id: 3, status: 'active'}]} : {releases: [{id: 3, sequence: 4, service_key: 'mission', status: 'expired',
    expires_at: '2026-01-01T00:00:00Z', evidence_url: '/api/replica/releases/3/evidence', artifacts: [{repository: 'project/image', digest: 'sha256:abc', proxy_repositories: ['replica/mission/image']}]}]});
  render(<Releases data={data}/>);
  expect(await screen.findByRole('link', {name: 'Download immutable release evidence'})).toHaveAttribute('href', '/api/replica/releases/3/evidence');
  expect(screen.getByText('Expired')).toBeInTheDocument();
  expect(await screen.findByText('Mission-continuity exception active')).toBeInTheDocument();
  expect(screen.getByText('replica/mission/image@sha256:abc')).toBeInTheDocument();
});

it('queues synchronization with the existing CSRF boundary', async () => {
  request.mockImplementation(async url => String(url).includes('/upstreams') ? [] : {sources: [], services: [], jobs: []});
  render(<Page data={{...data, can: {'replica.sync': {'*': true}}}}/>);
  fireEvent.click(screen.getByRole('button', {name: 'Synchronize now'}));
  await waitFor(() => expect(request).toHaveBeenCalledWith('/api/replica/sync', expect.objectContaining({method: 'POST', body: '{"source_id":null}'})));
  expect(await screen.findByText('Synchronization queued.')).toBeInTheDocument();
});


it('updates publisher pins without enabling a paused source', async () => {
  const oldPin = 'sha256:' + 'a'.repeat(64), newPin = 'sha256:' + 'b'.repeat(64);
  request.mockImplementation(async url => String(url).includes('/upstreams') ? [{id: 4, name: 'Local registry', endpoint: 'https://registry.local'}] : {sources: [
    {id: 2, name: 'Mission source', upstream_id: 4, repository: 'approved/mission/releases', poll_seconds: 300, enabled: false, trusted_publishers: [oldPin]}
  ], services: [], jobs: []});
  render(<Page data={{...data, can: {'replica.admin': {'*': true}, 'replica.sync': {'*': true}}}}/>);
  fireEvent.click(await screen.findByText('Edit Mission source'));
  const fields = screen.getAllByLabelText('Trusted publisher fingerprints');
  fireEvent.change(fields[1], {target: {value: newPin}});
  expect(screen.getByRole('button', {name: 'Synchronize'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button', {name: 'Update Mission source'}));
  await waitFor(() => expect(request).toHaveBeenCalledWith('/api/replica/sources/2', expect.objectContaining({method: 'PUT'})));
  const [, init] = request.mock.calls.find(([, init]) => init?.method === 'PUT')!;
  expect(JSON.parse(String(init?.body))).toEqual({name: 'Mission source', upstream_id: 4, repository: 'approved/mission/releases',
    poll_seconds: 300, enabled: false, trusted_publishers: [newPin]});
  expect(init?.headers).toEqual(expect.objectContaining({'X-CSRF-Token': 'token'}));
});

it('keeps expired release validity separate from captured compliant posture', async () => {
  request.mockImplementation(async url => String(url).includes('local-overrides') ? {overrides: [{status: 'active'}]}
    : {releases: [{id: 3, sequence: 4, status: 'expired'}]});
  render(<OperatingMode.Provider value="replica"><ServiceHeader data={{...data,
    view: {service: {...data.service, assessment_status: 'assessed'}, version: '1.0', compliant: true}}}/></OperatingMode.Provider>);
  expect(screen.getByText('Captured assessment')).toBeInTheDocument();
  expect(screen.queryByText('Compliant')).not.toBeInTheDocument();
  expect(await screen.findByText('Expired')).toBeInTheDocument();
  expect(await screen.findByText('Mission-continuity exception active')).toBeInTheDocument();
});

it('does not carry a previous service release status into a new service', async () => {
  request.mockImplementation(url => String(url).includes('service_key=mission')
    ? Promise.resolve({releases: [{id: 3, sequence: 4, status: 'active'}]}) : new Promise(() => {}));
  const page = render(<ReplicaReleaseIndicator serviceKey="mission"/>);
  expect(await screen.findByText('Approved release active')).toBeInTheDocument();
  page.rerender(<ReplicaReleaseIndicator serviceKey="another-service"/>);
  expect(screen.queryByText('Approved release active')).not.toBeInTheDocument();
  expect(screen.getByText('Checking local release status…')).toBeInTheDocument();
});

it('loads historical approval and mission evidence only when requested', async () => {
  request.mockImplementation(async url => String(url).includes('/context') ? {original_evidence: {
    actors: {'17': 'publishing.cyber'},
    records: {service_metadata: [{values: {mission_impact: 'Mission continuity required'}}], inventory_records: [{dataset: 'ppsm', values: {port: 443}}]},
    extension: {cyber_approvals: [{id: 12, status: 'approved', decision_rationale: 'Accepted captured risk'}], risk_decisions: [{decision: 'accept'}]}}}
    : String(url).includes('local-overrides') ? {overrides: []}
    : {releases: [{id: 3, sequence: 4, service_key: 'mission', status: 'active', context_url: '/api/replica/releases/3/context'}]});
  render(<Releases data={data}/>);
  const toggle = await screen.findByText('Review captured approval, mission and risk evidence');
  expect(request.mock.calls.some(([url]) => String(url).includes('/context'))).toBe(false);
  fireEvent.click(toggle);
  expect(await screen.findByText('Cyber approval records (1)')).toBeInTheDocument();
  expect(screen.getByText('Accepted captured risk')).toBeInTheDocument();
  expect(screen.getByText('PPSM and asset inventory (1)')).toBeInTheDocument();
  expect(screen.getByText('publishing.cyber')).toBeInTheDocument();
  expect(screen.getByRole('link', {name: /Open complete captured evidence/})).toHaveAttribute('href', '/api/replica/releases/3/context');
});

it('refreshes synchronization completion without a page reset', async () => {
  vi.useFakeTimers();
  let complete = false;
  request.mockImplementation(async url => String(url).includes('/upstreams') ? [] : {sources: [], services: [], jobs: [
    {id: 1, status: complete ? 'succeeded' : 'running', message: complete ? 'Release imported' : 'Import underway'}]});
  render(<Page data={data}/>);
  await act(async () => {await Promise.resolve();});
  expect(screen.getByText('Import underway')).toBeInTheDocument();
  complete = true;
  await act(async () => {await vi.advanceTimersByTimeAsync(5000);});
  expect(screen.getByText('Release imported')).toBeInTheDocument();
});

it('shows override enforcement details and an explicit empty history', async () => {
  let uses: any[] = [];
  request.mockImplementation(async url => String(url).endsWith('/uses') ? {uses}
    : String(url).includes('/releases') ? {releases: []}
    : {overrides: [{id: 1, release_id: 3, status: 'revoked', digests: []}]});
  render(<Overrides data={{...data, can: {'local_override.view_audit': {'7': true}}}}/>);
  fireEvent.click(await screen.findByRole('button', {name: 'View usage history'}));
  expect(await screen.findByText('No pulls have used this override.')).toBeInTheDocument();
  uses = [{id: 8, principal_id: 42, repository: 'replica/mission/image', digest: 'sha256:abc', release_id: 3, reason: 'expired'}];
  fireEvent.click(screen.getByRole('button', {name: 'View usage history'}));
  expect(await screen.findByText('Local Cyber override #1 / Release 3')).toBeInTheDocument();
  expect(screen.getByText('42')).toBeInTheDocument();
  expect(screen.getByText('expired')).toBeInTheDocument();
});

it('hides unavailable assessment actions on the public replica landing page', () => {
  render(<PublicHome data={data}/>);
  expect(screen.getByRole('link', {name: /Sign In/})).toBeInTheDocument();
  for (const name of [/Start Scan/, /Generate SBOM/, /Start Patch/]) expect(screen.queryByRole('link', {name})).not.toBeInTheDocument();
});
