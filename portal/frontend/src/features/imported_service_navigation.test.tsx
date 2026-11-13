import {afterEach, expect, it, vi} from 'vitest';
import {fireEvent, render, screen, within} from '@testing-library/react';
import {Shell} from '../components/Shell';
import {Page as Artifacts} from './service-artifacts';
import {Page as Overview} from './service_overview';
import {Page as Monitoring, Releases} from './replica';
import {requestJson, type PageData} from '../api';

vi.mock('../api', async original => ({...await original<object>(), requestJson: vi.fn()}));
const image = {id: 9, image_reference: 'registry/api:1', image_digest: `sha256:${'a'.repeat(64)}`, lifecycle_status: 'active'};
const data: PageData = {cats_mode: 'full', imported_service: true, read_only: true,
  current_user: {display_name: 'Operator', theme: 'cats'}, view: {service: {id: 7, service_key: 'imported', name: 'Imported', groups: []}, version: '1'},
  can: {'service.edit': {'7': true}, 'service.export': {'7': true}, 'approval.request': {'7': true}, 'replica.sync': {'*': true}},
  can_edit: true, can_image_workflow: true, can_patch_images: true,
  can_schedule_scans: true, scan_schedule: {cadence: 'daily', timezone: 'UTC'},
  image_inventory: [{image, count: 1, references: ['Deployment/api']}], service_images: [image]};
afterEach(() => {vi.resetAllMocks(); window.history.replaceState(null, '', '/');});
function mockReads() {
  vi.mocked(requestJson).mockImplementation(async () => ({releases: [], overrides: [], sources: [], jobs: [], services: []}));
}

it('keeps full navigation while imported service artifacts expose pull instructions and captured evidence', async () => {
  mockReads();
  render(<Shell data={data}><Artifacts data={data}/></Shell>);
  const navigation = screen.getByRole('navigation', {name: 'Primary navigation'});
  for (const label of ['Discovery', 'Scan', 'Patch']) expect(within(navigation).getByRole('link', {name: label})).toBeInTheDocument();
  fireEvent.click(within(navigation).getByText('More', {selector: 'summary'}));
  expect(screen.getByRole('link', {name: 'OCI monitoring'})).toHaveAttribute('href', '/admin/replica');
  expect(screen.getByRole('button', {name: 'Pull registry/api:1 from CATS'})).toBeInTheDocument();
  expect(screen.queryByRole('link', {name: 'Patch registry/api:1'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: '+ Add Artifact'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Replace image'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link', {name: 'Request Cyber Approval'})).not.toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Captured release evidence'})).toHaveAttribute('href', '/imported-releases?service=imported');
  expect(await screen.findByText('No verified release is available.')).toBeInTheDocument();
});

it('provides overview pull instructions to viewers while hiding imported mutations and scan schedules', () => {
  mockReads();
  render(<Shell data={data}><Overview data={data}/></Shell>);
  expect(screen.getByRole('button', {name: 'Pull registry/api:1 from CATS'})).toBeInTheDocument();
  expect(screen.queryByRole('link', {name: 'Patch registry/api:1'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Edit scan schedule'})).not.toBeInTheDocument();
});

it('retains local service editing and patch actions in the same full deployment', () => {
  const local = {...data, imported_service: false, read_only: false};
  render(<Shell data={local}><Artifacts data={local}/></Shell>);
  expect(screen.getByRole('button', {name: '+ Add Artifact'})).toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'Patch registry/api:1'})).toBeInTheDocument();
  expect(screen.getByRole('button', {name: 'Pull registry/api:1 from CATS'})).toBeInTheDocument();
  expect(screen.queryByLabelText('Imported service')).not.toBeInTheDocument();
});

it('exposes full-mode synchronization monitoring and imported history without replacing local approvals', async () => {
  mockReads();
  const view = render(<Monitoring data={data}/>);
  expect(screen.getByRole('heading', {name: 'OCI monitoring'})).toBeInTheDocument();
  expect(screen.getByRole('button', {name: 'Synchronize now'})).toBeInTheDocument();
  expect(screen.getByRole('link', {name: 'View imported release history and expiration'})).toHaveAttribute('href', '/imported-releases');
  expect(await screen.findByText('No release sources configured.')).toBeInTheDocument();
  view.rerender(<Releases data={data}/>);
  expect(screen.getByRole('link', {name: 'Locally approved releases'})).toHaveAttribute('href', '/approved-releases');
  expect(await screen.findByText('No verified releases have been imported.')).toBeInTheDocument();
});

it('does not advertise monitoring without source administration or synchronization permission', () => {
  render(<Shell data={{...data, can: {}, imported_service: false, read_only: false}}>Local workspace</Shell>);
  fireEvent.click(screen.getByText('More', {selector: 'summary'}));
  expect(screen.queryByRole('link', {name: 'OCI monitoring'})).not.toBeInTheDocument();
});
