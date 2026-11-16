import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {OCIDistribution} from './oci_distribution';
import {OperatingMode} from '../operatingMode';
vi.mock('../api', async original => ({...await original<any>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks(); vi.restoreAllMocks();});
it('creates scoped expiring machine access with CSRF and dismisses the one-time password', async () => {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return {secret:'one-time-password'} as any;
    if (url === '/api/oci/repositories') return [{id:3,public_repository:'project/api',pull_repository:'project/1/api',upstream_repository:'team/api',service_id:1,enabled:true}] as any;
    if (url === '/api/oci/status/overview') return {available_repositories:1,active_principals:0,services:[]} as any;
    return [] as any;
  });
  render(<OCIDistribution data={{csrf_token:'csrf'}}/>);
  await screen.findByText('project/1/api');
  fireEvent.click(screen.getByRole('button',{name:'Add machine account'}));
  fireEvent.change(screen.getByLabelText('Machine account name'),{target:{value:'ci-reader'}});
  fireEvent.click(screen.getByLabelText('project/1/api'));
  fireEvent.click(screen.getByRole('button',{name:'Save'}));
  await screen.findByText('one-time-password');
  const call = vi.mocked(requestJson).mock.calls.find(([, options]) => options?.method === 'POST');
  expect(call?.[0]).toBe('/api/oci/principals');
  expect(call?.[1]?.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({name:'ci-reader',repository_ids:[3],enabled:true});
  fireEvent.click(screen.getByRole('button',{name:'Dismiss password'}));
  await waitFor(() => expect(screen.queryByText('one-time-password')).not.toBeInTheDocument());
});

it('saves a project mapping without selecting a single service', async () => {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return {} as any;
    if (url === '/api/oci/upstreams') return [{id: 4, name: 'Harbor', enabled: true}] as any;
    if (url === '/api/oci/status/overview') return {services: [{id: 1, name: 'API'}]} as any;
    return [] as any;
  });
  render(<OCIDistribution data={{csrf_token: 'csrf'}}/>);
  await screen.findByText('Harbor');
  fireEvent.click(screen.getByRole('button', {name: 'Add mapping'}));
  expect(screen.getByLabelText('Service')).toBeRequired();
  fireEvent.change(screen.getByLabelText('Public repository'), {target: {value: 'approved/*'}});
  expect(screen.queryByLabelText('Service')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Upstream repository'), {target: {value: 'platform/*'}});
  fireEvent.change(screen.getByLabelText('Upstream'), {target: {value: '4'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save'}));
  await screen.findByText('Distribution settings saved.');
  const call = vi.mocked(requestJson).mock.calls.find(([, options]) => options?.method === 'POST');
  expect(call?.[0]).toBe('/api/oci/repositories');
  expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
    public_repository: 'approved/*', upstream_repository: 'platform/*', upstream_id: 4, service_id: null,
  });
});

it('tests a concrete project repository and identifies project-wide machine grants', async () => {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return {message: 'Connected'} as any;
    if (url === '/api/oci/repositories') return [{
      id: 7, public_repository: 'approved/*', pull_repository: 'approved/<service-id>/*', upstream_repository: 'platform/*', service_id: null, enabled: true,
    }] as any;
    return [] as any;
  });
  render(<OCIDistribution data={{csrf_token: 'csrf'}}/>);
  await screen.findByText('approved/<service-id>/*');
  fireEvent.click(screen.getByRole('button', {name: 'Add machine account'}));
  expect(screen.getByLabelText('approved/<service-id>/* (whole project; group pull policy applies)')).toBeInTheDocument();
  const prompt = vi.spyOn(window, 'prompt').mockReturnValueOnce('v2').mockReturnValueOnce('approved/42/team/api');
  fireEvent.click(screen.getByRole('button', {name: 'Test connection'}));
  await screen.findByText('Connected');
  expect(prompt).toHaveBeenCalledWith('Service pull repository, for example approved/42/image');
  const call = vi.mocked(requestJson).mock.calls.find(([, options]) => options?.method === 'POST');
  expect(call?.[0]).toBe('/api/oci/repositories/7/test');
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({repository: 'approved/42/team/api', reference: 'v2'});
});


it.each(['full', 'replica'] as const)('uses group pull policy when creating a mapping in %s mode', async mode => {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return {} as any;
    if (url === '/api/oci/upstreams') return [{id: 4, name: 'Local registry', enabled: true}] as any;
    if (url === '/api/oci/status/overview') return {services: [{id: 1, name: 'Mission'}]} as any;
    return [] as any;
  });
  render(<OperatingMode.Provider value={mode}><OCIDistribution data={{csrf_token: 'csrf'}}/></OperatingMode.Provider>);
  await screen.findByText('Local registry');
  fireEvent.click(screen.getByRole('button', {name: 'Add mapping'}));
  expect(screen.queryByLabelText('Maximum scan age (days)')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Public repository'), {target: {value: 'replica/mission/image'}});
  fireEvent.change(screen.getByLabelText('Upstream repository'), {target: {value: 'approved/image'}});
  fireEvent.change(screen.getByLabelText('Upstream'), {target: {value: '4'}});
  fireEvent.change(screen.getByLabelText('Service'), {target: {value: '1'}});
  expect(screen.queryByLabelText('Maximum approval age (days)')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Local maximum release age (days)')).not.toBeInTheDocument();
  expect(screen.getByText(/The owning group chooses approved releases, compliance rules, or both in General Policy/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Save'}));
  await screen.findByText('Distribution settings saved.');
  const call = vi.mocked(requestJson).mock.calls.find(([, options]) => options?.method === 'POST');
  expect(JSON.parse(String(call?.[1]?.body)).policy).toEqual({});
});


it.each(['full', 'replica'] as const)('clears retired age limits when editing a mapping in %s mode', async mode => {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'PUT') return {} as any;
    if (url === '/api/oci/upstreams') return [{id: 4, name: 'Harbor', enabled: true}] as any;
    if (url === '/api/oci/repositories') return [{
      id: 7, public_repository: 'approved/image', upstream_repository: 'platform/image',
      service_id: 1, upstream_id: 4, enabled: true,
      policy: {max_scan_age_days: 1, max_approval_age_days: 7},
    }] as any;
    if (url === '/api/oci/status/overview') return {services: [{id: 1, name: 'API'}]} as any;
    return [] as any;
  });
  render(<OperatingMode.Provider value={mode}><OCIDistribution data={{csrf_token: 'csrf'}}/></OperatingMode.Provider>);
  const repository = await screen.findByText('approved/image');
  fireEvent.click(repository.closest('tr')!.querySelector('button')!);
  expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Save'}));
  await screen.findByText('Distribution settings saved.');
  const call = vi.mocked(requestJson).mock.calls.find(([, options]) => options?.method === 'PUT');
  expect(call?.[0]).toBe('/api/oci/repositories/7');
  expect(call?.[1]?.headers).toMatchObject({'X-CSRF-Token': 'csrf'});
  expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
    public_repository: 'approved/image', upstream_repository: 'platform/image',
    upstream_id: 4, service_id: 1, enabled: true, policy: {},
  });
});
