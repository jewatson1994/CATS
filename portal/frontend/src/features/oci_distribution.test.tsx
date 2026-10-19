import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {OCIDistribution} from './oci_distribution';
vi.mock('../api', async original => ({...await original<any>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
it('creates scoped expiring machine access with CSRF and dismisses the one-time password', async () => {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return {secret:'one-time-password'} as any;
    if (url === '/api/oci/repositories') return [{id:3,public_repository:'project/api',upstream_repository:'team/api',service_id:1,enabled:true}] as any;
    if (url === '/api/oci/status/overview') return {available_repositories:1,active_principals:0,services:[]} as any;
    return [] as any;
  });
  render(<OCIDistribution data={{csrf_token:'csrf'}}/>);
  await screen.findByText('project/api');
  fireEvent.click(screen.getByRole('button',{name:'Add machine account'}));
  fireEvent.change(screen.getByLabelText('Machine account name'),{target:{value:'ci-reader'}});
  fireEvent.click(screen.getByLabelText('project/api'));
  fireEvent.click(screen.getByRole('button',{name:'Save'}));
  await screen.findByText('one-time-password');
  const call = vi.mocked(requestJson).mock.calls.find(([, options]) => options?.method === 'POST');
  expect(call?.[0]).toBe('/api/oci/principals');
  expect(call?.[1]?.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({name:'ci-reader',repository_ids:[3],enabled:true});
  fireEvent.click(screen.getByRole('button',{name:'Dismiss password'}));
  await waitFor(() => expect(screen.queryByText('one-time-password')).not.toBeInTheDocument());
});
