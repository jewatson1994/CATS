import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {ApiError, requestJson} from '../api';
import {Page as Sources} from './topic_polling';
import {Page as Unclaimed} from './unclaimed_services';

vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
const api = vi.mocked(requestJson);
const data = {cats_mode:'full', may_view_unclaimed:true, may_manage_topic_sources:true, csrf_token:'csrf'};
const groups = [{id:2,name:'Operations'}, {id:3,name:'Other group'}];
const source = {id:6,name:'Platform', origin:'https://gitlab.example',namespace:'dev/platform',topic:'cats',
  enabled:true,has_token:true,poll_seconds:300,claim_group_id:2};
const project = {id:7,project_name:'Web',project_path:'platform/web',web_url:'https://gitlab.example/platform/web',
  commit_sha:'abc123',source_name:'Platform',status:'ready',scanned:true,execution_id:51,claim_group_id:2,claim_group_ids:[2]};
const response = {page:1,pages:1,total:1,items:[project],groups};
afterEach(() => {cleanup(); vi.resetAllMocks(); window.history.replaceState({}, '', '/');});

it('opts new sources out until explicitly enabled and saves the selected group', async () => {
  api.mockResolvedValue({sources:[],groups});
  render(<Sources data={data}/>);
  await screen.findByLabelText('Source name');
  expect(screen.getByLabelText('Enable automatic polling')).not.toBeChecked();
  fireEvent.change(screen.getByLabelText('Source name'),{target:{value:'Platform'}});
  fireEvent.change(screen.getByLabelText('GitLab HTTPS origin'),{target:{value:source.origin}});
  fireEvent.change(screen.getByLabelText('Namespace'),{target:{value:source.namespace}});
  fireEvent.change(screen.getByLabelText('Project topic'),{target:{value:source.topic}});
  fireEvent.change(screen.getByLabelText('Claim group'),{target:{value:'2'}});
  fireEvent.click(screen.getByRole('button',{name:'Add source'}));
  await screen.findByText('Source added.');
  const write = api.mock.calls.find(([,options]) => options?.method === 'POST')!;
  expect(write[0]).toBe('/api/admin/topic-polling/sources');
  expect(write[1]?.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(write[1]?.body))).toEqual({name:'Platform',origin:source.origin,namespace:source.namespace,
    topic:'cats',claim_group_id:2,poll_seconds:300,enabled:false});
});

it('keeps token edits write-only and leaves the source identity fixed', async () => {
  api.mockResolvedValue({sources:[source],groups});
  render(<Sources data={data}/>);
  const card = within(await screen.findByRole('article',{name:'Platform'}));
  fireEvent.click(card.getByRole('button',{name:'Edit source'}));
  expect(card.getByLabelText('Replacement access token')).toHaveValue('');
  expect(card.queryByLabelText('GitLab HTTPS origin')).toBeNull();
  fireEvent.click(card.getByRole('button',{name:'Save changes'}));
  await card.findByText('Source saved.');
  const write = api.mock.calls.find(([,options]) => options?.method === 'PUT')!;
  expect(JSON.parse(String(write[1]?.body))).not.toHaveProperty('token');
  expect(JSON.parse(String(write[1]?.body))).not.toHaveProperty('clear_token');
  fireEvent.click(card.getByRole('button',{name:'Edit source'}));
  fireEvent.click(card.getByLabelText('Remove stored token'));
  fireEvent.click(card.getByRole('button',{name:'Save changes'}));
  await waitFor(() => expect(api.mock.calls.filter(([,options]) => options?.method === 'PUT')).toHaveLength(2));
  expect(JSON.parse(String(api.mock.calls.filter(([,options]) => options?.method === 'PUT')[1][1]?.body))).toHaveProperty('clear_token',true);
});

it('loads source projects on demand, pages through them and retries only the failed revision', async () => {
  api.mockImplementation(async (url) => url.includes('/projects?') ? {projects:[{id:7,project_path:'dev/web',default_branch:'main',
    commit_sha:'abc123',status:'failed',error:'Missing chart',revision_id:15,can_retry:true},
    {id:8,project_path:'dev/retired',status:'out_of_scope',revision_id:16,can_retry:false}],page:1,pages:2,total:51} :
    url.endsWith('/retry') ? {job_id:'j',status:'queued'} : {sources:[{...source,latest_job:{status:'completed',
      project_errors:[{gitlab_project_id:401,message:'Default branch unavailable'}]}}],groups});
  render(<Sources data={data}/>);
  const card = within(await screen.findByRole('article',{name:'Platform'}));
  fireEvent.click(card.getByText('Project errors from the latest poll (1)'));
  expect(card.getByText(/GitLab project 401.*Default branch unavailable/)).toBeVisible();
  expect(api.mock.calls.some(([url]) => url.includes('/projects?'))).toBe(false);
  fireEvent.click(card.getByRole('button',{name:'Projects'}));
  expect(await card.findByText('Missing chart')).toBeVisible();
  const retired = within(card.getByRole('row', {name: /dev\/retired/}));
  expect(retired.getByText('No longer matches this source')).toBeVisible();
  expect(retired.queryByRole('button', {name:'Retry revision'})).toBeNull();
  fireEvent.click(card.getByRole('button',{name:'Retry revision'}));
  await card.findByText('Revision queued for retry.');
  expect(api).toHaveBeenCalledWith('/api/admin/topic-polling/sources/6/revisions/15/retry',expect.objectContaining({method:'POST'}));
  fireEvent.click(card.getByRole('button',{name:'Next page'}));
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/admin/topic-polling/sources/6/projects?page=2',expect.objectContaining({signal:expect.any(AbortSignal)})));
});

it('presents safe provenance and permits claiming only to groups supplied for that project', async () => {
  api.mockImplementation(async (url, options) => options?.method === 'POST' ? {service_id:4,service_key:'service-4'} : response);
  render(<Unclaimed data={data}/>);
  expect(await screen.findByText('abc123')).toBeVisible();
  expect(screen.queryByRole('link',{name:'Open service evidence'})).toBeNull();
  const group = screen.getByRole('combobox',{name:'Claim group for platform/web'});
  expect(within(group).getAllByRole('option')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button',{name:'Claim service'}));
  expect(await screen.findByRole('link',{name:'Open service evidence'})).toHaveAttribute('href','/services/service-4');
  const write = api.mock.calls.find(([,options]) => options?.method === 'POST')!;
  expect(write[0]).toBe('/api/unclaimed-services/7/claim');
  expect(JSON.parse(String(write[1]?.body))).toEqual({group_id:2,execution_id:51,csrf_token:'csrf'});
});

it('reloads a conflicted claim and waits for an explicit claim against the newly displayed scan', async () => {
  const updated = {...response,items:[{...project,commit_sha:'def456',execution_id:52}]};
  api.mockResolvedValueOnce(response).mockRejectedValueOnce(new ApiError('Review the latest scan before claiming.',409))
    .mockResolvedValueOnce(updated).mockResolvedValueOnce({service_id:4,service_key:'service-4'})
    .mockResolvedValueOnce({...updated,items:[]});
  render(<Unclaimed data={data}/>);
  expect(await screen.findByText('Scan #51')).toBeVisible();
  fireEvent.click(screen.getByRole('button',{name:'Claim service'}));
  expect(await screen.findByText('Scan #52')).toBeVisible();
  expect(screen.getByRole('alert')).toHaveTextContent('Review the latest scan before claiming.');
  expect(screen.getByText('def456')).toBeVisible();
  expect(api.mock.calls.filter(([,options]) => options?.method === 'POST')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button',{name:'Claim service'}));
  await screen.findByRole('link',{name:'Open service evidence'});
  const scans = api.mock.calls.filter(([,options]) => options?.method === 'POST')
    .map(([,options]) => JSON.parse(String(options?.body)).execution_id);
  expect(scans).toEqual([51,52]);
  expect(screen.queryByRole('alert')).toBeNull();
});

it('keeps incomplete evidence unclaimable and permits paginated queue navigation', async () => {
  api.mockResolvedValue({...response,items:[{...project,status:'pending',scanned:false}],pages:2,total:51});
  render(<Unclaimed data={data}/>);
  expect(await screen.findByText('No unclaimed services on this page')).toBeVisible();
  expect(screen.queryByText('platform/web')).toBeNull();
  expect(screen.queryByRole('button',{name:'Claim service'})).toBeNull();
  expect(screen.getByRole('link',{name:'Next page'})).toHaveAttribute('href','/unclaimed-services?page=2');
});

it('skips protected API requests when either screen is outside its authorized scope', () => {
  const view = render(<Sources data={{...data,cats_mode:'replica'}}/>);
  expect(screen.getByText('Topic polling is unavailable')).toBeVisible();
  view.rerender(<Unclaimed data={{...data,may_view_unclaimed:false}}/>);
  expect(screen.getByText('Unclaimed Services is unavailable')).toBeVisible();
  expect(api).not.toHaveBeenCalled();
});
