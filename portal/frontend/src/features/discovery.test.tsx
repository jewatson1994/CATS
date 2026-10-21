import {afterEach, expect, it, vi} from 'vitest';

import {fireEvent, render, screen, waitFor} from '@testing-library/react';

import {Page, isPartial} from './discovery';

const catalog = {groups: [{id: 1, name: 'Platform'}], services: [{id: 2, name: 'Payments', service_key: 'payments', group_id: 1}, {id: 3, name: 'Other', service_key: 'other', group_id: 9}], jobs: [{id: 'job-1', status: 'completed', group_id: 1}]};

const inventory = {roots: [{id: 'root', path: 'deploy/chart', technology: 'helm', completeness: 'partial'}], nodes: [{id: 'node', root_id: 'root', name: 'api', kind: 'deployment', state: 'resolved', provenance: {path: 'templates/api.yaml'}}], images: [{reference: 'nginx:1', root_id: 'root'}], diagnostics: [{message: 'Missing values'}], completeness: 'partial'};

afterEach(() => vi.unstubAllGlobals());

it('requires selected roots and partial acknowledgement, confirms without scanning, and scopes services', async () => {

  const fetch = vi.fn(async (url: string, _init?: RequestInit) => new Response(JSON.stringify(url.endsWith('/confirm') ? {inventory_id: 'confirmed'} : url.endsWith('/job-1') ? {job: catalog.jobs[0], inventory} : catalog), {headers: {'Content-Type': 'application/json'}}));

  vi.stubGlobal('fetch', fetch); render(<Page data={{csrf_token: 'token'}}/>);

  await screen.findByText('nginx:1');

  expect(screen.queryByRole('option', {name: 'Other (other)'})).not.toBeInTheDocument();

  expect(screen.queryByRole('button', {name: 'Start scan'})).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Service'), {target: {value: '2'}});

  fireEvent.click(screen.getByRole('checkbox', {name: 'deploy/chart helm'}));

  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeDisabled();

  fireEvent.click(screen.getByRole('checkbox', {name: /I acknowledge/}));

  fireEvent.click(screen.getByRole('button', {name: 'Confirm inventory'}));

  await screen.findByRole('button', {name: 'Start scan'});

  const mutations = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');

  expect(mutations).toHaveLength(1);

  expect(mutations[0][0]).toContain('/confirm');

  expect(JSON.parse(String(mutations[0][1]?.body))).toEqual({csrf_token: 'token', service_id: 2, root_ids: ['root'], acknowledge_partial: true});

});

it('submits ordered non-secret configuration and the selected group', async () => {

  const fetch = vi.fn(async (url: string, _init?: RequestInit) => new Response(JSON.stringify(_init?.method === 'POST' ? {job_id: 'new'} : url.endsWith('/new') ? {job: {id: 'new', status: 'queued'}, inventory: null} : catalog), {headers: {'Content-Type': 'application/json'}}));

  vi.stubGlobal('fetch', fetch); render(<Page data={{csrf_token: 'token'}}/>);

  await screen.findByRole('option', {name: 'Platform'});

  fireEvent.change(screen.getByLabelText('Owning group'), {target: {value: '1'}});

  fireEvent.change(screen.getByLabelText('Source type'), {target: {value: 'reference'}});

  fireEvent.change(screen.getByLabelText('OCI image or chart reference'), {target: {value: 'docker.io/library/nginx:1.27'}});

  fireEvent.change(screen.getByLabelText('Environment'), {target: {value: 'staging'}});

  fireEvent.change(screen.getByLabelText('Values files, in override order'), {target: {value: 'values.yaml\n values-staging.yaml'}});

  fireEvent.click(screen.getByRole('button', {name: 'Start discovery'}));

  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true));

  const body = fetch.mock.calls.find(([, init]) => init?.method === 'POST')?.[1]?.body as FormData;

  expect(body.get('csrf_token')).toBe('token'); expect(body.get('group_id')).toBe('1');

  expect(JSON.parse(String(body.get('options')))).toEqual({environment: 'staging', values_files: ['values.yaml', 'values-staging.yaml']});

});

it('treats unknown completeness conservatively', () => {

  expect(isPartial('complete')).toBe(false); expect(isPartial({status: 'complete'})).toBe(false);

  expect(isPartial(undefined)).toBe(true); expect(isPartial('partial')).toBe(true);

});



it('offers service staging only with group authority and sends one owner through confirmation', async () => {

  const scoped = {...catalog, groups: [{id: 1, name: 'Platform', can_stage: true}]};

  const fetch = vi.fn(async (url: string, _init?: RequestInit) => new Response(JSON.stringify(url.endsWith('/confirm') ? {inventory_id: 'confirmed'} : url.endsWith('/job-1') ? {job: catalog.jobs[0], inventory} : scoped), {headers: {'Content-Type': 'application/json'}}));

  vi.stubGlobal('fetch', fetch); render(<Page data={{csrf_token: 'token'}}/>);

  await screen.findByText('nginx:1');

  fireEvent.change(screen.getByLabelText('Service'), {target: {value: 'new'}});

  fireEvent.change(screen.getByLabelText(/New service key/), {target: {value: 'new-service'}});

  fireEvent.click(screen.getByRole('checkbox', {name: 'deploy/chart helm'}));

  fireEvent.click(screen.getByRole('checkbox', {name: /I acknowledge/}));

  fireEvent.click(screen.getByRole('button', {name: 'Confirm inventory'}));

  await screen.findByRole('button', {name: 'Start scan'});

  const mutation = fetch.mock.calls.find(([,init]) => init?.method === 'POST');

  expect(JSON.parse(String(mutation?.[1]?.body))).toEqual({csrf_token:'token',new_service_key:'new-service',root_ids:['root'],acknowledge_partial:true});

});



it('uploads supplemental files with resolution choices and opens the new immutable version', async () => {

  const fetch = vi.fn(async (url: string, init?: RequestInit) => new Response(JSON.stringify(

    init?.method === 'POST' ? {job_id: 'job-2'} :

    url.endsWith('/job-2') ? {job: {id: 'job-2', status: 'completed', group_id: 1}, inventory: {...inventory, images: [{reference: 'redis:7', root_id: 'root'}]}} :

    url.endsWith('/job-1') ? {job: catalog.jobs[0], inventory} : catalog

  ), {headers: {'Content-Type': 'application/json'}}));

  vi.stubGlobal('fetch', fetch);

  render(<Page data={{csrf_token: 'supplement-token'}}/>);

  await screen.findByText('nginx:1');

  fireEvent.click(screen.getByText('Supply missing files'));

  const choices = {values_files: ['dependencies/values.yaml'], environment: 'staging'};

  fireEvent.change(screen.getByLabelText('Resolution settings'), {target: {value: JSON.stringify(choices)}});

  const file = new File(['image: redis:7'], 'values.yaml', {type: 'text/yaml'});

  fireEvent.change(screen.getByLabelText('Missing files or archive'), {target: {files: [file]}});

  // jsdom does not propagate fireEvent's FileList into native FormData(form).

  // Bridge only file extraction; all named fields use the real form serializer.

  const NativeFormData = FormData;

  vi.stubGlobal('FormData', class extends NativeFormData {

    constructor(form?: HTMLFormElement) {

      super(form);

      form?.querySelectorAll<HTMLInputElement>('input[type="file"]').forEach(input => {

        if (input.files?.[0]) this.set(input.name, input.files[0]);

      });

    }

  });

  fireEvent.change(screen.getByLabelText(/Destination directory/), {target: {value: 'dependencies'}});

  fireEvent.click(screen.getByRole('checkbox', {name: /These files contain no passwords/}));

  fireEvent.submit(screen.getByRole('button', {name: 'Add files and resolve new version'}).closest('form')!);

  await screen.findByText('redis:7');

  const mutations = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');

  expect(mutations).toHaveLength(1);

  expect(new URL(mutations[0][0]).pathname).toBe('/api/discovery/job-1/supplements');

  const body = mutations[0][1]?.body as FormData;

  expect(body).toBeInstanceOf(FormData);

  expect(body.get('upload')).toBeInstanceOf(File);

  expect((body.get('upload') as File).name).toBe('values.yaml');

  expect((body.get('upload') as File).size).toBe(file.size);

  expect(body.get('target_path')).toBe('dependencies');

  expect(body.get('acknowledge_non_secret')).toBe('true');

  expect(body.get('csrf_token')).toBe('supplement-token');

  expect(JSON.parse(String(body.get('options')))).toEqual(choices);

  expect(fetch.mock.calls.some(([url]) => new URL(url).pathname === '/api/discovery/job-2')).toBe(true);

  expect(screen.queryByText('nginx:1')).not.toBeInTheDocument();

});



it('shows missing chart keys and retries with selected values instead of a successful empty inventory', async () => {

  const empty = {...inventory, images: [], candidate_values_files: ['examples/values.yaml'], diagnostics: [{code: 'native_render_failed', path: 'Chart.yaml', message: 'Select deployment configuration.', value_paths: ['global.psql.host']}]};

  const fetch = vi.fn(async (url: string, init?: RequestInit) => new Response(JSON.stringify(init?.method === 'POST' ? {job_id: 'job-2'} : url.endsWith('/job-1') ? {job: catalog.jobs[0], inventory: empty} : url.endsWith('/job-2') ? {job: {id: 'job-2', status: 'queued'}, inventory: null} : catalog), {headers: {'Content-Type': 'application/json'}}));

  vi.stubGlobal('fetch', fetch); render(<Page data={{csrf_token: 'token'}}/>);

  await screen.findByText('Needs attention - Review unresolved configuration');
  expect(screen.getByText('No images were rendered.')).toBeVisible();
  const resolutionPanel = screen.getByText('Resolve configuration and rediscover').closest('details')!;
  expect(resolutionPanel.open).toBe(true);
  expect(resolutionPanel.compareDocumentPosition(screen.getByRole('checkbox', {name: 'deploy/chart helm'})) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

  expect(screen.getByText('global.psql.host')).toBeInTheDocument();

  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Add values file'), {target: {value: 'examples/values.yaml'}});

  fireEvent.click(screen.getByRole('button', {name: 'Render with selected values'}));

  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true));

  const mutation = fetch.mock.calls.find(([, init]) => init?.method === 'POST');

  expect(JSON.parse(String(mutation?.[1]?.body)).options.values_files).toEqual(['examples/values.yaml']);

});
