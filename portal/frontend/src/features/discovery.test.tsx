import {afterEach, expect, it, vi} from 'vitest';

import {act, fireEvent, render, screen, waitFor, within} from '@testing-library/react';

import {Page, isPartial} from './discovery';

const catalog = {groups: [{id: 1, name: 'Platform'}], services: [{id: 2, name: 'Payments', service_key: 'payments', group_id: 1}, {id: 3, name: 'Other', service_key: 'other', group_id: 9}], jobs: [{id: 'job-1', status: 'completed', group_id: 1}]};

const inventory = {roots: [{id: 'root', path: 'deploy/chart', technology: 'helm', completeness: 'partial'}], nodes: [{id: 'node', root_id: 'root', name: 'api', kind: 'deployment', state: 'resolved', provenance: {path: 'templates/api.yaml'}}], images: [{reference: 'nginx:1', root_id: 'root'}], diagnostics: [{message: 'Missing values'}], completeness: 'partial'};

afterEach(() => vi.unstubAllGlobals());

it('loads grouped GitLab revisions and submits the selected tag even when a branch has the same name', async () => {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/gitlab/refs')) return Response.json({branches: ['release'], tags: ['release'], truncated: true});
    if (init?.method === 'POST') return Response.json({job_id: 'new'});
    if (url.endsWith('/new')) return Response.json({job: {id: 'new', status: 'completed'}, inventory: {...inventory, gitlab_source: {
      repository_url: 'https://gitlab.example.com/team/project', requested_ref: 'release', ref_kind: 'tag', commit_sha: '9'.repeat(40),
    }}});
    return Response.json({...catalog, jobs: []});
  });
  vi.stubGlobal('fetch', fetch);
  render(<Page data={{csrf_token: 'csrf'}}/>);
  await screen.findByRole('option', {name: 'Platform'});
  fireEvent.change(screen.getByLabelText('Owning group'), {target: {value: '1'}});
  fireEvent.change(screen.getByLabelText('Source type'), {target: {value: 'gitlab'}});
  const repository = 'https://gitlab.example.com/team/project';
  fireEvent.change(screen.getByLabelText('GitLab repository URL'), {target: {value: repository}});
  const token = screen.getByLabelText('Access token (optional)');
  fireEvent.change(token, {target: {value: 'private-token'}});
  const manual = screen.getByLabelText('Branch or tag (optional)');
  fireEvent.change(manual, {target: {value: 'rel'}});
  fireEvent.click(screen.getByRole('button', {name: 'Load branches and tags'}));
  const picker = await screen.findByLabelText('Available branches and tags');
  const lookup = fetch.mock.calls.find(([url]) => url.endsWith('/gitlab/refs'))![1]!;
  expect(lookup.method).toBe('POST');
  expect(JSON.parse(String(lookup.body))).toEqual({group_id: 1, repository_url: repository, git_token: 'private-token', csrf_token: 'csrf', search: 'rel'});
  expect(token).toHaveValue('private-token');
  expect(within(picker).getByRole('group', {name: 'Tags'})).toBeInTheDocument();
  expect(within(picker).getByRole('group', {name: 'Branches'})).toBeInTheDocument();
  expect(screen.getByText(/More results are available/)).toBeVisible();
  fireEvent.change(picker, {target: {value: 'branch/release'}});
  expect(manual).toHaveValue('release');
  const form = screen.getByRole('button', {name: 'Start discovery'}).closest('form')!;
  expect(new FormData(form).get('git_ref_kind')).toBe('branch');
  fireEvent.change(manual, {target: {value: 'manual/ref'}});
  expect(new FormData(form).has('git_ref_kind')).toBe(false);
  fireEvent.change(picker, {target: {value: 'tag/release'}});
  fireEvent.click(screen.getByRole('checkbox', {name: /I confirm the repository files/}));
  fireEvent.click(screen.getByRole('button', {name: 'Start discovery'}));
  await screen.findByText('nginx:1');
  expect(screen.getByText('release', {selector: 'code'}).parentElement).toHaveTextContent('Tag release');
  const submit = fetch.mock.calls.find(([url, init]) => url.endsWith('/api/discovery') && init?.method === 'POST')![1]!;
  expect((submit.body as FormData).get('git_ref_kind')).toBe('tag');
  expect((submit.body as FormData).get('git_ref')).toBe('release');
  expect(token).toHaveValue('');
  expect(picker).not.toBeInTheDocument();
});

it('discards stale GitLab choices after project, credential or group changes and keeps manual entry on lookup failure', async () => {
  const pending: ((value: Response) => void)[] = [];
  vi.stubGlobal('fetch', async (url: string) => url.endsWith('/gitlab/refs')
    ? new Promise<Response>(resolve => pending.push(resolve))
    : Response.json({...catalog, jobs: [], groups: [...catalog.groups, {id: 2, name: 'Research'}]}));
  render(<Page data={{csrf_token: 'csrf'}}/>);
  await screen.findByRole('option', {name: 'Platform'});
  const group = screen.getByLabelText('Owning group');
  fireEvent.change(group, {target: {value: '1'}});
  fireEvent.change(screen.getByLabelText('Source type'), {target: {value: 'gitlab'}});
  const url = screen.getByLabelText('GitLab repository URL');
  const load = () => fireEvent.click(screen.getByRole('button', {name: 'Load branches and tags'}));
  const result = (name: string) => Response.json({branches: [name], tags: [], truncated: false});
  fireEvent.change(url, {target: {value: 'https://gitlab.example.com/team/one'}});
  load();
  fireEvent.change(url, {target: {value: 'https://gitlab.example.com/team/two'}});
  load();
  await act(async () => { pending[1](result('current')); pending[0](result('stale')); });
  expect(screen.getByRole('option', {name: 'current'})).toBeInTheDocument();
  expect(screen.queryByRole('option', {name: 'stale'})).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Access token (optional)'), {target: {value: 'new-token'}});
  expect(screen.queryByLabelText('Available branches and tags')).not.toBeInTheDocument();
  load();
  await act(async () => pending[2](result('private')));
  expect(screen.getByRole('option', {name: 'private'})).toBeInTheDocument();
  fireEvent.change(group, {target: {value: '2'}});
  expect(screen.queryByLabelText('Available branches and tags')).not.toBeInTheDocument();
  load();
  await act(async () => pending[3](Response.json({detail: 'GitLab denied access.'}, {status: 403})));
  expect(screen.getByRole('alert')).toHaveTextContent('GitLab denied access.');
  fireEvent.change(screen.getByLabelText('Branch or tag (optional)'), {target: {value: 'manual'}});
  expect(screen.getByLabelText('Branch or tag (optional)')).toHaveValue('manual');
});

it.each([
  {mode: 'private', ref: 'release/v2', token: 'test-read-token'},
  {mode: 'public', ref: '', token: ''},
])('submits a $mode GitLab repository and shows its resolved commit', async ({ref, token}) => {
  const repository = 'https://gitlab.example.com/team/platform/payments';
  const source = {repository_url: repository, requested_ref: ref, commit_sha: '01'.repeat(20)};
  let finishFetch!: (response: Response) => void;
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') return new Promise<Response>(resolve => {finishFetch = resolve;});
    if (url.endsWith('/new')) return Response.json({job: {id: 'new', group_id: 1, status: 'completed', gitlab_source: source}, inventory});
    return Response.json({...catalog, jobs: []});
  });
  vi.stubGlobal('fetch', fetch);
  render(<Page data={{csrf_token: 'csrf'}}/>);
  await screen.findByRole('option', {name: 'Platform'});
  fireEvent.change(screen.getByLabelText('Owning group'), {target: {value: '1'}});
  fireEvent.change(screen.getByLabelText('Source type'), {target: {value: 'gitlab'}});
  fireEvent.change(screen.getByLabelText('GitLab repository URL'), {target: {value: repository}});
  const tokenInput = screen.getByLabelText('Access token (optional)');
  expect(tokenInput).toHaveAttribute('type', 'password');
  if (ref) fireEvent.change(screen.getByLabelText('Branch or tag (optional)'), {target: {value: ref}});
  if (token) fireEvent.change(tokenInput, {target: {value: token}});

  const start = screen.getByRole('button', {name: 'Start discovery'});
  fireEvent.click(start);
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
  fireEvent.click(screen.getByRole('checkbox', {name: /I confirm the repository files/}));
  fireEvent.click(start);
  expect(screen.getByRole('button', {name: 'Fetching repository…'})).toBeDisabled();
  expect(tokenInput).toHaveValue('');

  const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(new URL(posts[0][0]).pathname).toBe('/api/discovery');
  expect(Object.fromEntries((posts[0][1]?.body as FormData).entries())).toEqual({
    input_kind: 'gitlab', group_id: '1', repository_url: repository, git_ref: ref, git_token: token,
    acknowledge_non_secret: 'true', csrf_token: 'csrf', options: JSON.stringify({environment: '', values_files: []}),
  });
  finishFetch(Response.json({job_id: 'new'}));
  expect(await screen.findByText(source.commit_sha)).toBeVisible();
  expect(screen.getByText(repository)).toBeVisible();
  expect(screen.getByText(ref || 'Default branch', {selector: 'code'})).toBeVisible();
});

it('shows a product chart identity with its source path and identifies unresolved children', async () => {
  const product = {...inventory,
    roots: [{...inventory.roots[0], chart_name: 'payments', chart_version: '2.1.0'}],
    diagnostics: [{code: 'catalog_chart_unresolved', component_name: 'billing-db', message: 'Missing chart archive.'}],
  };
  vi.stubGlobal('fetch', async (url: string) => new Response(JSON.stringify(
    url.endsWith('/job-1') ? {job: catalog.jobs[0], inventory: product} : catalog),
    {headers: {'Content-Type': 'application/json'}}));
  render(<Page data={{csrf_token: 'token'}}/>);
  expect(await screen.findByRole('checkbox', {name: 'payments 2.1.0 deploy/chart helm'})).toBeVisible();
  expect(screen.getByText('billing-db needs attention')).toBeVisible();
  expect(screen.getByText('Missing chart archive.')).toBeVisible();
});

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

it('restores isolated component values and submits explicit override order', async () => {
  const configured = {...inventory, candidate_values_files: ['a.yaml', 'b.yaml'], selection: {values_files: ['parent.yaml'], component_values: {child: ['a.yaml', 'b.yaml']}}, configurable_components: [{id: 'child', label: 'Child release', path: 'Chart.yaml', technology: 'helm', values_origin: 'Generated ConfigMap'}], diagnostics: [{code: 'native_render_failed', renderer: 'kustomize', path: 'kustomization.yaml', message: 'Missing base'}]};
  const fetch = vi.fn(async (url: string, init?: RequestInit) => new Response(JSON.stringify(init?.method === 'POST' ? {} : url.endsWith('/job-1') ? {job: catalog.jobs[0], inventory: configured} : catalog), {headers: {'Content-Type': 'application/json'}}));
  vi.stubGlobal('fetch', fetch); render(<Page data={{csrf_token: 'token'}}/>);
  await screen.findByText('Kustomize configuration needs attention');
  expect(screen.getByText('Base configuration: Generated ConfigMap')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Move b.yaml earlier for Child release', hidden: true}));
  fireEvent.click(screen.getByRole('button', {name: 'Render with selected values'}));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true));
  const request = fetch.mock.calls.find(([, init]) => init?.method === 'POST');
  expect(JSON.parse(String(request?.[1]?.body)).options).toEqual({values_files: ['parent.yaml'], component_values: {child: ['b.yaml', 'a.yaml']}});
});
