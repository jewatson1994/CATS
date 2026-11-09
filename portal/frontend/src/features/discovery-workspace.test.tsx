import {afterEach, expect, it, vi} from 'vitest';
import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {Page} from './discovery';

const catalog = {
  groups: [{id: 1, name: 'Platform'}],
  services: [{id: 2, name: 'Payments', service_key: 'payments', group_id: 1}],
  jobs: [{id: 'job-1', status: 'completed', group_id: 1}],
};
const options = {values_files: ['base.yaml'], component_values: {api: ['prod.yaml']}, component_overrides: {api: 'image:\n  tag: stable\n'}};
function inventory(unresolved = ['api', 'worker']) {
  return {
    roots: [{id: 'root', path: 'stack/catalog.yaml', technology: 'catalog', completeness: unresolved.length ? 'partial' : 'complete'}],
    nodes: ['api', 'worker'].map(id => ({id, root_id: 'root', name: id, kind: 'ChartReference', state: unresolved.includes(id) ? 'unresolved' : 'resolved'})),
    images: [{reference: 'registry.example/api:1', root_id: 'root', component_id: 'api'}],
    configurable_components: ['api', 'worker'].map(id => ({id, root_id: 'root', label: id, path: `stack/${id}/Chart.yaml`, technology: 'helm'})),
    diagnostics: unresolved.map(id => ({code: 'native_render_failed', component_id: id, root_id: 'root', path: `stack/${id}/Chart.yaml`, message: `Missing ${id} configuration`, blocking: true})),
    candidate_values_files: ['base.yaml', 'prod.yaml'],
    completeness: unresolved.length ? 'partial' : 'complete',
  };
}
const result = (id: string, unresolved = ['api', 'worker'], saved = options) => ({job: {id, status: 'completed', group_id: 1, options: saved}, inventory: inventory(unresolved)});
async function openRecent() {
  fireEvent.change(await screen.findByLabelText('Recent discoveries'), {target: {value: 'job-1'}});
  await screen.findByText('2 unresolved resources');
}
function showInventory() {
  const summary = screen.getByText('Review discovered inventory and select deployment roots (1)');
  if (!(summary.parentElement as HTMLDetailsElement).open) fireEvent.click(summary);
}
function acknowledgeOverrides() {
  fireEvent.click(screen.getByLabelText('These overrides contain no passwords, tokens, private keys or other secrets.'));
}
afterEach(() => vi.unstubAllGlobals());

it('keeps results, service and root selections through repeated passes while the unresolved queue shrinks', async () => {
  let completedSecond = false;
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/job-1/retry')) return Response.json({job_id: 'job-2'});
    if (url.endsWith('/job-2/retry')) return Response.json({job_id: 'job-3'});
    if (url.endsWith('/job-1')) return Response.json(result('job-1'));
    if (url.endsWith('/job-2')) return Response.json(completedSecond ? result('job-2', ['worker']) : {job: {id: 'job-2', status: 'queued', group_id: 1, options}, inventory: null});
    if (url.endsWith('/job-3')) return Response.json(result('job-3', []));
    if (init?.method === 'POST') throw new Error('Unexpected mutation');
    return Response.json(catalog);
  });
  vi.stubGlobal('fetch', fetch);
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  showInventory();
  fireEvent.click(screen.getByLabelText(/^stack\/catalog\.yaml/));
  fireEvent.change(screen.getByLabelText('Service'), {target: {value: '2'}});
  fireEvent.click(screen.getByLabelText(/I acknowledge this inventory is partial/));
  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeEnabled();
  acknowledgeOverrides();
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  expect(await screen.findByText(/Rendering your changes. Previous results stay visible/)).toBeVisible();
  expect(screen.getByText('registry.example/api:1')).toBeVisible();
  expect(screen.getByLabelText(/^stack\/catalog\.yaml/)).toBeChecked();
  expect(screen.getByLabelText('Service')).toHaveValue('2');
  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeDisabled();
  expect(JSON.parse((screen.getByLabelText('Resolution settings') as HTMLTextAreaElement).value)).toEqual(options);

  completedSecond = true;
  await screen.findByText('1 unresolved resource', {}, {timeout: 4000});
  expect(screen.getByLabelText(/^stack\/catalog\.yaml/)).toBeChecked();
  expect(screen.getByLabelText('Service')).toHaveValue('2');
  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  await screen.findByText('0 unresolved resources');
  expect(screen.getByLabelText(/^stack\/catalog\.yaml/)).toBeChecked();
  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeEnabled();
  const posts = fetch.mock.calls.filter(([url]) => url.endsWith('/retry'));
  expect(posts).toHaveLength(2);
  for (const [, init] of posts) expect(JSON.parse(String(init?.body))).toEqual({csrf_token: 'token', options, acknowledge_non_secret: true});
});

it('retains the last usable inventory after a failed pass and keeps confirmation disabled', async () => {
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/retry')) return Response.json({job_id: 'job-2'});
    if (url.endsWith('/job-1')) return Response.json(result('job-1'));
    if (url.endsWith('/job-2')) return Response.json({job: {id: 'job-2', status: 'failed', group_id: 1, options, error: 'Worker unavailable'}, inventory: null});
    return Response.json(catalog);
  });
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  showInventory();
  acknowledgeOverrides();
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  await screen.findByText('Worker unavailable');
  expect(screen.getByText(/This pass did not produce a new inventory/)).toBeVisible();
  expect(screen.getByText('registry.example/api:1')).toBeVisible();
  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeDisabled();
  expect(screen.getByRole('button', {name: 'Render updated configuration'})).toBeEnabled();
  expect(JSON.parse((screen.getByLabelText('Resolution settings') as HTMLTextAreaElement).value)).toEqual(options);
});

it('reopens an invalid pass with its latest errors and previous usable inventory', async () => {
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/job-1')) return Response.json({
      job: {id: 'job-1', status: 'completed', group_id: 1, options},
      inventory: {...inventory([]), images: [], completeness: 'invalid', diagnostics: [{message: 'Invalid new values'}]},
      previous_inventory: inventory(), previous_inventory_job_id: 'previous',
    });
    return Response.json(catalog);
  });
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  showInventory();
  expect(screen.getByText('registry.example/api:1')).toBeVisible();
  expect(screen.getByText('Latest render errors (1)')).toBeVisible();
  expect(screen.getByText(/Invalid new values/, {selector: 'pre'})).toBeVisible();
  fireEvent.click(screen.getByLabelText(/^stack\/catalog\.yaml/));
  fireEvent.change(screen.getByLabelText('Service'), {target: {value: '2'}});
  fireEvent.click(screen.getByLabelText(/I acknowledge this inventory is partial/));
  expect(screen.getByRole('button', {name: 'Confirm inventory'})).toBeDisabled();
});

it.each(['null', '[]', '{', '{"values_files":42}', '{"component_values":{"api":"bad"}}', '{"component_overrides":{"api":[]}}'])('keeps invalid advanced edits reviewable without submitting: %s', async text => {
  const fetch = vi.fn(async (url: string) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/job-1')) return Response.json(result('job-1'));
    return Response.json(catalog);
  });
  vi.stubGlobal('fetch', fetch);
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  fireEvent.change(screen.getByLabelText('Resolution settings'), {target: {value: text}});
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  expect(screen.getByRole('alert')).toBeVisible();
  expect(screen.getByLabelText('Resolution settings')).toHaveValue(text);
  expect(screen.getByText('2 unresolved resources')).toBeVisible();
  expect(fetch.mock.calls.some(([url]) => url.endsWith('/retry'))).toBe(false);
});

it('preserves choices when retry returns no job ID', async () => {
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/retry')) return Response.json({});
    if (url.endsWith('/job-1')) return Response.json(result('job-1'));
    return Response.json(catalog);
  });
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  acknowledgeOverrides();
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Your settings and previous results are preserved.');
  expect(screen.getByText('2 unresolved resources')).toBeVisible();
  expect(JSON.parse((screen.getByLabelText('Resolution settings') as HTMLTextAreaElement).value)).toEqual(options);
});

it('applies canonical scrubbed settings after rendering while preserving unrelated choices', async () => {
  const scrubbed = {...options, component_overrides: {api: ''}};
  let finish: ((value: Response) => void) | undefined;
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/retry')) return Response.json({job_id: 'job-2'});
    if (url.endsWith('/job-1')) return Response.json(result('job-1'));
    if (url.endsWith('/job-2')) return new Promise<Response>(resolve => {finish = resolve;});
    return Response.json(catalog);
  });
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  acknowledgeOverrides();
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  await waitFor(() => expect(finish).toBeDefined());
  await act(async () => {finish!(Response.json(result('job-2', ['worker'], scrubbed)));});
  expect(JSON.parse((screen.getByLabelText('Resolution settings') as HTMLTextAreaElement).value)).toEqual(scrubbed);
});

it('keeps library charts as evidence without allowing their confirmation as deployment roots', async () => {
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.endsWith('/ongoing')) return Response.json({jobs: []});
    if (url.endsWith('/job-1')) return Response.json({
      ...result('job-1'), inventory: {...inventory(), roots: [{id: 'library', path: 'charts/common', technology: 'helm', chart_type: 'library', completeness: 'complete'}]},
    });
    return Response.json(catalog);
  });
  render(<Page data={{csrf_token: 'token'}}/>);
  await openRecent();
  showInventory();
  expect(screen.getByLabelText(/^charts\/common/)).toBeDisabled();
  expect(screen.getByText('Library · evidence only')).toBeVisible();
});
