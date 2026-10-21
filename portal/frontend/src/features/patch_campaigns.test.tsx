import {afterEach, expect, it, vi} from 'vitest';
import {fireEvent, render, screen, waitFor} from '@testing-library/react';
import {Page} from './patch_campaigns';
const data = {services: [{service_key: 'payments', name: 'Payments'}], configured_registries: [{id: 'main', display_name: 'Internal registry'}], csrf_token: 'token'};
const images = [{id: 1, image_reference: 'registry/first:v1', image_digest: `sha256:${'a'.repeat(64)}`}, {id: 2, image_reference: 'registry/second:v1', image_digest: `sha256:${'b'.repeat(64)}`}, {id: 3, image_reference: 'registry/third:v1', image_digest: `sha256:${'c'.repeat(64)}`}];
const response = (value: unknown) => new Response(JSON.stringify(value), {headers: {'content-type': 'application/json'}});
afterEach(() => {vi.unstubAllGlobals(); window.history.replaceState(null, '', '/');});
function open() {window.history.replaceState(null, '', '/patch-campaigns?service_id=payments'); render(<Page data={data}/>);}
it('bounds select-all and enforces permission before submission', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({images, campaigns: [], can_patch: true, max_images: 2})));
  open();
  fireEvent.click(await screen.findByRole('button', {name: 'Select first 2 images'}));
  expect(screen.getByText('2 selected · Up to 2 images per campaign.')).toBeInTheDocument();
  expect(screen.getAllByRole('checkbox')[2]).toBeDisabled();
  expect(screen.getByRole('button', {name: 'Start patch campaign'})).toBeDisabled();
});
it('submits selected images and shows separate per-image failures and results', async () => {
  const fetch = vi.fn().mockResolvedValueOnce(response({images, campaigns: [], can_patch: true})).mockResolvedValueOnce(response({id: 9})).mockImplementation((url: string) => Promise.resolve(response(url.includes('/api/patch-campaigns/') ? {id: 9, status: 'completed', items: [{image_id: 1, image_reference: images[0].image_reference, status: 'complete', job_id: 'j1', result: {patch_status: 'PATCHED', signature_status: 'verified'}}, {image_id: 2, image_reference: images[1].image_reference, status: 'failed', error: 'Source image unavailable'}]} : {images, campaigns: [{id: 9, status: 'completed'}], can_patch: true})));
  vi.stubGlobal('fetch', fetch); open();
  fireEvent.click(await screen.findByRole('button', {name: 'Select all eligible images'}));
  fireEvent.change(screen.getByLabelText('Destination registry'), {target: {value: 'main'}});
  fireEvent.change(screen.getByLabelText('Destination prefix'), {target: {value: 'team/patched'}});
  fireEvent.click(screen.getByRole('button', {name: 'Start patch campaign'}));
  await screen.findByText('Source image unavailable');
  expect(screen.getByRole('link', {name: 'View image results'})).toHaveAttribute('href', '/api/public/patch-jobs/j1/results');
  const post = fetch.mock.calls.find((call: any[]) => call[1]?.method === 'POST');
  expect(JSON.parse(post![1].body)).toEqual({image_ids: [1, 2, 3], destination_registry_id: 'main', destination_prefix: 'team/patched'});
  expect(post![1].headers.get('X-CSRF-Token')).toBe('token');
});
it('leaves unauthorized selections and submission disabled', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({images, campaigns: [], can_patch: false})));
  open(); await screen.findByText('You do not have permission to start patch campaigns for this service.');
  for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled();
  expect(screen.getByRole('button', {name: 'Start patch campaign'})).toBeDisabled();
});
it('retries a failed inventory read', async () => {
  const fetch = vi.fn().mockRejectedValueOnce(new Error('Inventory unavailable')).mockResolvedValueOnce(response({images: [], campaigns: [], can_patch: true}));
  vi.stubGlobal('fetch', fetch); open();
  await screen.findByText('Inventory unavailable'); fireEvent.click(screen.getByRole('button', {name: 'Retry'}));
  await screen.findByText('No images available'); await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
});

it('does not select a mutable tag without retained digest evidence', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({images: [{id: 1, image_reference: 'registry/mutable:latest'}, images[1]], campaigns: [], can_patch: true})));
  open();
  fireEvent.click(await screen.findByRole('button', {name: 'Select all eligible images'}));
  expect(screen.getAllByRole('checkbox')[0]).toBeDisabled();
  expect(screen.getAllByRole('checkbox')[0]).not.toBeChecked();
  expect(screen.getAllByRole('checkbox')[1]).toBeChecked();
  expect(screen.getByText('A consistent immutable digest is required before patching.')).toBeInTheDocument();
});

it('allows an empty prefix and rejects conflicting immutable identities', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({images: [{...images[0], image_reference: `registry/first@sha256:${'b'.repeat(64)}`}, images[1]], campaigns: [], can_patch: true})));
  open();
  fireEvent.click(await screen.findByRole('button', {name: 'Select all eligible images'}));
  expect(screen.getAllByRole('checkbox')[0]).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Destination registry'), {target: {value: 'main'}});
  expect(screen.getByRole('button', {name: 'Start patch campaign'})).toBeEnabled();
});

it('uses server capabilities for scoped cancellation and safe retry', async () => {
  const detail = {id:9,status:'failed',items:[{id:10,image_id:1,image_reference:'registry/first',status:'queued',can_cancel:true},{id:11,image_id:2,image_reference:'registry/second',status:'failed',can_retry:true},{id:12,image_id:3,image_reference:'registry/third',status:'running',cancel_requested:true}]};
  const fetch = vi.fn().mockImplementation((url:string) => Promise.resolve(response(url.includes('/api/patch-campaigns/') ? detail : {images:[],campaigns:[{id:9,status:'failed'}],can_patch:true})));
  vi.stubGlobal('fetch',fetch); open();
  fireEvent.click(await screen.findByRole('button',{name:'Campaign 9 · failed'}));
  fireEvent.click(await screen.findByRole('button',{name:'Cancel image registry/first'}));
  await screen.findByText(/Cancellation requested/);
  await screen.findByRole('button',{name:'Retry image registry/second'});
  fireEvent.click(screen.getByRole('button',{name:'Retry image registry/second'}));
  await screen.findByText('Image retry requested.');
  const posts = fetch.mock.calls.filter(call => call[1]?.method === 'POST');
  expect(posts.map(call => new URL(call[0]).pathname)).toEqual(['/api/patch-campaigns/9/items/10/cancel','/api/patch-campaigns/9/items/11/retry']);
  expect(posts[0][1].headers.get('X-CSRF-Token')).toBe('token');
  expect(screen.queryByRole('button',{name:'Retry image registry/third'})).not.toBeInTheDocument();
  await screen.findByText('Cancellation pending worker acknowledgment.');
});
