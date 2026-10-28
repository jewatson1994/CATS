import {afterEach, expect, it} from 'vitest';
import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {ImagePatchAction, ImagePatchHistory} from './ImagePatchControls';

afterEach(cleanup);
const image = {id: 4, image_reference: 'registry/app:v1', image_digest: `sha256:${'a'.repeat(64)}`, lifecycle_status: 'active'};

it('opens the patch workflow with the exact service and image selected', () => {
  render(<ImagePatchAction image={image} serviceKey="my service" allowed/>);
  const url = new URL(screen.getByRole('link', {name: 'Patch registry/app:v1'}).getAttribute('href')!, window.location.origin);
  expect(url.pathname).toBe('/patch-campaigns');
  expect(url.searchParams.get('service_id')).toBe('my service');
  expect(url.searchParams.get('image_id')).toBe('4');
});

it('blocks missing or conflicting digests and hides actions for inactive or unauthorized images', () => {
  const {rerender} = render(<ImagePatchAction image={{...image, image_digest: ''}} serviceKey="app" allowed/>);
  expect(screen.getByRole('button', {name: 'Patch registry/app:v1'})).toBeDisabled();
  expect(screen.getByText(/Scan this image/)).toBeInTheDocument();
  rerender(<ImagePatchAction image={{...image, image_reference: `registry/app@sha256:${'b'.repeat(64)}`}} serviceKey="app" allowed/>);
  expect(screen.getByRole('button')).toBeDisabled();
  rerender(<ImagePatchAction image={{...image, lifecycle_status: 'replaced'}} serviceKey="app" allowed/>);
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
  rerender(<ImagePatchAction image={image} serviceKey="app" allowed={false}/>);
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
});

it('reveals original image, timestamp with timezone, and retained results from the marker', () => {
  const patched_at = '2026-10-25T12:34:56+00:00';
  const {container} = render(<ImagePatchHistory image={{...image, patch_history: [{original_image: 'registry/original:v0', result_image: image.image_reference, patched_at, job_id: 'job-1'}]}}/>);
  expect(container.querySelector('details')).not.toHaveAttribute('open');
  fireEvent.click(screen.getByLabelText('Patch history for registry/app:v1'));
  expect(container.querySelector('details')).toHaveAttribute('open');
  expect(screen.getByText('registry/original:v0')).toBeVisible();
  expect(container.querySelector('time')).toHaveAttribute('datetime', patched_at);
  expect(container.querySelector('time')).toHaveTextContent(new Date(patched_at).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'long'}));
  expect(screen.getByRole('link', {name: 'View patch results'})).toHaveAttribute('href', '/api/public/patch-jobs/job-1/results');
});

it('does not label ordinary replacements as patched without verified history', () => {
  const {container} = render(<ImagePatchHistory image={image}/>);
  expect(container).toBeEmptyDOMElement();
});
