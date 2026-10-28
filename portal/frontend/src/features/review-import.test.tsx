import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {ReviewImport} from './review-import';
import {Requests} from './remediations';

vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.clearAllMocks();});
const data = {service: {id: 1, service_key: 'sample key', name: 'Sample'}, csrf_token: 'csrf', review_import_kinds: ['poams', 'mitigations', 'exceptions']};
function openImport() {
  const {container} = render(<ReviewImport data={data}/>);
  container.querySelector('dialog')!.setAttribute('open', '');
  return container;
}

it('previews an uploaded file, then submits one batch with CSRF only after confirmation', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({token: 'preview-token', recognized: 2, errors: [], rows: [
    {row: 2, values: {title: 'Upgrade library', remediation: 'Update base image'}},
    {row: 3, values: {title: 'Rotate credentials', remediation: 'Replace secret'}},
  ]}).mockResolvedValueOnce({batch_id: 12, count: 2, href: '/requests?batch_id=12'});
  openImport();
  fireEvent.change(screen.getByLabelText('Entry type'), {target: {value: 'mitigations'}});
  expect(screen.getByRole('link', {name: 'Download Mitigations template'})).toHaveAttribute('href', '/services/sample%20key/review-imports/mitigations/template.csv');
  const upload = new File(['title,description,remediation'], 'plans.csv', {type: 'text/csv'});
  fireEvent.change(screen.getByLabelText('Import file'), {target: {files: [upload]}});
  fireEvent.submit(screen.getByLabelText('Import file').closest('form')!);
  await screen.findByRole('cell', {name: 'Upgrade library'});
  expect(requestJson).toHaveBeenCalledTimes(1);
  const [url, options] = vi.mocked(requestJson).mock.calls[0];
  expect(url).toBe('/services/sample%20key/review-imports/mitigations/preview');
  expect((options?.body as FormData).get('csrf_token')).toBe('csrf');
  expect((options?.body as FormData).get('upload')).toBeInstanceOf(File);
  fireEvent.click(screen.getByRole('button', {name: 'Submit 2 entries for Cyber review'}));
  expect(await screen.findByRole('link', {name: 'Open review request'})).toHaveAttribute('href', '/requests?batch_id=12');
  expect(screen.getByRole('status')).toHaveTextContent('Submitted 2 entries in one Cyber review request.');
  const [confirmUrl, confirmOptions] = vi.mocked(requestJson).mock.calls[1];
  expect(confirmUrl).toBe('/services/sample%20key/review-imports/confirm/preview-token');
  expect((confirmOptions?.body as FormData).get('csrf_token')).toBe('csrf');
});

it('blocks invalid imports and discards a preview when the file changes', async () => {
  vi.mocked(requestJson).mockResolvedValue({token: null, recognized: 1, rows: [{row: 2, values: {title: 'Short'}}],
    errors: [{row: 2, field: 'remediation', message: 'Supply at least 3 characters'}]});
  openImport();
  fireEvent.submit(screen.getByLabelText('Import file').closest('form')!);
  expect(await screen.findByRole('alert')).toHaveTextContent('Row 2: Remediation — Supply at least 3 characters');
  expect(screen.getByRole('button', {name: 'Submit 1 entry for Cyber review'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Import file'), {target: {files: [new File([''], 'corrected.csv')]}});
  expect(screen.queryByRole('region', {name: 'Import preview'})).not.toBeInTheDocument();
});

it('does not offer import without an allowed import kind', () => {
  render(<ReviewImport data={{...data, review_import_kinds: []}}/>);
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
});

const batch = {id: 12, name: 'Sample · mitigations.csv', count: 2, pending: 1, approved: 1, rejected: 0, href: '/requests?batch_id=12'};
const workflow = {id: 23, request_type: 'poam', service: data.service, subject: 'Upgrade library', requested_by: 'Owner', justification: 'Update base image', status: 'pending', can_review: true, import_row_number: 2};

it('shows one batch link on Requests and retains the individual request review flow', () => {
  render(<Requests data={{csrf_token: 'csrf', import_batches: [batch], workflows: [{...workflow, import_row_number: null}], request_type_filter: 'all'}}/>);
  expect(screen.getAllByRole('link', {name: batch.name})).toHaveLength(1);
  expect(screen.getByRole('link', {name: batch.name})).toHaveAttribute('href', batch.href);
  expect(screen.getByRole('button', {name: 'Review'})).toBeInTheDocument();
});

it('opens a batch with per-row approval and denial while reviewed entries have no controls', () => {
  render(<Requests data={{csrf_token: 'csrf', selected_import_batch: batch, workflows: [workflow,
    {...workflow, id: 24, import_row_number: 3, subject: 'Rotate credentials', status: 'approved', can_review: false, reviewed_by: 'Cyber analyst', review_reason: 'Verified'}]}}/>);
  expect(screen.getByText('2 entries · 1 pending · 1 approved · 0 denied')).toBeInTheDocument();
  const form = screen.getByRole('form', {name: 'Review row 2'});
  expect(form).toHaveAttribute('action', '/requests/23/review');
  expect(form.querySelector('[name="csrf_token"]')).toHaveValue('csrf');
  expect(within(form).getByRole('button', {name: 'Approve'})).toHaveAttribute('value', 'approved');
  fireEvent.click(within(form).getByRole('button', {name: 'Deny'}));
  expect(within(form).getByLabelText('Review note')).toBeRequired();
  expect(screen.queryByRole('form', {name: 'Review row 3'})).not.toBeInTheDocument();
  expect(screen.getByText('Cyber analyst')).toBeInTheDocument();
});

it('leaves pending rows read-only for a requester who cannot review', () => {
  render(<Requests data={{selected_import_batch: batch, workflows: [{...workflow, can_review: false}]}}/>);
  expect(screen.queryByRole('button', {name: 'Approve'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Deny'})).not.toBeInTheDocument();
});
