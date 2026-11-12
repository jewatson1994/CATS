import {act, cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import {ComposeFiles} from './compose_files';

const request = vi.hoisted(() => vi.fn());
vi.mock('../api', () => ({requestJson: request}));
beforeEach(() => request.mockReset());
afterEach(cleanup);
const names = ['project/Compose.txt', 'project/compose.main.yaml(2)', 'other/deployment'];
const variable = (name: string, required = false) => ({name, required, sources: [names[0]], services: ['web']});
const result = (missing = [variable('IMAGE_TAG', true), variable('RUNTIME_TOKEN')]) => ({files: names, default_files: [names[0]], missing_variables: missing});
function upload(files = [new File(['archive'], 'bundle.zip')]) {
  fireEvent.change(screen.getByLabelText(/Docker Compose files/), {target: {files}});
}
function body(index: number) { return request.mock.calls[index][1].body as FormData; }
function submittedValues() {
  const form = screen.getByLabelText(/Compose file order/).closest('form')!;
  return JSON.parse(new FormData(form).get('compose_variables') as string);
}
async function inspected() {
  await waitFor(() => expect(screen.queryByText('Inspecting Compose documents and variables…')).not.toBeInTheDocument());
}

it('lists archive documents and submits a unique, ordered subset using numbered dropdowns', async () => {
  request.mockResolvedValue({...result([]), default_files: []});
  const state = vi.fn();
  render(<form><ComposeFiles onStateChange={state} /></form>);
  upload();
  await screen.findByText('Detected Compose documents (3)');
  expect(request.mock.calls[0][0]).toBe('/api/public/compose/files');
  expect(body(0).getAll('compose_uploads')).toHaveLength(1);
  expect(body(0).has('compose_files')).toBe(false);
  expect(state).toHaveBeenLastCalledWith('Choose at least one Compose document and its merge order.');
  fireEvent.change(screen.getByLabelText(names[0]), {target: {value: '1'}});
  fireEvent.change(screen.getByLabelText(names[1]), {target: {value: '2'}});
  fireEvent.change(screen.getByLabelText(names[1]), {target: {value: '1'}});
  expect(screen.getByLabelText(names[0])).toHaveValue('2');
  expect(screen.getByLabelText(names[2])).toHaveValue('');
  expect(screen.getByLabelText(/Compose file order/)).toHaveValue(names[1] + '\n' + names[0]);
  const form = screen.getByLabelText(/Compose file order/).closest('form')!;
  expect(new FormData(form).get('compose_files')).toBe(names[1] + '\n' + names[0]);
  fireEvent.change(screen.getByLabelText(names[1]), {target: {value: ''}});
  expect(screen.getByLabelText(names[0])).toHaveValue('1');
  expect(state).toHaveBeenLastCalledWith('Wait for Compose file inspection to finish.');
  await inspected();
  expect(request).toHaveBeenCalledTimes(2);
  expect(body(1).get('compose_files')).toBe(names[0]);
  expect(state).toHaveBeenLastCalledWith('');
});

it('shows missing names and metadata, masks explicit values, and keeps untouched blanks absent', async () => {
  request.mockResolvedValue(result());
  const state = vi.fn();
  render(<form><ComposeFiles profiles="production" onStateChange={state} /></form>);
  upload();
  const imageTag = await screen.findByLabelText('IMAGE_TAG');
  expect(imageTag).toHaveAttribute('type', 'password');
  expect(imageTag).not.toBeRequired();
  expect(imageTag).toHaveAccessibleDescription(`Required by a Compose expression. Files: ${names[0]}. Services: web.`);
  expect(body(0).get('compose_profiles')).toBe('production');
  expect(body(0).get('compose_variables')).toBe('{}');
  expect(submittedValues()).toEqual({});
  fireEvent.change(imageTag, {target: {value: 'release-2'}});
  expect(submittedValues()).toEqual({IMAGE_TAG: 'release-2'});
  expect(request).toHaveBeenCalledTimes(1);
  expect(state).toHaveBeenLastCalledWith('');
  fireEvent.click(screen.getByLabelText('Use an empty value for RUNTIME_TOKEN'));
  expect(submittedValues()).toEqual({IMAGE_TAG: 'release-2', RUNTIME_TOKEN: ''});
  fireEvent.click(screen.getByLabelText('Use an empty value for RUNTIME_TOKEN'));
  fireEvent.change(imageTag, {target: {value: ''}});
  expect(submittedValues()).toEqual({});
});

it('supports variable names that also occur on JavaScript objects', async () => {
  request.mockResolvedValue(result(['constructor', '__proto__', 'toString'].map(name => variable(name))));
  render(<form><ComposeFiles onStateChange={vi.fn()} /></form>);
  upload();
  await screen.findByLabelText('constructor');
  for (const name of ['constructor', '__proto__', 'toString']) {
    expect(screen.getByLabelText(name)).toHaveValue('');
    fireEvent.change(screen.getByLabelText(name), {target: {value: `value-${name}`}});
  }
  expect(submittedValues()).toEqual(JSON.parse('{"constructor":"value-constructor","__proto__":"value-__proto__","toString":"value-toString"}'));
});

it('rechecks nested variables, retains resolved values, and includes current values when profiles or order change', async () => {
  request.mockResolvedValueOnce(result()).mockResolvedValue(result([variable('NESTED_TAG')]));
  const state = vi.fn();
  const view = render(<form><ComposeFiles onStateChange={state} /></form>);
  upload();
  fireEvent.change(await screen.findByLabelText('IMAGE_TAG'), {target: {value: 'release-2'}});
  fireEvent.click(screen.getByRole('button', {name: 'Recheck variables'}));
  await screen.findByLabelText('NESTED_TAG');
  expect(body(1).get('compose_variables')).toBe('{"IMAGE_TAG":"release-2"}');
  expect(screen.getByLabelText('IMAGE_TAG')).toHaveValue('release-2');
  expect(screen.getByLabelText('IMAGE_TAG')).toHaveAccessibleDescription(expect.stringContaining('Provided value retained.'));
  expect(submittedValues()).toEqual({IMAGE_TAG: 'release-2'});
  fireEvent.change(screen.getByLabelText('NESTED_TAG'), {target: {value: 'latest'}});
  view.rerender(<form><ComposeFiles profiles="production" onStateChange={state} /></form>);
  expect(state).toHaveBeenLastCalledWith('Wait for Compose file inspection to finish.');
  await inspected();
  expect(body(2).get('compose_profiles')).toBe('production');
  expect(body(2).get('compose_variables')).toBe('{"IMAGE_TAG":"release-2","NESTED_TAG":"latest"}');
  fireEvent.change(screen.getByLabelText(/Compose file order/), {target: {value: names[1] + '\n' + names[0]}});
  await inspected();
  expect(body(3).get('compose_files')).toBe(names[1] + '\n' + names[0]);
  fireEvent.change(screen.getByLabelText(/Compose file order/), {target: {value: ''}});
  await inspected();
  expect(body(4).get('compose_files')).toBe('');
  expect(state).toHaveBeenLastCalledWith('Choose at least one Compose document and its merge order.');
});

it('reports no missing variables for defaults and clears values when uploads change or are removed', async () => {
  request.mockResolvedValueOnce(result()).mockResolvedValueOnce(result([]))
    .mockResolvedValueOnce({files: [], default_files: [], missing_variables: []});
  const state = vi.fn();
  render(<form><ComposeFiles onStateChange={state} /></form>);
  upload();
  fireEvent.change(await screen.findByLabelText('IMAGE_TAG'), {target: {value: 'release-2'}});
  upload();
  expect(submittedValues()).toEqual({});
  await screen.findByText('No missing variables were found for the selected files and profiles.');
  expect(screen.getByLabelText(names[0])).toHaveValue('1');
  expect(screen.queryByLabelText('IMAGE_TAG')).not.toBeInTheDocument();
  expect(body(1).get('compose_variables')).toBe('{}');
  upload();
  await screen.findByText('No Compose documents were found in these files.');
  expect(screen.getByLabelText(/Compose file order/)).toHaveValue('');
  upload([]);
  expect(screen.queryByText(/Detected Compose documents/)).not.toBeInTheDocument();
  expect(state).toHaveBeenLastCalledWith('');
});

it('retries failed inspections and ignores responses for replaced uploads', async () => {
  let resolveOld!: (value: unknown) => void;
  request.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve; }))
    .mockRejectedValueOnce(new Error('Archive is corrupt'))
    .mockResolvedValueOnce({...result([]), files: [names[1]], default_files: [names[1]]});
  render(<ComposeFiles onStateChange={vi.fn()} />);
  upload();
  await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
  upload();
  await screen.findByRole('alert');
  expect(request.mock.calls[0][1].signal.aborted).toBe(true);
  fireEvent.click(screen.getByRole('button', {name: 'Retry inspection'}));
  await screen.findByLabelText(names[1]);
  await act(async () => resolveOld(result()));
  expect(screen.getByLabelText(/Compose file order/)).toHaveValue(names[1]);
  expect(screen.queryByLabelText('IMAGE_TAG')).not.toBeInTheDocument();
});

it('ignores an obsolete merge inspection and retains entered values through retry failures', async () => {
  let resolveOld!: (value: unknown) => void;
  request.mockResolvedValueOnce(result())
    .mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve; }))
    .mockRejectedValueOnce(new Error('Inspection unavailable'))
    .mockResolvedValueOnce(result([variable('NEW_TAG')]));
  const state = vi.fn();
  render(<form><ComposeFiles onStateChange={state} /></form>);
  upload();
  fireEvent.change(await screen.findByLabelText('IMAGE_TAG'), {target: {value: 'release-2'}});
  fireEvent.change(screen.getByLabelText(/Compose file order/), {target: {value: names[1]}});
  await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
  fireEvent.change(screen.getByLabelText(/Compose file order/), {target: {value: names[2]}});
  await screen.findByRole('alert');
  expect(state).toHaveBeenLastCalledWith('Inspection unavailable');
  expect(screen.getByLabelText('IMAGE_TAG')).toHaveValue('release-2');
  fireEvent.click(screen.getByRole('button', {name: 'Retry inspection'}));
  await screen.findByLabelText('NEW_TAG');
  await act(async () => resolveOld(result([variable('OBSOLETE')])));
  expect(screen.queryByLabelText('OBSOLETE')).not.toBeInTheDocument();
  expect(screen.getByLabelText(/Compose file order/)).toHaveValue(names[2]);
  expect(body(3).get('compose_variables')).toBe('{"IMAGE_TAG":"release-2"}');
  expect(submittedValues()).toEqual({IMAGE_TAG: 'release-2'});
});
