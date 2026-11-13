import {afterEach, expect, it, vi} from 'vitest';
import {fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {requestJson} from '../api';
import {ImagePullInstructions} from './ImagePullInstructions';

vi.mock('../api', async original => ({...await original<object>(), requestJson: vi.fn()}));
const request = vi.mocked(requestJson);
const image = {id: 8, image_reference: 'harbor.example/team/api:current'};
const digest = `sha256:${'a'.repeat(64)}`;
const route = {repository: 'approved/42/nested/api', digest,
  reference: `cats.example:5443/approved/42/nested/api@${digest}`,
  command: `docker pull cats.example:5443/approved/42/nested/api@${digest}`,
  login_command: 'docker login cats.example:5443'};
const available = {service_id: 42, image_id: 8, image_reference: image.image_reference,
  registry: 'cats.example:5443', status: 'available', reason: null, routes: [route]};
afterEach(() => {vi.resetAllMocks(); vi.unstubAllGlobals();});
const open = () => fireEvent.click(screen.getByRole('button', {name: `Pull ${image.image_reference} from CATS`}));

it('loads on demand and copies only the exact service-bound commands returned by CATS', async () => {
  request.mockResolvedValue(available);
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', {...window.navigator, clipboard: {writeText}});
  render(<ImagePullInstructions image={image} serviceKey="mission alpha"/>);
  expect(request).not.toHaveBeenCalled();
  open();
  const dialog = screen.getByRole('dialog', {name: 'Pull image from CATS'});
  expect(await within(dialog).findByText(route.command)).toBeInTheDocument();
  expect(request).toHaveBeenCalledWith('/api/services/mission%20alpha/artifacts/images/8/pull', expect.objectContaining({signal: expect.any(AbortSignal)}));
  fireEvent.click(within(dialog).getByRole('button', {name: 'Copy pull command'}));
  expect(writeText).toHaveBeenCalledWith(route.command);
  expect(await within(dialog).findByText('Pull command copied.')).toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole('button', {name: 'Copy login command'}));
  expect(writeText).toHaveBeenCalledWith(route.login_command);
});

it('shows the server reason without inventing a route for an unapproved image', async () => {
  request.mockResolvedValue({...available, status: 'unavailable', reason: 'The image is absent from this service’s current approved release.', routes: []});
  render(<ImagePullInstructions image={image} serviceKey="mission"/>); open();
  expect(await screen.findByText('The image is absent from this service’s current approved release.')).toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Copy pull command'})).not.toBeInTheDocument();
  expect(screen.queryByText(/^docker pull /)).not.toBeInTheDocument();
});

it('retries a failed request and makes copy failure recoverable without claiming success', async () => {
  request.mockRejectedValueOnce(new Error('Registry instructions unavailable')).mockResolvedValue(available);
  vi.stubGlobal('navigator', {...window.navigator, clipboard: {writeText: vi.fn().mockRejectedValue(new Error('Denied'))}});
  render(<ImagePullInstructions image={image} serviceKey="mission"/>); open();
  expect(await screen.findByRole('alert')).toHaveTextContent('Registry instructions unavailable');
  fireEvent.click(screen.getByRole('button', {name: 'Retry'}));
  fireEvent.click(await screen.findByRole('button', {name: 'Copy pull command'}));
  expect(await screen.findByText('Could not copy automatically. Select and copy the command below.')).toBeInTheDocument();
  expect(screen.queryByText('Pull command copied.')).not.toBeInTheDocument();
  expect(screen.getByText(route.command)).toBeInTheDocument();
});

it('aborts a pending request on close and rechecks approval when opened again', async () => {
  request.mockImplementationOnce(() => new Promise(() => {})).mockResolvedValue({...available, status: 'unavailable', reason: 'Approval expired.', routes: []});
  render(<ImagePullInstructions image={image} serviceKey="mission"/>); open();
  expect(screen.getByRole('status')).toHaveTextContent('Checking this service');
  const signal = request.mock.calls[0][1]?.signal;
  fireEvent.click(screen.getByRole('button', {name: 'Close'}));
  expect(signal?.aborted).toBe(true);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  open();
  expect(await screen.findByText('Approval expired.')).toBeInTheDocument();
  await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
});

it('retains multiple configured routes rather than choosing another service or image name', async () => {
  const other = {...route, repository: 'secondary/42/api', command: `docker pull cats.example:5443/secondary/42/api@${digest}`};
  request.mockResolvedValue({...available, routes: [route, other]});
  render(<ImagePullInstructions image={image} serviceKey="mission"/>); open();
  expect(await screen.findByRole('region', {name: 'Pull route 2'})).toHaveTextContent(other.command);
  expect(screen.getByRole('region', {name: 'Pull route 1'})).toHaveTextContent(route.command);
});
