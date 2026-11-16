import {act, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {OciGroupPullPolicy} from './OciGroupPullPolicy';

vi.mock('../api', async original => ({...await original<object>(), requestJson: vi.fn()}));
const request = vi.mocked(requestJson);
const policy = {mode: 'approved_release', blocked_severity: 'Critical', require_service_compliant: false, max_scan_age_days: null};
const response = (groupId = 2, changes = {}) => ({group_id: groupId, policy: {...policy, ...changes}, is_default: false});
const data = {csrf_token: 'group-csrf'};
afterEach(() => vi.resetAllMocks());

it('requires an owning group without requesting global or guessed settings', () => {
  render(<OciGroupPullPolicy data={data}/>);
  expect(screen.getByText(/Select an owning group/)).toBeInTheDocument();
  expect(request).not.toHaveBeenCalled();
});

it('loads the selected group and defaults to approved releases without active compliance controls', async () => {
  request.mockResolvedValue({...response(), is_default: true});
  render(<OciGroupPullPolicy data={data} groupId={2}/>);
  expect(await screen.findByLabelText('OCI pull requirements')).toHaveValue('approved_release');
  expect(screen.queryByLabelText('Block findings at or above')).not.toBeInTheDocument();
  expect(screen.getByText(/New findings and scans do not override/)).toBeInTheDocument();
  expect(request).toHaveBeenCalledWith('/api/oci/pull-policy?group_id=2', {signal: expect.any(AbortSignal)});
});

it.each(['compliance', 'both'])('saves %s rules with the selected group, exact policy, and CSRF', async mode => {
  request.mockResolvedValueOnce(response()).mockResolvedValueOnce(response(2, {mode, blocked_severity: 'High', require_service_compliant: true, max_scan_age_days: 14}));
  render(<OciGroupPullPolicy data={data} groupId={2}/>);
  fireEvent.change(await screen.findByLabelText('OCI pull requirements'), {target: {value: mode}});
  fireEvent.change(screen.getByLabelText('Block findings at or above'), {target: {value: 'High'}});
  fireEvent.click(screen.getByLabelText('Require service to be compliant'));
  fireEvent.change(screen.getByLabelText('Maximum scan age (days, optional)'), {target: {value: '14'}});
  expect(screen.getByText(/scan filters still apply/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Save OCI pull policy'}));
  expect(await screen.findByText(/Group OCI pull policy saved/)).toBeInTheDocument();
  expect(request).toHaveBeenLastCalledWith('/api/oci/pull-policy?group_id=2', {
    method: 'PUT', signal: expect.any(AbortSignal),
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': 'group-csrf'},
    body: JSON.stringify({mode, blocked_severity: 'High', require_service_compliant: true, max_scan_age_days: 14}),
  });
});

it('keeps scan age optional and rejects a compliance mode without any compliance rule', async () => {
  request.mockResolvedValue(response(2, {mode: 'compliance'}));
  render(<OciGroupPullPolicy data={data} groupId={2}/>);
  expect(await screen.findByLabelText('Maximum scan age (days, optional)')).toHaveValue(null);
  fireEvent.change(screen.getByLabelText('Block findings at or above'), {target: {value: 'None'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save OCI pull policy'}));
  expect(screen.getByRole('alert')).toHaveTextContent('Choose a severity to block or require service compliance.');
  expect(request).toHaveBeenCalledTimes(1);
});

it('does not claim a failed save succeeded and can reload the persisted policy', async () => {
  request.mockResolvedValueOnce(response()).mockRejectedValueOnce(new Error('You cannot administer this group scope'))
    .mockResolvedValueOnce(response());
  render(<OciGroupPullPolicy data={data} groupId={2}/>);
  fireEvent.change(await screen.findByLabelText('OCI pull requirements'), {target: {value: 'both'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save OCI pull policy'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('You cannot administer this group scope');
  expect(screen.queryByText(/Group OCI pull policy saved/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Reload pull policy'}));
  await waitFor(() => expect(screen.getByLabelText('OCI pull requirements')).toHaveValue('approved_release'));
});

it('rejects settings for another group and malformed policies instead of assuming approval or compliance', async () => {
  request.mockResolvedValue(response(3));
  render(<OciGroupPullPolicy data={data} groupId={2}/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('unexpected group pull policy');
  expect(screen.queryByLabelText('OCI pull requirements')).not.toBeInTheDocument();
});

it('ignores a delayed load after switching groups', async () => {
  let finish!: (value: unknown) => void;
  request.mockImplementationOnce(() => new Promise(resolve => {finish = resolve;}))
    .mockResolvedValueOnce(response(3, {mode: 'both'}));
  const {rerender} = render(<OciGroupPullPolicy data={data} groupId={2}/>);
  rerender(<OciGroupPullPolicy data={data} groupId={3}/>);
  expect(await screen.findByLabelText('OCI pull requirements')).toHaveValue('both');
  await act(async () => finish(response(2)));
  expect(screen.getByLabelText('OCI pull requirements')).toHaveValue('both');
  expect((request.mock.calls[0][1]?.signal as AbortSignal).aborted).toBe(true);
});

it('does not apply a delayed save to another group after navigation', async () => {
  let finish!: (value: unknown) => void;
  request.mockResolvedValueOnce(response()).mockImplementationOnce(() => new Promise(resolve => {finish = resolve;}))
    .mockResolvedValueOnce(response(3));
  const {rerender} = render(<OciGroupPullPolicy data={data} groupId={2}/>);
  fireEvent.change(await screen.findByLabelText('OCI pull requirements'), {target: {value: 'compliance'}});
  fireEvent.click(screen.getByRole('button', {name: 'Save OCI pull policy'}));
  expect(screen.getByRole('button', {name: 'Saving pull policy.'})).toBeDisabled();
  rerender(<OciGroupPullPolicy data={data} groupId={3}/>);
  expect(await screen.findByLabelText('OCI pull requirements')).toHaveValue('approved_release');
  await act(async () => finish(response(2, {mode: 'compliance'})));
  expect(screen.getByLabelText('OCI pull requirements')).toHaveValue('approved_release');
  expect(screen.queryByText(/Group OCI pull policy saved/)).not.toBeInTheDocument();
  expect((request.mock.calls[1][1]?.signal as AbortSignal).aborted).toBe(true);
});
