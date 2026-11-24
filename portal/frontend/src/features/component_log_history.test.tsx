import {fireEvent, render, screen} from '@testing-library/react';
import {expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {ReceivedByHQ} from './component_log_history';

vi.mock('../api', async importActual => ({...await importActual<typeof import('../api')>(), requestJson: vi.fn()}));

it('loads receipt details only when requested and passes the source ID safely', async () => {
  const api = vi.mocked(requestJson);
  api.mockResolvedValueOnce({components: [{source_id: 'site/A', source_name: 'Site A', last_received_at: '2026-01-01T00:00:00Z'}]})
    .mockResolvedValueOnce({events: [{id: 2, event_id: 'worker-event', received_at: '2026-01-01T00:00:00Z',
      timestamp: '2025-12-31T23:59:00Z', data: {message: 'scan completed'}}], next_before_id: 2})
    .mockResolvedValueOnce({events: [], next_before_id: null});
  render(<ReceivedByHQ/>);
  expect(api).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', {name: 'Received by HQ'}));
  fireEvent.click(await screen.findByRole('button', {name: 'Site A'}));
  expect(await screen.findByText('worker-event')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Older events'}));
  expect(await screen.findByText('No retained operational events for this source.')).toBeInTheDocument();
  expect(api.mock.calls[2][0]).toContain('source_id=site%2FA&limit=25&before_id=2');
});
