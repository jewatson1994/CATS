import {afterEach, expect, it} from 'vitest';
import {cleanup, render, screen} from '@testing-library/react';
import {Page} from './service-dependencies';
afterEach(cleanup);
const data = {view:{service:{id:1,service_key:'sample',name:'Sample'}},can:{},dependency_rows:[],dependency_all_total:null};
it.each(['pending','building'])('shows %s assessment without assessed zeros or empty evidence', status => {
  render(<Page data={{...data,dependency_projection_status:status} as any}/>);
  expect(screen.getByRole('status')).toHaveTextContent('background assessment');
  expect(screen.getByRole('button',{name:'Refresh assessment'})).toBeInTheDocument();
  expect(screen.queryByText(/No matching SBOM/)).not.toBeInTheDocument();
  expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0);
});
it('offers an explicit retry after projection failure', () => {
  render(<Page data={{...data,dependency_projection_status:'failed',dependency_projection_error:'Failed to build'} as any}/>);
  expect(screen.getByRole('alert')).toHaveTextContent('Failed to build');
  expect(screen.getByRole('link',{name:'Retry assessment'})).toHaveAttribute('href','/services/sample?dependencies=true&dependency_retry=true');
});
it('renders assessed zero counts only for ready evidence', () => {
  render(<Page data={{...data,dependency_projection_status:'ready',dependency_all_total:0} as any}/>);
  expect(screen.getByText('0')).toBeInTheDocument();
  expect(screen.getByText(/No matching SBOM/)).toBeInTheDocument();
});it('prepares a queued assessment in place and never reloads the document', async () => {
  const {vi} = await import('vitest');
  const {act} = await import('@testing-library/react');
  const {PageControlContext} = await import('../pageControl');
  vi.useFakeTimers({shouldAdvanceTime: true});
  const replace = vi.fn(), assign = vi.fn();
  const original = window.location;
  Object.defineProperty(window, 'location', {configurable: true, value: {...original, search: '?dependencies=true', pathname: '/services/sample', origin: original.origin, href: original.href, replace, assign}});
  const statuses = [{status: 'building', ready: false, terminal: false, revision: 'a'}, {status: 'ready', ready: true, terminal: true, revision: 'b'}];
  const fetch = vi.fn(() => Promise.resolve(new Response(JSON.stringify(statuses.shift() || {status: 'ready', terminal: true}), {headers: {'content-type': 'application/json'}})));
  vi.stubGlobal('fetch', fetch);
  const refresh = vi.fn(async () => {});
  try {
    render(<PageControlContext.Provider value={{refresh}}><Page data={{...data, dependency_projection_status: 'pending', dependency_selected_execution: {id: 42}} as any}/></PageControlContext.Provider>);
    for (let step = 0; step < 4; step++) await act(async () => {vi.advanceTimersByTime(3000);});
    expect((fetch.mock.calls[0] as any[])[0]).toContain('/api/v1/services/sample/dependencies/status?execution_id=42');
    expect(refresh).toHaveBeenCalledTimes(1); // ready: data replaced in place
    const calls = fetch.mock.calls.length;
    await act(async () => {vi.advanceTimersByTime(60000);});
    expect(fetch.mock.calls.length).toBe(calls);
    expect(replace).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  } finally {
    Object.defineProperty(window, 'location', {configurable: true, value: original});
    vi.unstubAllGlobals(); vi.useRealTimers();
  }
});


it('Refresh assessment after polling gave up refreshes in place and restarts the bounded poll', async () => {
  const {vi} = await import('vitest');
  const {act, fireEvent} = await import('@testing-library/react');
  const {PageControlContext} = await import('../pageControl');
  vi.useFakeTimers({shouldAdvanceTime: true});
  const fetch = vi.fn(() => Promise.resolve(new Response(JSON.stringify({status: 'building', ready: false, terminal: false, revision: 'a'}),
    {headers: {'content-type': 'application/json'}})));
  vi.stubGlobal('fetch', fetch);
  const refresh = vi.fn(async () => {});
  try {
    render(<PageControlContext.Provider value={{refresh}}><Page data={{...data, dependency_projection_status: 'building', dependency_selected_execution: {id: 42}} as any}/></PageControlContext.Provider>);
    for (let step = 0; step < 40; step++) await act(async () => {vi.advanceTimersByTime(10000);});  // past the 5-minute bound
    expect(screen.getByText(/Still preparing/)).toBeInTheDocument();
    const before = fetch.mock.calls.length;
    await act(async () => {vi.advanceTimersByTime(60000);});
    expect(fetch.mock.calls.length).toBe(before);  // stopped
    await act(async () => {fireEvent.click(screen.getByRole('button', {name: 'Refresh assessment'}));});
    expect(refresh).toHaveBeenCalledTimes(1);
    await act(async () => {vi.advanceTimersByTime(3000);});
    expect(fetch.mock.calls.length).toBeGreaterThan(before);  // a new round of status checks
    expect(String((fetch.mock.calls[fetch.mock.calls.length - 1] as any[])[0])).toContain('round=1');
    expect(screen.queryByText(/Still preparing/)).toBeNull();
  } finally {
    vi.unstubAllGlobals(); vi.useRealTimers();
  }
});
