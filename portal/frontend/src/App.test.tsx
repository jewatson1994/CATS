import {afterEach,expect,it,vi} from 'vitest';
import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {App,isPageRoute} from './App';
import {PAGE_MEDIA_TYPE} from './api';

afterEach(()=>{vi.unstubAllGlobals();window.history.replaceState(null,'','/');});
it('intercepts only native page routes, never exports or auth callbacks',()=>{
  for(const path of ['/scan','/services/payments','/services/payments/history','/services/payments/definitions','/services/payments/exchange','/services/payments/findings/12','/poam/entries/12']) expect(isPageRoute(path)).toBe(true);
  for(const path of ['/services/payments/export.xlsx','/login/oidc/callback','/services/payments/artifacts/1/download','/api/public/jobs/test/results.zip']) expect(isPageRoute(path)).toBe(false);
});
it('aborts stale navigation and never shows another page response in the new scope',async()=>{
  window.history.replaceState(null,'','/home');
  let finish: (response: Response)=>void=()=>{};
  const fetch=vi.fn().mockImplementationOnce(()=>new Promise<Response>(resolve=>{finish=resolve;})).mockResolvedValueOnce(new Response(JSON.stringify({schemaVersion:1,page:'request_error',data:{detail:'Latest scope'}}),{headers:{'content-type':PAGE_MEDIA_TYPE}}));
  vi.stubGlobal('fetch',fetch);vi.stubGlobal('scrollTo',vi.fn());
  render(<App initial={{schemaVersion:1,page:'home',data:{}}}/>);
  const header = screen.getByRole('banner');
  fireEvent.click(screen.getByRole('link',{name:'Start Scan →'}));
  await waitFor(()=>expect(fetch).toHaveBeenCalledTimes(1));
  expect(screen.queryByRole('heading',{name:'CATS'})).not.toBeInTheDocument();
  expect(screen.getByRole('banner')).toBe(header);
  expect(screen.getByRole('status')).toHaveTextContent('Loading page');
  act(()=>{window.history.pushState(null,'','/sbom');window.dispatchEvent(new PopStateEvent('popstate'));});
  await screen.findByText('Latest scope');
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
  await act(async()=>{finish(new Response(JSON.stringify({schemaVersion:1,page:'request_error',data:{detail:'Stale scan'}}),{headers:{'content-type':PAGE_MEDIA_TYPE}}));});
  expect(screen.queryByText('Stale scan')).not.toBeInTheDocument();
  expect(screen.getByText('Latest scope')).toBeInTheDocument();
  expect(screen.getByRole('banner')).toBe(header);
});
it('keeps navigation usable when a route fails and can retry', async () => {
  const fetch = vi.fn().mockRejectedValueOnce(new Error('Route unavailable')).mockResolvedValueOnce(new Response(JSON.stringify({schemaVersion:1,page:'request_error',data:{detail:'Recovered'}}), {headers:{'content-type':PAGE_MEDIA_TYPE}}));
  vi.stubGlobal('fetch', fetch); vi.stubGlobal('scrollTo', vi.fn());
  render(<App initial={{schemaVersion:1,page:'home',data:{current_user:{display_name:'Tester',theme:'cats'}}}}/>);
  const nav = screen.getByRole('navigation', {name:'Primary navigation'});
  fireEvent.click(screen.getByRole('link', {name:'Cybersecurity'}));
  await screen.findByText('Route unavailable');
  expect(screen.getByRole('navigation', {name:'Primary navigation'})).toBe(nav);
  fireEvent.click(screen.getByRole('button', {name:'Retry'}));
  await screen.findByText('Recovered');
});
