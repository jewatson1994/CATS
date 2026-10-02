import {render, screen} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Page} from './dashboard';

afterEach(() => vi.unstubAllGlobals());
it('loads the Services dashboard asynchronously after rendering its heading', async () => {
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({views:[], compliant_count:4, noncompliant_count:2}), {headers:{'content-type':'application/json'}})));
  render(<Page data={{dashboard_url:'/api/dashboard/services?lifecycle=active'}}/>);
  expect(screen.getByRole('heading', {name:'Services'})).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Loading dashboard data');
  await screen.findByRole('heading', {name:'Service Snapshot'});
  expect(screen.getByText('4')).toBeInTheDocument();
});
