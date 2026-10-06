import {afterEach, expect, it} from 'vitest';
import {cleanup, render, screen} from '@testing-library/react';
import {Page} from './service-validation';

afterEach(cleanup);
it('shows the observed failure and actionable guidance outside technical diagnostics', () => {
  render(<Page data={{view:{service:{id:1,service_key:'demo'}},validation:{status:'FAILED',phase:'COMPLETE',cleanup_status:'COMPLETE',failure_details:[{resource:'demo / nginx',reason:'CreateContainerConfigError',message:'image will run as root',guidance:'Set securityContext.runAsUser to a non-root UID.'}]}} as any} />);
  expect(screen.getByText('What failed and how to fix it')).toBeTruthy();
  expect(screen.getByText(/image will run as root/)).toBeTruthy();
  expect(screen.getByText(/Set securityContext.runAsUser/)).toBeTruthy();
});
it('pages validation history without loading every run', () => {
  render(<Page data={{view:{service:{id:1,service_key:'demo'}},validation:{status:'VERIFIED',phase:'COMPLETE',cleanup_status:'COMPLETE',terminal:true},
    validation_runs:[{run_key:'run-51',artifact_type:'ORIGINAL',status:'VERIFIED'}],
    validation_history:{page:2,pages:3,total:120,page_size:50}} as any} />);
  expect(screen.getByText('Page 2 of 3 · 120 runs')).toBeTruthy();
  expect(screen.getByRole('link',{name:'Previous'}).getAttribute('href')).toBe('/services/demo?validation=true&validation_page=1');
  expect(screen.getByRole('link',{name:'Next'}).getAttribute('href')).toBe('/services/demo?validation=true&validation_page=3');
});
