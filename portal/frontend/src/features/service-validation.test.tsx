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
