import {cleanup, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it} from 'vitest';
import {ComparisonCharts} from './remediation-comparison';

afterEach(cleanup);
it('shows paired severity observations and count changes including zero', () => {
  render(<ComparisonCharts before={{vulnerabilities:{Critical:0, High:0, Medium:127, Low:23}, patchable_vulnerabilities:164}} after={{vulnerabilities:{Critical:0, High:0, Medium:37, Low:9}, patchable_vulnerabilities:0}}/>);
  const severity = screen.getByRole('region', {name:'Vulnerabilities before and after'});
  expect(within(severity).getByText('127')).toBeInTheDocument();
  expect(within(severity).getByText('37')).toBeInTheDocument();
  expect(screen.getByText('164 fewer')).toBeInTheDocument();
});
it('does not turn missing candidate evidence into zero or a claimed reduction', () => {
  render(<ComparisonCharts before={{vulnerabilities:{Medium:127}, patchable_vulnerabilities:164}} after={{vulnerabilities:{Medium:null}}}/>);
  expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(0);
  expect(screen.getAllByText('Comparison unavailable')).toHaveLength(4);
  expect(screen.queryByText('164 fewer')).not.toBeInTheDocument();
});
