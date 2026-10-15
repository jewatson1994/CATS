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
  expect(screen.getAllByText('Comparison unavailable')).toHaveLength(5);
  expect(screen.queryByText('164 fewer')).not.toBeInTheDocument();
});

it('includes lower and unclassified severities without silently dropping observations', () => {
  render(<ComparisonCharts before={{vulnerabilities:{Negligible:17, Unknown:6, Informational:3}}} after={{vulnerabilities:{Negligible:4, Unknown:1, Informational:2}}}/>);
  const severity = within(screen.getByRole('region', {name:'Vulnerabilities before and after'}));
  expect(severity.getByRole('row', {name:'Negligible 17 4'})).toBeInTheDocument();
  expect(severity.getByRole('row', {name:'Unknown 6 1'})).toBeInTheDocument();
  expect(severity.getByRole('row', {name:'Informational 3 2'})).toBeInTheDocument();
});

it('shows explicit non-applicability neutrally while missing evidence stays unavailable', () => {
  render(<ComparisonCharts before={{helm_render:'NOT_APPLICABLE'}} after={{policy_validation:'NOT_APPLICABLE'}} validation={[{name:'helm_template',status:'NOT_APPLICABLE'}]}/>);
  const checks = within(screen.getByRole('region', {name:'Validation and risk'}));
  const rendering = within(checks.getByRole('row', {name:/Helm rendering/}));
  expect(rendering.getAllByText('Not Applicable')).toHaveLength(2);
  for (const label of checks.getAllByText('Not Applicable')) expect(label.closest('.badge')).toHaveClass('badge-neutral');
  expect(within(checks.getByRole('row', {name:/Configuration policy/})).getByText('Unavailable')).toBeInTheDocument();
  expect(within(checks.getByRole('row', {name:/Deployment validation/})).getByText('NOT RUN')).toBeInTheDocument();
});

it('separates vulnerability totals from known-fix counts and preserves comparability notes', () => {
  render(<ComparisonCharts before={{vulnerability_observations:200,patchable_vulnerabilities:164}} after={{vulnerability_observations:150,patchable_vulnerabilities:130,comparison_note:'Candidate image coverage differs from baseline.'}}/>);
  expect(screen.getByRole('row', {name:'Vulnerability observations 200 150 50 fewer'})).toBeInTheDocument();
  expect(screen.getByRole('row', {name:'Findings with a known fix 164 130 34 fewer'})).toBeInTheDocument();
  expect(screen.getByText('Candidate image coverage differs from baseline.')).toBeInTheDocument();
});

it('uses explicit applicability for configuration counts without treating absent counts as inapplicable', () => {
  const {rerender} = render(<ComparisonCharts before={{configuration_applicable:false}} after={{configuration_applicable:false}}/>);
  expect(screen.getByRole('row', {name:'Configuration observations Not Applicable Not Applicable Not Applicable'})).toBeInTheDocument();
  rerender(<ComparisonCharts before={{}} after={{}}/>);
  expect(screen.getByRole('row', {name:'Configuration observations Unavailable Unavailable Comparison unavailable'})).toBeInTheDocument();
});
