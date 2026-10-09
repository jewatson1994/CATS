import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it} from 'vitest';
import {ServiceHeader} from './ServiceHeader';

afterEach(cleanup);
const data = {view: {service: {id: 7, service_key: 'demo', name: 'Demo'}},
  can: {'service.export': {'7': true}, 'bundle.export': {'7': true}}};

it('offers one ZIP for All and keeps the individual downloads', () => {
  render(<ServiceHeader data={data}/>);
  fireEvent.click(screen.getByText('Export'));
  expect(screen.getByRole('link', {name: /All Individual exports/})).toHaveAttribute('href', '/services/demo/exports/all.zip');
  for (const [label, path] of [['PPSM', 'ppsm.xlsx'], ['POA&M', 'poam.xlsx'], ['Asset List', 'asset_list.xlsx'],
    ['Diagrams', 'diagrams.zip'], ['Mitigations', 'mitigations.xlsx'], ['Findings', 'findings.xlsx'], ['SBOM components', 'sbom.json']]) {
    expect(screen.getByRole('link', {name: label})).toHaveAttribute('href', `/services/demo/exports/${path}`);
  }
  expect(screen.getByRole('link', {name: 'Portable Service Bundle'})).toHaveAttribute('href', '/services/demo/bundle.zip');
});

it('hides the portable bundle without its separate permission', () => {
  render(<ServiceHeader data={{...data, can: {'service.export': {'7': true}}}}/>);
  fireEvent.click(screen.getByText('Export'));
  expect(screen.queryByRole('link', {name: 'Portable Service Bundle'})).not.toBeInTheDocument();
});

it('hides exports without service export permission', () => {
  render(<ServiceHeader data={{...data, can: {}}}/>);
  expect(screen.queryByText('Export')).not.toBeInTheDocument();
});
