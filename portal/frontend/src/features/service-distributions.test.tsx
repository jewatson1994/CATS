import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {FrozenDistribution, ServiceDistributions} from './service-distributions';

vi.mock('../api', async original => ({...await original<typeof import('../api')>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const charts = [
  {id:'a', label:'API', source_path:'charts/api', reference:'oci://registry/api', version:'1.2', default_enabled:true, state:'rendered'},
  {id:'m', label:'Metrics', source_path:'charts/metrics', reference:'oci://registry/metrics', version:'3.0', default_enabled:false, state:'rendered'},
];
const source = {id:'confirmed', inventory_id:'inventory-1', created_at:'2026-10-30T00:00:00Z', charts};
const original = {id:'dist-1', name:'Standard', confirmation_id:source.id, inventory_id:source.inventory_id, charts,
  enabled_chart_ids:['a'], disabled_chart_ids:['m'], images:['example/api:1.2'], selection_digest:'first'};
const catalog = {confirmations:[source], distributions:[original], can_manage:true, can_scan:true};
const endpoint = '/api/services/reports/distributions';

async function open(canRequestApproval = true) {
  render(<ServiceDistributions serviceKey="reports" csrfToken="token" canRequestApproval={canRequestApproval}/>);
  expect(requestJson).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', {name:'View distributions and chart selections'}));
  await screen.findByRole('heading', {name:'Standard'});
}

it('uses catalog defaults for a new distribution and scans the exact saved selection', async () => {
  const saved = {...original, id:'dist-2', name:'Metrics only', enabled_chart_ids:['m'], disabled_chart_ids:['a'],
    images:['example/metrics:3.0'], selection_digest:'second'};
  vi.mocked(requestJson).mockResolvedValueOnce(catalog).mockResolvedValueOnce({distribution:saved}).mockResolvedValueOnce({job_id:'scan-2'});
  await open();
  fireEvent.click(screen.getByRole('button', {name:'Create distribution'}));
  const api = screen.getByRole('checkbox', {name:/API.*Catalog default · Enabled/i});
  const metrics = screen.getByRole('checkbox', {name:/Metrics.*Catalog default · Disabled/i});
  expect(api).toBeChecked(); expect(metrics).not.toBeChecked();
  fireEvent.click(api); fireEvent.click(metrics);
  fireEvent.change(screen.getByLabelText('Distribution name'), {target:{value:'Metrics only'}});
  fireEvent.click(screen.getByRole('button', {name:'Save distribution'}));
  const selected = within(await screen.findByRole('article', {name:'Metrics only'}));
  expect(requestJson).toHaveBeenCalledWith(endpoint, expect.objectContaining({method:'POST', body:JSON.stringify({
    csrf_token:'token', name:'Metrics only', confirmation_id:'confirmed', enabled_chart_ids:['m']})}));
  fireEvent.click(selected.getByText(/Review selection/));
  expect(selected.getByRole('heading', {name:'Enabled charts (1)'}).nextElementSibling).toHaveTextContent('Metrics · 3.0');
  expect(selected.getByRole('heading', {name:'Disabled charts (1)'}).nextElementSibling).toHaveTextContent('API · 1.2');
  fireEvent.click(selected.getByRole('button', {name:'Scan distribution'}));
  expect(await screen.findByRole('link', {name:'View scan progress'})).toHaveAttribute('href','/scan?job_id=scan-2');
  expect(requestJson).toHaveBeenCalledWith(endpoint+'/dist-2/scan', expect.objectContaining({method:'POST',body:JSON.stringify({csrf_token:'token'})}));
  expect(selected.getByRole('link', {name:/Request Cyber approval/})).toHaveAttribute('href','/cyber-approvals?service=reports&distribution_id=dist-2');
  fireEvent.click(selected.getByRole('button', {name:'Edit as new distribution'}));
  expect(screen.getByLabelText('Distribution name')).toHaveValue('Metrics only');
  expect(screen.getByRole('checkbox', {name:/Metrics/})).toBeChecked();
  expect(screen.getByRole('checkbox', {name:/API/})).not.toBeChecked();
  expect(screen.getByRole('article', {name:'Standard'})).toBeInTheDocument();
});

it('applies nested defaults only when a parent makes the child available', async () => {
  const nested = (id: string, label: string, parents: string[], declared: boolean, effective: boolean) =>
    ({...charts[0], id, label, parent_chart_ids:parents, declared_enabled:declared, default_enabled:effective});
  const inventory = {...source, charts:[...charts,
    nested('exporter', 'Exporter', ['m'], true, false), nested('collector', 'Collector', ['exporter'], true, false),
    nested('addon', 'Addon', ['m'], false, false), nested('shared', 'Shared', ['a', 'm'], true, true)]};
  vi.mocked(requestJson).mockResolvedValue({...catalog, confirmations:[inventory]});
  await open();
  fireEvent.click(screen.getByRole('button', {name:'Create distribution'}));
  const box = (label: string) => screen.getByRole('checkbox', {name:new RegExp('^'+label)});
  expect(box('Exporter')).toBeDisabled();
  expect(box('Shared')).toBeChecked();
  fireEvent.click(box('Metrics'));
  expect(box('Exporter')).toBeChecked(); expect(box('Collector')).toBeChecked();
  expect(box('Addon')).toBeEnabled(); expect(box('Addon')).not.toBeChecked();
  fireEvent.click(box('Metrics'));
  expect(box('Collector')).not.toBeChecked(); expect(box('Exporter')).toBeDisabled();
  expect(box('Shared')).toBeChecked();
  fireEvent.click(box('Shared')); fireEvent.click(box('Metrics'));
  expect(box('Shared')).not.toBeChecked();
});

it('keeps chart selections readable for viewers without showing mutation controls', async () => {
  vi.mocked(requestJson).mockResolvedValue({...catalog, can_manage:false, can_scan:false});
  await open(false);
  fireEvent.click(screen.getByText(/Review selection/));
  expect(screen.getByRole('heading', {name:'Disabled charts (1)'})).toBeVisible();
  expect(screen.queryByRole('button', {name:/scan distribution|create distribution|edit as new/i})).not.toBeInTheDocument();
  expect(screen.queryByRole('link', {name:/Request Cyber approval/})).not.toBeInTheDocument();
});

it('requires an explicit choice before excluding an unresolved default chart', async () => {
  const unresolvedSource = {...source, charts:charts.map(chart => ({...chart, state:'unresolved'}))};
  vi.mocked(requestJson).mockResolvedValue({...catalog, confirmations:[unresolvedSource]});
  await open();
  fireEvent.click(screen.getByRole('button', {name:'Create distribution'}));
  fireEvent.change(screen.getByLabelText('Distribution name'), {target:{value:'External images only'}});
  expect(screen.getByRole('button', {name:'Save distribution'})).toBeDisabled();
  expect(screen.getByText(/Run Discovery again to resolve API/)).toBeVisible();
  fireEvent.click(screen.getByRole('checkbox', {name:/API/}));
  expect(screen.getByRole('button', {name:'Save distribution'})).toBeEnabled();
  expect(screen.getByRole('checkbox', {name:/Metrics/})).toBeDisabled();
});

it('shows nested native dependencies in the editor and frozen selection as settings of the parent render', async () => {
  const cache = {id:'c', label:'Cache', source_path:'charts/cache', version:'2.0', state:'resolved', enabled:true,
    dependencies:[{id:'s', label:'Storage', source_path:'charts/storage', version:'3.1', state:'resolved', enabled:false, condition:'storage.enabled'}]};
  const unknown = {id:'u', label:'Exporter', source_path:'charts/exporter', state:'unresolved', enabled:null, declared_version:'~4.0'};
  const nestedCharts = [{...charts[0], dependencies:[cache, unknown]}, charts[1]];
  vi.mocked(requestJson).mockResolvedValue({...catalog, confirmations:[{...source, charts:nestedCharts}]});
  await open();
  fireEvent.click(screen.getByRole('button', {name:'Create distribution'}));
  const editor = screen.getByRole('group', {name:'Charts enabled for this distribution'});
  render(<FrozenDistribution selection={{...original, charts:nestedCharts}}/>);
  const frozen = screen.getByRole('region', {name:'Frozen distribution selection'});

  for (const container of [editor, frozen]) {
    const view = within(container);
    fireEvent.click(view.getByText('Helm dependencies (2 direct)'));
    expect(view.getByText(/rerun Discovery to render the parent chart/)).toBeVisible();
    const cacheRow = view.getByText('Cache').closest('li')!;
    expect(cacheRow).toHaveTextContent('Cache · 2.0 · charts/cache · Parent render setting · Enabled');
    expect(within(cacheRow).getByText('Storage').closest('li')).toHaveTextContent('Storage · 3.1 · charts/storage · Parent render setting · Disabled · Condition storage.enabled');
    expect(view.getByText('Exporter').closest('li')).toHaveTextContent('Requested ~4.0 · Parent render setting · Unknown · Unresolved chart');
  }
  expect(within(editor).getAllByRole('checkbox')).toHaveLength(2);
  expect(within(editor).getByRole('checkbox', {name:/API/})).toBeChecked();
  expect(within(frozen).queryByRole('checkbox')).not.toBeInTheDocument();
});
