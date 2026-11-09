import {useState} from 'react';
import {expect, it, vi} from 'vitest';
import {fireEvent, render, screen, within} from '@testing-library/react';
import {buildTuningResources, DiscoveryTuning, nextActionForDiagnostic, type DiscoveryTuningProps, type TuningInventory} from './discovery-tuning';

const inventory: TuningInventory = {
  roots: [{id: 'root', path: 'stack/catalog.yaml', technology: 'catalog', completeness: 'partial'}],
  nodes: [{id: 'api', root_id: 'root', name: 'API', kind: 'ChartReference', state: 'unresolved'}, {id: 'worker', root_id: 'root', name: 'worker', kind: 'Deployment', state: 'rendered'}],
  edges: [{source: 'api', target: 'worker', kind: 'declares'}],
  images: [{reference: 'registry/api:1', root_id: 'root', component_id: 'worker'}],
  configurable_components: [{id: 'api', root_id: 'root', label: 'API', path: 'stack/catalog.yaml', technology: 'helm', values_origin: ['chart defaults', 'inline values']}],
  diagnostics: [{code: 'native_render_failed', component_id: 'api', root_id: 'root', path: 'stack/api/templates/a.yaml', message: 'Missing image tag', value_paths: ['image.tag'], blocking: true},
    {code: 'native_render_failed', component_id: 'api', root_id: 'root', path: 'stack/api/templates/b.yaml', message: 'Missing image tag', value_paths: ['image.tag'], occurrences: 3, blocking: true}],
  candidate_values_files: ['base.yaml', 'prod.yaml'],
};

function propsFor(source: TuningInventory = inventory): DiscoveryTuningProps {
  return {inventory: source, selectedValues: [], componentValues: {}, componentOverrides: {}, acknowledgeNonSecret: false, busy: false,
    onValuesChange: vi.fn(), onComponentValuesChange: vi.fn(), onComponentOverrideChange: vi.fn(), onAcknowledgeNonSecret: vi.fn(), onRender: vi.fn(), onSupplyFiles: vi.fn()};
}

it('groups repeated failures under their configurable owner without duplicating the parent’s partial status', () => {
  const resources = buildTuningResources(inventory);
  const api = resources.find(item => item.id === 'api')!;
  expect(resources.filter(item => item.needsAttention).map(item => item.id)).toEqual(['api']);
  expect(api.imageCount).toBe(1);
  expect(api.issues).toHaveLength(1);
  expect(api.issues[0]).toMatchObject({occurrences: 4, valuePaths: ['image.tag'], paths: ['stack/api/templates/a.yaml', 'stack/api/templates/b.yaml']});
  expect(api.issues[0].diagnostics).toHaveLength(2);
});

it('retains source-level failures and treats explicit informational diagnostics as configuration only', () => {
  const source: TuningInventory = {roots: [{id: 'library', path: 'lib/Chart.yaml', technology: 'helm', completeness: 'complete'}], nodes: [], images: [], diagnostics: [
    {root_id: 'library', code: 'helm_library_chart', blocking: false, severity: 'info', message: 'Library charts provide templates.'},
    {code: 'no_supported_deployment_roots', path: 'unrelated/source.txt', message: 'No supported resources found.'},
  ]};
  const resources = buildTuningResources(source);
  expect(resources.find(item => item.id === 'library')).toMatchObject({needsAttention: false, configurationOnly: true});
  expect(resources.find(item => item.id === '__source__')).toMatchObject({needsAttention: true});
  expect(resources.flatMap(item => item.issues.flatMap(issue => issue.diagnostics))).toHaveLength(2);
});

it('does not suggest values edits for missing renderers, secret inputs or missing source files', () => {
  expect(nextActionForDiagnostic({code: 'native_renderer_unavailable'})).toContain('administrator');
  expect(nextActionForDiagnostic({code: 'worker_isolation_unavailable'})).toContain('host isolation');
  expect(nextActionForDiagnostic({code: 'secret_values_not_rendered'})).toContain('Keep secret contents outside');
  expect(nextActionForDiagnostic({code: 'helm_dependency_unavailable'})).toContain('Supply the referenced file');
  expect(nextActionForDiagnostic({code: 'native_render_failed', renderer: 'kustomize'})).toContain('overlay');
});

it('keeps issues compact, expands one owner, and exposes deduplicated evidence and supply action', () => {
  const props = propsFor({...inventory, roots: [...inventory.roots, {id: 'library', path: 'lib/Chart.yaml', technology: 'helm', completeness: 'complete'}]}); render(<DiscoveryTuning {...props}/>);
  expect(screen.getByText('1 unresolved resource')).toBeVisible();
  expect(screen.getByText('Missing image tag')).toBeVisible();
  expect(screen.queryByLabelText(/Non-secret YAML for API/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Tune API'}));
  expect(screen.getAllByText('Missing image tag')).toHaveLength(2);
  expect(screen.getByText('4 occurrences')).toBeVisible();
  fireEvent.click(screen.getByRole('button', {name: 'Supply files for this resource'}));
  expect(props.onSupplyFiles).toHaveBeenCalledWith('stack/api/templates/a.yaml');
  fireEvent.click(screen.getByRole('button', {name: 'Ready (1)'}));
  expect(screen.queryByRole('button', {name: 'Close API'})).not.toBeInTheDocument();
  expect(screen.getByText('Configuration only')).toBeVisible();
});

it('edits and reorders only the selected component and requires non-secret acknowledgment before rendering', () => {
  const props = propsFor();
  function Stateful() {
    const [paths, setPaths] = useState<Record<string, string[]>>({api: ['base.yaml', 'prod.yaml']});
    const [yaml, setYaml] = useState<Record<string, string>>({});
    const [ack, setAck] = useState(false);
    return <DiscoveryTuning {...props} componentValues={paths} componentOverrides={yaml} acknowledgeNonSecret={ack}
      onComponentValuesChange={(id, values) => {props.onComponentValuesChange(id, values); setPaths({...paths, [id]: values});}}
      onComponentOverrideChange={(id, value) => {props.onComponentOverrideChange(id, value); setYaml({...yaml, [id]: value}); setAck(false);}}
      onAcknowledgeNonSecret={setAck}/>;
  }
  render(<Stateful/>);
  fireEvent.click(screen.getByRole('button', {name: 'Tune API'}));
  fireEvent.click(screen.getByRole('button', {name: 'Move prod.yaml earlier for API'}));
  expect(props.onComponentValuesChange).toHaveBeenLastCalledWith('api', ['prod.yaml', 'base.yaml']);
  fireEvent.click(screen.getByRole('button', {name: 'Remove base.yaml for API'}));
  expect(props.onComponentValuesChange).toHaveBeenLastCalledWith('api', ['prod.yaml']);
  fireEvent.change(screen.getByLabelText('Add values for API'), {target: {value: 'base.yaml'}});
  expect(props.onComponentValuesChange).toHaveBeenLastCalledWith('api', ['prod.yaml', 'base.yaml']);
  fireEvent.change(screen.getByLabelText(/Non-secret YAML for API/), {target: {value: 'image:\n  tag: stable'}});
  expect(props.onComponentOverrideChange).toHaveBeenLastCalledWith('api', 'image:\n  tag: stable');
  expect(screen.getByRole('button', {name: 'Render updated configuration'})).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', {name: /These overrides contain no passwords/}));
  fireEvent.click(screen.getByRole('button', {name: 'Render updated configuration'}));
  expect(props.onRender).toHaveBeenCalledTimes(1);
  expect(props.onValuesChange).not.toHaveBeenCalled();
});

it('honors an explicit empty override and file list instead of restoring inventory selections', () => {
  const source = {...inventory, configurable_components: [{...inventory.configurable_components![0], selected_values: ['prod.yaml'], values_yaml: 'image:\n  tag: old'}]};
  const props = {...propsFor(source), componentValues: {api: []}, componentOverrides: {api: ''}};
  render(<DiscoveryTuning {...props}/>);
  fireEvent.click(screen.getByRole('button', {name: 'Tune API'}));
  expect(screen.getByLabelText(/Non-secret YAML for API/)).toHaveValue('');
  expect(screen.queryByRole('button', {name: 'Remove prod.yaml for API'})).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox', {name: /These overrides/})).not.toBeInTheDocument();
  expect(screen.getByRole('button', {name: 'Render updated configuration'})).toBeEnabled();
});

it('bounds long inventories, filters by issue text, and leaves ready resources collapsed', () => {
  const source: TuningInventory = {roots: Array.from({length: 80}, (_, index) => ({id: `root-${index}`, path: `chart-${String(index).padStart(2, '0')}/Chart.yaml`, technology: 'helm', completeness: 'complete'})), nodes: [], images: [],
    diagnostics: [{root_id: 'root-50', code: 'native_render_failed', message: 'A unique required deployment value is missing.'}]};
  render(<DiscoveryTuning {...propsFor(source)}/>);
  expect(screen.getAllByRole('article')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', {name: 'All (80)'}));
  expect(screen.getAllByRole('article')).toHaveLength(25);
  expect(within(screen.getByRole('navigation', {name: 'Resource pages'})).getByText('1–25 of 80 resources')).toBeVisible();
  fireEvent.click(screen.getByRole('button', {name: 'Next resources'}));
  expect(screen.getByText('26–50 of 80 resources')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Find a resource'), {target: {value: 'unique required'}});
  expect(screen.getAllByRole('article')).toHaveLength(1);
  expect(screen.getByRole('button', {name: 'Tune chart-50/Chart.yaml'})).toHaveAttribute('aria-expanded', 'false');
});
