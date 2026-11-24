import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {Page, type RuntimeOverview} from './runtime';
import {ApiError, requestJson} from '../api';
import {Shell} from '../components/Shell';

vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
const data = {csrf_token: 'csrf-token', can: {'runtime.view': {'*': true}, 'runtime.manage': {'*': true}}, current_user: {display_name: 'Tester', theme: 'cats'}};
const overview = (): RuntimeOverview => ({
  environments: [{id: 1, name: 'Core Cluster 01', kind: 'kubernetes', service_ids: [7], created_at: '2026-11-09T12:00:00Z'}],
  agents: [{id: 'agent-1', environment_id: 1, name: 'Cluster observer', source_id: 'cluster-uid-123', version: '1.0', enabled: true,
    last_seen_at: new Date().toISOString(), observed_at: new Date().toISOString(), inventory_observed_at: new Date().toISOString(),
    complete: true, errors: [], coverage: 'fresh', workload_count: 1}],
  workloads: [{agent_id: 'agent-1', environment_id: 1, uid: 'pod-1', namespace: 'production', workload: 'Payments', container: 'app', node: 'node-1',
    image_ref: 'registry.example/payments:1', image_id: 'sha256:abc', state: 'running', chart_name: 'payments', chart_version: '1.0.0', helm_release: 'payments-prod',
    compliance: {status: 'approved', reason: 'exact_digest_match', service_id: 7, release_id: 8, approval_id: 9}}],
  groups: [{id: 3, name: 'Payments team'}],
  services: [{id: 7, name: 'Payments service'}, {id: 8, name: 'Orders service'}], permissions: {manage: true},
});
let current: RuntimeOverview;
beforeEach(() => {
  current = overview();
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (url === '/api/runtime/environments' && options?.method === 'POST') {
      const saved = {id: 2, created_at: new Date().toISOString(), ...JSON.parse(String(options.body))};
      current = {...current, environments: [...current.environments, saved]};
      return saved;
    }
    if (options?.method === 'PUT') {
      const saved = {...current.environments[0], ...JSON.parse(String(options.body))};
      current = {...current, environments: [saved]};
      return saved;
    }
    return current;
  });
});
afterEach(() => {cleanup(); vi.resetAllMocks(); vi.useRealTimers(); window.history.replaceState(null, '', '/');});
const ready = async () => {render(<Page data={data}/>); await screen.findByRole('button', {name: 'Link agent'});};

it('drills from a cluster to its issues and distinguishes expired approvals from missing evidence', async () => {
  const pod = {environment_id: 1, agent_id: 'agent-1', uid:'pay-uid', workload: 'payments-rs', pod:'payments-pod-1',
    container:'web', namespace:'production', image_ref:'registry.example/payments:v2', image_id:'sha256:expired'};
  current.issues = [{...pod, severity:'error', code:'noncompliant', reason:'release_expired'},
    {...pod, uid:'sidecar', container:'sidecar', image_id:'', severity:'warning', code:'unverified', reason:'immutable_runtime_identity_unavailable'}];
  current.namespaces = [{environment_id:1, name:'production', workload_count:2, issue_count:2}];
  vi.mocked(requestJson).mockImplementation(async url => url.includes('issue_code=unverified')
    ? {...current, issues:current.issues?.filter(row => row.code === 'unverified'), total_issues:1} : current);
  await ready();
  expect(screen.getByText('Namespaces (1)')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name:'View issues for Core Cluster 01'}));
  const issues = within(screen.getByRole('region', {name:'Runtime issues'}));
  expect(issues.getByLabelText('Cluster or host')).toHaveValue('1');
  const expired = issues.getByText(/approved release for this image has expired/).closest('tr')!;
  for (const value of ['production', 'payments-rs', 'payments-pod-1', 'Container web', 'registry.example/payments:v2', 'sha256:expired']) expect(expired).toHaveTextContent(value);
  expect(within(expired).getByText('Confirmed policy failure')).toBeVisible();
  expect(issues.getByText(/lacks a verified runtime image digest/)).toBeVisible();
  fireEvent.change(issues.getByLabelText('Issue type'), {target:{value:'unverified'}});
  expect(await issues.findByText('Container sidecar')).toBeVisible();
  expect(issues.queryByText(/approved release for this image has expired/)).not.toBeInTheDocument();
  expect(requestJson).toHaveBeenCalledWith(expect.stringContaining('environment_id=1&issue_code=unverified'), expect.anything());
});

it('finds an issue outside the loaded page using fleet namespace counts and resets the offset when filtering', async () => {
  const initial = {environment_id:1, agent_id:'agent-1', code:'noncompliant', reason:'release_expired', severity:'error', namespace:'production'};
  const later = {...initial, namespace:'settlement', workload:'payments-settlement'};
  current.issues = [initial]; current.total_issues = 401; current.next_issue_offset = 200;
  current.namespaces = [{environment_id:1,name:'production',workload_count:400,issue_count:400}, {environment_id:1,name:'settlement',workload_count:1,issue_count:1}];
  vi.mocked(requestJson).mockImplementation(async url => {
    const query = new URL(url, 'https://cats.example').searchParams;
    if (query.get('issue_namespace') === 'settlement') return {...current, issues:[later], next_issue_offset:null, total_issues:1};
    if (query.get('issue_offset') === '200') return {...current, issues:[{...initial, workload:'second-page-workload'}], next_issue_offset:400};
    return current;
  });
  await ready();
  fireEvent.click(screen.getByRole('button', {name:'View issues for Core Cluster 01'}));
  const region = within(screen.getByRole('region', {name:'Runtime issues'}));
  fireEvent.click(await screen.findByRole('button', {name:'Next issues'}));
  await region.findByText('second-page-workload');
  expect(region.queryByText('payments-settlement')).not.toBeInTheDocument();
  fireEvent.change(region.getByLabelText('Namespace'), {target:{value:'settlement'}});
  expect(await region.findByText('payments-settlement')).toBeVisible();
  expect(requestJson).toHaveBeenCalledWith(expect.stringContaining('issue_offset=0&environment_id=1&issue_namespace=settlement'), expect.anything());
  fireEvent.change(region.getByLabelText('Issue type'), {target:{value:'noncompliant'}});
  await region.findByText('payments-settlement');
  expect(requestJson).toHaveBeenCalledWith(expect.stringContaining('issue_offset=0&environment_id=1&issue_namespace=settlement&issue_code=noncompliant'), expect.anything());
  expect(screen.queryByRole('button', {name:'Next issues'})).not.toBeInTheDocument();
});

it('does not present retained denials as confirmed when reporting is stale', async () => {
  current.agents[0].coverage = 'stale';
  current.issues = [{environment_id:1,agent_id:'agent-1', namespace:'production', severity:'error', code:'noncompliant',reason:'release_expired'}];
  await ready();
  fireEvent.click(screen.getByRole('button', {name:'Issues'}));
  const issues = within(screen.getByRole('region', {name:'Runtime issues'}));
  expect(issues.getByText('Reason from retained evidence.')).toBeVisible();
  expect(issues.queryByText('Confirmed policy failure', {selector:'.badge'})).not.toBeInTheDocument();
});

it('shows an approved release alongside an exact scan failure in the workload and its issue', async () => {
  const image = current.workloads[0];
  const scannedAt = '2026-11-09T11:17:14Z';
  image.compliance.scan_assessment = {status:'noncompliant', reason:'scan_image_noncompliant', execution_id:42, source:'local_scan', scanned_at:scannedAt};
  current.workloads.push({...image, uid:'other-pod', workload:'No matched scan', compliance:{...image.compliance,
    scan_assessment:{status:'unverified', reason:'scan_image_evidence_unavailable'}}});
  current.issues = [{environment_id:1, agent_id:image.agent_id, uid:image.uid, workload:image.workload, namespace:image.namespace,
    code:'scan_noncompliant', codes:['scan_noncompliant'], reason:'scan_image_noncompliant', severity:'error', compliance:image.compliance}];
  await ready();
  const table = within(screen.getByRole('region', {name:'Observed workloads'}));
  const matched = within(table.getByText('Payments').closest('tr')!);
  expect(matched.getByText('Approved').closest('.badge')).toHaveClass('badge-success');
  expect(matched.getByText('Scan noncompliant').closest('.badge')).toHaveClass('badge-danger');
  expect(matched.getByText('Assessment execution 42')).toBeVisible();
  expect(matched.getByText('Local scan')).toBeVisible();
  expect(matched.getByText('Scanned').querySelector('time')).toHaveAttribute('datetime', scannedAt);
  const unknown = within(table.getByText('No matched scan').closest('tr')!);
  expect(unknown.getByText('Scan unverified').closest('.badge')).toHaveClass('badge-neutral');
  expect(unknown.queryByText('Scan noncompliant')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name:'Issues'}));
  const issues = within(screen.getByRole('region', {name:'Runtime issues'}));
  fireEvent.change(issues.getByLabelText('Issue type'), {target:{value:'scan_noncompliant'}});
  const row = within((await issues.findByText('Release approved')).closest('tr')!);
  expect(row.getByText('Scan noncompliant')).toBeVisible();
  expect(row.getByText('Assessment execution 42')).toBeVisible();
  expect(row.getByText('Local scan')).toBeVisible();
  expect(row.getByText('Scanned').querySelector('time')).toHaveAttribute('datetime', scannedAt);
  expect(issues.getAllByRole('row')).toHaveLength(2);
  expect(requestJson).toHaveBeenCalledWith(expect.stringContaining('issue_code=scan_noncompliant'), expect.anything());
});

it('preserves the publisher scan timestamp and source when reporting a historical failure', async () => {
  current.agents[0].coverage = 'stale';
  const image = current.workloads[0];
  const scannedAt = '2026-11-07T10:00:00Z';
  image.compliance.scan_assessment = {status:'noncompliant', reason:'scan_image_noncompliant', source:'publisher_capture', scanned_at:scannedAt};
  current.issues = [{environment_id:1, agent_id:image.agent_id, severity:'error', code:'scan_noncompliant',
    reason:'scan_image_noncompliant', compliance:image.compliance}];
  await ready();
  expect(screen.getByText('Scan status unchecked').closest('.badge')).toHaveClass('badge-neutral');
  fireEvent.click(screen.getByRole('button', {name:'Issues'}));
  const issues = within(screen.getByRole('region', {name:'Runtime issues'}));
  expect(issues.getByText('Last assessment was noncompliant.')).toBeVisible();
  expect(issues.getByText('Verified publisher capture')).toBeVisible();
  expect(issues.getByText('Scanned').querySelector('time')).toHaveAttribute('datetime', scannedAt);
  expect(issues.queryByText('Scan noncompliant')).not.toBeInTheDocument();
  expect(issues.queryByText('Confirmed policy failure')).not.toBeInTheDocument();
});

it('lists all linked agents across clusters and opens the selected host', async () => {
  current.environments.push({id: 2, name: 'Edge Docker', created_at:'2026-11-09', kind:'docker', service_ids:[8]});
  current.agents.push({...current.agents[0], id:'agent-2', name:'Edge collector', environment_id:2, enabled:false, coverage:'revoked'});
  await ready();
  fireEvent.click(screen.getByRole('button', {name:'All agents'}));
  const agents = within(screen.getByRole('region', {name:'All linked agents'}));
  expect(agents.getByText('Cluster observer')).toBeVisible();
  expect(agents.getByText('Edge collector')).toBeVisible();
  const edge = within(agents.getByText('Edge collector').closest('tr')!);
  expect(edge.getByText('Revoked')).toBeVisible();
  expect(edge.queryByRole('button', {name:'Revoke agent'})).not.toBeInTheDocument();
  fireEvent.click(edge.getByRole('button', {name:'Edge Docker'}));
  expect(within(screen.getByRole('region', {name:'Environment details'})).getByRole('heading', {name:'Edge Docker'})).toBeVisible();
});

it('includes a Helm enrollment command with a protected key file and no embedded credential', async () => {
  await ready();
  vi.mocked(requestJson).mockResolvedValueOnce({environment_id:1, expires_at:new Date(Date.now() + 3600000).toISOString(), linking_key:'key-plaintext-example'});
  fireEvent.click(screen.getByRole('button', {name:'Link agent'}));
  const panel = within(await screen.findByRole('region', {name:'Link an agent'}));
  expect(panel.getByLabelText('Linking key')).toHaveValue('key-plaintext-example');
  const example = panel.getByText(/helm upgrade --install/);
  expect(example).toHaveTextContent('--set-string catsUrl="$CATS_URL"');
  expect(example).toHaveTextContent('--set-file linkingKey=./linking-key');
  expect(example).not.toHaveTextContent('key-plaintext-example');
  expect(panel.getByText('--set-string linkingKeySecret=SECRET_NAME')).toBeVisible();
});

it('pages cluster observations and fleet issues independently', async () => {
  current.inventory_truncated = true;
  current.next_offset = 200;
  current.total_workloads = 5010;
  const issue = {environment_id:1, code:'coverage', reason:'coverage_unlinked', severity:'warning'};
  current.issues = [issue]; current.total_issues = 201; current.next_issue_offset = 200;
  vi.mocked(requestJson).mockImplementation(async url => {
    if (url.includes('issue_offset=200')) return {...current, next_issue_offset:null, issues:[{...issue, reason:'coverage_never_reported'}]};
    if (url.includes('offset=200')) return {...current, inventory_truncated:true, next_offset:null,
      workloads:[{...current.workloads[0], workload:'Final observation'}]};
    return current;
  });
  await ready();
  fireEvent.click(await screen.findByRole('button', {name:'Next observations'}));
  await screen.findByText('Final observation');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime?limit=200&issue_limit=200&offset=200&environment_id=1', expect.anything());
  expect(screen.getByRole('button', {name:'Next observations'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button', {name:'Issues'}));
  expect(await screen.findByText(/1 of 201 reported issues/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', {name:'Next issues'}));
  await screen.findByText('The agent has not sent its first report.');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime?limit=200&issue_limit=200&issue_offset=200', expect.anything());
  expect(screen.getByRole('button', {name:'Next issues'})).toBeDisabled();
  expect(screen.getByRole('button', {name:'Previous issues'})).toBeEnabled();
});

it('shows a neutral discovery observation in development clusters', async () => {
  current.workloads[0].compliance = {status: 'observed', reason: 'development_inventory'};
  await ready();
  expect(screen.getByText('Observed')).toBeVisible();
  expect(screen.getByText('Observed in development.')).toBeVisible();
  expect(screen.getByText('No scan assessment')).toBeVisible();
});

it('creates new clusters with dynamic all-service scope by default', async () => {
  await ready();
  fireEvent.click(screen.getByRole('button', {name:'New environment'}));
  const form = within(screen.getByRole('region', {name:'New environment'}));
  fireEvent.change(form.getByLabelText('Environment name'), {target:{value:'Site B'}});
  fireEvent.click(form.getByRole('button', {name:'Create environment'}));
  await screen.findByText('Environment saved.');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/environments', expect.objectContaining({method:'POST',
    body:JSON.stringify({name:'Site B',kind:'kubernetes',service_scope:'all',service_ids:[],cluster_role:'unspecified',discovery_group_id:null})}));
  expect(screen.getByRole('button', {name:'Link agent'})).toBeEnabled();
});

it('creates a named environment with explicit services and a CSRF header', async () => {
  await ready();
  fireEvent.click(screen.getByRole('button', {name: 'New environment'}));
  const form = screen.getByRole('region', {name: 'New environment'});
  expect(within(form).getByLabelText('Environment name')).toHaveAttribute('maxlength', '160');
  expect(within(form).getByLabelText('Approval scope')).toHaveValue('all');
  fireEvent.change(within(form).getByLabelText('Approval scope'), {target:{value:'selected'}});
  expect(within(form).getByText(/Select at least one/)).toBeVisible();
  fireEvent.change(within(form).getByLabelText('Environment name'), {target: {value: 'Edge Docker 02'}});
  fireEvent.change(within(form).getByLabelText('Runtime type'), {target: {value: 'docker'}});
  expect(within(form).queryByLabelText('Cluster role')).toBeNull();
  fireEvent.click(within(form).getByLabelText('Orders service'));
  fireEvent.click(within(form).getByRole('button', {name: 'Create environment'}));
  await screen.findByText('Environment saved.');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/environments', expect.objectContaining({method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-token'},
    body: JSON.stringify({name: 'Edge Docker 02', kind: 'docker', service_scope: 'selected', service_ids: [8]}),
  }));
  expect(screen.getByRole('button', {name: 'Edge Docker 02 Docker'})).toHaveAttribute('aria-pressed', 'true');
  vi.mocked(requestJson).mockResolvedValueOnce({linking_key: 'new-environment-key', expires_at: new Date(Date.now() + 600000).toISOString(), environment_id: 2});
  fireEvent.click(screen.getByRole('button', {name: 'Link agent'}));
  expect(await screen.findByLabelText('Linking key')).toHaveValue('new-environment-key');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/environments/2/link-tokens', expect.objectContaining({method: 'POST'}));
});

it('edits environment scope without changing the runtime type', async () => {
  await ready();
  fireEvent.click(screen.getByRole('button', {name: 'Edit environment'}));
  const form = screen.getByRole('region', {name: 'Edit environment'});
  expect(within(form).getByLabelText('Runtime type')).toBeDisabled();
  fireEvent.change(within(form).getByLabelText('Environment name'), {target: {value: 'Core Cluster 01 renamed'}});
  fireEvent.change(within(form).getByLabelText('Cluster role'), {target: {value: 'validation'}});
  fireEvent.change(within(form).getByLabelText('Discovery group'), {target: {value: '3'}});
  fireEvent.click(within(form).getByLabelText('Payments service'));
  expect(within(form).getByRole('button', {name:'Save environment'})).toBeDisabled();
  fireEvent.change(within(form).getByLabelText('Approval scope'), {target:{value:'all'}});
  fireEvent.click(within(form).getByRole('button', {name: 'Save environment'}));
  await screen.findByText('Environment saved.');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/environments/1', expect.objectContaining({method: 'PUT',
    body: JSON.stringify({name: 'Core Cluster 01 renamed', service_scope: 'all', service_ids: [], cluster_role: 'validation', discovery_group_id: 3}),
  }));
});

it('shows a linking key and expiration once and clears it when dismissed', async () => {
  const expires = new Date(Date.now() + 600000).toISOString();
  vi.mocked(requestJson).mockImplementation(async url => url.endsWith('/link-tokens') ? {linking_key: 'one-use-secret', expires_at: expires, environment_id: 1} : current);
  await ready();
  fireEvent.click(screen.getByRole('button', {name: 'Link agent'}));
  expect(await screen.findByLabelText('Linking key')).toHaveValue('one-use-secret');
  const panel = screen.getByRole('region', {name: 'Link an agent'});
  expect(panel).toHaveTextContent(new Date(expires).toLocaleString());
  expect(panel).toHaveTextContent('one-use key');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/environments/1/link-tokens', expect.objectContaining({method: 'POST', body: '{}'}));
  fireEvent.click(within(panel).getByRole('button', {name: 'Close linking key'}));
  expect(screen.queryByLabelText('Linking key')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Refresh'}));
  await waitFor(() => expect(screen.getByRole('button', {name: 'Refresh'})).toBeEnabled());
  expect(screen.queryByDisplayValue('one-use-secret')).not.toBeInTheDocument();
});

it('removes a linking key when it expires', async () => {
  vi.useFakeTimers();
  vi.mocked(requestJson).mockImplementation(async url => url.endsWith('/link-tokens') ? {linking_key: 'expires-soon', expires_at: new Date(Date.now() + 1000).toISOString(), environment_id: 1} : current);
  await act(async () => {render(<Page data={data}/>);});
  await act(async () => {fireEvent.click(screen.getByRole('button', {name: 'Link agent'}));});
  expect(screen.getByLabelText('Linking key')).toHaveValue('expires-soon');
  await act(async () => {vi.advanceTimersByTime(1001);});
  expect(screen.queryByLabelText('Linking key')).not.toBeInTheDocument();
});

it('requires a local confirmation before revoking and refreshes the agent report', async () => {
  vi.mocked(requestJson).mockImplementation(async url => {
    if (url.endsWith('/revoke')) {current = {...current, agents: current.agents.map(agent => ({...agent, enabled: false, coverage: 'revoked'}))}; return {};}
    return current;
  });
  await ready();
  fireEvent.click(screen.getByRole('button', {name: 'Revoke agent'}));
  expect(vi.mocked(requestJson).mock.calls.some(([url]) => url.endsWith('/revoke'))).toBe(false);
  fireEvent.click(screen.getByRole('button', {name: 'Confirm revoke'}));
  await screen.findByText('Agent revoked. It can no longer submit reports.');
  expect(requestJson).toHaveBeenCalledWith('/api/runtime/agents/agent-1/revoke', expect.objectContaining({method: 'POST', body: '{}'}));
  await waitFor(() => expect(screen.queryByRole('button', {name: 'Revoke agent'})).not.toBeInTheDocument());
  expect(screen.getAllByText('Revoked').length).toBeGreaterThan(0);
});

it('does not present stale approved observations as current compliance or green approval', async () => {
  current.agents[0].coverage = 'stale';
  await ready();
  expect(screen.getByText(/Current runtime compliance is not established/)).toBeInTheDocument();
  expect(screen.getAllByText('Stale report')).toHaveLength(2);
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-neutral');
  expect(screen.getByText('Retained observation only')).toBeInTheDocument();
  expect(screen.getByText('Unverified provenance')).toBeInTheDocument();
  expect(screen.getByText('cluster-uid-123')).toBeInTheDocument();
});

it('shows incomplete coverage, retained inventory time and report issues', async () => {
  current.agents[0] = {...current.agents[0], coverage: 'incomplete', complete: false, observed_at: '2026-11-09T13:00:00Z', inventory_observed_at: '2026-11-09T12:00:00Z', errors: ['A namespace could not be read.']};
  current.inventory_truncated = true; current.total_workloads = 6000;
  await ready();
  expect(screen.getByText(/retained inventory may be from an earlier complete report/)).toBeInTheDocument();
  expect(await screen.findByText(/on this inventory page/)).toHaveTextContent('1 of 6000');
  const agents = screen.getByRole('region', {name: 'Agents'});
  expect(within(agents).getByText('Inventory observed').nextElementSibling).toHaveTextContent(new Date('2026-11-09T12:00:00Z').toLocaleString());
  fireEvent.click(screen.getByText('Report issues (1)'));
  expect(screen.getByText('A namespace could not be read.')).toBeVisible();
});

it('hides management controls for read-only viewers', async () => {
  current.permissions.manage = false;
  render(<Page data={data}/>);
  await screen.findByRole('region', {name: 'Agents'});
  for (const name of ['New environment', 'Edit environment', 'Link agent', 'Revoke agent']) expect(screen.queryByRole('button', {name})).not.toBeInTheDocument();
});

it('surfaces denied link requests without displaying a secret or claiming success', async () => {
  vi.mocked(requestJson).mockImplementation(async url => {if (url.endsWith('/link-tokens')) throw new Error('Runtime management permission is required.'); return current;});
  await ready();
  fireEvent.click(screen.getByRole('button', {name: 'Link agent'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Runtime management permission is required.');
  expect(screen.queryByLabelText('Linking key')).not.toBeInTheDocument();
  expect(screen.getByRole('button', {name: 'Link agent'})).toBeEnabled();
});

it('marks retained observations as unchecked when refresh fails', async () => {
  await ready();
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-success');
  vi.mocked(requestJson).mockRejectedValue(new Error('Runtime view permission is required.'));
  fireEvent.click(screen.getByRole('button', {name: 'Refresh'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('current coverage could not be checked');
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-neutral');
});

it('clears retained inventory when access is revoked between refreshes', async () => {
  await ready();
  vi.mocked(requestJson).mockRejectedValue(new ApiError('Runtime access denied.', 403));
  fireEvent.click(screen.getByRole('button', {name:'Refresh'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Runtime access denied.');
  expect(screen.queryByText('cluster-uid-123')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', {name:'Link agent'})).not.toBeInTheDocument();
});

it('refreshes after 30 seconds without trusting pending reads or overlapping requests', async () => {
  vi.useFakeTimers();
  let finish!: (value: RuntimeOverview) => void;
  const pending = new Promise<RuntimeOverview>(resolve => {finish = resolve;});
  let view!: ReturnType<typeof render>;
  await act(async () => {view = render(<Page data={data}/>);});
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-success');
  vi.mocked(requestJson).mockReturnValueOnce(pending);
  await act(async () => {vi.advanceTimersByTime(30000);});
  expect(requestJson).toHaveBeenCalledTimes(2);
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-neutral');
  expect(screen.getAllByText('Checking coverage')).toHaveLength(2);
  await act(async () => {vi.advanceTimersByTime(90000);});
  expect(requestJson).toHaveBeenCalledTimes(2);
  view.unmount();
  expect(vi.mocked(requestJson).mock.calls[1][1]?.signal?.aborted).toBe(true);
  await act(async () => {finish(current); vi.advanceTimersByTime(60000);});
  expect(requestJson).toHaveBeenCalledTimes(2);
});

it('locally expires five-minute evidence before the next poll', async () => {
  vi.useFakeTimers();
  current.agents[0].observed_at = new Date(Date.now() - 299000).toISOString();
  await act(async () => {render(<Page data={data}/>);});
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-success');
  await act(async () => {vi.advanceTimersByTime(1002);});
  expect(requestJson).toHaveBeenCalledTimes(1);
  expect(screen.getAllByText('Stale report')).toHaveLength(2);
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-neutral');
  expect(screen.getByText(/Current runtime compliance is not established/)).toBeInTheDocument();
});

it('keeps a failed refresh warning through the next pending retry until success', async () => {
  vi.useFakeTimers();
  await act(async () => {render(<Page data={data}/>);});
  vi.mocked(requestJson).mockRejectedValueOnce(new Error('Runtime service unavailable.'));
  await act(async () => {vi.advanceTimersByTime(30000);});
  expect(screen.getByRole('alert')).toHaveTextContent('Runtime service unavailable.');
  expect(screen.getAllByText('Coverage unchecked')).toHaveLength(2);
  let finish!: (value: RuntimeOverview) => void;
  vi.mocked(requestJson).mockReturnValueOnce(new Promise<RuntimeOverview>(resolve => {finish = resolve;}));
  await act(async () => {vi.advanceTimersByTime(30000);});
  expect(screen.getByRole('alert')).toHaveTextContent('Runtime service unavailable.');
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-neutral');
  await act(async () => {finish(current);});
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByText('Approved').closest('.badge')).toHaveClass('badge-success');
});

it('shows Runtime navigation to authorized users in full and replica modes', () => {
  window.history.replaceState(null, '', '/runtime');
  const {rerender} = render(<Shell data={data}>Runtime content</Shell>);
  expect(screen.getByRole('link', {name: 'Clusters & agents'})).toHaveAttribute('aria-current', 'page');
  rerender(<Shell data={{...data, can: {}}}>Runtime content</Shell>);
  expect(screen.queryByRole('link', {name: 'Clusters & agents'})).not.toBeInTheDocument();
  rerender(<Shell data={{...data, cats_mode: 'replica'}}>Runtime content</Shell>);
  expect(screen.getByRole('link', {name: 'Clusters & agents'})).toHaveAttribute('href', '/runtime');
});
