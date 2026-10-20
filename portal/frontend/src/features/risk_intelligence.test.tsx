import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {Page, Sources} from './risk_intelligence';
import {requestJson} from '../api';
vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const service = {id: 1, name: 'Payments', service_key: 'payments'};
const assessment = {id: 7, as_of: '2026-10-19T12:00:00Z', summary: {assessment_state: 'no_scan', findings: 0, uncertain: 0, counts: {}}, details: [], provenance: {preview: true}, stale: true, stale_reasons: ['Policy changed']};
function setup({manage = false, kinds = [] as string[], canAssess = false, hasAssessment = true, sources = false} = {}) {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return {id: 9};
    if (url === '/api/risk/capabilities') return {manage, groups: [{id: 1, name: 'Payments group'}, {id: 2, name: 'Operations'}], default_policy: {"severity_weights": {"unknown": 40, "negligible": 5, "low": 15, "medium": 35, "high": 65, "critical": 85}, "epss_weight": 15, "kev_override": 95, "missing_floor": 40, "age_weight": 10, "age_days": 90, "exception_multiplier": 1.0, "fix_weight": 5, "uncertainty_weight": 10, "vex_not_affected_multiplier": 0.25, "thresholds": {"low": 0, "medium": 30, "high": 60, "critical": 85}, "max_age_hours": 24, "authority_labels": {"recommendation": "Cyber recommendation", "delegated_approval": "Delegated approval", "ao_decision": "Authorizing Official decision"}}};
    if (url.startsWith('/api/risk/services?')) return {items: [service]};
    if (url === '/api/risk/services/payments') return {service, compliance: 'RED', policy: null, can_assess: canAssess, assessment: hasAssessment ? assessment : null, decision_kinds: kinds, history: [], decisions: []};
    if (url === '/api/risk/sources') return {items: [{id: 3, name: 'Vendor', enabled: false, trusted: false, max_age_days: 30, documents: 0, statements: 0}], catalog: []};
    if (url.startsWith('/api/risk/profiles?')) return {items: []};
    throw new Error(`Unexpected request: ${url}`);
  });
  render(sources?<div/>:<Page data={{csrf_token: 'csrf', selected_group_id: 1, may_manage_risk_policy: true}}/>);
}
async function selectService() {
  fireEvent.click(await screen.findByRole('button', {name: 'Assessments'}));
  await screen.findByRole('option', {name: 'Payments'});
  fireEvent.change(screen.getByLabelText('Service'), {target: {value: 'payments'}});
  await screen.findByRole('heading', {name: 'Payments'});
}
it.each([false, true])('marks evidence informational and scopes source administration (manage=%s)', async manage => {
  setup({manage});
  const nav = await screen.findByRole('navigation', {name: 'Risk Policy'});
  expect(screen.getByText('Informational only.')).toBeInTheDocument();
  expect(screen.getByText(/do not change compliance, remediation, publication or runtime enforcement/)).toBeInTheDocument();
  expect(within(nav).getByRole('button', {name: 'Assessments'})).toBeInTheDocument();
  expect(within(nav).getByRole('button', {name: 'Risk Profiles'})).toBeInTheDocument();
  for (const name of ['Sources', 'VEX Explorer']) expect(Boolean(within(nav).queryByRole('button', {name}))).toBe(false);
});
it('distinguishes no scan, stale evidence and preview from a clean assessment', async () => {
  setup(); await selectService();
  expect(screen.getByText('No scan')).toBeInTheDocument();
  expect(screen.getByText(/Reassessment needed: Policy changed/)).toBeInTheDocument();
  expect(screen.getByText(/Preview only.*does not change the assigned policy/)).toBeInTheDocument();
  expect(screen.queryByRole('button', {name: 'Reassess'})).not.toBeInTheDocument();
  expect(screen.queryByText('Record a human risk decision')).not.toBeInTheDocument();
});
it('offers assessment action only when scoped permission is present, and requires assessment evidence for a decision', async () => {
  setup({canAssess: true, kinds: ['ao_decision'], hasAssessment: false}); await selectService();
  expect(screen.getByRole('button', {name: 'Reassess'})).toBeEnabled();
  expect(screen.getByText(/No assessment yet/)).toBeInTheDocument();
  expect(screen.queryByText('Record a human risk decision')).not.toBeInTheDocument();
});
it.each(['recommendation', 'delegated_approval', 'ao_decision'])('offers only the server-authorized %s decision authority', async kind => {
  setup({kinds: [kind]}); await selectService();
  fireEvent.click(screen.getByText('Record a human risk decision'));
  const authority = screen.getByLabelText('Decision authority');
  expect(within(authority).getAllByRole('option')).toHaveLength(1);
  expect(authority).toHaveValue(kind);
  expect(screen.getByText(/They do not approve publication or authorize workloads/)).toBeInTheDocument();
  expect(screen.queryByLabelText(/Reviewer/)).not.toBeInTheDocument();
  for (const label of ['Mission impact', 'Compensating controls', 'Decision justification', 'Evidence references (one per line)', 'Expires / reassess by']) expect(screen.getByLabelText(label)).toBeRequired();
});
it('explains manual document verification limits and uploads the original file with CSRF', async () => {
  setup({manage: true, sources: true});
  render(<Sources data={{csrf_token:'csrf'}}/>);
  expect(await screen.findByText(/A manual document upload stays unverified/)).toBeInTheDocument();
  await screen.findByRole('option', {name: 'Vendor'});
  fireEvent.change(screen.getByLabelText('Configured source'), {target: {value: '3'}});
  fireEvent.change(screen.getByLabelText('Import type'), {target: {value: 'documents'}});
  expect(screen.getByRole('option', {name: 'Unverified VEX document (4 MiB maximum)'})).toBeInTheDocument();
  const file = new File(['{"statements":[]}'], 'vex.json', {type: 'application/json'});
  fireEvent.change(screen.getByLabelText('File'), {target: {files: [file]}});
  fireEvent.submit(screen.getByLabelText('File').closest('form')!);
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/risk/sources/3/documents', expect.objectContaining({method: 'POST', body: file, headers: {'X-CSRF-Token': 'csrf', 'Content-Type': 'application/octet-stream'}})));
  expect(await screen.findByText('Saved.')).toBeInTheDocument();
  expect(screen.getByText(/A manual document upload stays unverified/)).toBeInTheDocument();
});
it('shows packaged general intelligence separately from VEX and preserves failure and acquisition context', async () => {
  setup({manage: true, sources: true});
  const existing = vi.mocked(requestJson).getMockImplementation()!;
  vi.mocked(requestJson).mockImplementation(async (url, options) => url === '/api/risk/sources' ? {
    items: [], catalog: [], embedded_package: {status: 'failed', version: '2026.10.18', built_at: '2026-10-18T00:00:00Z', installed_at: '2026-10-19T00:00:00Z', last_error: 'Signature rejected', counts: {sources: 1, records: 12, vex_documents: 0, vex_statements: 0, products: 2}, sources: [{id: 'kev', name: 'Packaged KEV', health: 'stale', trusted: true, enabled: true, acquired_at: '2026-10-17T00:00:00Z', expires_at: '2026-10-18T00:00:00Z', coverage: 'Known exploited vulnerabilities', url: 'https://example.com/audit', counts: {records: 12}}], exclusions: ['Unlicensed feeds excluded']}
  } : existing(url, options));
  render(<Sources data={{csrf_token:'csrf'}}/>);
  const packaged = await screen.findByRole('region', {name: 'Embedded intelligence package'});
  expect(within(packaged).getByText('2026.10.18')).toBeInTheDocument();
  expect(within(packaged).getByText(/Deployment does not refresh upstream evidence/)).toBeInTheDocument();
  expect(within(packaged).getByRole('alert')).toHaveTextContent('Signature rejected');
  expect(within(packaged).getByText('Packaged KEV')).toBeInTheDocument();
  expect(within(packaged).getAllByText('stale')).toHaveLength(2);
  expect(within(packaged).getByText('Acquired: 2026-10-17T00:00:00Z')).toBeInTheDocument();
  expect(within(packaged).getByText('VEX statements')).toBeInTheDocument();
  expect(within(packaged).getByRole('link', {name: 'Source audit reference'})).toHaveAttribute('href', 'https://example.com/audit');
  expect(within(packaged).queryByRole('button')).not.toBeInTheDocument();
  expect(screen.getByRole('heading', {name: 'Configured VEX sources'})).toBeInTheDocument();
});

it('labels bounded retained counts separately from exact package snapshot counts', async () => {
  setup({manage: true, sources: true});
  const existing = vi.mocked(requestJson).getMockImplementation()!;
  vi.mocked(requestJson).mockImplementation(async (url, options) => url === '/api/risk/sources' ? {
    items: [{id: 3, name: 'Vendor', enabled: true, trusted: true, documents: 12000,
      statements: null, statement_count_state: 'lower_bound', statement_count_lower_bound: 10001}],
    catalog: [], embedded_package: {status: 'installed', version: 'snapshot', counts: {},
      sources: [{id: 'vendor', name: 'Packaged vendor', counts: {vex_statements: 29000000}}]}
  } : existing(url, options));
  render(<Sources data={{csrf_token:'csrf'}}/>);
  expect(await screen.findByText(/10,001\+ retained statements \(total not counted\)/)).toBeInTheDocument();
  expect(screen.getByText('Latest package snapshot counts')).toBeInTheDocument();
  expect(screen.getByText(/12000 retained documents/)).toBeInTheDocument();
  expect(screen.getByText('29000000')).toBeInTheDocument();
});
it('shows saved service coverage and finding evidence to an authorized service viewer', async () => {
  setup();
  const existing = vi.mocked(requestJson).getMockImplementation()!;
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    const result = await existing(url, options) as Record<string, unknown>;
    if (url !== '/api/risk/services/payments') return result;
    return {...result, assessment: {...assessment, summary: {findings: 1, counts: {high: 1}, coverage: {
      total_findings: 1, counts: {authoritative_vex: 1, applicable_vex: 0, advisory_only: 0, kev: 0, epss: 1, no_intelligence: 0, unresolved_identity: 1, stale_or_conflicting: 0}, images: [],
    }}, details: [{finding_id: 1, cve: 'CVE-2026-1234', band: 'high', score: 70, observations: [{
      package: 'openssl', installed_version: '3', image: 'ubi:9', reasons: [], identity: {purl: 'pkg:rpm/redhat/openssl@3'},
      vex: {status: 'under_investigation', reasons: ['missing_product_context'], statements: []},
    }]}]}};
  });
  await selectService();
  expect(screen.getByRole('region', {name: 'Intelligence coverage'})).toBeInTheDocument();
  expect(screen.getByRole('table', {name: 'Service coverage — 1 unique findings'})).toBeInTheDocument();
  fireEvent.click(screen.getByText('Review 1 component observation(s)'));
  expect(screen.getByText('VEX: Under Investigation')).toBeInTheDocument();
  expect(screen.getByText('missing product context')).toBeInTheDocument();
  expect(screen.getByText('Observed component identity and scanner evidence')).toBeInTheDocument();
});

it('uses group-scoped requests and clears service selection when switching groups', async () => {
  setup(); await selectService();
  expect(requestJson).toHaveBeenCalledWith('/api/risk/services?group_id=1&q=&after=0', expect.anything());
  fireEvent.change(screen.getByLabelText('Owning group'), {target: {value: '2'}});
  await waitFor(()=>expect(requestJson).toHaveBeenCalledWith('/api/risk/profiles?group_id=2', expect.anything()));
  expect(screen.queryByRole('heading', {name:'Payments'})).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Assignment scope')).not.toBeInTheDocument();
});
it('saves a profile for the selected group and exposes the administration tab', async () => {
  setup();
  await screen.findByLabelText('Profile name');
  fireEvent.change(screen.getByLabelText('Profile name'),{target:{value:'Review policy'}});
  fireEvent.click(screen.getByRole('button',{name:'Save new version'}));
  await waitFor(()=>expect(requestJson).toHaveBeenCalledWith('/api/risk/profiles',expect.objectContaining({method:'POST',body:expect.stringContaining('"group_id":1')})));
  expect(screen.getByRole('link',{name:'Risk Policy'})).toHaveAttribute('href','/admin/risk-policy?group_id=1');
});

it('edits scoring controls and saves the configuration for the selected group', async () => {
  setup();
  const input=await screen.findByLabelText('Medium starts at');
  expect(input).toHaveValue(30);
  fireEvent.change(input,{target:{value:'45'}});
  fireEvent.change(screen.getByLabelText('Profile name'),{target:{value:'Production'}});
  fireEvent.click(screen.getByRole('button',{name:'Save new version'}));
  await waitFor(()=>expect(requestJson).toHaveBeenCalledWith('/api/risk/profiles',expect.objectContaining({method:'POST',body:expect.any(String)})));
  const call=vi.mocked(requestJson).mock.calls.find(([url,options])=>url==='/api/risk/profiles'&&options?.method==='POST')!;
  const payload=JSON.parse(String(call[1]?.body));
  expect(payload.group_id).toBe(1);
  expect(payload.configuration.thresholds).toEqual({low:0,medium:45,high:60,critical:85});
  expect(payload.configuration.severity_weights.critical).toBe(85);
});
it('blocks saving unordered thresholds and allows correction', async () => {
  setup();
  fireEvent.change(await screen.findByLabelText('Profile name'),{target:{value:'Production'}});
  fireEvent.change(screen.getByLabelText('Medium starts at'),{target:{value:'70'}});
  expect(screen.getByRole('alert')).toHaveTextContent('Thresholds must increase');
  expect(screen.getByRole('button',{name:'Save new version'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Medium starts at'),{target:{value:'30'}});
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByRole('button',{name:'Save new version'})).toBeEnabled();
});
