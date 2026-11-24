import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {ApiError, requestJson} from '../api';
import {ApprovalDetail, Destinations, Page as Approvals, ReleaseDetail, Releases, RequestApproval, Reassessment} from './cyber_approvals';

vi.mock('../api', async original => ({...await original<any>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks(); window.history.replaceState({}, '', '/');});
const data = {csrf_token:'csrf', can:{'approval.request':{'7':true},'release.destination.manage':{'*':true}}};
const ready = {service_id:7, ready:true, blockers:[], version:'1.0', scan_date:'2026-10-14', destinations:[{id:2,name:'Approved registry',endpoint:'registry.test',namespace:'approved',is_default:true}],remediations:[{id:'rem-1',label:'Remediation 1'}]};

it('keeps approval requests, approved releases, and detail navigation inside the selected service', async () => {
  const serviceKey = 'gateway 1';
  const query = new URLSearchParams({service: serviceKey});
  window.history.replaceState({}, '', `/approved-releases?${query}`);
  vi.mocked(requestJson).mockResolvedValue({items: [{id: 9, service_name: 'Gateway', service_key: serviceKey}]});
  const releases = render(<Releases data={data}/>);
  const top = within(screen.getByRole('navigation', {name: 'Service views'}));
  expect(top.getByRole('link', {name: 'Releases'})).toHaveAttribute('aria-current', 'page');
  expect(top.queryByRole('link', {name: 'Approvals'})).toBeNull();
  const sections = within(screen.getByRole('navigation', {name: 'Release views'}));
  const requests = sections.getByRole('link', {name: 'Approval requests'});
  expect(requests).toHaveAttribute('href', `/cyber-approvals?${query}`);
  expect(sections.getByRole('link', {name: 'Approved releases'})).toHaveAttribute('aria-current', 'page');
  const detail = await screen.findByRole('link', {name: 'Gateway'});
  expect(detail).toHaveAttribute('href', `/approved-releases?id=9&${query}`);
  window.history.replaceState({}, '', detail.getAttribute('href')!);
  releases.rerender(<Releases data={data}/>);
  expect(screen.getByRole('link', {name: 'Service releases'})).toHaveAttribute('href', `/approved-releases?${query}`);
  releases.unmount();
  window.history.replaceState({}, '', `/cyber-approvals?${query}`);
  render(<Approvals data={data}/>);
  expect(within(screen.getByRole('navigation', {name: 'Release views'})).getByRole('link', {name: 'Approval requests'})).toHaveAttribute('aria-current', 'page');
  expect(await screen.findByRole('link', {name: 'Gateway · #9'})).toHaveAttribute('href', `/cyber-approvals?id=9&${query}`);
});
const distribution = {id:'dist-1', name:'Regional gateway', inventory_id:'inv-2', selection_digest:'sha256:frozen',
  enabled_chart_ids:['cache'], disabled_chart_ids:['worker'], images:['registry/cache:1'],
  charts:[{id:'cache', label:'Cache', version:'1', reference:'oci://reg/cache',source_path:'charts/cache'},
    {id:'worker', label:'Worker', version:'2', reference:'oci://reg/worker',source_path:'charts/worker'}]};

it('shows catalog identities and service roles for assessed digests', async () => {
  vi.mocked(requestJson).mockResolvedValue({...ready, runtime_candidate:{id:12,status:'draft'},
    runtime_evidence:{assessments:[
      {reference:'registry/api',status:'complete',catalog_matches:[{artifact_id:77,media_type:'application/octet-stream',
        platform:'unknown',roles:['release','source']}]},
      {name:'api chart',status:'complete',catalog_matches:[]}, {name:'pending image',status:'queued'}
    ]}});
  render(<RequestApproval data={data} serviceKey="sample" runtimeCandidateId="12"/>);
  fireEvent.click(await screen.findByText('Artifact assessments and SBOMs'));
  const table = within(screen.getByRole('table', {name:'Service catalog entries with the assessed digest'}));
  expect(table.getByRole('columnheader', {name:'Catalog platform'})).toBeVisible();
  expect(table.getByRole('row', {name:/#77 application\/octet-stream unknown release, source/})).toBeVisible();
  expect(screen.getAllByText('No service catalog entries match this assessed digest.')).toHaveLength(1);
});

it('submits the reviewed runtime evidence using its candidate and digest', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({...ready, can_request:true, review_digest:'sha256:review',
    runtime_candidate:{id:12, status:'returned', approval_id:11, decision_rationale:'Update the scan'},
    runtime_evidence:{source:{cluster:'Validation', namespace:'team-one'}, fingerprint:'sha256:inventory',
      revision:3, proposed_version:'2.1'}}).mockResolvedValueOnce({id:14});
  render(<RequestApproval data={data} serviceKey="sample" runtimeCandidateId="12"/>);
  await screen.findByText('Validation');
  expect(screen.getByText(/Update the scan/)).toBeVisible();
  expect(screen.getByRole('link', {name:'Previous review'})).toHaveAttribute('href','/cyber-approvals?id=11');
  expect(screen.queryByLabelText('Release variant')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name:'Submit for Cyber Review'}));
  await screen.findByRole('link', {name:'Review request #14'});
  expect(JSON.parse(String(vi.mocked(requestJson).mock.calls[1][1]?.body))).toEqual(
    {service_key:'sample',variant:'current_service',runtime_candidate_id:12,review_digest:'sha256:review'});
});

it('links a submitted runtime candidate directly to its immutable review', async () => {
  vi.mocked(requestJson).mockResolvedValue({runtime_candidate:{id:12,status:'submitted',approval_id:13},ready:false,can_request:false});
  render(<RequestApproval data={data} serviceKey="sample" runtimeCandidateId="12"/>);
  expect(await screen.findByRole('link',{name:'Open submitted snapshot and Cyber decision'})).toHaveAttribute('href','/cyber-approvals?id=13');
  expect(screen.queryByRole('button',{name:'Submit for Cyber Review'})).not.toBeInTheDocument();
});

it('hides runtime submission when the service only grants classic approval requests', async () => {
  vi.mocked(requestJson).mockResolvedValue({...ready, can_request:false, runtime_candidate:{id:12, status:'draft'}});
  render(<RequestApproval data={{...data, can_request:true}} serviceKey="sample" runtimeCandidateId="12"/>);
  await screen.findByText('You do not have permission to request Cyber approval for this service.');
  expect(screen.queryByRole('button', {name:'Submit for Cyber Review'})).not.toBeInTheDocument();
});

it('shows only retained inventory and audit events for a superseded unsubmitted draft', async () => {
  vi.mocked(requestJson).mockResolvedValue({ready:false, can_request:false,
    historical_inventory:{source:{cluster:'Validation'}, revision:1, fingerprint:'original-fingerprint',
      proposed_version:'1.2', created_at:'2026-11-20T14:00:00Z', applications:[], images:[], charts:[],
      history:[{action:'runtime.candidate.superseded',recorded_at:'2026-11-20T15:00:00Z',actor:'System'}]}});
  render(<RequestApproval data={data} serviceKey="sample" runtimeCandidateId="12"/>);
  await screen.findByRole('heading', {name:'Superseded runtime candidate for sample'});
  expect(screen.getByText('original-fingerprint')).toBeVisible();
  expect(screen.getByRole('heading', {name:'Candidate history'})).toBeVisible();
  expect(screen.getByText(/Superseded · System/i)).toBeVisible();
  expect(screen.queryByRole('button', {name:'Submit for Cyber Review'})).not.toBeInTheDocument();
  expect(screen.queryByText(/No findings recorded/)).not.toBeInTheDocument();
});

it('returns the frozen runtime submission with a reason and retains unknown comparison results', async () => {
  const row = {id:12, status:'pending', can_decide:true, service_key:'sample', runtime_candidate_id:3,
    snapshot:{runtime_evidence:{source:{cluster:'Validation'}, findings:[], comparison:{
      baseline_available:true, revision_id:9, added:[], removed:null, updated:[], vulnerabilities_comparable:false}}}};
  vi.mocked(requestJson).mockResolvedValue(row);
  render(<ApprovalDetail data={data} id="12"/>);
  await screen.findByRole('heading',{name:'Runtime inventory and assessment'});
  expect(screen.getByText(/removals unknown/)).toBeVisible();
  fireEvent.change(screen.getByLabelText('Decision'), {target:{value:'returned'}});
  const button = screen.getByRole('button',{name:'Return for changes'});
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Decision rationale'), {target:{value:'Supply the missing artifact evidence'}});
  fireEvent.click(button);
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/cyber-approvals/12/decision',expect.objectContaining({
    body:JSON.stringify({decision:'returned',rationale:'Supply the missing artifact evidence'})})));
});

it('requests the exact saved distribution and its reviewed scan execution', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({...ready, distribution, source_execution_id:91}).mockResolvedValueOnce({id:20});
  render(<RequestApproval data={data} serviceKey="sample" distributionId="dist-1"/>);
  await screen.findByText('Ready for Cyber review');
  expect(screen.getByText('Regional gateway')).toBeInTheDocument();
  expect(screen.queryByLabelText('Release variant')).not.toBeInTheDocument();
  expect(requestJson).toHaveBeenCalledWith('/api/services/sample/cyber-approval-readiness?variant=current_service&distribution_id=dist-1', expect.anything());
  fireEvent.click(screen.getByRole('button', {name:'Request Cyber Approval'}));
  await screen.findByRole('link', {name:'Review request #20'});
  const options = vi.mocked(requestJson).mock.calls[1][1];
  expect(JSON.parse(String(options?.body))).toEqual({service_key:'sample',variant:'current_service',distribution_id:'dist-1',expected_source_execution_id:91});
});

it.each([{id:'dist-2', execution:91},{id:'dist-1', execution:null}])('blocks a scoped request without its matching scan (%o)', async ({id, execution}) => {
  vi.mocked(requestJson).mockResolvedValue({...ready, distribution:{...distribution, id}, source_execution_id:execution});
  render(<RequestApproval data={data} serviceKey="sample" distributionId="dist-1"/>);
  await screen.findByText('Evidence incomplete');
  expect(screen.getByRole('button', {name:'Request Cyber Approval'})).toBeDisabled();
});

it.each([ApprovalDetail, ReleaseDetail])('shows frozen chart settings and image identities in the decision and release views', async Detail => {
  vi.mocked(requestJson).mockResolvedValue({id:22, service_key:'sample', status:'approved', snapshot:{distribution}});
  render(<Detail data={data} id="22"/>);
  const frozen = within(await screen.findByRole('region', {name:'Frozen distribution selection'}));
  expect(frozen.getByRole('heading', {name:'Regional gateway'})).toBeVisible();
  expect(frozen.getByRole('heading', {name:'Enabled charts (1)'}).nextElementSibling).toHaveTextContent('oci://reg/cache');
  expect(frozen.getByRole('heading', {name:'Disabled charts (1)'}).nextElementSibling).toHaveTextContent('oci://reg/worker');
  fireEvent.click(frozen.getByText('Images in this distribution (1)'));
  expect(frozen.getByText('registry/cache:1')).toBeVisible();
  if (Detail === ApprovalDetail) {
    expect(screen.getByRole('link', {name:'Service distributions'})).toHaveAttribute('href','/services/sample?artifacts=true#service-distributions');
    expect(screen.queryByRole('region', {name:'Scheduled reassessment'})).not.toBeInTheDocument();
  }
});

it('shows compact frozen service context with attributed ports and expandable coverage', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:12, status:'pending', snapshot:{
    service_context:{description:'Internal reporting service',owner:'Platform team',deployment_types:['Docker Compose', 'Helm'],
      architecture:{components:{ComposeService:2,ComposeNetwork:1},relationships:3,unresolved:1,incomplete:true}},
    artifacts:[{kind:'image'}, {kind:'image'}, {kind:'chart'}], overview:{source:'Docker Compose',
      environment:{PASSWORD:'never-show-this'}, ports:Array.from({length:7}, (_, index) => ({
        service:`workload-${index}`, port:String(8000 + index), protocol:index === 0 ? 'UDP' : 'TCP',
        declared_by:index === 0 ? 'Compose published host port 9000' : 'Compose expose',
        boundary:index === 0 ? 'Host published' : 'Internal', source_file:'compose.yaml', fqdn:index === 0 ? 'api.example.test' : undefined,
      }))}}});
  render(<ApprovalDetail data={data} id="12"/>);
  const summary = within(await screen.findByRole('region', {name:'Service at a glance'}));
  expect(summary.getByText('Internal reporting service')).toBeInTheDocument();
  expect(summary.getByText('Platform team')).toBeInTheDocument();
  expect(summary.getByText('Docker Compose + Helm')).toBeInTheDocument();
  expect(summary.getByText('2 Compose Service')).toBeInTheDocument();
  expect(summary.getByText('3 relationships')).toBeInTheDocument();
  expect(summary.getByText(/runtime reachability is not verified/)).toHaveTextContent('Coverage is incomplete');
  expect(summary.getByText('2 images')).toBeInTheDocument();
  expect(summary.getByText('1 Helm charts')).toBeInTheDocument();
  expect(summary.getByText('UDP')).toBeInTheDocument();
  expect(summary.getByText('Compose published host port 9000')).toBeInTheDocument();
  expect(summary.getByText('Host published')).toBeInTheDocument();
  expect(summary.getByText('api.example.test')).toBeInTheDocument();
  expect(summary.queryByText('never-show-this')).not.toBeInTheDocument();
  expect(summary.queryByText('workload-6')).not.toBeInTheDocument();
  fireEvent.click(summary.getByRole('button', {name:'Show all 7 port declarations'}));
  expect(summary.getByText('workload-6')).toBeInTheDocument();
  fireEvent.click(summary.getByRole('button', {name:'Show fewer ports'}));
  expect(summary.queryByText('workload-6')).not.toBeInTheDocument();
  expect(requestJson).toHaveBeenCalledTimes(1);
});

it.each(['current_service', 'cats_remediated'])('keeps missing %s port evidence unknown without using live service data', async variant => {
  vi.mocked(requestJson).mockResolvedValue({id:12, variant, status:'pending', snapshot:{}, overview:{ports:[{port:'1234'}]}});
  render(<ApprovalDetail data={data} id="12"/>);
  const summary = within(await screen.findByRole('region', {name:'Service at a glance'}));
  expect(summary.getByText(/Ports and protocols were not recorded/)).toBeInTheDocument();
  expect(summary.getByText('Artifact inventory not recorded')).toBeInTheDocument();
  expect(summary.getByText('Description not recorded in this snapshot.')).toBeInTheDocument();
  expect(summary.getByText('Architecture was not recorded in this snapshot.')).toBeInTheDocument();
  expect(summary.queryByRole('table')).not.toBeInTheDocument();
});

it('blocks a request when evidence is missing and exposes the specific blocker', async () => {
  vi.mocked(requestJson).mockResolvedValue({...ready,ready:false,blockers:['Missing vulnerability scan for image api@sha256:123']});
  render(<RequestApproval data={data} serviceKey="sample"/>);
  expect(await screen.findByText('Missing vulnerability scan for image api@sha256:123')).toBeInTheDocument();
  expect(screen.getByRole('button', {name:'Request Cyber Approval'})).toBeDisabled();
});

it('submits only the selected variant and includes CSRF', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce(ready).mockResolvedValueOnce({id:12});
  render(<RequestApproval data={data} serviceKey="sample"/>);
  await screen.findByText('Ready for Cyber review');
  expect(screen.getAllByRole('combobox')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', {name:'Request Cyber Approval'}));
  expect(await screen.findByRole('link', {name:'Review request #12'})).toHaveAttribute('href','/cyber-approvals?id=12&service=sample');
  const [url, options] = vi.mocked(requestJson).mock.calls[1];
  expect(url).toBe('/api/cyber-approvals');
  expect(options?.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(options?.body))).toEqual({service_key:'sample',variant:'current_service'});
});

it('selects the retained candidate directly in the variant selector', async () => {
  vi.mocked(requestJson).mockResolvedValue(ready);
  render(<RequestApproval data={data} serviceKey="sample"/>);
  await screen.findByRole('option', {name: /Remediation 1/});
  fireEvent.change(screen.getByLabelText('Release variant'),{target:{value:'cats_remediated:rem-1'}});
  await waitFor(() => expect(requestJson).toHaveBeenLastCalledWith(expect.stringContaining('remediation_id=rem-1'),expect.anything()));
  await waitFor(() => expect(screen.getByRole('button',{name:'Request Cyber Approval'})).toBeEnabled());
});

it('requires a decision rationale and posts the decision against the retained approval', async () => {
  const row = {id:12,status:'pending',can_decide:true,service_key:'sample',variant:'current_service',snapshot:{findings:[{cve:'CVE-2026-1234',severity:'high'}],mitigations:[],exceptions:[]}};
  vi.mocked(requestJson).mockResolvedValue(row);
  render(<ApprovalDetail data={data} id="12"/>);
  await screen.findByRole('button', {name:'CVE-2026-1234'});
  expect(screen.getByRole('button',{name:'Approve snapshot'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Decision'),{target:{value:'denied'}});
  fireEvent.change(screen.getByLabelText('Decision rationale'),{target:{value:'Unresolved critical exposure'}});
  fireEvent.click(screen.getByRole('button',{name:'Deny snapshot'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/cyber-approvals/12/decision',expect.objectContaining({body:JSON.stringify({decision:'denied',rationale:'Unresolved critical exposure'})})));
});

it('keeps approval distinct from failed publication and permits an authorized retry', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:22,approval_id:12,service_key:'sample',validity_status:'valid', publish_status:'failed',can_retry:true,publication:{error:'Registry unavailable',diagnostic:{stage:'Transferring artifact 1',cause:'Registry access was denied.',http_status:403},correlation_id:'job-123'},artifacts:[]});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByText('Registry unavailable')).toBeInTheDocument();
  expect(screen.getByText('Transferring artifact 1')).toBeInTheDocument();
  expect(screen.getByText('Registry access was denied.')).toBeInTheDocument();
  expect(screen.getByText('403')).toBeInTheDocument();
  expect(screen.getByText('job-123')).toBeInTheDocument();
  expect(screen.getByText(/Artifact delivery is not complete/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Retry publication'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/approved-releases/22/retry',expect.objectContaining({method:'POST'})));
});

it.each([
  ['unapproved_blob_origin', 'GET blob', true],
  ['cross_origin_operation', 'POST blob upload', false],
] as const)('shows redirect details and recovery for %s', async (reason, operation, allowStorage) => {
  const diagnostic = {http_status:307, redirect_reason:reason, operation, registry_origin:'https://registry.test',
    redirect_from_origin:allowStorage ? 'https://storage.test' : undefined, redirect_origin:'https://redirect.test:8443'};
  vi.mocked(requestJson).mockResolvedValue({id:22, validity_status:'valid', publish_status:'failed', publication:{diagnostic}});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByText(operation)).toBeInTheDocument();
  expect(screen.getByText('https://registry.test')).toBeInTheDocument();
  if (allowStorage) expect(screen.getByText('https://storage.test')).toBeInTheDocument();
  expect(screen.getByText('https://redirect.test:8443')).toBeInTheDocument();
  expect(screen.queryByRole('link', {name:'https://redirect.test:8443'})).not.toBeInTheDocument();
  expect(!!screen.queryByText('CATS_OCI_BLOB_REDIRECT_ORIGINS')).toBe(allowStorage);
});

it('explains how to get the missing target for a previously recorded redirect', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:22, validity_status:'valid', publish_status:'failed', publication:{diagnostic:{http_status:307}}});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByText(/This attempt did not record the redirect target/)).toBeInTheDocument();
  expect(screen.queryByText('CATS_OCI_BLOB_REDIRECT_ORIGINS')).not.toBeInTheDocument();
});

it('retains destination secrets on edit without echoing credentials into fields', async () => {
  vi.mocked(requestJson).mockResolvedValue({items:[{id:2,name:'Production',endpoint:'https://registry.test',namespace:'approved',group_ids:[1],credentials_configured:true}]});
  render(<Destinations data={data}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Edit Production'}));
  expect(screen.getByLabelText('Registry password / token')).toHaveValue('');
  fireEvent.click(screen.getByRole('button',{name:'Save destination'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/approved-release-destinations',expect.objectContaining({method:'POST'})));
  const options = vi.mocked(requestJson).mock.calls.find(call => call[1]?.method === 'POST')?.[1];
  expect(JSON.parse(String(options?.body))).not.toHaveProperty('password');
  expect(JSON.parse(String(options?.body))).not.toHaveProperty('ca_pem');
});


it('renders published backend receipts, immutable references and authorized downloads', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:22,service_key:'sample',validity_status:'valid', publish_status:'published',
    evidence_url:'/api/cyber-approvals/22/download/evidence',offline_bundle_url:'/api/cyber-approvals/22/download/offline',
    publication:{release:{reference:'registry.test/approved/release@sha256:abc',signature:{status:'verified'}},
      artifacts:[{kind:'image',reference:'registry.test/approved/image@sha256:def',digest:'sha256:def',signature:{status:'verified'}}]}});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByRole('link',{name:'Download retained evidence'})).toHaveAttribute('href','/api/cyber-approvals/22/download/evidence');
  expect(screen.getByRole('link',{name:'Download offline release bundle'})).toHaveAttribute('href','/api/cyber-approvals/22/download/offline');
  expect(screen.getByText('registry.test/approved/image@sha256:def')).toBeInTheDocument();
  expect(screen.getByText('oras pull registry.test/approved/release@sha256:abc')).toBeInTheDocument();
});

it('shows revoked releases as audit records and suppresses retries', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:22,service_key:'sample',validity_status:'valid', publish_status:'failed',can_retry:true,
    revoked:true,revocation_reason:'New exposure discovered'});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('no longer authorized for deployment');
  expect(screen.getByText('Retained artifacts and evidence are shown for audit history.')).toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Retry publication'})).not.toBeInTheDocument();
});


it('permits evidence-complete requests when risks or publication setup need Cyber review', async () => {
  vi.mocked(requestJson).mockResolvedValue({...ready, destinations:[], review_notes:['No Helm charts', 'Unverified deployment', 'Configure signing']});
  render(<RequestApproval data={data} serviceKey="sample"/>);
  await screen.findByText('Ready for Cyber review');
  expect(screen.getByRole('button', {name:'Request Cyber Approval'})).toBeEnabled();
  expect(screen.getAllByRole('combobox')).toHaveLength(1);
});

it('shows coverage limitations and remaining candidate vulnerabilities to Cyber', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:12, status:'pending',variant:'cats_remediated', snapshot:{
    review_notes:['No Helm charts were supplied.', 'Deployment verification failed.'],
    findings:{vulnerability_scans:{image1:{matches:[{vulnerability:{id:'CVE-REMAINING'}}]}}}}});
  render(<ApprovalDetail data={data} id="12"/>);
  expect(await screen.findByText('No Helm charts were supplied.')).toBeInTheDocument();
  expect(screen.getByText('Deployment verification failed.')).toBeInTheDocument();
  expect(screen.getByRole('heading', {name:'Vulnerability findings'})).toBeInTheDocument();
  expect(screen.getAllByText(/CVE-REMAINING/).length).toBeGreaterThan(0);
});

it.each(['expired', 'reapproval_required', 'invalid'])('shows %s releases as audit history without publication retry', async (validity_status) => {
  vi.mocked(requestJson).mockResolvedValue({id:23, service_name:'Expired release', status:'approved',
    publish_status:'failed', validity_status, can_retry:true, expires_at:'2026-01-01T00:00:00Z'});
  render(<ReleaseDetail data={data} id="23"/>);
  expect(await screen.findByText(/needs a new Cyber approval before deployment/)).toBeInTheDocument();
  expect(screen.getByText('Expires').nextElementSibling).toHaveTextContent(new Date('2026-01-01T00:00:00Z').toLocaleString());
  expect(screen.queryByRole('button', {name:'Retry publication'})).not.toBeInTheDocument();
});


it('updates a scoped reassessment schedule with CSRF and links renewal review', async () => {
  const permissions = Object.fromEntries(['service.view','service.edit','service.export','approval.request','scan.ingest'].map(key => [key, {'7':true}]));
  vi.mocked(requestJson).mockResolvedValue({schedule:{enabled:true,interval_days:14,next_run:'2026-10-20T00:00:00Z'},events:[{id:'event',state:'pending_review',renewal_id:42}]});
  render(<Reassessment data={{csrf_token:'csrf',can:permissions}} row={{id:12,service_id:7,snapshot:{artifacts:[{kind:'image',reference:'registry/image@sha256:'+'a'.repeat(64)}]}}}/>);
  expect(await screen.findByRole('link',{name:'Review renewal #42'})).toHaveAttribute('href','/cyber-approvals?id=42');
  expect(screen.getByLabelText('Reassessment interval (days)')).toHaveValue(14);
  fireEvent.change(screen.getByLabelText('Reassessment interval (days)'),{target:{value:'21'}});
  fireEvent.click(screen.getByLabelText('Enable scheduled reassessment'));
  fireEvent.click(screen.getByRole('button',{name:'Save reassessment schedule'}));
  await screen.findByText('Reassessment schedule saved.');
  expect(requestJson).toHaveBeenCalledWith('/api/cyber-approvals/12/reassessment',expect.objectContaining({method:'PUT',headers:expect.objectContaining({'X-CSRF-Token':'csrf'}),body:JSON.stringify({interval_days:21,enabled:false})}));
});

it('requires scoped scan ingestion permission for schedule controls', async () => {
  vi.mocked(requestJson).mockResolvedValue({schedule:null,events:[]});
  render(<Reassessment data={data} row={{id:12,service_id:7,snapshot:{artifacts:[{kind:'image',reference:'registry/image@sha256:'+'a'.repeat(64)}]}}}/>);
  await screen.findByText('No reassessment events recorded.');
  expect(screen.queryByRole('button',{name:'Save reassessment schedule'})).not.toBeInTheDocument();
  expect(screen.getByText(/A scoped Service Manager/)).toBeInTheDocument();
});

it('passes the amendment identity through the existing approval request', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({...ready, can_request:true}).mockResolvedValueOnce({id:88});
  render(<RequestApproval data={data} serviceKey="payments" amendmentProposalId={19}/>);
  expect(screen.getByRole('note')).toHaveTextContent('actual fresh service assessment');
  await screen.findByText('Ready for Cyber review');
  fireEvent.click(screen.getByRole('button', {name:'Request Cyber Approval'}));
  await screen.findByText('Review request #88');
  const call = vi.mocked(requestJson).mock.calls.find(([url]) => url === '/api/cyber-approvals');
  expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({amendment_proposal_id:19, service_key:'payments'});
});


const legacyRelease = {id:5, service_id:7, service_key:'sample', service_name:'Example service', status:'approved',
  publish_status:'published', validity_status:'valid', approved_by:'Actual Cyber Reviewer', decided_at:'2026-11-12T10:00:00Z',
  can_revoke:true, revoked:false, destination:{name:'Cyber Approved',endpoint:'https://registry.test',namespace:'approved'},
  snapshot:{portable_release:{publisher:'trusted'}}, publication:{artifacts:[]}};
function mockLegacyRelease(row: Record<string, any> = legacyRelease, mutation?: (url: string, options?: RequestInit) => Promise<any>) {
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (options?.method === 'POST') return mutation ? mutation(url, options) : {...row, revoked:true, can_revoke:false, revocation_reason:'Exposure found', revoked_at:'2026-11-14T12:00:00Z'};
    if (url.endsWith('/revision')) throw new ApiError('This approval has no governed revision', 404);
    return row;
  });
}
it('pulls the image by its frozen artifact slot before publication completes', async () => {
  const image = 'registry.example/team/app@sha256:abc';
  vi.mocked(requestJson).mockImplementation(async url => {
    if (url.endsWith('/revision')) throw new ApiError('No governed revision', 404);
    if (url.endsWith('/pull')) return {status:'unavailable', reason:'Mapping unavailable.', routes:[]};
    return {...legacyRelease, publish_status:'queued', snapshot:{artifacts:[
      {kind:'chart', reference:'chart'}, {kind:'image', reference:image}]}};
  });
  render(<ReleaseDetail data={data} id="5"/>);
  fireEvent.click(await screen.findByRole('button', {name:`Pull ${image} from CATS`}));
  expect(await screen.findByText('Mapping unavailable.')).toBeVisible();
  expect(requestJson).toHaveBeenCalledWith('/api/approved-releases/5/artifacts/1/pull', expect.anything());
});

it('revokes a legacy release without a governed revision using the approval endpoint and CSRF', async () => {
  mockLegacyRelease();
  render(<ReleaseDetail data={data} id="5"/>);
  expect(await screen.findByText('Actual Cyber Reviewer')).toBeVisible();
  await waitFor(() => expect(screen.queryByText('Advanced release controls')).not.toBeInTheDocument());
  expect(screen.queryByText('This release has no governed revision record.')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name:'Revoke release'}));
  const confirmation = within(screen.getByRole('region', {name:'Confirm release revocation'}));
  expect(confirmation.getByText(/Running containers and images already downloaded are not removed/)).toBeVisible();
  expect(confirmation.getByText(/signed revocation/)).toBeVisible();
  expect(confirmation.getByRole('button', {name:'Confirm revocation'})).toBeDisabled();
  fireEvent.change(confirmation.getByLabelText('Revocation reason'), {target:{value:'  Exposure found  '}});
  fireEvent.click(confirmation.getByRole('button', {name:'Confirm revocation'}));
  await screen.findByText('Release revoked. Future pulls must satisfy another current approval.');
  expect(requestJson).toHaveBeenCalledWith('/api/approved-releases/5/revoke', expect.objectContaining({method:'POST',
    headers:expect.objectContaining({'X-CSRF-Token':'csrf'}), body:JSON.stringify({rationale:'Exposure found'})}));
  expect(screen.getByRole('alert')).toHaveTextContent('no longer authorized for deployment');
  expect(screen.queryByRole('button', {name:'Revoke release'})).not.toBeInTheDocument();
  expect(screen.getByText('Actual Cyber Reviewer')).toBeVisible();
});
it('cancels release revocation without a mutation and requires a meaningful reason', async () => {
  mockLegacyRelease(); render(<ReleaseDetail data={data} id="5"/>);
  fireEvent.click(await screen.findByRole('button', {name:'Revoke release'}));
  fireEvent.change(screen.getByLabelText('Revocation reason'), {target:{value:'  '}});
  expect(screen.getByRole('button', {name:'Confirm revocation'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button', {name:'Cancel'}));
  expect(screen.queryByLabelText('Revocation reason')).not.toBeInTheDocument();
  expect(vi.mocked(requestJson).mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  fireEvent.click(screen.getByRole('button', {name:'Revoke release'}));
  expect(screen.getByLabelText('Revocation reason')).toHaveValue('');
});
it('keeps a failed revocation reviewable and blocks duplicate submission while pending', async () => {
  let fail!: (reason: Error) => void;
  mockLegacyRelease(legacyRelease, () => new Promise((_resolve, reject) => {fail = reject;}));
  render(<ReleaseDetail data={data} id="5"/>);
  fireEvent.click(await screen.findByRole('button', {name:'Revoke release'}));
  fireEvent.change(screen.getByLabelText('Revocation reason'), {target:{value:'Exposure found'}});
  fireEvent.click(screen.getByRole('button', {name:'Confirm revocation'}));
  expect(screen.getByRole('button', {name:'Revoking release…'})).toBeDisabled();
  expect(screen.getByRole('button', {name:'Cancel'})).toBeDisabled();
  expect(screen.getByRole('button', {name:'Refresh publication'})).toBeDisabled();
  fail(new Error('Publication started; refresh before retrying.'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Publication started');
  expect(screen.getByLabelText('Revocation reason')).toHaveValue('Exposure found');
  expect(screen.getByRole('button', {name:'Confirm revocation'})).toBeEnabled();
  expect(vi.mocked(requestJson).mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
});
it.each(['published', 'queued', 'publishing'])('honors server revocation capability for %s releases', async publish_status => {
  mockLegacyRelease({...legacyRelease, publish_status, can_revoke:false});
  render(<ReleaseDetail data={{...data,can:{'approval.decide':{'7':true}}}} id="5"/>);
  await screen.findByText('Actual Cyber Reviewer');
  expect(screen.queryByRole('button', {name:'Revoke release'})).not.toBeInTheDocument();
  if (publish_status !== 'published') expect(screen.getByText('Revocation is available after publication completes or fails.')).toBeVisible();
});
it('retries a failed signed revocation while retaining the revoked approval state', async () => {
  mockLegacyRelease({...legacyRelease, revoked:true, can_revoke:false, publish_status:'failed', can_retry:true,
    publication:{revocation:{status:'failed',portable:{target_release_id:'5'},error:'Registry unavailable'}}});
  render(<ReleaseDetail data={data} id="5"/>);
  fireEvent.click(await screen.findByRole('button', {name:'Retry revocation publication'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/approved-releases/5/retry',expect.objectContaining({method:'POST'})));
  expect(screen.queryByRole('button',{name:'Retry publication'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Revoke release'})).not.toBeInTheDocument();
});
it('shows the recorded approver in the release list and allows searching by name', async () => {
  window.history.replaceState({}, '', '/approved-releases');
  vi.mocked(requestJson).mockResolvedValue({items:[legacyRelease,{...legacyRelease,id:6,service_name:'Unknown reviewer service',approved_by:null}]});
  render(<Releases data={data}/>);
  expect(await screen.findByRole('columnheader',{name:/Approved by/})).toBeVisible();
  expect(screen.getByText('Actual Cyber Reviewer')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Find a release'),{target:{value:'Actual Cyber Reviewer'}});
  expect(screen.getByRole('link',{name:'Example service'})).toBeVisible();
  expect(screen.queryByRole('link',{name:'Unknown reviewer service'})).not.toBeInTheDocument();
});
it('copies immutable references and reports clipboard failure without losing the reference', async () => {
  const writeText = vi.fn().mockRejectedValue(new Error('Clipboard unavailable'));
  Object.defineProperty(window.navigator, 'clipboard', {configurable:true,value:{writeText}});
  mockLegacyRelease({...legacyRelease,publication:{artifacts:[{kind:'image',reference:'registry.test/image@sha256:abc'}]}});
  render(<ReleaseDetail data={data} id="5"/>);
  fireEvent.click(await screen.findByRole('button', {name:'Copy image reference'}));
  expect(await screen.findByText('Select the reference to copy it manually.')).toBeVisible();
  expect(writeText).toHaveBeenCalledWith('registry.test/image@sha256:abc');
  expect(screen.getByText('registry.test/image@sha256:abc')).toBeVisible();
});

it('shows missing approver identity honestly instead of using the requester', async () => {
  mockLegacyRelease({...legacyRelease, approved_by:null, requested_by:'Requesting service manager'});
  render(<ReleaseDetail data={data} id="5"/>);
  expect((await screen.findByText('Approved by')).nextElementSibling).toHaveTextContent('Not recorded');
  expect(screen.queryByText('Requesting service manager')).not.toBeInTheDocument();
});
it('does not apply a late revocation response to a different release', async () => {
  let finish!: (value: any) => void;
  vi.mocked(requestJson).mockImplementation(async (url, options) => {
    if (url.endsWith('/revision')) throw new ApiError('No revision',404);
    if (options?.method === 'POST') return new Promise(resolve => {finish=resolve;});
    return url.endsWith('/6') ? {...legacyRelease,id:6,service_name:'Different release'} : legacyRelease;
  });
  const view = render(<ReleaseDetail data={data} id="5"/>);
  fireEvent.click(await screen.findByRole('button',{name:'Revoke release'}));
  fireEvent.change(screen.getByLabelText('Revocation reason'),{target:{value:'Withdraw original release'}});
  fireEvent.click(screen.getByRole('button',{name:'Confirm revocation'}));
  view.rerender(<ReleaseDetail data={data} id="6"/>);
  await screen.findByRole('heading',{name:'Different release'});
  finish({...legacyRelease, revoked:true, can_revoke:false});
  await waitFor(() => expect(screen.getByRole('heading',{name:'Different release'})).toBeVisible());
  expect(screen.getByRole('button',{name:'Revoke release'})).toBeEnabled();
  expect(screen.queryByText('Release revoked. Future pulls must satisfy another current approval.')).not.toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
