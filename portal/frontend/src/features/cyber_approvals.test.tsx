import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {ApprovalDetail, Destinations, ReleaseDetail, RequestApproval} from './cyber_approvals';

vi.mock('../api', async original => ({...await original<any>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const data = {csrf_token:'csrf', can:{'approval.request':{'7':true},'release.destination.manage':{'*':true}}};
const ready = {service_id:7, ready:true, blockers:[], version:'1.0', scan_date:'2026-10-14', destinations:[{id:2,name:'Approved registry',endpoint:'registry.test',namespace:'approved',is_default:true}],remediations:[{id:'rem-1',label:'Remediation 1'}]};

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
  expect(await screen.findByRole('link', {name:'Review request #12'})).toHaveAttribute('href','/cyber-approvals?id=12');
  const [url, options] = vi.mocked(requestJson).mock.calls[1];
  expect(url).toBe('/api/cyber-approvals');
  expect(options?.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(options?.body))).toEqual({service_key:'sample',variant:'current_service'});
});

it('selects the retained candidate directly in the variant selector', async () => {
  vi.mocked(requestJson).mockResolvedValue(ready);
  render(<RequestApproval data={data} serviceKey="sample"/>);
  await screen.findByText('Ready for Cyber review');
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
  vi.mocked(requestJson).mockResolvedValue({id:22,approval_id:12,service_key:'sample',validity_status:'valid', publish_status:'failed',can_retry:true,publication:{error:'Registry unavailable'},artifacts:[]});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByText('Registry unavailable')).toBeInTheDocument();
  expect(screen.getByText(/Artifact delivery is not complete/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Retry publication'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/approved-releases/22/retry',expect.objectContaining({method:'POST'})));
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
  expect(screen.getByText(/Expires:/)).toBeInTheDocument();
  expect(screen.queryByRole('button', {name:'Retry publication'})).not.toBeInTheDocument();
});
