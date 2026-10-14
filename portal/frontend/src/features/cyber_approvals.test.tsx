import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {ApprovalDetail, Destinations, ReleaseDetail, RequestApproval} from './cyber_approvals';

vi.mock('../api', async original => ({...await original<any>(), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const data = {csrf_token:'csrf', can:{'approval.request':{'7':true},'release.destination.manage':{'*':true}}};
const ready = {service_id:7, ready:true, blockers:[], version:'1.0', scan_date:'2026-10-14', destinations:[{id:2,name:'Approved registry',endpoint:'registry.test',namespace:'approved',is_default:true}],remediations:[{id:'rem-1',label:'Remediation 1'}]};

it('blocks a request when evidence is missing and exposes the specific blocker', async () => {
  vi.mocked(requestJson).mockResolvedValue({...ready,ready:false,blockers:['Missing vulnerability scan for image api@sha256:123']});
  render(<RequestApproval data={data} serviceKey="sample"/>);
  expect(await screen.findByText('Missing vulnerability scan for image api@sha256:123')).toBeInTheDocument();
  expect(screen.getByRole('button', {name:'Request Cyber Approval'})).toBeDisabled();
});

it('freezes the selected destination with the request and includes CSRF', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce(ready).mockResolvedValueOnce({id:12});
  render(<RequestApproval data={data} serviceKey="sample"/>);
  await screen.findByText('Ready for Cyber review');
  fireEvent.change(screen.getByLabelText('Request context'), {target:{value:'Release for review'}});
  fireEvent.click(screen.getByRole('button', {name:'Request Cyber Approval'}));
  expect(await screen.findByRole('link', {name:'Review request #12'})).toHaveAttribute('href','/cyber-approvals?id=12');
  const [url, options] = vi.mocked(requestJson).mock.calls[1];
  expect(url).toBe('/api/cyber-approvals');
  expect(options?.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(options?.body))).toEqual({service_key:'sample',variant:'current_service',destination_id:2,rationale:'Release for review'});
});

it('requires retained remediation provenance before submitting CATS Remediated', async () => {
  vi.mocked(requestJson).mockResolvedValue(ready);
  render(<RequestApproval data={data} serviceKey="sample"/>);
  await screen.findByText('Ready for Cyber review');
  fireEvent.change(screen.getByLabelText('Release variant'),{target:{value:'cats_remediated'}});
  await screen.findByText('Remediation 1');
  expect(screen.getByRole('button',{name:'Request Cyber Approval'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Remediation provenance'),{target:{value:'rem-1'}});
  await waitFor(() => expect(requestJson).toHaveBeenLastCalledWith(expect.stringContaining('remediation_id=rem-1'),expect.anything()));
  await waitFor(() => expect(screen.getByRole('button',{name:'Request Cyber Approval'})).toBeEnabled());
});

it('requires a decision rationale and posts the decision against the retained approval', async () => {
  const row = {id:12,status:'pending',can_decide:true,service_key:'sample',variant:'current_service',snapshot:{findings:[{cve:'CVE-2026-1234',severity:'high'}],mitigations:[],exceptions:[]}};
  vi.mocked(requestJson).mockResolvedValue(row);
  render(<ApprovalDetail data={data} id="12"/>);
  await screen.findByText('CVE-2026-1234', {selector:'summary'});
  expect(screen.getByRole('button',{name:'Approve snapshot'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Decision'),{target:{value:'denied'}});
  fireEvent.change(screen.getByLabelText('Decision rationale'),{target:{value:'Unresolved critical exposure'}});
  fireEvent.click(screen.getByRole('button',{name:'Deny snapshot'}));
  await waitFor(() => expect(requestJson).toHaveBeenCalledWith('/api/cyber-approvals/12/decision',expect.objectContaining({body:JSON.stringify({decision:'denied',rationale:'Unresolved critical exposure'})})));
});

it('keeps approval distinct from failed publication and permits an authorized retry', async () => {
  vi.mocked(requestJson).mockResolvedValue({id:22,approval_id:12,service_key:'sample',publish_status:'failed',can_retry:true,publication:{error:'Registry unavailable'},artifacts:[]});
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
  vi.mocked(requestJson).mockResolvedValue({id:22,service_key:'sample',publish_status:'published',
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
  vi.mocked(requestJson).mockResolvedValue({id:22,service_key:'sample',publish_status:'failed',can_retry:true,
    revoked:true,revocation_reason:'New exposure discovered'});
  render(<ReleaseDetail data={data} id="22"/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('no longer authorized for deployment');
  expect(screen.getByText('Retained artifacts and evidence are shown for audit history.')).toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Retry publication'})).not.toBeInTheDocument();
});
