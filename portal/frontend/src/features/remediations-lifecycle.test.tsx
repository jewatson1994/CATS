import {cleanup, render, screen, within} from '@testing-library/react';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {Report, Service} from './remediations';

vi.mock('../components/ServiceHeader', () => ({ServiceHeader: () => null, ServiceTabs: () => null}));
afterEach(cleanup);
const job = {
  job_key:'candidate-1', status:'completed', revision_number:2, original_revision:'V7', source_version_id:17,
  remediation_status:'completed', delivery_status:'failed', verification_status:'not_run', signing_status:'verified',
  before_snapshot:{vulnerabilities:{}}, after_snapshot:{vulnerabilities:{}}, validation:[], changed_artifacts:[],
  patched_images:[], configuration_changes:[], stages:[], logs:[], output_mode:'bundle', has_artifact:true,
};
const data = {service:{id:7,service_key:'example',name:'Example'}, can:{'service.export':{'7':true}}, job};

describe('remediation candidate lifecycle', () => {
  it('groups remediation and destination actions and keeps POA&M creation in its tab', () => {
    const workspace = {...data,can:{'service.edit':{'7':true}},can_remediate:true,remediation_enabled:true,can_create_poam:true,remediation_preview:{images:2,charts:1,configuration_changes:0,manual_review:12},remediation_jobs:[],poams:[],tab:'pipeline'};
    const {rerender} = render(<Service data={workspace}/>);
    const actions = within(screen.getByRole('group',{name:'Remediation actions'}));
    expect(actions.getByRole('button',{name:'Remediate'})).toBeInTheDocument();
    expect(actions.getByRole('button',{name:'OCI destinations'})).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Create POA&M entry'})).not.toBeInTheDocument();
    rerender(<Service data={{...workspace,tab:'poams'}}/>);
    expect(screen.getByRole('button',{name:'Create POA&M entry'})).toBeInTheDocument();
    rerender(<Service data={{...workspace,can:{},can_remediate:false,can_create_poam:false,tab:'poams'}}/>);
    expect(screen.queryByRole('button',{name:'Remediate'})).not.toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'OCI destinations'})).not.toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Create POA&M entry'})).not.toBeInTheDocument();
  });
  it('renders the tab at once and loads a pending plan preview on demand', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({images:3,charts:1,configuration_changes:2,manual_review:4,error:null}),{status:200,headers:{'Content-Type':'application/json'}}));
    vi.stubGlobal('fetch', fetchMock);
    try {
      const workspace = {...data,can:{'service.edit':{'7':true}},can_remediate:true,remediation_enabled:true,remediation_preview:{pending:true},remediation_jobs:[],poams:[],tab:'pipeline'};
      render(<Service data={workspace}/>);
      expect(screen.getByText('Remediation candidates')).toBeInTheDocument();
      expect(screen.getByText('Preparing the remediation plan preview…')).toBeInTheDocument();
      expect(await screen.findByText(/3 service images · 1 retained Helm charts · 2 mapped configuration changes · 4 configuration items/)).toBeInTheDocument();
      expect(String((fetchMock.mock.calls[0] as any[])[0])).toContain('/api/v1/services/example/remediation-preview');
    } finally { vi.unstubAllGlobals(); }
  });
  it('pages service remediation collections with server-side page links', () => {
    const workspace = {...data,can:{},remediation_preview:{images:0,charts:0,configuration_changes:0,manual_review:0},remediation_jobs:[],poams:[],mitigations:[],exceptions:[{kind:'Vulnerability',item:'CVE-1',severity:'High',status:'Active',service:data.service}],
      tab:'exceptions',page:2,page_count:3,total_items:120,pagination_base:'/services/example?remediations=true&tab=exceptions&page_size=50'};
    render(<Service data={workspace}/>);
    expect(screen.getAllByText('Page 2 of 3 · 120 records')).toHaveLength(2);
    expect(screen.getAllByRole('link',{name:'Previous'})[0]).toHaveAttribute('href','/services/example?remediations=true&tab=exceptions&page_size=50&page=1');
    expect(screen.getAllByRole('link',{name:'Next'})[0]).toHaveAttribute('href','/services/example?remediations=true&tab=exceptions&page_size=50&page=3');
    cleanup();
    render(<Service data={{...workspace,tab:'pipeline',exceptions:[],page:1,page_count:2,remediation_jobs:[job]}}/>);
    expect(screen.getByText('Page 1 of 2 · 120 records')).toBeInTheDocument();
  });
  it('shows terminal patch blockers rather than suggesting patching is still pending', () => {
    render(<Report data={{...data,job:{...job,status:'review_required',patched_images:[{original:'ubuntu:test',classification:'REVIEW REQUIRED',reason:'No explicit package repository mirror policy is configured for remediation'}]}}}/>);
    expect(screen.getByText(/Copa not started/)).toBeInTheDocument();
    expect(screen.getByText(/No explicit package repository mirror policy/)).toBeInTheDocument();
    expect(screen.queryByText(/Pending patch\/publish/)).not.toBeInTheDocument();
    expect(screen.getByRole('region',{name:'Remediation progress'})).toHaveTextContent('0 of 1 images reached the patch worker');
  });
  it('keeps remediation success independent of delivery failure and retains download access', () => {
    render(<Report data={data}/>);
    expect(screen.getByText('Candidate R2 · Source authoritative version: V7 (version #17)')).toBeInTheDocument();
    const lifecycle = within(screen.getByRole('region', {name:'Candidate lifecycle'}));
    for (const [label, value] of [['Remediation','completed'],['Delivery','failed'],['Verification','not run'],['Signing','verified']]) {
      expect(lifecycle.getByText(label).nextElementSibling).toHaveTextContent(value);
    }
    expect(screen.getByRole('link', {name:'Download candidate evidence for troubleshooting'})).toHaveAttribute('href','/services/example/remediations/candidate-1/candidate.zip');
  });
  it('does not invent candidate or source versions when metadata is missing', () => {
    render(<Report data={{...data,job:{...job,revision_number:null,original_revision:null,source_version_id:null,resulting_revision:'legacy-generated-name'}}}/>);
    expect(screen.getByText('Candidate Unassigned · Source authoritative version: Unknown')).toBeInTheDocument();
    expect(screen.queryByText(/legacy-generated-name/)).not.toBeInTheDocument();
  });
  it('shows each independent lifecycle state in the candidate list', () => {
    render(<Service data={{...data,tab:'pipeline',remediation_jobs:[job]}}/>);
    expect(screen.getByRole('link', {name:'R2 · candidate-1'})).toHaveAttribute('href','/services/example/remediations/candidate-1');
    expect(screen.getByText('V7 (version #17)')).toBeInTheDocument();
    for (const label of ['Remediation','Delivery','Verification','Signing']) expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText('completed')).toBeInTheDocument();
    expect(screen.getByText('failed')).toBeInTheDocument();
  });
  it('downloads only the exact independently verified final bundle', () => {
    render(<Report data={{...data,job:{...job,workflow:{stage:'deliver',validation_resolved:true},delivery_attempts:[
      {id:41,result:'download_ready',validation_type:'standard-bundle',verification:{status:'VERIFIED'}},
      {id:42,result:'validation_failed',validation_type:'offline-bundle',verification:{status:'FAILED',offlineVerified:false}},
      {id:43,result:'download_ready',validation_type:'offline-bundle',verification:{status:'VERIFIED',offlineVerified:true,network:{isolated:true,external_chart_fetches:0,external_image_pulls:0}}},
    ]}}}/>);
    expect(screen.getByRole('link',{name:'Download verified Standard Bundle'})).toHaveAttribute('href','/services/example/remediations/candidate-1/deliveries/41/bundle.zip');
    expect(screen.getByRole('link',{name:'Download verified Offline Bundle'})).toHaveAttribute('href','/services/example/remediations/candidate-1/deliveries/43/bundle.zip');
    expect(screen.queryByRole('link',{name:/42/})).not.toBeInTheDocument();
    expect(screen.getByRole('region',{name:'CATSchrödinger’s evidence'})).toHaveTextContent('Original artifact validation');
  });
  it('does not claim offline verification or measured isolation when evidence is missing', () => {
    render(<Report data={{...data,job:{...job,workflow:{stage:'deliver',validation_resolved:true},delivery_attempts:[{id:44,result:'download_ready',validation_type:'offline-bundle',verification:{status:'VERIFIED'}}]}}}/>);
    expect(screen.queryByRole('link',{name:'Download verified Offline Bundle'})).not.toBeInTheDocument();
    for(const term of screen.getAllByText('Network isolated')) expect(term.nextElementSibling).toHaveTextContent('Unavailable');
    for(const term of screen.getAllByText('External image pulls')) expect(term.nextElementSibling).toHaveTextContent('Unavailable');
  });
});
