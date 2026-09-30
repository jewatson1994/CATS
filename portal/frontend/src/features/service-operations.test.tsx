import {afterEach,beforeAll,describe,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen,within,waitFor} from '@testing-library/react';
import {Page as Artifacts} from './service-artifacts';
import {Page as Dependencies} from './service-dependencies';
import {Page as Validation,isTerminal} from './service-validation';
import type {PageData} from '../api';

beforeAll(() => {
  HTMLDialogElement.prototype.showModal = vi.fn(function(this:HTMLDialogElement) {this.setAttribute('open','');});
  HTMLDialogElement.prototype.close = vi.fn(function(this:HTMLDialogElement) {this.removeAttribute('open');});
});
afterEach(() => {cleanup();vi.useRealTimers();vi.unstubAllGlobals();});
const fixture = (extra:Partial<PageData> = {}):PageData => ({csrf_token:'csrf-proof',view:{service:{id:7,service_key:'sample',name:'Sample'},version:'1.0'},can:{'service.edit':{'7':true},'remediation.execute':{'7':true},'service.export':{'7':true}},can_edit:true,can_validate:true,can_image_workflow:true,...extra});
const image = {id:9,image_reference:'registry/image:tag',scan_status:'never_scanned',lifecycle_status:'active'};
const chart = {semantic_type:'helm_chart',artifact:{id:11,chart_name:'Test Chart',source_type:'repository',source_metadata:{versions:[{version:'1.2.3'}]}},file_count:0,validation:{key:'not-validated',label:'Not Validated'}};
const response = (data:any) => ({ok:true,status:200,redirected:false,headers:new Headers({'content-type':'application/json'}),json:async () => data});

describe('native service operations', () => {
  it('acquires only the selected artifact source and retains multipart CSRF contract', () => {
    render(<Artifacts data={fixture()} />);
    fireEvent.click(screen.getByRole('button',{name:'+ Add Helm Chart'}));
    const dialog = screen.getByRole('dialog');
    const form = dialog.querySelector('form')!;
    expect(form).toHaveAttribute('action','/services/sample/artifacts/acquire');
    expect(form).toHaveAttribute('enctype','multipart/form-data');
    expect(form.querySelector('[name="csrf_token"]')).toHaveValue('csrf-proof');
    expect(form.querySelector('[name="source_reference"]')).toBeNull();
    expect(within(dialog).getByLabelText('Packaged chart (.tgz)')).toBeRequired();
    fireEvent.click(within(dialog).getByLabelText('OCI Registry'));
    expect(within(dialog).getByLabelText('OCI reference')).toBeRequired();
    expect(form.querySelector('[name="files"]')).toBeNull();
  });
  it('keeps materialize version and image replacement identities separate', () => {
    render(<Artifacts data={fixture({artifact_rows:[chart],image_inventory:[{image,count:1,references:['Deployment/sample']}]})} />);
    expect(screen.getByLabelText('Version for Test Chart')).toHaveValue('1.2.3');
    expect(screen.getByRole('button',{name:'Materialize'})).toHaveAttribute('form','materialize-11');
    fireEvent.click(screen.getByRole('button',{name:'Replace image'}));
    const form = screen.getByRole('dialog').querySelector('form')!;
    expect(form).toHaveAttribute('action','/services/sample/artifacts/images/9/replace');
    expect(within(form).getByLabelText('Replacement')).toBeRequired();
    expect(form.querySelector('[name="csrf_token"]')).toHaveValue('csrf-proof');
  });
  it('filters chart and image state locally and gates mutation by scoped permissions', () => {
    render(<Artifacts data={fixture({can:{'service.edit':{'8':true}},artifact_rows:[chart],image_inventory:[{image,count:0,references:[]}]})} />);
    expect(screen.queryByRole('button',{name:'+ Add Artifact'})).not.toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Replace image'})).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search charts'),{target:{value:'no match'}});
    expect(screen.queryByText('Test Chart')).not.toBeInTheDocument();
    expect(screen.getByText('No charts match these filters.')).toBeInTheDocument();
  });
  it('polls pending image state, updates filters and stops after completion', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn().mockResolvedValue(response({images:[{id:9,status:'scanned'}]}));vi.stubGlobal('fetch',fetch);
    render(<Artifacts data={fixture({image_inventory:[{image:{...image,scan_status:'queued'},count:0,references:[]}]})} />);
    await act(async () => {await vi.advanceTimersByTimeAsync(1500);});
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(screen.getByText('scanned',{selector:'.status'})).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Scan state'),{target:{value:'scanned'}});
    expect(screen.getByText('registry/image:tag')).toBeInTheDocument();
    await act(async () => {await vi.advanceTimersByTimeAsync(6000);});
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('retains dependency evidence filters, pagination and unknown semantics', () => {
    render(<Dependencies data={fixture({dependency_query:{q:'openssl',epss:0.2,filter:'kev'},dependency_page:2,dependency_pages:3,dependency_total:20,dependency_page_url:'/services/sample?dependencies=true&dependency_execution=5&page=',dependency_rows:[{name:'openssl',version:'3',image:'image',vulnerabilities:['CVE-A'],epss:0.1234,risk:[],fixed_versions:[]}],dependency_executions:[{id:5,execution_key:'scan-5',scanned_at:'Yesterday'}]})} />);
    expect(screen.getByLabelText('Search')).toHaveValue('openssl');
    expect(screen.getByLabelText('Minimum EPSS')).toHaveValue(0.2);
    expect(screen.getByRole('link',{name:'Next'})).toHaveAttribute('href','/services/sample?dependencies=true&dependency_execution=5&page=3');
    expect(screen.getByText('Layer: Unknown',{exact:false})).toBeInTheDocument();
    expect(screen.getByText('Policy status: Not configured')).toBeInTheDocument();
    expect(screen.getByText('— · EPSS 0.123')).toBeInTheDocument();
  });
  it('preserves preflight boundary evidence and independent static results', () => {
    render(<Validation data={fixture({validation:{status:'COULD_NOT_VALIDATE',phase:'COMPLETE',cleanup_status:'NOT_REQUIRED',terminal:true,static_scan_complete:true,reason_category:'SECURITY_POLICY_VIOLATION',security_policy_violations:[{rule_id:'BOUNDARY',kind:'Pod',name:'test',field_path:'spec.hostPID',value:true,source_template:'templates/pod.yaml',source_line:3}],capability_assessment:[{capability:'Configuration dependencies',status:'AVAILABLE',dependency_rows:[{kind:'ConfigMap',name:'config',status:'AVAILABLE',required_by:['Pod/test']}]}]}})} />);
    expect(screen.getAllByText('BLOCKED BY PREFLIGHT').length).toBeGreaterThan(0);
    expect(screen.getByText('Static Scan: Complete')).toBeInTheDocument();
    expect(screen.getByText('BOUNDARY')).toBeInTheDocument();
    expect(screen.getByText('ConfigMap/config')).toBeInTheDocument();
    expect(screen.getByText('templates/pod.yaml')).toBeInTheDocument();
    expect(isTerminal({status:'VERIFIED',phase:'CLEANING_UP',cleanup_status:'RUNNING'})).toBe(false);
  });
  it('starts a new validation run with CSRF then polls the new run', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(response({run_id:'run-new',url:'/services/sample?validation=true&validation_run=run-new',run:{run_key:'run-new',status:'QUEUED',phase:'QUEUED',cleanup_status:'PENDING'}})).mockResolvedValueOnce(response({run_key:'run-new',status:'VERIFIED',phase:'COMPLETE',cleanup_status:'COMPLETE',terminal:true}));vi.stubGlobal('fetch',fetch);
    render(<Validation data={fixture({validation:{status:'NOT_ATTEMPTED',phase:'COMPLETE',terminal:true}})} />);
    fireEvent.submit(screen.getByRole('button',{name:'Re-run Validation'}).closest('form')!);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    expect((fetch.mock.calls[0][1].body as FormData).get('csrf_token')).toBe('csrf-proof');
    expect(fetch.mock.calls[1][0]).toContain('/deployment-validations/run-new');
    await waitFor(() => expect(screen.getAllByText('Verified').length).toBeGreaterThan(0));
  });
});
