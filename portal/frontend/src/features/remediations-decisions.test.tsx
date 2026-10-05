import {fireEvent, render, screen, waitFor, cleanup} from '@testing-library/react';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {Remediate} from './remediations';
import {requestJson, type PageData} from '../api';
vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson:vi.fn()}));
afterEach(() => {cleanup(); vi.clearAllMocks();});
const data = {service:{service_key:'demo'},csrf_token:'token',oci_destinations:[]} as unknown as PageData;
const safe = {finding_id:1,rule_id:'Escalation',category:'SAFE_AUTOMATIC',editable:true,new_value:false,original_value:true,proposed_value_source:'Hardening Policy'};
describe('remediation decisions', () => {
  it('paginates findings without losing decisions across pages', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:Array.from({length:12},(_,index) => ({...safe,finding_id:index+1,rule_id:`rule-${index+1}`,category:'DECISION_REQUIRED'})),images:[]});
    const {container} = render(<Remediate data={data}/>);
    container.querySelector('dialog')!.setAttribute('open','');
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    await screen.findByText('rule-1 · DECISION REQUIRED');
    expect(screen.queryByText('rule-12 · DECISION REQUIRED')).not.toBeInTheDocument();
    fireEvent.change(screen.getAllByLabelText('Decision')[0],{target:{value:'unresolved'}});
    fireEvent.click(screen.getByRole('button',{name:'Next'}));
    expect(screen.getByText('rule-12 · DECISION REQUIRED')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Previous'}));
    expect(screen.getAllByLabelText('Decision')[0]).toHaveValue('unresolved');
    fireEvent.change(screen.getByLabelText('Findings per page'),{target:{value:'25'}});
    expect(screen.getAllByLabelText('Decision')).toHaveLength(12);
  });
  it('reviews image vulnerability evidence in a separate tab without losing configuration decisions', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,category:'DECISION_REQUIRED'}],images:[{original:'ubuntu:latest',vulnerabilities:[{cve:'CVE-test',severity:'High',package:'openssl'}]}]});
    const {container} = render(<Remediate data={data}/>);
    // jsdom does not implement the native dialog showModal method.
    container.querySelector('dialog')!.setAttribute('open','');
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    expect(await screen.findByLabelText('Decision')).toHaveValue('proposed');
    fireEvent.click(screen.getByRole('tab',{name:'Vulnerability'}));
    expect(screen.getByText('ubuntu:latest')).toBeVisible();
    expect(screen.getByText(/Copa attempts supported package fixes/)).toBeVisible();
    fireEvent.click(screen.getByText('Retained vulnerabilities'));
    expect(screen.getByText(/CVE-test/)).toBeVisible();
    fireEvent.click(screen.getByRole('tab',{name:'Configuration'}));
    expect(screen.getByLabelText('Decision')).toHaveValue('proposed');
  });
  it('shows original finding identity even without an editable mapping', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{finding_id:1,rule_id:'CUSTOM-1',category:'MANUAL_ONLY',finding_target:'Deployment/api',finding_namespace:'production',scanner:'Trivy',finding_title:'Application-specific check',finding_description:'Review application configuration'}],images:[]});
    render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    await screen.findByText('No configuration changes are available.');
    expect(screen.queryByText('CUSTOM-1 · MANUAL ONLY')).not.toBeInTheDocument();
  });
  it.each([false,true,0,7,'','enum',[],['ALL'],{}, {key:false}].map(value => [value]))('offers a typed proposal %j', async value => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,category:'DECISION_REQUIRED',new_value:value}],images:[]});
    const {container} = render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    const selector = await screen.findByLabelText('Decision');
    expect(screen.getByRole('option',{name:`Apply proposed value (${JSON.stringify(value)})`,hidden:true})).toBeInTheDocument();
    expect(selector).toHaveValue('proposed');
    expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1'].action).toBe('proposed');
    expect(screen.queryByText('Source: No proposed value')).not.toBeInTheDocument();
  });
  it.each([null,undefined])('does not offer an absent proposal %j', async value => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,category:'DECISION_REQUIRED',new_value:value}],images:[]});
    render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    expect(await screen.findByLabelText('Decision')).toHaveValue('unresolved');
    expect(screen.queryByRole('option',{name:/Apply proposed/,hidden:true})).not.toBeInTheDocument();
    expect(screen.getByText('Source: No proposed value')).toBeInTheDocument();
  });
  it('persists the selected container target id rather than choosing the first resource', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,category:'DECISION_REQUIRED',editable:false,target_options:[
      {target_id:'app-id',resource:'Deployment/api',container_type:'container',container_name:'app',editable:true},
      {target_id:'sidecar-id',resource:'Deployment/api',container_type:'container',container_name:'sidecar',editable:true}]}],images:[]});
    const {container} = render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    const target = await screen.findByLabelText('Target resource');
    expect(target).toHaveValue('');
    fireEvent.change(target,{target:{value:'__all__'}});
    expect(screen.getByLabelText('Decision')).toHaveValue('proposed');
    expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1']).toEqual({target_all:true,action:'proposed'});
    fireEvent.change(target,{target:{value:''}});
    expect(screen.getByLabelText('Decision')).toHaveValue('unresolved');
    fireEvent.change(target,{target:{value:'sidecar-id'}});
    fireEvent.change(screen.getByLabelText('Decision'),{target:{value:'proposed'}});
    expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1']).toEqual({target_id:'sidecar-id',action:'proposed',value:false});
  });
  it('requires target selection before submitting a false proposal and permits leaving unresolved', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,rule_id:'KSV-0017',category:'DECISION_REQUIRED',editable:false,original_value:null,target_options:[{resource:'Deployment/api',editable:true,original_value:null,source_mapping:{values_file:'values.yaml',values_key:'api.privileged'}}]}],images:[]});
    const {container} = render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    const decision = await screen.findByLabelText('Decision');
    expect(decision).toHaveValue('unresolved');
    expect(screen.queryByRole('option',{name:'Apply proposed value (false)',hidden:true})).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Target resource'),{target:{value:'Deployment/api'}});
    expect(decision).toHaveValue('proposed');
    fireEvent.change(decision,{target:{value:'proposed'}});
    expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1']).toEqual({target_resource:'Deployment/api',action:'proposed',value:false});
    fireEvent.change(decision,{target:{value:'unresolved'}});
    expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1'].action).toBe('unresolved');
    fireEvent.change(screen.getByLabelText('Target resource'),{target:{value:''}});
    expect(screen.queryByRole('option',{name:'Apply proposed value (false)',hidden:true})).not.toBeInTheDocument();
  });
  it('keeps a known target separate from unavailable source mapping', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,category:'DECISION_REQUIRED',editable:false,target_resolution:'automatically-resolved',source_resolution:'unavailable',actionability:'source-unavailable',resource:'Deployment/api',reason:'The rendered target is known, but its authoritative source mapping is unavailable.'}],images:[]});
    render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    await screen.findByText('No configuration changes are available.');
    expect(screen.queryByLabelText('Decision')).not.toBeInTheDocument();
  });
  it('requires an explicit quantity without inventing a proposal', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{...safe,rule_id:'KSV-0016',category:'DECISION_REQUIRED',input_type:'quantity',new_value:null,field_path:'resources.requests.cpu'}],images:[]});
    const {container} = render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    const decision = await screen.findByLabelText('Decision');
    expect(decision).toHaveValue('unresolved');
    expect(screen.queryByRole('option',{name:/Apply proposed/,hidden:true})).not.toBeInTheDocument();
    fireEvent.change(decision,{target:{value:'custom'}});
    expect(screen.getByLabelText('Resource quantity')).toHaveValue('');
    fireEvent.change(screen.getByLabelText('Resource quantity'),{target:{value:'250m'}});
    expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1']).toEqual({action:'custom',value:'250m'});
  });
  it('skips automatic reviews when no decision is required', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[safe],images:[],plan_digest:'digest'});
    render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'automated'}});
    fireEvent.click(screen.getByText('Build plan'));
    await waitFor(() => expect(screen.getByText('Delivery / Verification')).toBeInTheDocument());
    expect(screen.queryByText('Decision')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Final review'));
    expect(screen.getByText(/1 configuration changes accepted/)).toBeInTheDocument();
  });
  it('guided exposes safe, sensitive and manual findings with typed custom values', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[safe,{...safe,finding_id:2,rule_id:'Nonroot',category:'DECISION_REQUIRED'}, {finding_id:3,rule_id:'Application',category:'MANUAL_ONLY'}],images:[],plan_digest:'digest'});
    const {container} = render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
    fireEvent.click(screen.getByText('Build plan'));
    await screen.findByText('Nonroot · DECISION REQUIRED');
    expect(screen.queryByText('Application · MANUAL ONLY')).not.toBeInTheDocument();
    expect(screen.getAllByLabelText('Decision')).toHaveLength(2);
    fireEvent.change(screen.getAllByLabelText('Decision')[1],{target:{value:'custom'}});
    fireEvent.change(screen.getByLabelText('Custom value'),{target:{value:'false'}});
    const decisions = JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value);
    expect(decisions['2']).toEqual({action:'custom',value:false});
    expect(decisions['3'].action).toBe('unresolved');
  });
  it('offers explicit final bundle modes and requires final validation', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[safe],images:[],plan_digest:'digest'});
    render(<Remediate data={data}/>);
    fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'automated'}});
    fireEvent.click(screen.getByText('Build plan'));
    await screen.findByText('Delivery / Verification');
    const delivery = screen.getByLabelText('Delivery');
    expect(screen.getByRole('option',{name:'Standard Bundle',hidden:true})).toHaveValue('standard-bundle');
    expect(screen.getByRole('option',{name:'Offline Bundle',hidden:true})).toHaveValue('offline-bundle');
    fireEvent.change(delivery,{target:{value:'offline-bundle'}});
    expect(screen.getByLabelText('CATSchrödinger’s final delivery verification')).toBeChecked();
    expect(screen.getByLabelText('CATSchrödinger’s final delivery verification')).toBeDisabled();
    fireEvent.click(screen.getByText('Final review'));
    expect(screen.getByText('Offline Bundle · Final delivery verification required')).toBeInTheDocument();
  });
});
