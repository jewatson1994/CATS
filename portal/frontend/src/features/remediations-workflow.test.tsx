import {act, cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Remediate, Report} from './remediations';
import {requestJson, type PageData} from '../api';
vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson:vi.fn()}));
afterEach(() => {cleanup();vi.resetAllMocks();vi.useRealTimers();});
const options = [
  {mode:'bundle',label:'Download Artifacts',description:'Retained artifacts and evidence',available:true},
  {mode:'oci',label:'OCI Push',description:'Publish immutable candidate to an authorized registry',available:true},
  {mode:'standard-bundle',label:'Standard Bundle',description:'Portable artifacts',available:true},
  {mode:'offline-bundle',label:'Offline Bundle',description:'Vendored images and dependencies',available:true},
];
const plan = {plan_digest:'plan-7',source_execution_id:17,source_version:'V7',images:[{original:'app@sha256:123'}],charts:[{path:'app/chart.tgz'}],configuration_changes:[],manual_review:[{rule_id:'CUSTOM',reason:'Operator action required'}]};
const job = {job_key:'job-7',status:'completed',remediation_status:'completed',has_artifact:true,artifact_digest:'sha256:candidate',original_revision:'V7',source_version_id:17,static_status:'PASS',verification_status:'not_run',delivery_status:'not_requested',before_snapshot:{vulnerabilities:{}},after_snapshot:{vulnerabilities:{}},validation:[],changed_artifacts:[],patched_images:[],configuration_changes:[],stages:[],logs:[]};
const data = (workflow:Record<string,unknown>={},extra:Record<string,unknown>={}):PageData => ({service:{id:7,service_key:'example',name:'Example'},csrf_token:'csrf',can:{'remediation.execute':{'7':true},'service.export':{'7':true}},oci_destinations:[{id:3,name:'Approved registry',endpoint:'https://registry.example',repository_prefix:'approved'}],job:{...job,workflow:{stage:'validate',state:'awaiting_validation',validation_outcome:'not_verified',validation_resolved:false,validation_required:true,can_skip_validation:false,approved_plan:plan,delivery_options:options,...workflow},...extra}});
const activeStage = () => screen.getByRole('list',{name:'Remediation steps'}).querySelector('[aria-current="step"]');

it('requires all planning stages, explicit confirmation and one stable submission key', async () => {
  vi.mocked(requestJson).mockResolvedValue(plan);
  const {container} = render(<Remediate data={data()}/>);
  container.querySelector('dialog')!.setAttribute('open','');
  expect(activeStage()).toHaveTextContent('Plan');
  expect(within(screen.getByRole('list',{name:'Remediation steps'})).getAllByRole('listitem')).toHaveLength(6);
  fireEvent.click(screen.getByText('Build plan'));
  await screen.findByText('Review proposed changes');
  expect(activeStage()).toHaveTextContent('Review');
  expect(screen.getByText(/Source version: V7/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Final review'));
  expect(activeStage()).toHaveTextContent('Confirm');
  expect(screen.getByRole('button',{name:'Execute remediation'})).toBeDisabled();
  expect(container.querySelector('[name="output_mode"]')).toBeNull();
  const form = container.querySelector('form')!;
  expect(fireEvent.submit(form)).toBe(false);
  fireEvent.click(screen.getByLabelText('I authorize execution of this remediation plan.'));
  const key = (form.querySelector('[name="submission_key"]') as HTMLInputElement).value;
  expect(key).toMatch(/^[a-f\d-]{36}$/i);
  expect(new FormData(form).get('confirmed')).toBe('yes');
  expect(fireEvent.submit(form)).toBe(true);
  expect(screen.getByRole('button',{name:'Starting remediation…'})).toBeDisabled();
  expect(fireEvent.submit(form)).toBe(false);
  expect(form.querySelector('[name="submission_key"]')).toHaveValue(key);
});
it('permits returning to review and resets authorization', async () => {
  vi.mocked(requestJson).mockResolvedValue(plan);
  const {container}=render(<Remediate data={data()}/>);container.querySelector('dialog')!.setAttribute('open','');
  fireEvent.click(screen.getByText('Build plan'));await screen.findByText('Review proposed changes');
  fireEvent.click(screen.getByText('Final review'));fireEvent.click(screen.getByLabelText('I authorize execution of this remediation plan.'));
  fireEvent.click(screen.getByRole('button',{name:'Back'}));expect(activeStage()).toHaveTextContent('Review');
  fireEvent.click(screen.getByText('Final review'));expect(screen.getByRole('button',{name:'Execute remediation'})).toBeDisabled();
});
it.each(['remediate','validate','deliver'])('restores authoritative %s stage after unmount and refresh', stage => {
  vi.mocked(requestJson).mockImplementation(() => new Promise(() => {}));
  const props=data({stage,validation_resolved:stage==='deliver'},stage==='remediate'?{status:'running'}:{});
  const {unmount}=render(<Report data={props}/>);
  expect(activeStage()).toHaveTextContent(stage[0].toUpperCase()+stage.slice(1));
  unmount();render(<Report data={props}/>);
  expect(activeStage()).toHaveTextContent(stage[0].toUpperCase()+stage.slice(1));
  expect(screen.getByText('Review approved Plan, Review and Confirm stages (read-only)')).toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Execute remediation'})).not.toBeInTheDocument();
  expect(vi.mocked(requestJson).mock.calls.every(([url])=>String(url).endsWith('/status'))).toBe(true);
});
it.each(['not_verified','failed','verified'])('shows explicit %s outcome and gates unresolved delivery', outcome => {
  render(<Report data={data({validation_outcome:outcome})}/>);
  const lifecycle=within(screen.getByRole('region',{name:'Candidate lifecycle'}));
  expect(lifecycle.getByText(outcome==='verified'?'Verified':outcome==='failed'?'Failed':'Not Verified',{selector:'strong'})).toBeInTheDocument();
  expect(screen.queryByRole('group',{name:'Delivery method'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Continue without validation'})).not.toBeInTheDocument();
});
it('permits an explicit persisted skip only when policy allows it', () => {
  render(<Report data={data({validation_required:false,can_skip_validation:true})}/>);
  const form=screen.getByRole('button',{name:'Continue without validation'}).closest('form')!;
  expect(form).toHaveAttribute('action','/services/example/remediations/job-7/validation/skip');
  expect(form.querySelector('[name="csrf_token"]')).toHaveValue('csrf');
  expect(screen.queryByRole('group',{name:'Delivery method'})).not.toBeInTheDocument();
});
it.each(['bundle','oci','standard-bundle','offline-bundle'])('selects %s as an independent delivery using accessible native radio cards', mode => {
  render(<Report data={data({stage:'deliver',validation_resolved:true,validation_outcome:'verified'})}/>);
  const group=screen.getByRole('group',{name:'Delivery method'});
  const radios=within(group).getAllByRole('radio');expect(radios).toHaveLength(4);
  const radio=radios.find(row=>(row as HTMLInputElement).value===mode)!;
  radio.focus();expect(radio).toHaveFocus();fireEvent.click(radio);expect(radio).toBeChecked();
  const form=radio.closest('form')!;
  expect(form).toHaveAttribute('action','/services/example/remediations/job-7/delivery');
  expect(new FormData(form).get('output_mode')).toBe(mode);
  if(mode==='oci') {fireEvent.change(screen.getByLabelText('Destination'),{target:{value:'3'}});expect(new FormData(form).get('destination_id')).toBe('3');}
  if(mode==='bundle') expect(screen.getByRole('link',{name:'Download Artifacts'})).toHaveAttribute('href','/services/example/remediations/job-7/candidate.zip');
});
it('honors policy and publication RBAC availability while preserving troubleshooting downloads', () => {
  render(<Report data={data({stage:'deliver',validation_resolved:true,validation_outcome:'failed',delivery_options:options.map(option=>({...option,available:option.mode==='bundle',reason:option.mode==='bundle'?'Troubleshooting only':'Publication requires Verified and publish permission'}))})}/>);
  expect(screen.getByRole('radio',{name:/OCI Push/})).toBeDisabled();
  expect(screen.getByRole('radio',{name:/Download Artifacts/})).toBeEnabled();
  expect(screen.getByRole('button',{name:'Deliver this revision'})).toBeDisabled();
});
it('preserves successful remediation and prior deliveries when a later operation fails', () => {
  render(<Report data={data({stage:'deliver',validation_resolved:true,validation_outcome:'verified'},{delivery_status:'failed',delivery_attempts:[{id:1,result:'download_ready',validation_type:'standard-bundle',artifact_digest:'sha256:candidate',verification:{status:'VERIFIED'}},{id:2,result:'failed',destination:'registry.example',error:'Registry unavailable'}]})}/>);
  expect(screen.getByRole('heading',{name:'Remediation Complete'})).toBeInTheDocument();
  expect(screen.getByRole('link',{name:'Download verified Standard Bundle'})).toHaveAttribute('href','/services/example/remediations/job-7/deliveries/1/bundle.zip');
  expect(screen.getByText(/latest delivery failed/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('radio',{name:/Offline Bundle/}));
  expect(screen.getByRole('button',{name:'Deliver this revision'})).toBeEnabled();
});
it.each([['failed','Remediation failed'],['review_required','Remediation partially completed']])('does not label %s remediation complete', (status,label) => {
  render(<Report data={data({stage:'remediate'},{status,remediation_status:status,has_artifact:false})}/>);
  expect(screen.getByRole('heading',{name:label})).toBeInTheDocument();
  expect(screen.queryByRole('heading',{name:'Remediation Complete'})).not.toBeInTheDocument();
});
it('merges lightweight progress without discarding approved plan while fetching terminal evidence', async () => {
  vi.useFakeTimers();
  const terminal=data({stage:'deliver',validation_resolved:true,validation_outcome:'verified'});
  vi.mocked(requestJson).mockResolvedValueOnce({status:'completed',verification_status:'verified',revision:'r2',terminal:true,workflow:{stage:'deliver',validation_resolved:true,validation_outcome:'verified'}}).mockResolvedValueOnce({data:terminal});
  render(<Report data={data({stage:'validate'},{verification_status:'running'})}/>);
  await act(async()=>{await Promise.resolve();await vi.advanceTimersByTimeAsync(1500);});
  expect(activeStage()).toHaveTextContent('Deliver');
  expect(screen.getByText(/Source version: V7/)).toBeInTheDocument();
  expect(screen.getByRole('radio',{name:/OCI Push/})).toBeInTheDocument();
  expect(requestJson).toHaveBeenCalledTimes(2);
});

it.each(['vulnerability','configuration'] as const)('preserves %s finding scope through planning and confirmation', async finding_type => {
  vi.mocked(requestJson).mockResolvedValue(plan);
  const {container}=render(<Remediate data={data()} finding_type={finding_type} finding_id={42}/>);
  container.querySelector('dialog')!.setAttribute('open','');
  fireEvent.click(screen.getByText('Build plan'));
  await screen.findByText('Review proposed changes');
  expect(requestJson).toHaveBeenCalledWith(`/services/example/remediations/plan?finding_type=${finding_type}&finding_id=42`);
  fireEvent.click(screen.getByText('Final review'));
  const fields=new FormData(container.querySelector('form')!);
  expect(fields.get('finding_type')).toBe(finding_type);
  expect(fields.get('finding_id')).toBe('42');
  expect(fields.get('confirmed')).toBe('');
  expect(screen.getByRole('button',{name:'Execute remediation'})).toBeDisabled();
});
it('omits unsupported delivery formats while keeping supported policy restrictions visible', () => {
  render(<Report data={data({stage:'deliver',validation_resolved:true,delivery_options:options.map(option=>({...option,supported:option.mode!=='offline-bundle'}))})}/>);
  expect(screen.queryByRole('radio',{name:/Offline Bundle/})).not.toBeInTheDocument();
  expect(screen.getAllByRole('radio')).toHaveLength(3);
});

it('offers a reviewed new plan for legacy jobs and retains approved-plan retry with scoped permission', () => {
  const props={...data({approved_plan:null},{status:'failed'}),remediation_enabled:true};
  const {rerender}=render(<Report data={props}/>);
  expect(screen.queryByRole('button',{name:'Retry as new job'})).not.toBeInTheDocument();
  expect(screen.getByRole('link',{name:'Review a new remediation plan'})).toHaveAttribute('href','/services/example?remediations=true');
  rerender(<Report data={{...data({}, {status:'failed'}),remediation_enabled:true}}/>);
  expect(screen.getByRole('button',{name:'Retry as new job'}).closest('form')).toHaveAttribute('action','/services/example/remediations/job-7/retry');
  expect(screen.queryByRole('link',{name:'Review a new remediation plan'})).not.toBeInTheDocument();
  rerender(<Report data={{...props,can:{}}}/>);
  expect(screen.queryByRole('link',{name:'Review a new remediation plan'})).not.toBeInTheDocument();
});
it.each(['staged','publishing'])('locks delivery choices and submission while the retained attempt is %s', delivery_status => {
  vi.mocked(requestJson).mockImplementation(() => new Promise(() => {}));
  const ready=data({stage:'deliver',validation_resolved:true});
  const {rerender}=render(<Report data={ready}/>);
  fireEvent.click(screen.getByRole('radio',{name:/OCI Push/}));
  fireEvent.change(screen.getByLabelText('Destination'),{target:{value:'3'}});
  rerender(<Report data={{...ready,job:{...ready.job,delivery_status}}}/>);
  screen.getAllByRole('radio').forEach(radio=>expect(radio).toBeDisabled());
  expect(screen.getByLabelText('Destination')).toBeDisabled();
  const submit=screen.getByRole('button',{name:'Deliver this revision'});
  expect(submit).toBeDisabled();
  expect(fireEvent.submit(submit.closest('form')!)).toBe(false);
  expect(screen.getByText(/Delivery is in progress/)).toBeInTheDocument();
});
