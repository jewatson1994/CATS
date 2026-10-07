import {act, cleanup, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Report} from './remediations';
import {PAGE_MEDIA_TYPE, requestJson, type PageData} from '../api';

vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson:vi.fn()}));
afterEach(() => {cleanup(); vi.useRealTimers(); vi.resetAllMocks();});

const baseJob = {
  job_key:'candidate-1', status:'completed', remediation_status:'complete', delivery_status:'not_run',
  verification_status:'not_run', static_status:'PASS', has_artifact:true, output_mode:'bundle',
  before_snapshot:{vulnerabilities:{}}, after_snapshot:{vulnerabilities:{}}, validation:[],
  changed_artifacts:[], patched_images:[], configuration_changes:[], stages:[], logs:[],
};
const page = (job:Record<string,unknown> = {}, permissions = true):PageData => ({
  service:{id:7,service_key:'example',name:'Example'}, csrf_token:'test-csrf',
  can:permissions ? {'remediation.execute':{'7':true}} : {}, job:{...baseJob,...job},
} as unknown as PageData);
const button = () => screen.queryByRole('button',{name:'Validate retained candidate'});

it('keeps applied source edits in the summary and unresolved findings in their own list', () => {
  render(<Report data={page({summary_of_changes:{schema_version:1, final_configuration_scan_complete:true,
    configuration_changes:[{rule_id:'APPLIED-CPU', resource:'Deployment/api', status:'VERIFIED', accepted:true,
      source_modified:true, verified:true, original_value:'100m', proposed_value:'200m', actual_value:'200m', actual_value_available:true}],
    unresolved:[{rule_id:'UNRESOLVED-VOLUME',resource:'Deployment/api',status:'UNRESOLVED',reason:'Requires an operator decision'}],
  }})}/>);
  const summary = within(screen.getByRole('region',{name:'Summary of changes'}));
  expect(summary.getByText(/1 accepted · 1 source edits · 1 verified/)).toBeInTheDocument();
  expect(summary.getByText(/APPLIED-CPU/, {selector:'summary'})).toBeInTheDocument();
  expect(summary.queryByText(/UNRESOLVED-VOLUME/, {selector:'summary'})).not.toBeInTheDocument();
  expect(summary.getByRole('heading',{name:'Remaining findings'})).toBeInTheDocument();
  expect(summary.getByText(/UNRESOLVED-VOLUME.*Requires an operator decision/, {selector:'p'})).toBeInTheDocument();
});

it('posts exact retained candidate validation with CSRF and does not poll a terminal report', () => {
  render(<Report data={page()}/>);
  const form = button()!.closest('form')!;
  expect(form).toHaveAttribute('method','post');
  expect(form).toHaveAttribute('action','/services/example/remediations/candidate-1/validate');
  expect(form.querySelector('[name="csrf_token"]')).toHaveValue('test-csrf');
  expect(within(form).getByText(/Uses this exact candidate and digest/)).toBeInTheDocument();
  expect(requestJson).not.toHaveBeenCalled();
});

it.each([
  ['static blocker',{static_status:'BLOCKING'},true],
  ['missing candidate',{has_artifact:false},true],
  ['missing permission',{},false],
  ['queued remediation',{status:'queued'},true],
  ['running remediation',{status:'running'},true],
  ['queued verification',{verification_status:'queued'},true],
  ['running verification',{verification_status:'running'},true],
])('hides validation for %s', (_label, job, permissions) => {
  vi.mocked(requestJson).mockImplementation(() => new Promise(() => {}));
  render(<Report data={page(job,permissions)}/>);
  expect(button()).not.toBeInTheDocument();
});

it('shows static blockers and runtime evidence independently without implying remediation failed', () => {
  render(<Report data={page({static_status:'BLOCKING', candidate_validation:{status:'COULD_NOT_VALIDATE',
    detail:'Retained chart failed lint',request_id:'request-1',validation_id:'runtime-1',cleanup_status:'COMPLETE'}})}/>);
  const lifecycle = within(screen.getByRole('region',{name:'Candidate lifecycle'}));
  expect(lifecycle.getByText('Remediation').nextElementSibling).toHaveTextContent('complete');
  expect(lifecycle.getByText(/Static: BLOCKING · Runtime: COULD_NOT_VALIDATE/)).toBeInTheDocument();
  expect(lifecycle.getByText('Retained chart failed lint')).toBeInTheDocument();
  expect(lifecycle.getByText('request-1')).toBeInTheDocument();
  expect(lifecycle.getByText('runtime-1')).toBeInTheDocument();
  expect(lifecycle.getByText(/Cleanup: COMPLETE/)).toBeInTheDocument();
});

it('polls active runtime validation through the status contract and stops at terminal evidence', async () => {
  vi.useFakeTimers();
  const active = page({verification_status:'running',candidate_validation:{status:'RUNNING',detail:'Waiting for workloads'}});
  const terminal = page({verification_status:'verified',candidate_validation:{status:'VERIFIED',detail:'Exact candidate verified',cleanup_status:'COMPLETE'}});
  vi.mocked(requestJson)
    .mockResolvedValueOnce({status:'completed',verification_status:'verified',revision:'r2',terminal:true})
    .mockResolvedValueOnce({data:terminal});
  render(<Report data={active}/>);
  await act(async () => {await Promise.resolve();});
  // The poll reads the lightweight status only, never the full report.
  expect(requestJson).toHaveBeenNthCalledWith(1,'/api/v1/services/example/remediations/candidate-1/status',expect.objectContaining({signal:expect.any(AbortSignal)}));
  await act(async () => {await vi.advanceTimersByTimeAsync(1500);});
  // Terminal: one final detail read restores the complete evidence.
  expect(requestJson).toHaveBeenNthCalledWith(2,'/services/example/remediations/candidate-1',expect.objectContaining({headers:{Accept:PAGE_MEDIA_TYPE}}));
  expect(screen.getByText('Exact candidate verified')).toBeInTheDocument();
  expect(button()).toBeInTheDocument();
  await act(async () => {await vi.advanceTimersByTimeAsync(30000);});
  expect(requestJson).toHaveBeenCalledTimes(2);
});
