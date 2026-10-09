import {render,screen,cleanup,within} from '@testing-library/react';
import {afterEach,it,expect,vi} from 'vitest';
import {Page as Finding} from './finding';
import {Page as Service} from './service';
import {Entry} from './poam';
import {Requests,Report} from './remediations';
vi.mock('../hooks/useJob',()=>({useJob:vi.fn(()=>({job:null,error:null,retry:vi.fn(),elapsedSeconds:0}))}));
afterEach(cleanup);
const service={id:7,name:'Service',service_key:'key',groups:[]};
const finding={service,finding:{id:3,cve:'CVE-1',severity:'High',active:true,recurrence_count:1},evidence:{description:'<img src=x onerror=alert(1)>',data_source:'javascript:alert(1)',urls:['javascript:alert(2)','data:text/html,<script>alert(1)</script>','https://example.com/advisory'],cvss:[]},risk:{},remediation_classification:{reason:'Manual',classification:'manual'},current_observations:[],remediation_enabled:true,csrf_token:'csrf',can:{'remediation.execute':{'7':true}}};
it('renders finding text safely and rejects executable reference URLs',async()=>{
 const {container}=render(<Finding data={finding}/>);
 expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();expect(container.querySelector('img')).not.toBeInTheDocument();
 expect(screen.getByText('javascript:alert(1)')).not.toHaveAttribute('href');expect(screen.getByText('javascript:alert(2)')).not.toHaveAttribute('href');expect(screen.getByText('https://example.com/advisory')).toHaveAttribute('href','https://example.com/advisory');
 await screen.findByRole('button',{name:'Remediate'});
 const form=container.querySelector('dialog form')! as HTMLFormElement;expect(form).toHaveAttribute('action','/services/key/remediations/start');const fields=new FormData(form);expect(fields.get('csrf_token')).toBe('csrf');expect(fields.get('finding_type')).toBe('vulnerability');expect(fields.get('finding_id')).toBe('3');expect(fields.get('confirmed')).toBe('');expect(screen.queryByText('Execute remediation')).not.toBeInTheDocument();
});
it('hides finding remediation for denied scope or resolved findings',()=>{
 const {rerender}=render(<Finding data={{...finding,can:{'remediation.execute':{'8':true}}}}/>);expect(screen.queryByText('Remediate')).not.toBeInTheDocument();
 rerender(<Finding data={{...finding,finding:{...finding.finding,active:false}}}/>);expect(screen.queryByText('Remediate')).not.toBeInTheDocument();
});
const entry={id:2,title:'Title',item_type:'missing_evidence',description:'Description',remediation:'Plan',status:'active',service};
it('keeps POAM change/completion actions native and hides pending or denied actions',()=>{
 const {rerender}=render(<Entry data={{entry,can_change:true,history:[],csrf_token:'csrf'}}/>);
 expect(screen.getByText('Submit for approval').closest('form')).toHaveAttribute('action','/poam/entries/2/update');const completion=screen.getByText('Submit for verification').closest('form')!;
 expect(completion).toHaveAttribute('action','/poam/entries/2/complete');expect(new FormData(completion).get('csrf_token')).toBe('csrf');expect(screen.getByLabelText('Replacement evidence reference')).toBeRequired();
 rerender(<Entry data={{entry,can_change:true,pending_change:{request_type:'poam_update'},history:[]}}/>);expect(screen.queryByText('Submit for approval')).not.toBeInTheDocument();
 rerender(<Entry data={{entry,can_change:false,history:[]}}/>);expect(screen.queryByText('Submit for verification')).not.toBeInTheDocument();expect(screen.getByText('No lifecycle actions are currently available.')).toBeInTheDocument();
});
it('only exposes scoped request review when the projection explicitly authorizes it',()=>{
 const requests={csrf_token:'csrf',request_type_filter:'all',workflows:[{id:1,request_type:'poam_update',service,status:'pending',requested_by:'Creator',justification:'Reason',can_review:true},{id:2,request_type:'exception',service,status:'pending',requested_by:'Self',justification:'Reason',can_review:false}]};
 const {container}=render(<Requests data={requests}/>);
 const forms=container.querySelectorAll('form');expect(forms).toHaveLength(1);expect(forms[0]).toHaveAttribute('action','/requests/1/review');expect(new FormData(forms[0]).get('csrf_token')).toBe('csrf');
 expect(within(forms[0]).getByText('Approve')).toHaveAttribute('value','approved');expect(within(forms[0]).getByText('Reject')).toHaveAttribute('value','rejected');
});
const job={workflow:{approved_plan:{images:[],configuration_changes:[]}},job_key:'job',status:'failed',failure_reason:'Unable to patch',has_artifact:true,output_mode:'bundle',before_snapshot:{vulnerabilities:{Critical:2}},after_snapshot:{vulnerabilities:{}},validation:[],changed_artifacts:[],patched_images:[],configuration_changes:[],stages:[{name:'patch',status:'failed',detail:'No candidate'}],logs:['Failed safely']};
it('renders terminal failures with permission-scoped retry and downloads',()=>{
 const {rerender}=render(<Report data={{service,job,remediation_enabled:true,csrf_token:'csrf',can:{'remediation.execute':{'7':true},'service.export':{'7':true}}}}/>);
 expect(screen.getByRole('alert')).toHaveTextContent('Unable to patch');const form=screen.getByText('Retry as new job').closest('form')!;expect(form).toHaveAttribute('action','/services/key/remediations/job/retry');expect(new FormData(form).get('csrf_token')).toBe('csrf');expect(screen.getByText('Download candidate evidence for troubleshooting')).toHaveAttribute('href','/services/key/remediations/job/candidate.zip');
 rerender(<Report data={{service,job,remediation_enabled:true,can:{}}}/>);expect(screen.queryByText('Retry as new job')).not.toBeInTheDocument();expect(screen.queryByText('Download candidate evidence for troubleshooting')).not.toBeInTheDocument();
});

it('routes configuration finding actions into the scoped confirmation workflow',async()=>{
 const {container}=render(<Service data={{view:{service},policy_findings:[{id:91,finding:'RULE-91',active:true,severity:'High',remediation_classification:'PATCH'}],findings:[],selected_findings_view:'raw',finding_state:'active',remediation_enabled:true,csrf_token:'csrf',can:{'remediation.execute':{'7':true}}}}/>);
 await screen.findByRole('button',{name:'Remediate'});
 const form=container.querySelector('dialog.remediation-wizard form')! as HTMLFormElement;
 expect(form).toHaveAttribute('action','/services/key/remediations/start');
 const fields=new FormData(form);expect(fields.get('finding_type')).toBe('configuration');expect(fields.get('finding_id')).toBe('91');expect(fields.get('confirmed')).toBe('');
 expect(container.querySelector('form[action$="/remediate"]')).toBeNull();
});
