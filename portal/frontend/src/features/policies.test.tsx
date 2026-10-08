import {render,screen,fireEvent,cleanup,within} from '@testing-library/react';
import {afterEach,it,expect} from 'vitest';
import {PolicyPage} from './policies';
afterEach(cleanup);
const data={csrf_token:'csrf',configuration:{compliance_mode:'risk_based',overdue_days:'30',minimum_severity:'High',kev_enabled:'true',kev_noncompliant:'true',epss_enabled:'true'},groups:[{id:2,name:'Group'}],selected_group_id:2,may_manage:true,may_audit:false,may_manage_users:false,export_templates:[],events:[],shown_count:0,retained_count:0,raw_due_rules:[{severity:'High',days:30}],epss_rules:[{severity:'Any',threshold:0.9,noncompliant:true}],entries:[]};
it('keeps locked rule payloads, supports editable additions/removal and raw mode',()=>{
 const {container}=render(<PolicyPage data={data} kind="compliance"/>);
 expect(screen.getByLabelText('EPSS severity 1')).toBeDisabled();
 const form=container.querySelector('form[method=post]')! as HTMLFormElement;
 expect(new FormData(form).getAll('epss_severity')).toEqual(['Any']);expect(new FormData(form).getAll('raw_due_days')).toEqual(['30']);
 fireEvent.click(screen.getByText('Add EPSS rule'));fireEvent.change(screen.getByLabelText('EPSS threshold 2'),{target:{value:'0.5'}});
 expect(new FormData(form).getAll('epss_rule_threshold')).toEqual(['0.9','0.5']);
 fireEvent.click(within(screen.getByLabelText('EPSS threshold 2').closest('tr')!).getByText('Done'));expect(screen.getByLabelText('EPSS threshold 2')).toBeDisabled();
 fireEvent.click(within(screen.getByLabelText('EPSS threshold 2').closest('tr')!).getByText('Remove'));expect(new FormData(form).getAll('epss_rule_threshold')).toEqual(['0.9']);
 fireEvent.click(screen.getByLabelText('Raw'));expect(screen.getByText('Add severity rule')).toBeVisible();expect(screen.getByText('Add EPSS rule')).not.toBeVisible();
 expect(form).toHaveAttribute('action','/admin/compliance?group_id=2');expect(new FormData(form).get('csrf_token')).toBe('csrf');
});
it('shows scoped parent/template/audit controls according to permissions',()=>{
 const {rerender,container}=render(<PolicyPage data={{...data,may_audit:true,selected_group:{id:2,parent_id:3},groups:[...data.groups,{id:3,name:'Parent'}],export_templates:[{kind:'poam',name:'POAM',mode:'inherit',source:'Parent',enabled_count:3}],events:[{created_at:'Yesterday',actor:'system',action:'updated',target_type:'portal',detail:{changed:['warning_days']}}]}} kind="general"/>);
 expect(screen.getByLabelText('Parent group for inherited templates')).toHaveValue('3');expect(screen.getByText('View / configure')).toHaveAttribute('href','/admin/general-policy/export-templates/poam?group_id=2');
 expect(container.querySelector('form[action="/admin/audit-policy?group_id=2"]')).toBeInTheDocument();expect(screen.getByText('Recent audit activity')).toBeInTheDocument();
 rerender(<PolicyPage data={{...data,may_manage:false,may_audit:true}} kind="general"/>);expect(screen.queryByText('Save audit policy')).not.toBeInTheDocument();expect(screen.getByText('Recent audit activity')).toBeInTheDocument();
});
it('preserves watchlist edit/delete and multipart import names',()=>{
 const {container}=render(<PolicyPage data={{...data,entries:[{id:8,purl:'pkg:pypi/example',ecosystem:'python',name:'example',version_constraint:'>=1',enabled:false}]}} kind="watchlist"/>);
 const edit=screen.getByText('Delete').closest('form')!;expect(new FormData(edit).get('entry_id')).toBe('8');expect(new FormData(edit).has('enabled')).toBe(false);expect(screen.getByText('Delete')).toHaveAttribute('name','action');
 expect(container.querySelector('form[enctype="multipart/form-data"]')).toHaveAttribute('action','/admin/dependency-watchlist/import');expect(screen.getByLabelText('Watchlist file')).toHaveAttribute('name','file');expect(screen.getByLabelText('Watchlist file')).toBeRequired();
});
it('retains evidence, workflow and hardening field names and bounds',()=>{
 const {rerender,container}=render(<PolicyPage data={{...data,configuration:{skipped_images_incomplete:'false',incomplete_noncompliant:'true'}}} kind="evidence"/>);
 expect(screen.getByLabelText('Skipped images')).toHaveValue('false');expect(screen.getByLabelText('Incomplete evidence treatment')).toHaveAttribute('name','incomplete_noncompliant');
 rerender(<PolicyPage data={{...data,configuration:{warning_days:'14',exception_max_days:'0'}}} kind="workflow"/>);
 expect(screen.getByLabelText('Maximum exception duration (days)')).toHaveAttribute('min','0');expect(screen.getByLabelText('Warning window (days)')).toHaveAttribute('max','3650');
 rerender(<PolicyPage data={{...data,configuration:{hardening_overdue_days:'90',hardening_noncompliant:'false'}}} kind="hardening"/>);
 expect(screen.getByLabelText('Overdue hardening treatment')).toHaveValue('false');expect(container.querySelector('form[method=post]')).toHaveAttribute('action','/admin/compliance-frameworks?group_id=2');
});

it('keeps global warning selections in Workflow independently of group scope',()=>{
 const {container}=render(<PolicyPage kind="general" data={{...data,cyber_warning_policy:{kev:false,critical_high:true}}}/>);
 expect(screen.getByLabelText('KEV')).not.toBeChecked();
 expect(screen.getByLabelText('Critical / High findings')).toBeChecked();
 const form=container.querySelector('form[action="/admin/configuration/cyber-warning-policy"]') as HTMLFormElement;
 expect(new FormData(form).getAll('conditions')).not.toContain('kev');
 expect(form.closest('.panel')?.querySelector('h2')).toHaveTextContent('Workflow');
 expect(new FormData(form).get('group_id')).toBeNull();
});
