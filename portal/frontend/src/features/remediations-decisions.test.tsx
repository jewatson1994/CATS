import {fireEvent, render, screen, waitFor, cleanup} from '@testing-library/react';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {Remediate} from './remediations';
import {requestJson, type PageData} from '../api';
vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson:vi.fn()}));
afterEach(() => {cleanup(); vi.clearAllMocks();});
const data = {service:{service_key:'demo'},csrf_token:'token',oci_destinations:[]} as unknown as PageData;
const safe = {finding_id:1,rule_id:'Escalation',category:'SAFE_AUTOMATIC',editable:true,new_value:false,original_value:true,proposed_value_source:'Hardening Policy'};
describe('remediation decisions', () => {
  it('skips automatic reviews when no decision is required', async () => {
    vi.mocked(requestJson).mockResolvedValue({configuration_changes:[safe],images:[],plan_digest:'digest'});
    render(<Remediate data={data}/>);
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
    fireEvent.click(screen.getByText('Build plan'));
    await screen.findByText('Will remain unresolved.');
    expect(screen.getAllByLabelText('Decision')).toHaveLength(2);
    fireEvent.change(screen.getAllByLabelText('Decision')[1],{target:{value:'custom'}});
    fireEvent.change(screen.getByLabelText('Custom value'),{target:{value:'false'}});
    const decisions = JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value);
    expect(decisions['2']).toEqual({action:'custom',value:false});
    expect(decisions['3'].action).toBe('unresolved');
  });
});
