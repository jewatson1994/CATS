import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Remediate, Report} from './remediations';
import {requestJson, type PageData} from '../api';
vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson:vi.fn()}));
afterEach(() => {cleanup(); vi.clearAllMocks();});

it('shows source edits as unverified until final scan evidence exists', () => {
  const job = {job_key:'test',status:'completed',before_snapshot:{vulnerabilities:{}},after_snapshot:{vulnerabilities:{}},
    validation:[],changed_artifacts:[],patched_images:[],configuration_changes:[],stages:[],logs:[],output_mode:'bundle',
    summary_of_changes:{schema_version:1,final_configuration_scan_complete:false,configuration_changes:[
      {rule_id:'KSV1',resource:'Pod/api',status:'UNVERIFIED',accepted:true,source_modified:true,verified:false,
       original_value:true,proposed_value:false,actual_value:false,actual_value_available:true,reason:'Policy',approval:'automatic'}]}};
  render(<Report data={{service:{id:1,service_key:'api',name:'API'},job} as unknown as PageData}/>);
  const report = screen.getByRole('region',{name:'Summary of changes'});
  expect(report).toHaveTextContent('1 accepted · 1 source edits · 0 verified · 1 unresolved or unverified');
  expect(report).toHaveTextContent('Final configuration scan: Unavailable');
  expect(report).toHaveTextContent('Actual: false');
});

it('collects manager resource quantities without offering a null proposal', async () => {
  vi.mocked(requestJson).mockResolvedValue({configuration_changes:[{finding_id:1,rule_id:'CPU',category:'DECISION_REQUIRED',
    editable:true,new_value:null,input_type:'quantity',field_path:'resources.requests.cpu'}],images:[]});
  const {container} = render(<Remediate data={{service:{service_key:'api'},csrf_token:'token',oci_destinations:[]} as unknown as PageData}/>);
  fireEvent.change(screen.getByLabelText('Mode'),{target:{value:'guided'}});
  fireEvent.click(screen.getByText('Build plan'));
  const decision = await screen.findByLabelText('Decision');
  expect(screen.queryByRole('option',{name:/Apply proposed value/})).not.toBeInTheDocument();
  fireEvent.change(decision,{target:{value:'custom'}});
  fireEvent.change(screen.getByLabelText('Resource quantity'),{target:{value:'100m'}});
  expect(JSON.parse((container.querySelector('[name="decisions"]') as HTMLInputElement).value)['1']).toEqual({action:'custom',value:'100m'});
});
