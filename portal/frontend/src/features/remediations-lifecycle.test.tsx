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
  it('keeps remediation success independent of delivery failure and retains download access', () => {
    render(<Report data={data}/>);
    expect(screen.getByText('Candidate R2 · Source authoritative version: V7 (version #17)')).toBeInTheDocument();
    const lifecycle = within(screen.getByRole('region', {name:'Candidate lifecycle'}));
    for (const [label, value] of [['Remediation','completed'],['Delivery','failed'],['Verification','not run'],['Signing','verified']]) {
      expect(lifecycle.getByText(label).nextElementSibling).toHaveTextContent(value);
    }
    expect(screen.getByRole('link', {name:'Download remediation bundle'})).toHaveAttribute('href','/services/example/remediations/candidate-1/candidate.zip');
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
});
