import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {Report} from './remediations';
import type {PageData} from '../api';

vi.mock('../api', async importOriginal => ({...await importOriginal<typeof import('../api')>(), requestJson:vi.fn(() => new Promise(() => {}))}));
afterEach(cleanup);

const authorization = 'I authorize publishing this release documentation to the selected registry and its approved audience.';
const documentation = {
  status:'published',sha256:'documentation-hash',revision:'release-1',
  manifest:{snapshot:{service_id:7,service_key:'example',source_version_id:17,source_version:'V7',remediation:{remediation_id:22,job_key:'job-7',candidate_digest:'sha256:candidate',validation:{validation_id:11,request_id:'request-11',validator_id:'validator-2'}},source_execution_id:9,source_execution_key:'scan-9'},documentation:{digest:'documentation-hash',bytes:1234},artifacts:[{reference:'registry.example/app@sha256:artifact',digest:'sha256:artifact'}]},
  files:{'documentation.zip':'sha256:docs','release-manifest.json':'sha256:manifest','VERIFY.txt':'sha256:instructions','release-manifest.sig':'sha256:signature','release-public-key.pem':'sha256:key'},
  signing:{status:'signed',key_fingerprint:'sha256:trusted-key'},
  publications:[{reference:'registry.example/app@sha256:docs',digest:'sha256:docs',subject:'registry.example/app@sha256:artifact',association_mode:'compatibility_tag',status:'published'}],
};
const data = (extra:Record<string,unknown>={}):PageData => ({
  service:{id:7,service_key:'example',name:'Example'},csrf_token:'csrf',
  can:{'service.export':{'7':true},'artifact.publish':{'7':true}},
  oci_destinations:[{id:3,name:'Approved registry',endpoint:'https://registry.example'},{id:4,name:'Second registry',endpoint:'https://other.example'}],
  job:{job_key:'job-7',status:'completed',remediation_status:'completed',delivery_status:'not_requested',has_artifact:true,
    before_snapshot:{vulnerabilities:{}},after_snapshot:{vulnerabilities:{}},validation:[],changed_artifacts:[],patched_images:[],configuration_changes:[],stages:[],logs:[],
    workflow:{stage:'deliver',validation_resolved:true,delivery_options:[{mode:'oci',available:true},{mode:'standard-bundle',available:true},{mode:'offline-bundle',available:true}]},...extra},
});
const selectRegistry = () => {
  fireEvent.click(screen.getByRole('radio',{name:/OCI Push/}));
  fireEvent.change(screen.getByLabelText('Destination'),{target:{value:'3'}});
};

it('requires explicit documentation audience authorization and submits its server field', () => {
  render(<Report data={data()}/>);
  selectRegistry();
  const consent=screen.getByRole('checkbox',{name:authorization});
  const button=screen.getByRole('button',{name:'Deliver this revision'});
  const form=button.closest('form')!;
  expect(consent).not.toBeChecked();
  expect(consent).toBeRequired();
  expect(button).toBeDisabled();
  expect(fireEvent.submit(form)).toBe(false);
  expect(new FormData(form).get('authorize_documentation')).toBeNull();
  expect(screen.getByText(/Release documentation is attached by default/)).toHaveTextContent('PPSM, POA&M, Assets, findings, SBOM');
  fireEvent.click(consent);
  expect(button).toBeEnabled();
  expect(new FormData(form).get('authorize_documentation')).toBe('yes');
  expect(fireEvent.submit(form)).toBe(true);
  expect(screen.getByRole('button',{name:'Queuing delivery…'})).toBeDisabled();
});

it('clears audience authorization when the selected registry or delivery method changes', () => {
  render(<Report data={data()}/>);
  selectRegistry();
  fireEvent.click(screen.getByRole('checkbox',{name:authorization}));
  fireEvent.change(screen.getByLabelText('Destination'),{target:{value:'4'}});
  expect(screen.getByRole('checkbox',{name:authorization})).not.toBeChecked();
  fireEvent.click(screen.getByRole('checkbox',{name:authorization}));
  fireEvent.click(screen.getByRole('radio',{name:/Standard Bundle/}));
  expect(screen.queryByRole('checkbox',{name:authorization})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('radio',{name:/OCI Push/}));
  expect(screen.getByRole('checkbox',{name:authorization})).not.toBeChecked();
});

it('disables OCI documentation publication when service export permission is missing', () => {
  render(<Report data={{...data(),can:{'artifact.publish':{'7':true}}}}/>);
  expect(screen.getByRole('radio',{name:/OCI Push/})).toBeDisabled();
  expect(screen.getByText(/requires service export permission/)).toBeInTheDocument();
});

it.each(['Standard Bundle','Offline Bundle'])('explains included documentation and configured signing for %s', name => {
  render(<Report data={data()}/>);
  fireEvent.click(screen.getByRole('radio',{name:new RegExp(name)}));
  expect(screen.getByText(/Standard and Offline Bundles include/)).toHaveTextContent('verified release signature when signing is configured');
  expect(screen.getByText(/Standard and Offline Bundles include/)).toHaveTextContent('exact revision');
  expect(screen.getByRole('list',{name:'Remediation steps'}).children).toHaveLength(6);
});

it('renders structured release progress, exact publication identities, and authorized download links', () => {
  render(<Report data={data({delivery_attempts:[{id:41,status:'published',destination:{name:'Approved registry'},result:{release_stage:'documentation_published',documentation}}]})}/>);
  expect(screen.getByText('Release progress: documentation published')).toBeInTheDocument();
  const release=within(screen.getByRole('region',{name:'Release documentation'}));
  expect(release.getByText('Signed and verified')).toBeInTheDocument();
  expect(release.getByText('sha256:trusted-key')).toBeInTheDocument();
  expect(release.getByText('documentation-hash')).toBeInTheDocument();
  expect(release.getByRole('link',{name:'Download release documentation'})).toHaveAttribute('href','/services/example/remediations/job-7/deliveries/41/documentation.zip');
  expect(release.getByRole('link',{name:'Download release manifest'})).toHaveAttribute('href','/services/example/remediations/job-7/deliveries/41/release-manifest.json');
  expect(release.getByRole('link',{name:'Download verification instructions'})).toHaveAttribute('href','/services/example/remediations/job-7/deliveries/41/VERIFY.txt');
  expect(release.getByRole('link',{name:'Download release signature'})).toHaveAttribute('href','/services/example/remediations/job-7/deliveries/41/release-manifest.sig');
  expect(release.getByRole('link',{name:'Download release public key'})).toHaveAttribute('href','/services/example/remediations/job-7/deliveries/41/release-public-key.pem');
  const publications=release.getByRole('list',{name:'Documentation publications'});
  expect(publications).toHaveTextContent('registry.example/app@sha256:docs');
  expect(publications).toHaveTextContent('registry.example/app@sha256:artifact');
  expect(publications).toHaveTextContent('compatibility tag');
  expect(release.getByText(/Source version: V7/)).toHaveTextContent('Service: example');
  expect(release.getByText(/Source version: V7/)).toHaveTextContent('Remediation: job-7');
  expect(release.getByText('sha256:candidate')).toBeInTheDocument();
  expect(release.getByText(/Documentation SHA-256:/)).toHaveTextContent('Size: 1,234 bytes');
  expect(release.getByText(/Source execution:/)).toHaveTextContent('9 · scan-9');
  expect(release.getByText(/Candidate validation:/)).toHaveTextContent('11 · Request: request-11 · Validator: validator-2');
});

it('uses the manifest digest when the receipt has no duplicate digest and offers unsigned verification instructions', () => {
  render(<Report data={data({delivery_attempts:[{id:44,status:'download_ready',result:{documentation:{...documentation,sha256:undefined,status:'ready',signing:{status:'unsigned'}}}}]})}/>);
  const release=within(screen.getByRole('region',{name:'Release documentation'}));
  expect(release.getByText('documentation-hash')).toBeInTheDocument();
  expect(release.getByText('Unsigned')).toBeInTheDocument();
  expect(release.getByRole('link',{name:'Download verification instructions'})).toBeInTheDocument();
  expect(release.queryByRole('link',{name:'Download release signature'})).not.toBeInTheDocument();
  expect(release.queryByRole('link',{name:'Download release public key'})).not.toBeInTheDocument();
});

it('does not offer optional verification files absent from the retained receipt', () => {
  render(<Report data={data({delivery_attempts:[{id:45,status:'published',result:{documentation:{...documentation,files:{}}}}]})}/>);
  const release=within(screen.getByRole('region',{name:'Release documentation'}));
  expect(release.getByRole('link',{name:'Download release manifest'})).toBeInTheDocument();
  expect(release.queryByRole('link',{name:'Download verification instructions'})).not.toBeInTheDocument();
  expect(release.queryByRole('link',{name:'Download release signature'})).not.toBeInTheDocument();
  expect(release.queryByRole('link',{name:'Download release public key'})).not.toBeInTheDocument();
});

it.each([['unsigned','Unsigned'],['verification_failed','Verification failed'],['pending','Not yet verified']])('reports %s release signing without claiming verified signing', (status,label) => {
  render(<Report data={data({delivery_attempts:[{id:42,status:'failed',result:{error:'Registry refused documentation',documentation:{...documentation,status:'failed',signing:{status}}}}]})}/>);
  expect(screen.getByText('Registry refused documentation')).toBeInTheDocument();
  const release=within(screen.getByRole('region',{name:'Release documentation'}));
  expect(release.getByText(label)).toBeInTheDocument();
  expect(release.queryByText('Signed and verified')).not.toBeInTheDocument();
  expect(release.queryByRole('link',{name:'Download release documentation'})).not.toBeInTheDocument();
});

it('hides release downloads when the viewer lacks export permission', () => {
  render(<Report data={{...data({delivery_attempts:[{id:43,status:'published',result:{documentation}}]}),can:{}}}/>);
  expect(screen.getByRole('region',{name:'Release documentation'})).toBeInTheDocument();
  expect(screen.queryByRole('link',{name:'Download release documentation'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link',{name:'Download release manifest'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link',{name:'Download verification instructions'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link',{name:'Download release signature'})).not.toBeInTheDocument();
  expect(screen.queryByRole('link',{name:'Download release public key'})).not.toBeInTheDocument();
});
