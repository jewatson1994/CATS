import {afterEach, expect, it, vi} from 'vitest';

import {fireEvent, render, screen, waitFor} from '@testing-library/react';

import {Page, Recommendations} from './artifact_catalog';



const source = {id: 1, digest: `sha256:${'a'.repeat(64)}`, media_type: 'application/vnd.oci.image.manifest.v1+json', platform: 'linux/amd64'};

const target = {...source, id: 2, digest: `sha256:${'b'.repeat(64)}`};

const response = (value: unknown) => new Response(JSON.stringify(value), {headers: {'content-type': 'application/json'}});

const serviceData = {service: {service_key: 'payments', name: 'Payments'}, csrf_token: 'token'};

afterEach(() => vi.unstubAllGlobals());



it('renders scoped identities and blocked verification reasons', async () => {

  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({items: [{...source, eligibility: {eligible: false, reasons: ['Missing signature']}, services: [{service_key: 'payments', name: 'Payments'}]}], total: 1})));

  render(<Page data={{}}/>);

  expect(await screen.findByText(source.digest)).toBeInTheDocument();

  expect(screen.getByText('Missing signature')).toBeInTheDocument();

  expect(screen.getByRole('link', {name: 'Payments'})).toHaveAttribute('href', '/services/payments/artifact-recommendations');

  expect(screen.getByRole('button', {name: 'Next'})).toBeDisabled();

});



it('searches on submission and shows an actionable load failure', async () => {

  const fetch = vi.fn().mockResolvedValueOnce(response({items: [], total: 0})).mockRejectedValueOnce(new Error('Catalog unavailable')).mockResolvedValueOnce(response({items: [], total: 0}));

  vi.stubGlobal('fetch', fetch);

  render(<Page data={{}}/>);

  await screen.findByText('No artifacts found');

  fireEvent.change(screen.getByLabelText('Search artifacts'), {target: {value: 'linux/arm64'}});

  fireEvent.click(screen.getByRole('button', {name: 'Search'}));

  await screen.findByText('Catalog unavailable');

  expect(fetch.mock.calls[1][0]).toContain('search=linux%2Farm64');

  fireEvent.click(screen.getByRole('button', {name: 'Retry'}));

  await screen.findByText('No artifacts found');

});



it('requires both server permission and verified eligibility for a proposal', async () => {

  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({items: [{id: 3, status: 'pending_verification', source_artifact: source, target_artifact: target, eligibility: {eligible: false, reasons: ['Missing signature']}, can_adopt: true}]})));

  const view = render(<Recommendations data={serviceData}/>);

  expect(await screen.findByRole('button', {name: 'Propose adoption'})).toBeDisabled();

  view.unmount();

  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({items: [{id: 3, status: 'eligible', source_artifact: source, target_artifact: target, eligibility: {eligible: true, reasons: []}}]})));

  render(<Recommendations data={serviceData}/>);

  await screen.findByText('You do not have permission to adopt artifacts for this service.');

  expect(screen.queryByRole('button', {name: 'Propose adoption'})).not.toBeInTheDocument();

});



it('posts a scoped proposal with CSRF and refreshes without claiming deployment', async () => {

  const item = {id: 3, status: 'eligible', source_artifact: source, target_artifact: target, eligibility: {eligible: true, reasons: []}, can_adopt: true};

  const fetch = vi.fn().mockResolvedValueOnce(response({items: [item]})).mockResolvedValueOnce(response({status: 'proposed'})).mockResolvedValueOnce(response({items: [{...item, status: 'proposed'}]}));

  vi.stubGlobal('fetch', fetch);

  render(<Recommendations data={serviceData}/>);

  fireEvent.click(await screen.findByRole('button', {name: 'Propose adoption'}));

  await screen.findByText('Adoption proposed for this service. Approval and release checks are still required.');

  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));

  expect(fetch.mock.calls[1][0]).toContain('/api/services/payments/artifact-recommendations/3/adopt');

  expect(fetch.mock.calls[1][1].method).toBe('POST');

  expect(fetch.mock.calls[1][1].headers.get('X-CSRF-Token')).toBe('token');

  expect(screen.queryByRole('button', {name: 'Propose adoption'})).not.toBeInTheDocument();

});


it('requires a dismissal reason and reopens deferred recommendations', async () => {
  const item = {id:3,status:'pending_verification',source_artifact:source,target_artifact:target,can_adopt:true};
  const fetch = vi.fn().mockResolvedValueOnce(response({items:[item],can_adopt:true})).mockResolvedValueOnce(response({status:'dismissed'})).mockImplementation(() => Promise.resolve(response({items:[{...item,status:'dismissed',can_adopt:false}],can_adopt:true})));
  vi.stubGlobal('fetch',fetch); render(<Recommendations data={serviceData}/>);
  expect(await screen.findByRole('button',{name:'Dismiss recommendation'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Reason for recommendation 3'),{target:{value:'Not suitable for this service'}});
  fireEvent.click(screen.getByRole('button',{name:'Dismiss recommendation'}));
  await screen.findByText('Recommendation dismissed.');
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({action:'dismiss',reason:'Not suitable for this service'});
  fireEvent.click(await screen.findByRole('button',{name:'Reopen recommendation'}));
  await screen.findByText('Recommendation reopened.');
  expect(fetch.mock.calls.some(call => call[1]?.body && JSON.parse(call[1].body).action === 'reopen')).toBe(true);
});
it('reopens persisted amendment review without allowing proposal decisions', async () => {
  vi.stubGlobal('fetch',vi.fn().mockImplementation((url:string) => Promise.resolve(response(url.includes('readiness') ? {ready_for_cyber_review:false,blockers:[{code:'missing',message:'Retain fresh assessment',next_action:'Submit isolated inventory evidence'}]} : {can_adopt:true,items:[{id:3,status:'proposed',amendment_proposal_id:12,source_artifact:source,target_artifact:target,can_adopt:false}]}))));
  render(<Recommendations data={serviceData}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Continue amendment review'}));
  expect(screen.getByRole('heading',{name:'Amendment proposal #12'})).toBeInTheDocument();
  await screen.findByText('Retain fresh assessment');
  expect(screen.queryByRole('button',{name:'Request Cyber Approval'})).not.toBeInTheDocument();
  expect(screen.getByText('Next step: Submit isolated inventory evidence')).toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Defer recommendation'})).not.toBeInTheDocument();
});

it('shows precise adoption blockers before live readiness finishes', async () => {
  const item = {id:3,status:'pending_verification',source_artifact:source,target_artifact:target,can_adopt:true,eligibility:{eligible:true,reasons:[]}};
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url:string, options:any) => {
    if (url.includes('/readiness')) return new Promise(() => {});
    if (options?.method === 'POST') return Promise.resolve(response({amendment_proposal_id:12,proposal:{assessment_readiness:{message:'Isolated proposed scan missing',next_action:'Submit a complete proposed inventory scan'}}}));
    return Promise.resolve(response({can_adopt:true,items:[item]}));
  }));
  render(<Recommendations data={serviceData}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Propose adoption'}));
  await screen.findByText('Isolated proposed scan missing');
  expect(screen.getByText('Next step: Submit a complete proposed inventory scan')).toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Request Cyber Approval'})).not.toBeInTheDocument();
});
