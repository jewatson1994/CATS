import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {requestJson} from '../api';
import {ReleaseRevision} from './release_revision';
vi.mock('../api', async original => ({...await original<any>(), requestJson:vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const revision = {id:3,decision:'approved',suspended:false,revoked:false,version:7,pointer_version:2,active_revision_id:1,manifest_digest:'digest',manifest:{artifacts:[]}};
it('uses pointer version for activation and state version for restrictions', async () => {
  vi.mocked(requestJson).mockResolvedValueOnce(revision).mockResolvedValueOnce({...revision,active_revision_id:3}).mockResolvedValueOnce({...revision,suspended:true});
  render(<ReleaseRevision data={{csrf_token:'token',can:{'approval.decide':{'9':true}}}} approvalId="8" serviceId={9}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Activate revision'}));
  await screen.findByText('Release revision activated.');
  expect(JSON.parse(String(vi.mocked(requestJson).mock.calls[1][1]?.body))).toEqual({expected_version:2});
  fireEvent.change(screen.getByLabelText('Restriction reason'),{target:{value:'Evidence withdrawn'}});
  fireEvent.click(screen.getByRole('button',{name:'Suspend revision'}));
  await screen.findByText('Release revision suspended.');
  expect(JSON.parse(String(vi.mocked(requestJson).mock.calls[2][1]?.body))).toEqual({expected_version:7,reason:'Evidence withdrawn'});
});
it('shows evidence without decision controls for a reader', async () => {
  vi.mocked(requestJson).mockResolvedValue(revision);
  render(<ReleaseRevision data={{}} approvalId="8" serviceId={9}/>);
  await screen.findByText('Review frozen revision manifest');
  expect(screen.queryByRole('button',{name:'Activate revision'})).not.toBeInTheDocument();
});
