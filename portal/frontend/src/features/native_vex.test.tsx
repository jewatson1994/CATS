import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {requestJson} from '../api';
import {VexSettings,VexEvidence,VexPoamReview} from './native_vex';
vi.mock('../api',async()=>({...await vi.importActual('../api'),requestJson:vi.fn()}));
afterEach(()=>{cleanup();vi.resetAllMocks();});
it('does not request policy or show controls without config permission',()=>{render(<VexSettings data={{}}/>);expect(requestJson).not.toHaveBeenCalled();expect(screen.queryByRole('button')).not.toBeInTheDocument();});
it('requires a version-matched preview before enabling and submits CSRF',async()=>{
 vi.mocked(requestJson).mockImplementation(async(url,options)=>{if(options?.method==='POST')return {enabled:true,version:3};if(url.includes('preview'))return {version:2,items:[{service_id:1,name:'Payments',eligible_before:2,eligible_after:1,noncompliant_before:1,noncompliant_after:0}]};return {enabled:false,version:2};});
 render(<VexSettings data={{csrf_token:'token',can:{'config.manage':{'*':true}}}}/>);
 await screen.findByText('Disabled');expect(screen.getByRole('button',{name:'Enable automatic exclusion'})).toBeDisabled();
 fireEvent.click(screen.getByRole('button',{name:'Preview exclusion impact'}));await screen.findByText('Payments');fireEvent.click(screen.getByRole('button',{name:'Enable automatic exclusion'}));
 await waitFor(()=>expect(requestJson).toHaveBeenCalledWith('/api/risk/native-vex/policy',expect.objectContaining({method:'POST',headers:expect.objectContaining({'X-CSRF-Token':'token'}),body:JSON.stringify({enabled:true,version:2})})));
});
it('loads scoped evidence on demand and labels retained observations',async()=>{
 vi.mocked(requestJson).mockResolvedValue({enabled:true,current:true,evaluation:null,items:[{id:1,finding_id:7,observation_id:9,effective_disposition:'vex_not_affected',evidence:{reason:'authoritative'}}]});
 render(<VexEvidence serviceKey="payments" findingId={7}/>);expect(requestJson).not.toHaveBeenCalled();fireEvent.click(screen.getByText('Automatic VEX disposition and evidence'));await screen.findByText('VEX Excluded');expect(requestJson).toHaveBeenCalledWith('/api/risk/services/payments/native-vex?after=0&finding_id=7',expect.anything());
});

it('flags fully excluded POAM findings independently of evidence pagination',async()=>{
 vi.mocked(requestJson).mockResolvedValue({enabled:true,current:true,finding_disposition:'vex_not_affected',items:[],next_after:100});
 render(<VexPoamReview serviceKey="payments" findingId={7}/>);
 await screen.findByText(/Cyber review required/);
});
