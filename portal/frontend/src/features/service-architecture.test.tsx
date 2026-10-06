import {afterEach,describe,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen} from '@testing-library/react';
import {Page} from './service-architecture';

afterEach(()=>{cleanup();vi.useRealTimers();vi.unstubAllGlobals();});
const node={id:'pod',kind:'Pod',name:'Example',label:'Pod · Example',namespace:'default',evidence:[{detail:'Rendered evidence',source:'template.yaml'}]};
const layout={node_ids:['pod'],positions:{pod:{x:100,y:100}},edges:[],bounds:{x:0,y:0,width:200,height:200}};
const data={view:{service:{service_key:'demo',name:'Demo'}},architecture_graph:{nodes:[node],relationships:[],layouts:{all:layout,declared:layout},summary:{nodes:1}},architecture_verification:{state:'DECLARED',label:'Declared'}};
describe('native architecture',()=>{
  it('supports keyboard selection, layers and zoom/reset controls',()=>{
    render(<Page data={data}/>);
    fireEvent.keyDown(screen.getByRole('button',{name:'Pod · Example'}),{key:'Enter'});
    expect(screen.getByRole('complementary',{name:'Selection details'})).toHaveTextContent('Rendered evidence');
    fireEvent.click(screen.getByRole('button',{name:'Zoom in'}));expect(screen.getByText('125%')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Reset'}));expect(screen.getByText('100%')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Layer'),{target:{value:'declared'}});
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });
  it('refreshes evidence and cleans up the polling timer',async()=>{
    vi.useFakeTimers();const fetch=vi.fn().mockResolvedValue({ok:true,status:200,headers:new Headers({'content-type':'application/json'}),json:async()=>({architecture:{state:'VERIFIED',label:'Verified',observed:1,expected:1},graph:data.architecture_graph})});vi.stubGlobal('fetch',fetch);
    const {unmount}=render(<Page data={{...data,architecture_polling:true}}/>);
    await act(async()=>{await vi.advanceTimersByTimeAsync(5000);});
    expect(screen.getByText('✓ Verified')).toBeInTheDocument();expect(new URL(fetch.mock.calls[0][0]).pathname).toBe('/api/v1/services/demo/architecture-evidence');
    unmount();await vi.advanceTimersByTimeAsync(10000);expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('keeps live evidence scoped to the selected version',async()=>{
    vi.useFakeTimers();const fetch=vi.fn().mockResolvedValue({ok:true,status:200,headers:new Headers({'content-type':'application/json'}),json:async()=>({architecture:{},graph:data.architecture_graph})});vi.stubGlobal('fetch',fetch);
    render(<Page data={{...data,view_version:'1.2 / test',architecture_polling:true}}/>);
    await act(async()=>{await vi.advanceTimersByTimeAsync(5000);});
    expect(new URL(fetch.mock.calls[0][0]).searchParams.get('view_version')).toBe('1.2 / test');
  });
  it('retains the selected version when refreshing responsive layouts',async()=>{
    vi.useFakeTimers();let resize:()=>void=()=>{};
    vi.stubGlobal('ResizeObserver',class {constructor(callback:()=>void){resize=callback;}observe(){}disconnect(){}});
    const fetch=vi.fn().mockResolvedValue({ok:true,status:200,headers:new Headers({'content-type':'application/json'}),json:async()=>({all:layout})});vi.stubGlobal('fetch',fetch);
    render(<Page data={{...data,view_version:'historical'}}/>);
    vi.spyOn(screen.getByLabelText('Service architecture graph'),'getBoundingClientRect').mockReturnValue({width:800,height:620} as DOMRect);
    resize();await act(async()=>{await vi.advanceTimersByTimeAsync(180);});
    const url=new URL(fetch.mock.calls[0][0]);expect(url.searchParams.get('view_version')).toBe('historical');expect(url.searchParams.get('layout_width')).toBe('800');
  });
});
