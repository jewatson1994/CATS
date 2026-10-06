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
  const json=(body:any)=>({ok:true,status:200,headers:new Headers({'content-type':'application/json'}),json:async()=>body});
  const finalGraph={...data.architecture_graph,nodes:[{...node,id:'svc',label:'Service · Final',name:'Final'}],layouts:{all:{...layout,node_ids:['svc'],positions:{svc:{x:100,y:100}}}},summary:{nodes:1,declared:1}};
  const evidenceServer=(summaries:any[],full:any={architecture:{state:'VERIFIED',label:'Verified',observed:1,expected:1,run_key:'run-1'},graph:finalGraph,active_validation:null})=>vi.fn().mockImplementation(async(url:string)=>{
    const parsed=new URL(url);
    if(parsed.searchParams.get('summary')==='true')return json(summaries.length>1?summaries.shift():summaries[0]);
    return json(full);
  });
  const isSummary=(call:any[])=>new URL(call[0]).searchParams.get('summary')==='true';
  it('polls only the summary while validation runs and loads the full graph once at the terminal state',async()=>{
    vi.useFakeTimers();
    const fetch=evidenceServer([
      {architecture:{state:'DECLARED',label:'Declared'},graph:{summary:{nodes:1,declared:3}},active_validation:{run_key:'run-1',run_id:'run-1'}},
      {architecture:{state:'DECLARED',label:'Declared'},graph:{summary:{nodes:1,declared:3}},active_validation:{run_key:'run-1',run_id:'run-1'}},
      {architecture:{state:'VERIFIED',label:'Verified',observed:1,expected:1,run_key:'run-1'},graph:{summary:{nodes:1,declared:1}},active_validation:null},
    ]);vi.stubGlobal('fetch',fetch);
    const {unmount}=render(<Page data={{...data,architecture_polling:true}}/>);
    await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});
    expect(fetch.mock.calls.every(isSummary)).toBe(true);
    expect(new URL(fetch.mock.calls[0][0]).pathname).toBe('/api/v1/services/demo/architecture-evidence');
    await act(async()=>{await vi.advanceTimersByTimeAsync(5000);});
    const full=fetch.mock.calls.filter(call=>!isSummary(call));
    expect(full).toHaveLength(1);expect(fetch).toHaveBeenCalledTimes(4);
    expect(screen.getByText('✓ Verified')).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Service · Final'})).toBeInTheDocument();
    await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
    expect(fetch).toHaveBeenCalledTimes(4);
    unmount();await vi.advanceTimersByTimeAsync(10000);expect(fetch).toHaveBeenCalledTimes(4);
  });
  it('does not poll when no validation is running',async()=>{
    vi.useFakeTimers();const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
    render(<Page data={data}/>);
    await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
    expect(fetch).not.toHaveBeenCalled();
    expect(screen.getByRole('button',{name:'Pod · Example'})).toBeInTheDocument();
  });
  it('resumes summary polling when a new validation is found after the page becomes visible',async()=>{
    vi.useFakeTimers();
    const fetch=evidenceServer([
      {architecture:{state:'DECLARED',label:'Declared'},graph:{summary:{nodes:1}},active_validation:{run_key:'run-2'}},
      {architecture:{state:'DECLARED',label:'Declared'},graph:{summary:{nodes:1}},active_validation:{run_key:'run-2'}},
    ]);vi.stubGlobal('fetch',fetch);
    render(<Page data={data}/>);
    await act(async()=>{document.dispatchEvent(new Event('visibilitychange'));await vi.advanceTimersByTimeAsync(0);});
    expect(fetch).toHaveBeenCalledTimes(1);
    await act(async()=>{await vi.advanceTimersByTimeAsync(5000);});
    expect(fetch).toHaveBeenCalledTimes(2);expect(fetch.mock.calls.every(isSummary)).toBe(true);
  });
  it('does not refetch the full graph for an unchanged idle state',async()=>{
    vi.useFakeTimers();
    const fetch=evidenceServer([{architecture:{state:'DECLARED',label:'Declared'},graph:{summary:{nodes:1}},active_validation:null}]);vi.stubGlobal('fetch',fetch);
    render(<Page data={data}/>);
    for(let index=0;index<3;index++)await act(async()=>{document.dispatchEvent(new Event('visibilitychange'));await vi.advanceTimersByTimeAsync(0);});
    expect(fetch).toHaveBeenCalledTimes(3);expect(fetch.mock.calls.every(isSummary)).toBe(true);
  });
  it('reports a failed final graph request without dropping the shown evidence',async()=>{
    vi.useFakeTimers();
    const fetch=vi.fn().mockImplementation(async(url:string)=>new URL(url).searchParams.get('summary')==='true'
      ?json({architecture:{state:'VERIFIED',label:'Verified',run_key:'run-3'},graph:{summary:{nodes:1}},active_validation:null})
      :({ok:false,status:500,headers:new Headers({'content-type':'application/json'}),json:async()=>({detail:'boom'})}));vi.stubGlobal('fetch',fetch);
    render(<Page data={{...data,architecture_polling:true}}/>);
    await act(async()=>{await vi.advanceTimersByTimeAsync(5000);});
    expect(screen.getByText(/Could not load the final architecture evidence/)).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Pod · Example'})).toBeInTheDocument();
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
