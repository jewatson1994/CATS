import {act,renderHook} from '@testing-library/react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {useJob,type JobState} from './useJob';

afterEach(()=>vi.useRealTimers());
describe('job lifecycle isolation',()=>{
  it('aborts old scope and ignores its late response',async()=>{
    let resolveOld!: (value:JobState)=>void;
    const signals:AbortSignal[]=[];
    const load=vi.fn((url:string,signal:AbortSignal)=>{signals.push(signal);return url==='/old' ? new Promise<JobState>(resolve=>{resolveOld=resolve;}) : Promise.resolve({status:'complete',message:'new'});});
    const {result,rerender,unmount}=renderHook(({url})=>useJob(url,url,load),{initialProps:{url:'/old'}});
    rerender({url:'/new'});
    await act(async()=>{});
    expect(signals[0].aborted).toBe(true);
    expect(result.current.job?.message).toBe('new');
    await act(async()=>resolveOld({status:'running',message:'stale'}));
    expect(result.current.job?.message).toBe('new');
    unmount();expect(signals[1].aborted).toBe(true);
  });
  it('retries transient failures, then stops at a terminal status',async()=>{
    vi.useFakeTimers();
    const load=vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue({status:'validated',started_at:'2026-01-01T00:00:00Z',finished_at:'2026-01-01T00:00:05Z'});
    const {result,unmount}=renderHook(()=>useJob('/job','job',load));
    await act(async()=>{});expect(result.current.error).toBe('offline');
    await act(async()=>{await vi.advanceTimersByTimeAsync(3000);});
    expect(result.current.error).toBeNull();expect(result.current.elapsedSeconds).toBe(5);
    await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});expect(load).toHaveBeenCalledTimes(2);
    unmount();expect(vi.getTimerCount()).toBe(0);
  });
  it('never polls an absent job',()=>{
    const load=vi.fn();const {unmount}=renderHook(()=>useJob(null,'none',load));
    expect(load).not.toHaveBeenCalled();unmount();
  });
  it('continues elapsed time across phases and freezes on completion',async()=>{
    vi.useFakeTimers();vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    let current:JobState={status:'running',started_at:'2026-01-01T00:00:00Z',phase:'prepare'};
    const load=vi.fn(async()=>current);
    const {result,unmount}=renderHook(()=>useJob('/job','job',load));
    await act(async()=>{});
    await act(async()=>{await vi.advanceTimersByTimeAsync(3000);});
    expect(result.current.elapsedSeconds).toBe(3);
    current={...current,phase:'scan'};
    await act(async()=>{await vi.advanceTimersByTimeAsync(3000);});
    expect(result.current.job?.phase).toBe('scan');expect(result.current.elapsedSeconds).toBe(6);
    current={...current,status:'complete',finished_at:'2026-01-01T00:00:07Z'};
    await act(async()=>{await vi.advanceTimersByTimeAsync(3000);});
    expect(result.current.elapsedSeconds).toBe(7);
    const calls=load.mock.calls.length;
    await act(async()=>{await vi.advanceTimersByTimeAsync(60000);});
    expect(result.current.elapsedSeconds).toBe(7);expect(load).toHaveBeenCalledTimes(calls);
    unmount();expect(vi.getTimerCount()).toBe(0);
  });
});
