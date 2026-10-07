import {useCallback, useEffect, useState} from 'react';
import {requestJson} from '../api';
import {visibleTimeout} from './visibleTimer';

export interface JobState {
  status: string;
  started_at?: string | null;
  finished_at?: string | null;
  [key: string]: unknown;
}
export const TERMINAL = new Set(['complete', 'incomplete', 'error', 'cancelled', 'failed',
  'succeeded', 'validated', 'could_not_validate', 'partially_verified', 'verified', 'timed_out']);

const loadJson = <T,>(url: string, signal: AbortSignal) => requestJson<T>(url, {signal});

/** Each service/version/job scope owns its requests and timers. Never retain old evidence. */
export function useJob<T extends JobState>(url: string | null, scope: string,
  load: (url: string, signal: AbortSignal) => Promise<T> = loadJson) {
  const [result, setResult] = useState<{scope: string; job: T | null; error: string | null}>({scope, job: null, error: null});
  const [attempt, setAttempt] = useState(0);
  const [now, setNow] = useState(Date.now());
  const retry = useCallback(() => setAttempt(value => value + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    let cancelTimer = () => {};
    setResult({scope, job: null, error: null});
    if (!url) return () => controller.abort();
    const poll = async () => {
      try {
        const job = await load(url, controller.signal);
        if (controller.signal.aborted) return;
        setResult({scope, job, error: null});
        if (!TERMINAL.has(job.status.toLowerCase())) cancelTimer = visibleTimeout(poll, 1500);
      } catch (error) {
        if (controller.signal.aborted) return;
        setResult(previous => ({scope, job: previous.scope === scope ? previous.job : null,
          error: error instanceof Error ? error.message : 'Unable to read job status.'}));
        cancelTimer = visibleTimeout(poll, 3000);
      }
    };
    void poll();
    return () => {controller.abort(); cancelTimer();};
  }, [url, scope, attempt, load]);
  const job = result.scope === scope ? result.job : null;
  useEffect(() => {
    if (!job?.started_at || job.finished_at || TERMINAL.has(job.status.toLowerCase())) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [scope, job?.started_at, job?.finished_at, job?.status]);
  const start = job?.started_at ? Date.parse(job.started_at) : NaN;
  const end = job?.finished_at ? Date.parse(job.finished_at) : now;
  const elapsedSeconds = Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, Math.floor((end - start) / 1000)) : 0;
  return {job, error: result.scope === scope ? result.error : null, retry, elapsedSeconds};
}
