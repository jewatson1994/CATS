import {useEffect, useState} from 'react';
import {requestJson, type PageData} from '../api';
import {visibleTimeout} from './visibleTimer';

/** Dashboard data is request scoped. Abort and identity checks prevent stale routes replacing newer data. */
export function useDashboard(pageData: PageData, {pollPending = false} = {}) {
  const url = pageData.dashboard_url as string | undefined;
  const [result, setResult] = useState<{url: string; data?: PageData; error?: string} | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!url) return;
    const controller = new AbortController();
    let cancelRetry: (() => void) | undefined;
    let delay = 3000;
    setResult(previous => previous?.url === url && previous.data ? {url, data: previous.data} : null);
    async function load(target: string) {
      try {
        const data = await requestJson<PageData>(target, {signal: controller.signal});
        if (controller.signal.aborted) return;
        setResult({url: target, data});
        if (pollPending && data.posture_preparing > 0) {
          cancelRetry = visibleTimeout(() => void load(target), delay);
          delay = Math.min(delay * 2, 30000);
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        const message = error instanceof Error ? error.message : 'Unable to load dashboard data.';
        setResult(previous => ({url: target, data: previous?.url === target ? previous.data : undefined, error: message}));
      }
    }
    void load(url);
    return () => {controller.abort(); cancelRetry?.();};
  }, [url, attempt, pollPending]);
  const current = result?.url === url ? result : null;
  return {data: url ? current?.data ? {...pageData, ...current.data} : null : pageData,
    error: current?.error, retry: () => setAttempt(value => value + 1)};
}
