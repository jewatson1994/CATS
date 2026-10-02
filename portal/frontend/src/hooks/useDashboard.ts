import {useEffect, useState} from 'react';
import {requestJson, type PageData} from '../api';

/** Dashboard data is request scoped. Abort and identity checks prevent stale routes replacing newer data. */
export function useDashboard(pageData: PageData) {
  const url = pageData.dashboard_url as string | undefined;
  const [result, setResult] = useState<{url: string; data?: PageData; error?: string} | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!url) return;
    const controller = new AbortController();
    setResult(null);
    requestJson<PageData>(url, {signal: controller.signal}).then(data => {
      if (!controller.signal.aborted) setResult({url, data});
    }).catch(error => {
      if (!controller.signal.aborted) setResult({url, error: error instanceof Error ? error.message : 'Unable to load dashboard data.'});
    });
    return () => controller.abort();
  }, [url, attempt]);
  const current = result?.url === url ? result : null;
  return {data: url ? current?.data ? {...pageData, ...current.data} : null : pageData,
    error: current?.error, retry: () => setAttempt(value => value + 1)};
}
