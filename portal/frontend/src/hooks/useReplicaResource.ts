import {useEffect, useState} from 'react';
import {requestJson} from '../api';

/** Poll only after a request finishes, so a slow local registry cannot queue requests. */
export function useReplicaResource<T>(url: string, pollMilliseconds = 0) {
  const [state, setState] = useState<{url: string; value: T | null; error: string}>({url, value: null, error: ''});
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = async () => {
      try {
        const result = await requestJson<T>(url, {signal: controller.signal});
        if (!controller.signal.aborted) setState({url, value: result, error: ''});
      } catch (error) {
        if (!controller.signal.aborted) setState(previous => ({url, value: previous.url === url ? previous.value : null,
          error: error instanceof Error ? error.message : 'The operation failed.'}));
      } finally {
        if (pollMilliseconds && !controller.signal.aborted) timer = setTimeout(() => void refresh(), pollMilliseconds);
      }
    };
    void refresh();
    return () => {controller.abort(); clearTimeout(timer);};
  }, [url, version, pollMilliseconds]);
  return {value: state.url === url ? state.value : null, error: state.url === url ? state.error : '', reload: () => setVersion(version => version + 1)};
}
