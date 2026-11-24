import {useEffect, useState} from 'react';
import {requestJson} from '../api';

/** Poll only after a request finishes, so a slow local registry cannot queue requests. */
export function useReplicaResource<T>(url: string | null, pollMilliseconds: number | ((value: T) => number) = 0) {
  const [state, setState] = useState<{url: string | null; value: T | null; error: string}>({url, value: null, error: ''});
  const [version, setVersion] = useState(0);
  useEffect(() => {
    if (!url) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = async () => {
      let delay = typeof pollMilliseconds === 'number' ? pollMilliseconds : 0;
      try {
        const result = await requestJson<T>(url, {signal: controller.signal});
        if (typeof pollMilliseconds === 'function') delay = pollMilliseconds(result);
        if (!controller.signal.aborted) setState({url, value: result, error: ''});
      } catch (error) {
        if (!controller.signal.aborted) setState(previous => ({url, value: previous.url === url ? previous.value : null,
          error: error instanceof Error ? error.message : 'The operation failed.'}));
      } finally {
        if (delay && !controller.signal.aborted) timer = setTimeout(() => void refresh(), delay);
      }
    };
    void refresh();
    return () => {controller.abort(); clearTimeout(timer);};
  }, [url, version, pollMilliseconds]);
  return {value: state.url === url ? state.value : null, error: state.url === url ? state.error : '', reload: () => setVersion(version => version + 1)};
}
