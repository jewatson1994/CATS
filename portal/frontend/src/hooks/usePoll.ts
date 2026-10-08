import {useEffect, useRef, useState} from 'react';
import {requestJson} from '../api';

export interface PollStatus {revision?: string; terminal?: boolean; [key: string]: unknown}

export interface PollOptions<T extends PollStatus> {
  /** Status URL; null disables polling. Changing it restarts the loop. */
  url: string | null;
  intervalMs?: number;
  maxIntervalMs?: number;
  /** Give up after this long without reaching a terminal state (0 = never). */
  maxDurationMs?: number;
  isTerminal?: (status: T) => boolean;
  /**
   * Called for every status, with whether its revision differs from the last
   * one handled successfully, and the poll's signal (aborted on unmount or URL
   * change) for any detail request it makes. If it throws, the status counts
   * as not handled: polling continues with backoff (even at a terminal state)
   * until it succeeds.
   */
  onStatus?: (status: T, changed: boolean, signal: AbortSignal) => void | Promise<void>;
  load?: (url: string, signal: AbortSignal) => Promise<T>;
}

const jitter = (value: number) => Math.round(value * (0.85 + Math.random() * 0.3));
const hidden = () => typeof document !== 'undefined' && document.visibilityState === 'hidden';

/**
 * Lightweight status polling: one request at a time (never overlapping),
 * cancelled on unmount or URL change, paused while the document is hidden and
 * resumed immediately when it becomes visible, exponential backoff with
 * jitter on errors and while nothing changes, and a stop at terminal state
 * once that state has been handled.
 */
export function usePoll<T extends PollStatus>({url, intervalMs = 2000, maxIntervalMs = 15000, maxDurationMs = 0,
  isTerminal = status => Boolean(status.terminal), onStatus, load}: PollOptions<T>) {
  const [state, setState] = useState<{url: string | null; status: T | null; error: string | null; stopped: boolean}>(
    {url, status: null, error: null, stopped: false});
  const callbacks = useRef({onStatus, isTerminal, load});
  callbacks.current = {onStatus, isTerminal, load};
  useEffect(() => {
    setState({url, status: null, error: null, stopped: !url});
    if (!url) return;
    const controller = new AbortController();
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let running = false;
    let delay = intervalMs;
    let revision: string | undefined;
    let done = false;
    const schedule = (wait: number) => {
      clearTimeout(timer);
      if (done || controller.signal.aborted || hidden()) return;
      timer = setTimeout(tick, jitter(wait));
    };
    async function tick() {
      if (running || done || controller.signal.aborted) return;
      if (hidden()) return; // resumed by visibilitychange
      if (maxDurationMs && Date.now() - started > maxDurationMs) {
        done = true;
        setState(previous => ({...previous, url, stopped: true, error: previous.error}));
        return;
      }
      running = true;
      try {
        const loader = callbacks.current.load || ((target: string, signal: AbortSignal) => requestJson<T>(target, {signal}));
        const status = await loader(url as string, controller.signal);
        if (controller.signal.aborted) return;
        const changed = status.revision === undefined || status.revision !== revision;
        const terminal = callbacks.current.isTerminal(status);
        try {
          await callbacks.current.onStatus?.(status, changed, controller.signal);
        } catch (cause) {
          // Not handled (e.g. the final detail could not be loaded): keep the
          // latest status visible and retry; never stop on a terminal state
          // whose detail has not arrived.
          if (controller.signal.aborted) return;
          setState({url, status, error: cause instanceof Error ? cause.message : 'Unable to refresh the details.', stopped: false});
          delay = Math.min(maxIntervalMs, delay * 2);
          schedule(delay);
          return;
        }
        if (controller.signal.aborted) return;
        revision = status.revision;
        setState({url, status, error: null, stopped: terminal});
        if (terminal) {done = true; return;}
        // Back off gently while nothing changes; snap back on change.
        delay = changed ? intervalMs : Math.min(maxIntervalMs, Math.round(delay * 1.5));
        schedule(delay);
      } catch (cause) {
        if (controller.signal.aborted) return;
        setState(previous => ({...previous, url, error: cause instanceof Error ? cause.message : 'Unable to read status.'}));
        delay = Math.min(maxIntervalMs, delay * 2);
        schedule(delay);
      } finally {
        running = false;
      }
    }
    const visibility = () => {if (!hidden() && !done) {delay = intervalMs; clearTimeout(timer); void tick();}};
    document.addEventListener('visibilitychange', visibility);
    void tick();
    return () => {controller.abort(); clearTimeout(timer); document.removeEventListener('visibilitychange', visibility);};
  }, [url, intervalMs, maxIntervalMs, maxDurationMs]);
  const current = state.url === url ? state : {status: null, error: null, stopped: !url};
  return {status: current.status as T | null, error: current.error, stopped: current.stopped};
}
