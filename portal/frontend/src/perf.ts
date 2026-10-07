/**
 * Local navigation timings. Kept in memory only (never sent anywhere) and
 * readable from the browser console with `catsPerformance()`. Recording is
 * always on and bounded; long-task observation is opt-in via
 * `localStorage.setItem('cats.performance', '1')` because it costs a little.
 */
export interface NavigationTiming {
  location: string;
  source: 'cache' | 'network' | 'revalidate' | 'prefetch';
  started: number;
  usefulMs: number | null;
  fetchMs: number | null;
  bytes: number | null;
  changed?: boolean;
}

const LIMIT = 100;
const timings: NavigationTiming[] = [];
let longTasks = 0;

export function recordTiming(timing: NavigationTiming) {
  timings.push(timing);
  if (timings.length > LIMIT) timings.splice(0, timings.length - LIMIT);
}

/** Resolve after the browser has painted the committed update. */
export function afterPaint(callback: () => void) {
  if (typeof requestAnimationFrame !== 'function') {setTimeout(callback, 0); return;}
  requestAnimationFrame(() => setTimeout(callback, 0));
}

function enabled() {
  try {return window.localStorage?.getItem('cats.performance') === '1';} catch {return false;}
}

export function installPerformanceTools() {
  (window as any).catsPerformance = () => ({timings: timings.slice(), longTasks});
  if (!enabled() || typeof PerformanceObserver !== 'function') return;
  try {
    new PerformanceObserver(list => {longTasks += list.getEntries().length;}).observe({type: 'longtask', buffered: true});
  } catch {/* Unsupported entry type. */}
}
