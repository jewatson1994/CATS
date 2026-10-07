/**
 * setTimeout that does not fire while the document is hidden: the callback
 * runs when the delay has elapsed AND the page is visible. Returns a cancel
 * function. Used by polling loops so background tabs make no requests.
 */
export function visibleTimeout(callback: () => void, delayMs: number): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cancelled = false;
  const hidden = () => typeof document !== 'undefined' && document.visibilityState === 'hidden';
  const onVisible = () => {
    if (cancelled || hidden()) return;
    document.removeEventListener('visibilitychange', onVisible);
    callback();
  };
  timer = setTimeout(() => {
    if (cancelled) return;
    if (hidden()) document.addEventListener('visibilitychange', onVisible);
    else callback();
  }, delayMs);
  return () => {cancelled = true; clearTimeout(timer); document.removeEventListener('visibilitychange', onVisible);};
}
