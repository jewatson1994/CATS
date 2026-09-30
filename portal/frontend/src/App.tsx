import {useEffect, useState, type ComponentType} from 'react';
import {PAGE_MEDIA_TYPE, requestJson, type PageEnvelope, type PageData} from './api';
import {Shell} from './components/Shell';
import {ErrorBoundary} from './components/ErrorBoundary';
import {Page as Home} from './features/home';
import {Page as Login} from './features/login';
import {Page as Dashboard} from './features/dashboard';
import {Page as Password} from './features/password';
import {Page as Appearance} from './features/appearance';
import {Page as SelfService} from './features/self_service';
import {Page as Patch} from './features/patch';
import {Page as Cybersecurity} from './features/cybersecurity';
import {Page as Service} from './features/service';

const routes = new Set(['/', '/home', '/login', '/account/password', '/account/appearance', '/scan', '/sbom', '/patch', '/cybersecurity']);
const pages: Record<string, ComponentType<{data: PageData}>> = {
  home: Home, login: Login, dashboard: Dashboard, password: Password, appearance: Appearance,
  self_service: SelfService, patch: Patch, cybersecurity: Cybersecurity,
  service: Service, service_simplified: Service,
  request_error: ({data}) => <section className="panel padded" role="alert"><h1>Request could not be completed</h1>
    <p>{data.detail}</p><a href={data.home_url || '/'}>Return to CATS</a></section>,
  boozled: ({data}) => <section className="panel padded" role="alert"><h1>Something went wrong</h1>
    <p>Please try again.</p><a href={data.home_url || '/'}>Return to CATS</a></section>,
};

export function readBootstrap(): PageEnvelope | null {
  const node = document.getElementById('cats-bootstrap');
  if (!node?.textContent) return null;
  try {
    const value: PageEnvelope = JSON.parse(node.textContent);
    return value.schemaVersion === 1 && value.page in pages ? value : null;
  } catch {return null;}
}

export function App({initial}: {initial: PageEnvelope | null}) {
  const [location, setLocation] = useState(window.location.pathname + window.location.search);
  const [page, setPage] = useState<{location: string; envelope: PageEnvelope} | null>(initial ? {location, envelope: initial} : null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const navigate = () => setLocation(window.location.pathname + window.location.search);
    const click = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const link = (event.target as HTMLElement).closest('a');
      if (!link || link.hasAttribute('download') || link.target || link.getAttribute('aria-disabled') === 'true') return;
      const url = new URL(link.href, window.location.href);
      if (url.origin !== window.location.origin || !routes.has(url.pathname) || url.hash) return;
      event.preventDefault(); window.history.pushState(null, '', url.pathname + url.search); navigate();
    };
    window.addEventListener('popstate', navigate); document.addEventListener('click', click);
    return () => {window.removeEventListener('popstate', navigate); document.removeEventListener('click', click);};
  }, []);
  useEffect(() => {
    if (page?.location === location && attempt === 0) return;
    const controller = new AbortController();
    setError(null);
    requestJson<PageEnvelope>(location, {signal: controller.signal, headers: {Accept: PAGE_MEDIA_TYPE}})
      .then(envelope => {
        if (controller.signal.aborted) return;
        if (envelope.schemaVersion !== 1 || !(envelope.page in pages)) throw new Error('This page is not available in the frontend.');
        setPage({location, envelope}); window.scrollTo(0, 0);
      }).catch(cause => {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Unable to load the page.');});
    return () => controller.abort();
    // The page result must not restart its own request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location, attempt]);
  const current = page?.location === location ? page.envelope : null;
  useEffect(() => {document.title = current ? `${current.page.replaceAll('_', ' ')} · CATS` : 'CATS';}, [current?.page]);
  if (!current) return <main aria-busy={!error}>{error ? <section role="alert"><h1>Unable to load page</h1>
    <p>{error}</p><button onClick={() => setAttempt(value => value + 1)}>Retry</button></section> : <p role="status">Loading CATS…</p>}</main>;
  const Page = pages[current.page];
  return <Shell data={current.data}><ErrorBoundary key={location}><Page data={current.data}/></ErrorBoundary></Shell>;
}
