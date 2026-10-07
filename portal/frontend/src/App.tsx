import {lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ComponentType} from 'react';
import {PageControlContext, type PageControl} from './pageControl';
import {ApiError, onMutation, type PageEnvelope, type PageData} from './api';
import {digestText, pageStore, type PageStore} from './pageStore';
import {afterPaint, installPerformanceTools, recordTiming} from './perf';
import {Shell} from './components/Shell';
import {ErrorBoundary} from './components/ErrorBoundary';
import {Page as Home} from './features/home';
import {Page as Login} from './features/login';
import {Page as Dashboard} from './features/dashboard';
import {Page as Password} from './features/password';
import {Page as Appearance} from './features/appearance';
import {Page as Cybersecurity} from './features/cybersecurity';
import {Page as Service} from './features/service';
import {Page as Finding, Watchlist} from './features/finding';
import {Page as ServiceOverview} from './features/service_overview';
import {Page as ServiceActivity} from './features/service_activity';
import {Page as ServiceDependencies} from './features/service-dependencies';
import {Page as ServiceArtifacts} from './features/service-artifacts';

/** Infrequent or administrative pages load as separate local chunks. */
const loaders: Record<string, () => Promise<any>> = {
  './features/admin': () => import('./features/admin'),
  './features/audit': () => import('./features/audit'),
  './features/compliance': () => import('./features/compliance'),
  './features/compliance_frameworks': () => import('./features/compliance_frameworks'),
  './features/configuration': () => import('./features/configuration'),
  './features/dependency_watchlist': () => import('./features/dependency_watchlist'),
  './features/evidence_policy': () => import('./features/evidence_policy'),
  './features/exchange': () => import('./features/exchange'),
  './features/general_policy': () => import('./features/general_policy'),
  './features/patch': () => import('./features/patch'),
  './features/patch_results': () => import('./features/patch_results'),
  './features/poam': () => import('./features/poam'),
  './features/public_results': () => import('./features/public_results'),
  './features/purpose_export_template': () => import('./features/purpose_export_template'),
  './features/remediations': () => import('./features/remediations'),
  './features/self_service': () => import('./features/self_service'),
  './features/service-architecture': () => import('./features/service-architecture'),
  './features/service-validation': () => import('./features/service-validation'),
  './features/service_definitions': () => import('./features/service_definitions'),
  './features/service_history': () => import('./features/service_history'),
  './features/staging': () => import('./features/staging'),
  './features/validators': () => import('./features/validators'),
  './features/workflow_policy': () => import('./features/workflow_policy'),
};
const lazyPage = (module: string, name: string) => lazy(() => loaders[module]().then(loaded => ({default: loaded[name] as ComponentType<{data: PageData}>})));
const Patch = lazyPage('./features/patch', 'Page');
const SelfService = lazyPage('./features/self_service', 'Page');
const PublicResults = lazyPage('./features/public_results', 'Page');
const PatchResults = lazyPage('./features/patch_results', 'Page');
const Poam = lazyPage('./features/poam', 'Page');
const ServicePoam = lazyPage('./features/poam', 'Service');
const PoamEntry = lazyPage('./features/poam', 'Entry');
const ServiceHistory = lazyPage('./features/service_history', 'Page');
const ServiceValidation = lazyPage('./features/service-validation', 'Page');
const ServiceDefinitions = lazyPage('./features/service_definitions', 'Page');
const Exchange = lazyPage('./features/exchange', 'Page');
const PurposeExportTemplate = lazyPage('./features/purpose_export_template', 'Page');
const Remediations = lazyPage('./features/remediations', 'Page');
const ServiceRemediations = lazyPage('./features/remediations', 'Service');
const RemediationReport = lazyPage('./features/remediations', 'Report');
const Requests = lazyPage('./features/remediations', 'Requests');
const ServiceArchitecture = lazyPage('./features/service-architecture', 'Page');
const Admin = lazyPage('./features/admin', 'Page');
const Staging = lazyPage('./features/staging', 'Page');
const Configuration = lazyPage('./features/configuration', 'Page');
const Validators = lazyPage('./features/validators', 'Page');
const Audit = lazyPage('./features/audit', 'Page');
const GeneralPolicy = lazyPage('./features/general_policy', 'Page');
const EvidencePolicy = lazyPage('./features/evidence_policy', 'Page');
const WorkflowPolicy = lazyPage('./features/workflow_policy', 'Page');
const Compliance = lazyPage('./features/compliance', 'Page');
const ComplianceFrameworks = lazyPage('./features/compliance_frameworks', 'Page');
const DependencyWatchlist = lazyPage('./features/dependency_watchlist', 'Page');
/** Fetch every lazy chunk once the browser is idle, so later navigation never waits on one. */
export function preloadPages() {for (const load of Object.values(loaders)) void load().catch(() => {});}

const routes = new Set(['/', '/home', '/login', '/account/password', '/account/appearance', '/scan', '/sbom', '/patch', '/cybersecurity',
  '/poam', '/remediations', '/requests', '/admin', '/admin/staging', '/admin/audit', '/admin/configuration',
  '/admin/validators', '/admin/general-policy', '/admin/evidence-policy', '/admin/workflow-policy', '/admin/compliance',
  '/admin/compliance-frameworks', '/admin/dependency-watchlist']);
/** Only page routes are intercepted. Export, auth and artifact links remain native. */
export const isPageRoute = (path: string) => routes.has(path) || [
  /^\/services\/[^/]+\/(history|definitions|exchange)$/,
  /^\/services\/[^/]+$/, /^\/services\/[^/]+\/(findings|watchlist)\/\d+$/,
  /^\/services\/[^/]+\/remediations\/[^/]+$/, /^\/poam\/services\/[^/]+$/, /^\/poam\/entries\/\d+$/,
  /^\/api\/public\/jobs\/[^/]+\/results\/view$/, /^\/api\/public\/patch-jobs\/[^/]+\/results$/,
  /^\/admin\/(configuration|general-policy)\/export-templates\/(poam|ppsm|assets)$/,
].some(pattern => pattern.test(path));
const pages: Record<string, ComponentType<{data: PageData}>> = {
  home: Home, login: Login, dashboard: Dashboard, password: Password, appearance: Appearance,
  self_service: SelfService, patch: Patch, cybersecurity: Cybersecurity,
  service: Service, service_simplified: Service,
  public_results: PublicResults, patch_results: PatchResults, finding: Finding, watchlist_match: Watchlist,
  poam: Poam, poam_service: ServicePoam, poam_entry: PoamEntry,
  service_overview: ServiceOverview, service_activity: ServiceActivity, service_history: ServiceHistory,
  service_dependencies: ServiceDependencies, service_artifacts: ServiceArtifacts, service_validation: ServiceValidation,
  service_definitions: ServiceDefinitions, exchange: Exchange, purpose_export_template: PurposeExportTemplate,
  remediations: Remediations, service_remediations: ServiceRemediations, remediation_report: RemediationReport, requests: Requests,
  service_architecture: ServiceArchitecture,
  admin: Admin, staging: Staging, configuration: Configuration, validators: Validators, audit: Audit,
  general_policy: GeneralPolicy, evidence_policy: EvidencePolicy, workflow_policy: WorkflowPolicy,
  compliance: Compliance, compliance_frameworks: ComplianceFrameworks, dependency_watchlist: DependencyWatchlist,
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

/** Cached pages younger than this render without a background refresh. */
export const FRESH_MS = 2000;
/** Hover/focus intent before a deliberate prefetch (never on page load). */
const PREFETCH_DELAY_MS = 120;
const PREFETCH_FRESH_MS = 30000;
const MAX_PREFETCHES = 2;
const ACCESS_ERRORS = new Set([401, 403, 404]);


interface View {location: string; envelope: PageEnvelope; generation: number}
const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
const currentLocation = () => window.location.pathname + window.location.search;

export function App({initial, store = pageStore}: {initial: PageEnvelope | null; store?: PageStore}) {
  const [location, setLocation] = useState(currentLocation);
  const generation = useRef(0);
  const [view, setView] = useState<View | null>(initial ? {location, envelope: initial, generation: 0} : null);
  const [error, setError] = useState<{location: string; message: string} | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const locationRef = useRef(location);
  const scrolls = useRef(new Map<string, number>());
  const popped = useRef(false);
  const handledAttempt = useRef(0);

  useEffect(() => {
    installPerformanceTools();
    const idle = (window as any).requestIdleCallback as ((callback: () => void, options?: {timeout: number}) => number) | undefined;
    const preload = () => preloadPages();
    const handle = idle ? idle(preload, {timeout: 4000}) : window.setTimeout(preload, 1500);
    if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual';
    if (initial) {
      const text = JSON.stringify(initial);
      store.put(location, {envelope: initial, bytes: text.length, digest: digestText(text), fetchedAt: Date.now()});
    }
    const stop = onMutation(() => store.invalidate());
    return () => {stop(); if (idle) (window as any).cancelIdleCallback?.(handle); else window.clearTimeout(handle);};
    // Bootstrap is read once per document.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const go = (pop: boolean) => {
      scrolls.current.set(locationRef.current, window.scrollY);
      popped.current = pop;
      setLocation(currentLocation());
    };
    const popstate = () => go(true);
    const click = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const link = (event.target as HTMLElement).closest('a');
      if (!link || link.hasAttribute('download') || link.target || link.getAttribute('aria-disabled') === 'true') return;
      const url = new URL(link.href, window.location.href);
      if (url.origin !== window.location.origin || !isPageRoute(url.pathname) || url.hash) return;
      event.preventDefault(); window.history.pushState(null, '', url.pathname + url.search); go(false);
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    let active = 0;
    const intent = (event: Event) => {
      const link = (event.target as HTMLElement | null)?.closest?.('a[data-prefetch]') as HTMLAnchorElement | null;
      if (!link) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        const url = new URL(link.href, window.location.href);
        const target = url.pathname + url.search;
        if (url.origin !== window.location.origin || !isPageRoute(url.pathname) || target === locationRef.current) return;
        const cached = store.peek(target);
        if ((cached && Date.now() - cached.fetchedAt < PREFETCH_FRESH_MS) || store.isLoading(target) || active >= MAX_PREFETCHES) return;
        active += 1;
        const started = now();
        store.load(target).then(page => recordTiming({location: target, source: 'prefetch', started, usefulMs: null,
          fetchMs: now() - started, bytes: page.bytes})).catch(() => {}).finally(() => {active -= 1;});
      }, PREFETCH_DELAY_MS);
    };
    const cancel = () => clearTimeout(timer);
    window.addEventListener('popstate', popstate); document.addEventListener('click', click);
    document.addEventListener('pointerover', intent); document.addEventListener('focusin', intent);
    document.addEventListener('pointerout', cancel);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('popstate', popstate); document.removeEventListener('click', click);
      document.removeEventListener('pointerover', intent); document.removeEventListener('focusin', intent);
      document.removeEventListener('pointerout', cancel);
    };
  }, [store]);

  const show = useCallback((target: string, envelope: PageEnvelope) => {
    generation.current += 1;
    setView({location: target, envelope, generation: generation.current});
  }, []);

  useEffect(() => {
    locationRef.current = location;
    const forced = attempt !== handledAttempt.current;
    handledAttempt.current = attempt;
    if (!forced && view?.location === location) return;
    const controller = new AbortController();
    const started = now();
    const pop = popped.current;
    popped.current = false;
    const placeScroll = () => window.scrollTo(0, pop ? scrolls.current.get(location) || 0 : 0);
    setError(null); setNotice(null);
    const valid = (envelope: PageEnvelope) => envelope.schemaVersion === 1 && envelope.page in pages;
    const cached = forced ? undefined : store.get(location);
    if (cached && valid(cached.envelope)) {
      show(location, cached.envelope);
      afterPaint(() => {placeScroll(); recordTiming({location, source: 'cache', started, usefulMs: now() - started, fetchMs: null, bytes: cached.bytes});});
      if (Date.now() - cached.fetchedAt < FRESH_MS) return () => controller.abort();
      const refreshStarted = now();
      store.load(location, controller.signal).then(page => {
        if (controller.signal.aborted) return;
        const changed = page.digest !== cached.digest;
        if (changed && valid(page.envelope)) show(location, page.envelope);
        recordTiming({location, source: 'revalidate', started: refreshStarted, usefulMs: null, fetchMs: now() - refreshStarted, bytes: page.bytes, changed});
      }).catch(cause => {
        if (controller.signal.aborted) return;
        if (cause instanceof ApiError && ACCESS_ERRORS.has(cause.status)) {
          // Access changed: never keep showing the saved copy.
          store.delete(location);
          setView(null);
          setError({location, message: cause.message});
        } else {
          setNotice('Showing the most recently loaded copy; it could not be refreshed.');
        }
      });
      return () => controller.abort();
    }
    store.load(location, controller.signal).then(page => {
      if (controller.signal.aborted) return;
      if (!valid(page.envelope)) throw new Error('This page is not available in the frontend.');
      show(location, page.envelope);
      afterPaint(() => {placeScroll(); recordTiming({location, source: 'network', started, usefulMs: now() - started, fetchMs: null, bytes: page.bytes});});
    }).catch(cause => {
      if (!controller.signal.aborted) setError({location, message: cause instanceof Error ? cause.message : 'Unable to load the page.'});
    });
    return () => controller.abort();
    // The page result must not restart its own request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location, attempt]);

  const control = useMemo<PageControl>(() => ({
    refresh: async () => {
      const target = locationRef.current;
      const before = store.peek(target);
      const page = await store.load(target);
      if (locationRef.current === target && page.envelope.schemaVersion === 1 && page.envelope.page in pages
          && page.digest !== before?.digest) show(target, page.envelope);
    },
  }), [store, show]);

  const current = view?.location === location ? view.envelope : null;
  const failed = error?.location === location ? error.message : null;
  // An uncached navigation keeps the previous page on screen (inert, dimmed)
  // until the new one arrives, instead of blanking the workspace.
  const previous = !current && !failed && view ? view : null;
  const pageTitle = current ? `${current.page.replaceAll('_', ' ')} · CATS` : 'CATS';
  useEffect(() => {document.title = pageTitle;}, [pageTitle]);
  const shown = current ? view : previous;
  const Page = shown ? pages[shown.envelope.page] : null;
  return <Shell data={(current || previous?.envelope)?.data || {}}>
    <PageControlContext.Provider value={control}>
      {notice && current && <p className="page-refresh-notice" role="status">{notice}</p>}
      {shown && Page && !failed ? <div className={previous ? 'page-navigating' : undefined} aria-busy={previous ? true : undefined}
        inert={previous ? true : undefined}>
        {previous && <p className="sr-only" role="status">Loading page…</p>}
        <ErrorBoundary key={`${shown.location}#${shown.generation}`}><Suspense fallback={<section className="panel padded" aria-busy="true"><p role="status">Loading page…</p></section>}><Page data={shown.envelope.data}/></Suspense></ErrorBoundary>
      </div> : <section className="panel padded" aria-busy={!failed}>
        {failed ? <div role="alert"><h1>Unable to load page</h1><p>{failed}</p><button onClick={() => setAttempt(value => value + 1)}>Retry</button></div>
          : <p role="status">Loading page…</p>}
      </section>}
    </PageControlContext.Provider>
  </Shell>;
}
