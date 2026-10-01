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
import {Page as PublicResults} from './features/public_results';
import {Page as PatchResults} from './features/patch_results';
import {Page as Finding, Watchlist} from './features/finding';
import {Page as Poam, Service as ServicePoam, Entry as PoamEntry} from './features/poam';
import {Page as ServiceOverview} from './features/service_overview';
import {Page as ServiceActivity} from './features/service_activity';
import {Page as ServiceHistory} from './features/service_history';
import {Page as ServiceDependencies} from './features/service-dependencies';
import {Page as ServiceArtifacts} from './features/service-artifacts';
import {Page as ServiceValidation} from './features/service-validation';
import {Page as ServiceDefinitions} from './features/service_definitions';
import {Page as Exchange} from './features/exchange';
import {Page as PurposeExportTemplate} from './features/purpose_export_template';
import {Page as Remediations, Service as ServiceRemediations, Report as RemediationReport, Requests} from './features/remediations';
import {Page as ServiceArchitecture} from './features/service-architecture';
import {Page as Admin} from './features/admin';
import {Page as Staging} from './features/staging';
import {Page as Configuration} from './features/configuration';
import {Page as Audit} from './features/audit';
import {Page as GeneralPolicy} from './features/general_policy';
import {Page as EvidencePolicy} from './features/evidence_policy';
import {Page as WorkflowPolicy} from './features/workflow_policy';
import {Page as Compliance} from './features/compliance';
import {Page as ComplianceFrameworks} from './features/compliance_frameworks';
import {Page as DependencyWatchlist} from './features/dependency_watchlist';

const routes = new Set(['/', '/home', '/login', '/account/password', '/account/appearance', '/scan', '/sbom', '/patch', '/cybersecurity',
  '/poam', '/remediations', '/requests', '/admin', '/admin/staging', '/admin/audit', '/admin/configuration',
  '/admin/general-policy', '/admin/evidence-policy', '/admin/workflow-policy', '/admin/compliance',
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
  admin: Admin, staging: Staging, configuration: Configuration, audit: Audit,
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
      if (url.origin !== window.location.origin || !isPageRoute(url.pathname) || url.hash) return;
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
  const pageTitle = current ? `${current.page.replaceAll('_', ' ')} · CATS` : 'CATS';
  useEffect(() => {document.title = pageTitle;}, [pageTitle]);
  if (!current) return <main aria-busy={!error}>{error ? <section role="alert"><h1>Unable to load page</h1>
    <p>{error}</p><button onClick={() => setAttempt(value => value + 1)}>Retry</button></section> : <p role="status">Loading CATS…</p>}</main>;
  const Page = pages[current.page];
  return <Shell data={current.data}><ErrorBoundary key={location}><Page data={current.data}/></ErrorBoundary></Shell>;
}
