import {useId, useMemo, useState} from 'react';

export interface TuningDiagnostic {
  code?: string; message?: string; path?: string; root_id?: string; component_id?: string;
  component_name?: string; value_paths?: string[]; renderer?: string; reason?: string;
  severity?: string; blocking?: boolean; occurrences?: number;
}
export interface TuningRoot {id: string; path: string; chart_name?: string; chart_version?: string; chart_type?: string; state?: string; technology: string; completeness?: unknown}
export interface TuningNode {id: string; name: string; kind: string; root_id?: string; state?: string; provenance?: unknown}
export interface TuningComponent {
  id: string; label: string; path: string; technology: string; root_id?: string;
  values_origin?: unknown; selected_values?: string[]; values_yaml?: string;
}
export interface TuningInventory {
  roots: TuningRoot[]; nodes: TuningNode[];
  images: {reference: string; root_id?: string; component_id?: string; provenance?: unknown}[];
  edges?: unknown[]; diagnostics?: TuningDiagnostic[]; candidate_values_files?: string[];
  configurable_components?: TuningComponent[]; completeness?: unknown;
}
export interface TuningIssue {
  key: string; code: string; cause: string; nextAction: string; blocking: boolean;
  occurrences: number; paths: string[]; valuePaths: string[]; diagnostics: TuningDiagnostic[];
}
export interface TuningResource {
  id: string; label: string; path: string; technology: string; rootId?: string;
  component?: TuningComponent; issues: TuningIssue[]; imageCount: number;
  needsAttention: boolean; configurationOnly: boolean;
}
export interface DiscoveryTuningProps {
  inventory: TuningInventory; selectedValues: string[]; componentValues: Record<string, string[]>;
  componentOverrides: Record<string, string>; acknowledgeNonSecret: boolean; busy: boolean;
  onValuesChange: (paths: string[]) => void;
  onComponentValuesChange: (id: string, paths: string[]) => void;
  onComponentOverrideChange: (id: string, yaml: string) => void;
  onAcknowledgeNonSecret: (value: boolean) => void;
  onRender: () => void; onSupplyFiles?: (path?: string) => void;
}

const informationalCodes = new Set(['helm_library_chart', 'helm_dependency_disabled', 'custom_resource_configuration', 'source_values_parser_limitation']);
const normalizePath = (path: string) => path.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/$/, '');
const hasOwn = (object: object, key: string) => Object.prototype.hasOwnProperty.call(object, key);
const readable = (value: string) => value.replace(/_/g, ' ');
const blocks = (diagnostic: TuningDiagnostic) => diagnostic.blocking !== false && diagnostic.severity !== 'info' && !informationalCodes.has(diagnostic.code || '');

export function nextActionForDiagnostic(diagnostic: TuningDiagnostic): string {
  const code = diagnostic.code || '';
  if (!blocks(diagnostic)) return 'No correction is required for this notice. Review the evidence if needed.';
  if (/secret/.test(code)) return 'Use an existing secret reference or a non-secret configuration file. Keep secret contents outside this editor.';
  if (code === 'worker_isolation_unavailable') return 'Ask an administrator to repair the discovery worker’s host isolation, then render again.';
  if (/renderer_unavailable/.test(code) || diagnostic.reason === 'helm_unavailable') return 'Ask an administrator to enable the required renderer, then render again.';
  if (diagnostic.reason === 'artifact_retrieval_failed') return 'Check the chart source and version, or supply the required local chart, then render again.';
  if (diagnostic.reason === 'missing_resource' || diagnostic.reason === 'patch_target_missing') return 'Check the referenced resource path and include its source files, then render again.';
  if (/missing_|unavailable|requires_local_artifact|source.*unresolved|chart.*unresolved/.test(code)) return 'Supply the referenced file or local chart, check its path, then render again.';
  if (/image/.test(code) && !/images_not_verified/.test(code)) return 'Set a concrete image repository and tag in the source configuration or non-secret values, then render again.';
  if (/render_failed|render_blocked_by_values|values|inline/.test(code)) return diagnostic.renderer === 'kustomize'
    ? 'Check the overlay and include its referenced files, then render again.'
    : 'Choose the values for this deployment or edit its non-secret YAML, then render again.';
  if (/dependency/.test(code)) return 'Review the dependency and its enabled condition. Supply the required source if it should deploy, then render again.';
  if (/custom_resource|not_evaluated|unsupported/.test(code)) return 'Review this resource’s source and controller behavior. Supply supported workload manifests when available; retain unresolved evidence until verified.';
  if (/ambiguous/.test(code)) return 'Review the conflicting source definitions and select the intended configuration before rendering again.';
  return 'Review the source evidence for this resource, correct its configuration or supply missing files, then render again.';
}

/** Keep every diagnostic attached to one owner, while folding repeated notices into a single issue. */
export function buildTuningResources(inventory: TuningInventory): TuningResource[] {
  const resources = new Map<string, TuningResource>();
  const roots = new Map(inventory.roots.map(root => [root.id, root]));
  const nodes = new Map(inventory.nodes.map(node => [node.id, node]));
  for (const root of inventory.roots) resources.set(root.id, {
    id: root.id, label: root.chart_name || root.path || root.id, path: root.path,
    technology: root.technology, rootId: root.id, issues: [], imageCount: 0, needsAttention: false, configurationOnly: false,
  });
  for (const component of inventory.configurable_components || []) {
    const existing = resources.get(component.id);
    resources.set(component.id, {...existing, id: component.id, label: component.label, path: component.path,
      technology: component.technology, rootId: component.root_id || existing?.rootId || nodes.get(component.id)?.root_id,
      component, issues: existing?.issues || [], imageCount: 0, needsAttention: false, configurationOnly: false});
  }
  const parents = new Map<string, string>();
  for (const edge of inventory.edges || []) {
    if (edge && typeof edge === 'object' && 'source' in edge && 'target' in edge && 'kind' in edge
      && edge.kind === 'declares' && typeof edge.source === 'string' && typeof edge.target === 'string') parents.set(edge.target, edge.source);
  }
  const owningResource = (id?: string): TuningResource | undefined => {
    const visited = new Set<string>();
    while (id && !visited.has(id)) {
      if (resources.has(id)) return resources.get(id);
      visited.add(id); id = parents.get(id);
    }
  };
  const pathOwners = [...resources.values()].filter(resource => resource.path).sort((a, b) => b.path.length - a.path.length);
  const byPath = (path: string) => pathOwners.find(resource => {
    const source = normalizePath(resource.path), target = normalizePath(path);
    if (source === target) return true;
    const directory = /\.(?:ya?ml|json)$/i.test(source) ? (source.includes('/') ? source.slice(0, source.lastIndexOf('/')) : '') : source;
    return directory && target.startsWith(directory + '/');
  });
  const issueMaps = new Map<string, Map<string, TuningIssue>>();
  const addDiagnostic = (resource: TuningResource, diagnostic: TuningDiagnostic) => {
    const code = diagnostic.code || 'unresolved_configuration';
    const cause = diagnostic.message?.trim() || readable(code) + '.';
    const blocking = blocks(diagnostic);
    const key = JSON.stringify([code, cause, diagnostic.reason, diagnostic.renderer, blocking, [...(diagnostic.value_paths || [])].sort()]);
    let issues = issueMaps.get(resource.id);
    if (!issues) {issues = new Map(); issueMaps.set(resource.id, issues);}
    let issue = issues.get(key);
    if (!issue) {
      issue = {key, code, cause, nextAction: nextActionForDiagnostic(diagnostic), blocking,
        occurrences: 0, paths: [], valuePaths: diagnostic.value_paths || [], diagnostics: []};
      issues.set(key, issue); resource.issues.push(issue);
    }
    issue.occurrences += Math.max(1, diagnostic.occurrences || 1);
    if (diagnostic.path && !issue.paths.includes(diagnostic.path)) issue.paths.push(diagnostic.path);
    issue.diagnostics.push(diagnostic);
    resource.needsAttention ||= blocking;
  };
  for (const diagnostic of inventory.diagnostics || []) {
    let resource = owningResource(diagnostic.component_id);
    if (!resource && diagnostic.component_id && (diagnostic.component_name || nodes.has(diagnostic.component_id))) {
      const node = nodes.get(diagnostic.component_id);
      resource = {id: diagnostic.component_id, label: diagnostic.component_name || node!.name,
        path: diagnostic.path || '', technology: node?.kind || 'Component', rootId: diagnostic.root_id || node?.root_id,
        issues: [], imageCount: 0, needsAttention: false, configurationOnly: false};
      resources.set(resource.id, resource);
    }
    resource ||= diagnostic.root_id ? resources.get(diagnostic.root_id) : undefined;
    resource ||= diagnostic.component_name ? [...resources.values()].find(item => item.label === diagnostic.component_name) : undefined;
    resource ||= diagnostic.path ? byPath(diagnostic.path) : undefined;
    if (!resource) {
      resource = resources.get('__source__');
      if (!resource) {
        resource = {id: '__source__', label: 'Source files', path: '', technology: 'Source', issues: [], imageCount: 0, needsAttention: false, configurationOnly: false};
        resources.set(resource.id, resource);
      }
    }
    addDiagnostic(resource, diagnostic);
  }
  for (const image of inventory.images) {
    const resource = owningResource(image.component_id) || (image.root_id ? resources.get(image.root_id) : undefined);
    if (resource) resource.imageCount++;
  }
  // Older runs can report partial status without emitting a diagnostic. Keep those visible.
  const rootsWithIssues = new Set([...resources.values()].filter(item => item.needsAttention).map(item => item.rootId));
  for (const resource of resources.values()) {
    const root = roots.get(resource.id);
    const node = nodes.get(resource.id);
    const status = typeof root?.completeness === 'object' && root.completeness !== null && 'status' in root.completeness
      ? root.completeness.status : root?.completeness;
    const isLibrary = root?.chart_type === 'library' || root?.state === 'library';
    if (!resource.issues.length && !isLibrary && ((root && ['partial', 'blocked', 'invalid', 'unresolved'].includes(String(status)) && !rootsWithIssues.has(root.id))
      || (!root && node?.state === 'unresolved'))) {
      addDiagnostic(resource, {code: 'unresolved_configuration', message: 'This resource has unresolved configuration. Review its source evidence.', blocking: true});
    }
    resource.configurationOnly = !resource.needsAttention && resource.imageCount === 0;
    resource.issues.sort((a, b) => Number(b.blocking) - Number(a.blocking));
  }
  const componentParents = new Set([...resources.values()].filter(resource => resource.component && resource.rootId !== resource.id).map(resource => resource.rootId));
  return [...resources.values()]
    .filter(resource => resource.component || !componentParents.has(resource.id) || resource.issues.length > 0 || resource.imageCount > 0)
    .sort((a, b) => Number(b.needsAttention) - Number(a.needsAttention) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
}

function ValuesOrder({label, paths, candidates, onChange, busy}: {
  label: string; paths: string[]; candidates: string[]; onChange: (paths: string[]) => void; busy: boolean;
}) {
  const [search, setSearch] = useState('');
  const available = candidates.filter(path => !paths.includes(path) && path.toLowerCase().includes(search.toLowerCase()));
  const move = (index: number, direction: number) => {
    const next = [...paths]; [next[index], next[index + direction]] = [next[index + direction], next[index]]; onChange(next);
  };
  return <div className="discovery-tuning-values">
    <div className="discovery-tuning-file-picker"><label>Find values for {label}<input type="search" value={search} disabled={busy} placeholder="File name, environment or directory" onChange={event => setSearch(event.target.value)}/></label>
      <label>Add values for {label}<select value="" disabled={busy} onChange={event => {if (event.target.value) onChange([...paths, event.target.value]);}}>
        <option value="">Choose a values file</option>{available.map(path => <option key={path} value={path}>{path}</option>)}
      </select></label></div>
    <p className="muted">{paths.length ? 'Files apply in this order; later values win.' : 'No additional values files selected.'}</p>
    {paths.length > 0 && <ol className="discovery-values-order">{paths.map((path, index) => <li key={path}><div className="discovery-values-path"><code>{path}</code>
      {!candidates.includes(path) && <p className="discovery-tuning-missing">Not listed among suggested values files. Check its path if rendering reports it missing.</p>}</div>
      <span className="discovery-values-actions"><button type="button" className="secondary-button" disabled={busy || index === 0} aria-label={`Move ${path} earlier for ${label}`} onClick={() => move(index, -1)}>Earlier</button>
        <button type="button" className="secondary-button" disabled={busy || index === paths.length - 1} aria-label={`Move ${path} later for ${label}`} onClick={() => move(index, 1)}>Later</button>
        <button type="button" className="secondary-button" disabled={busy} aria-label={`Remove ${path} for ${label}`} onClick={() => onChange(paths.filter((_, i) => i !== index))}>Remove</button></span>
    </li>)}</ol>}
  </div>;
}

function ResourceEditor({resource, editorId, ...props}: DiscoveryTuningProps & {resource: TuningResource; editorId: string}) {
  const [allIssues, setAllIssues] = useState(false);
  const component = resource.component;
  const configuredPaths = component ? (hasOwn(props.componentValues, component.id) ? props.componentValues[component.id] : component.selected_values || []) : [];
  const paths = Array.isArray(configuredPaths) ? configuredPaths.filter(path => typeof path === 'string') : [];
  const configuredYaml = component ? (hasOwn(props.componentOverrides, component.id) ? props.componentOverrides[component.id] : component.values_yaml || '') : '';
  const yaml = typeof configuredYaml === 'string' ? configuredYaml : '';
  const issues = allIssues ? resource.issues : resource.issues.slice(0, 6);
  return <div className="discovery-tuning-editor" id={editorId}>
    {issues.length > 0 && <ul className="discovery-tuning-issues">{issues.map(issue => <li key={issue.key}>
      <p><strong>{issue.cause}</strong>{issue.occurrences > 1 && <span className="badge">{issue.occurrences} occurrences</span>}</p>
      <p className="discovery-tuning-next">{issue.nextAction}</p>
      {issue.valuePaths.length > 0 && <p>Values to review: {issue.valuePaths.map((path, index) => <span key={path}>{index > 0 && ', '}<code>{path}</code></span>)}</p>}
      <details><summary>Issue details{issue.paths.length > 1 ? ` · ${issue.paths.length} source paths` : ''}</summary><pre>{JSON.stringify(issue.diagnostics, null, 2)}</pre></details>
    </li>)}</ul>}
    {!allIssues && resource.issues.length > issues.length && <button type="button" className="secondary-button" onClick={() => setAllIssues(true)}>Show all {resource.issues.length} issues</button>}
    {component ? <>
      <p className="muted">Base configuration: {Array.isArray(component.values_origin) ? component.values_origin.join(' → ') : typeof component.values_origin === 'string' ? component.values_origin : 'Chart defaults'}. Selected files apply next; the YAML below applies last.</p>
      <ValuesOrder label={resource.label} paths={paths} candidates={props.inventory.candidate_values_files || []} busy={props.busy} onChange={next => props.onComponentValuesChange(component.id, next)}/>
      <label>Non-secret YAML for {resource.label}<textarea className="discovery-tuning-yaml" rows={7} spellCheck={false} value={yaml} disabled={props.busy} aria-describedby={`${editorId}-yaml-help`} onChange={event => props.onComponentOverrideChange(component.id, event.target.value)} placeholder={'# Values for this component only\nimage:\n  tag: stable'}/></label>
      <p id={`${editorId}-yaml-help`} className="muted discovery-tuning-yaml-help">Enter a YAML mapping. Use references for secrets; keep passwords, tokens and private keys out. Clear this field to remove its override.</p>
    </> : <p className="muted">{resource.needsAttention ? 'Update this resource’s source file or supply its missing dependencies. Values editing is available for configurable Helm components.' : 'No correction is required for this resource. Its source evidence remains available in the inventory below.'}</p>}
    <div className="discovery-actions">{props.onSupplyFiles && resource.needsAttention && <button type="button" className="secondary-button" disabled={props.busy} onClick={() => props.onSupplyFiles?.(resource.issues.find(issue => issue.blocking)?.paths[0] || resource.path)}>Supply files for this resource</button>}</div>
  </div>;
}

export function DiscoveryTuning(props: DiscoveryTuningProps) {
  const listId = useId();
  const resources = useMemo(() => buildTuningResources(props.inventory), [props.inventory]);
  const [filter, setFilter] = useState<'attention' | 'all' | 'ready'>('attention');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const attention = resources.filter(resource => resource.needsAttention).length;
  const matches = resources.filter(resource => (filter === 'all' || resource.needsAttention === (filter === 'attention'))
    && [resource.label, resource.path, resource.technology, ...resource.issues.flatMap(issue => [issue.cause, issue.code, ...issue.paths, ...issue.valuePaths])].join(' ').toLowerCase().includes(search.trim().toLowerCase()));
  const pageSize = 25, currentPage = Math.min(page, Math.max(0, Math.ceil(matches.length / pageSize) - 1));
  const visible = matches.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const hasOverrides = Object.values(props.componentOverrides).some(value => typeof value === 'string' && value.trim())
    || (props.inventory.configurable_components || []).some(component => !hasOwn(props.componentOverrides, component.id) && Boolean(component.values_yaml?.trim()));
  return <section className="discovery-tuning" aria-label="Resource tuning">
    <div className="discovery-tuning-heading"><div><h3>Tune discovery</h3><p className="muted">Resolve each resource, then render the updated configuration. Earlier inventory stays available.</p></div>
      <span className={attention ? 'discovery-tuning-counter attention' : 'discovery-tuning-counter'} role="status">{attention} unresolved {attention === 1 ? 'resource' : 'resources'}</span></div>
    <div className="discovery-tuning-toolbar"><div className="discovery-tuning-filters" role="group" aria-label="Filter resources">{([
      ['attention', 'Needs attention', attention], ['all', 'All', resources.length], ['ready', 'Ready', resources.length - attention],
    ] as const).map(([value, label, count]) => <button key={value} type="button" className="secondary-button" aria-pressed={filter === value} onClick={() => {setFilter(value); setPage(0);}}>{label} ({count})</button>)}</div>
      <label>Find a resource<input type="search" value={search} placeholder="Name, path or issue" onChange={event => {setSearch(event.target.value); setPage(0);}}/></label></div>
    <div className="discovery-tuning-list">{visible.map((resource, index) => {
      const issueCount = resource.issues.filter(issue => issue.blocking).length;
      const isOpen = expanded === resource.id;
      const rowId = `${listId}-${currentPage * pageSize + index}`;
      return <article className="discovery-tuning-resource" key={resource.id}>
        <button type="button" className="discovery-tuning-row" aria-expanded={isOpen} aria-label={`${isOpen ? 'Close' : 'Tune'} ${resource.label}`} aria-describedby={`${rowId}-path ${rowId}-state ${rowId}-images${resource.needsAttention ? ` ${rowId}-cause` : ''}`} aria-controls={isOpen ? `${rowId}-editor` : undefined} onClick={() => setExpanded(isOpen ? null : resource.id)}>
          <span className="discovery-tuning-chevron" aria-hidden="true">{isOpen ? '−' : '+'}</span>
          <span className="discovery-tuning-identity"><strong>{resource.label}</strong><span id={`${rowId}-path`}>{resource.path || 'Discovery source'}</span>{resource.needsAttention && <span className="discovery-tuning-cause" id={`${rowId}-cause`}>{resource.issues.find(issue => issue.blocking)?.cause}</span>}</span>
          <span className="discovery-tuning-technology">{resource.technology}</span><span id={`${rowId}-state`} className={resource.needsAttention ? 'discovery-tuning-state attention' : 'discovery-tuning-state'}>{resource.needsAttention ? `${issueCount} ${issueCount === 1 ? 'issue' : 'issues'}` : resource.configurationOnly ? 'Configuration only' : 'Ready'}</span>
          <span className="discovery-tuning-image-count" id={`${rowId}-images`}>{resource.imageCount} {resource.imageCount === 1 ? 'image' : 'images'}</span>
        </button>
        {isOpen && <ResourceEditor key={resource.id} {...props} resource={resource} editorId={`${rowId}-editor`}/>}
      </article>;
    })}</div>
    {matches.length === 0 && <p className="discovery-tuning-empty" role="status">{search ? 'No resources match this search.' : filter === 'attention' ? 'No unresolved resources. Open Ready or All to review configuration.' : 'No resources in this view.'}</p>}
    {matches.length > pageSize && <nav className="discovery-tuning-pagination" aria-label="Resource pages"><span aria-live="polite" aria-atomic="true">{currentPage * pageSize + 1}–{Math.min((currentPage + 1) * pageSize, matches.length)} of {matches.length} resources</span><button type="button" className="secondary-button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous resources</button><button type="button" className="secondary-button" disabled={(currentPage + 1) * pageSize >= matches.length} onClick={() => setPage(currentPage + 1)}>Next resources</button></nav>}
    <details className="discovery-tuning-shared"><summary>Shared values files{props.selectedValues.length > 0 ? ` (${props.selectedValues.length})` : ''}</summary><p className="muted">Chart defaults are already loaded. These files apply across the discovery in the order shown. Choose component values above for a narrower change.</p>
      <ValuesOrder label="all resources" paths={props.selectedValues} candidates={props.inventory.candidate_values_files || []} onChange={props.onValuesChange} busy={props.busy}/></details>
    {hasOverrides && <label className="discovery-root-choice discovery-tuning-acknowledge"><input type="checkbox" checked={props.acknowledgeNonSecret} disabled={props.busy} onChange={event => props.onAcknowledgeNonSecret(event.target.checked)}/>These overrides contain no passwords, tokens, private keys or other secrets.</label>}
    <div className="discovery-tuning-render"><button type="button" disabled={props.busy || (hasOverrides && !props.acknowledgeNonSecret)} onClick={props.onRender}>{props.busy ? 'Rendering…' : 'Render updated configuration'}</button><span className="muted">Rechecks the updated values and supplied files. Unchanged supported renders can be reused.</span></div>
  </section>;
}
