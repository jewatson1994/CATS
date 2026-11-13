import {useEffect, useState, type FormEvent} from 'react';
import {requestJson} from '../api';
import {useServiceReadOnly} from '../operatingMode';
import '../styles/service-distributions.css';

interface ChartIdentityData {
  id: string; label: string; source_path: string; version?: string; reference?: string;
}
interface HelmDependency extends ChartIdentityData {
  enabled?: boolean | null; state: string; declared_version?: string; condition?: string | null; tags?: string[];
  dependencies?: HelmDependency[];
}
interface SelectionChart extends ChartIdentityData {
  default_enabled: boolean; state: string; dependencies?: HelmDependency[];
  declared_enabled?: boolean; parent_chart_ids?: string[];
}
interface ConfirmedInventory {
  id: string; inventory_id: string; created_at: string; charts: SelectionChart[];
}
export interface Distribution {
  id: string; name: string; confirmation_id: string; inventory_id: string; charts: SelectionChart[];
  enabled_chart_ids: string[]; disabled_chart_ids: string[]; images: string[]; selection_digest: string;
}
interface DistributionCatalog {
  confirmations: ConfirmedInventory[]; distributions: Distribution[]; can_manage: boolean; can_scan: boolean;
}

function ChartIdentity({chart}: {chart: ChartIdentityData}) {
  return <><strong>{chart.label}</strong>{chart.version && <> · {chart.version}</>}
    {chart.reference && <> · <code>{chart.reference}</code></>}{chart.source_path && <> · <code>{chart.source_path}</code></>}</>;
}

function DependencyList({items, parentEnabled}: {items: HelmDependency[]; parentEnabled: boolean | null}) {
  return <ul>{items.map(dependency => {
    const enabled = parentEnabled === false || dependency.enabled === false ? false
      : parentEnabled === true && dependency.enabled === true ? true : null;
    return <li key={dependency.id}><ChartIdentity chart={dependency}/>
      {!dependency.version && dependency.declared_version && <> · Requested {dependency.declared_version}</>}
      <> · Parent render setting · {enabled === null ? 'Unknown' : enabled ? 'Enabled' : 'Disabled'}</>
      {dependency.condition && <> · Condition <code>{dependency.condition}</code></>}
      {dependency.tags?.length ? <> · Tags {dependency.tags.join(', ')}</> : null}
      {dependency.state === 'unresolved' && <> · Unresolved chart</>}
      {dependency.dependencies?.length ? <DependencyList items={dependency.dependencies} parentEnabled={enabled}/> : null}
    </li>;
  })}</ul>;
}

function ParentDependencies({items = []}: {items?: HelmDependency[]}) {
  if (!items.length) return null;
  return <details><summary>Helm dependencies ({items.length} direct)</summary>
    <p>To change a dependency setting, update the parent chart’s values and rerun Discovery to render the parent chart.</p>
    <DependencyList items={items} parentEnabled={true}/>
  </details>;
}

export function DistributionDetails({selection}: {selection: Distribution}) {
  const charts = new Map(selection.charts.map(chart => [chart.id, chart]));
  return <div className="distribution-details">
    <p>Inventory <code>{selection.inventory_id}</code> · Selection digest <code>{selection.selection_digest}</code></p>
    {(['enabled', 'disabled'] as const).map(state => {
      const ids = selection[`${state}_chart_ids`];
      return <div key={state}><h4>{state === 'enabled' ? 'Enabled charts' : 'Disabled charts'} ({ids.length})</h4>
        {ids.length > 0 && <ul>{ids.map(id => {
          const chart = charts.get(id);
          return <li key={id}>{chart ? <><ChartIdentity chart={chart}/><ParentDependencies items={chart.dependencies}/></> : <code>{id}</code>}</li>;
        })}</ul>}</div>;
    })}
    <details><summary>Images in this distribution ({selection.images.length})</summary>
      {selection.images.length ? <ul>{selection.images.map(image => <li key={image}><code>{image}</code></li>)}</ul> : <p>No images belong to this selection.</p>}
    </details>
  </div>;
}

export function FrozenDistribution({selection}: {selection?: Distribution}) {
  if (!selection) return null;
  return <section className="panel padded" aria-label="Frozen distribution selection"><h2>Distribution selection</h2>
    <h3>{selection.name}</h3><DistributionDetails selection={selection}/></section>;
}

function DistributionEditor({confirmations, original, busy, save, close}: {
  confirmations: ConfirmedInventory[]; original: Distribution | null; busy: boolean;
  save: (name: string, confirmationId: string, enabled: string[]) => Promise<void>; close: () => void;
}) {
  const [name, setName] = useState(original?.name || '');
  const [confirmationId, setConfirmationId] = useState(original?.confirmation_id || confirmations[0].id);
  const confirmation = confirmations.find(item => item.id === confirmationId)!;
  const defaults = (item: ConfirmedInventory) => item.charts.filter(chart => chart.default_enabled).map(chart => chart.id);
  const [enabled, setEnabled] = useState(() => original?.enabled_chart_ids || defaults(confirmation));
  const selected = new Set(enabled);
  const names = new Map(confirmation.charts.map(chart => [chart.id, chart.label]));
  const unresolved = confirmation.charts.filter(chart => chart.state !== 'rendered' && selected.has(chart.id));
  function toggle(id: string, checked: boolean) {
    const children = new Map<string, SelectionChart[]>();
    for (const chart of confirmation.charts) {
      for (const parent of chart.parent_chart_ids || []) {
        if (!children.has(parent)) children.set(parent, []);
        children.get(parent)!.push(chart);
      }
    }
    const next = new Set(selected);
    if (checked) next.add(id);
    else next.delete(id);
    const changed = [id];
    for (const parent of changed) {
      for (const child of children.get(parent) || []) {
        const owners = child.parent_chart_ids!;
        if (checked) {
          if (next.has(child.id) || !(child.declared_enabled ?? child.default_enabled) || owners.some(owner => selected.has(owner))) continue;
          next.add(child.id);
        } else {
          if (!next.has(child.id) || owners.some(owner => next.has(owner))) continue;
          next.delete(child.id);
        }
        changed.push(child.id);
      }
    }
    setEnabled([...next]);
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!busy && name.trim() && !unresolved.length) void save(name.trim(), confirmationId, enabled);
  }
  return <form onSubmit={submit}><fieldset disabled={busy}><legend>{original ? 'Edit as a new distribution' : 'Create distribution'}</legend>
    <label>Distribution name<input required maxLength={120} value={name} onChange={event => setName(event.target.value)}/></label>
    <label>Confirmed inventory<select value={confirmationId} onChange={event => {
      const next = confirmations.find(item => item.id === event.target.value)!;
      setConfirmationId(next.id); setEnabled(defaults(next));
    }}>{confirmations.map(item => <option key={item.id} value={item.id}>{item.inventory_id} · {new Date(item.created_at).toLocaleString()} · {item.id}</option>)}</select></label>
    <fieldset><legend>Charts enabled for this distribution</legend>
      {confirmation.charts.length ? confirmation.charts.map(chart => {
        const parents = chart.parent_chart_ids || [];
        const available = !parents.length || parents.some(parent => selected.has(parent));
        return <div className="distribution-chart" key={chart.id}>
          <label className="distribution-choice">
            <input type="checkbox" checked={selected.has(chart.id)}
              disabled={!selected.has(chart.id) && (!available || chart.state !== 'rendered')}
              aria-describedby={parents.length ? 'owners-'+chart.id : undefined} onChange={event => toggle(chart.id, event.target.checked)}/>
            <span><ChartIdentity chart={chart}/><small>Catalog default · {(chart.declared_enabled ?? chart.default_enabled) ? 'Enabled' : 'Disabled'}</small></span>
            {chart.state !== 'rendered' && <small>Chart resolution incomplete</small>}
          </label>
          {parents.length > 0 && <small id={'owners-'+chart.id}>Requires an enabled parent · {parents.map(parent => names.get(parent) || parent).join(' or ')}</small>}
          <ParentDependencies items={chart.dependencies}/>
        </div>;
      }) : <p>This inventory contains no selectable charts.</p>}
    </fieldset>
    {unresolved.length > 0 && <p role="status">Run Discovery again to resolve {unresolved.map(chart => chart.label).join(', ')}, or disable those charts for this distribution.</p>}
    <button type="submit" disabled={!name.trim() || unresolved.length > 0}>{busy ? 'Saving…' : 'Save distribution'}</button>{' '}
    <button type="button" className="secondary-button" onClick={close}>Cancel edit</button>
  </fieldset></form>;
}

interface ServiceDistributionProps {serviceKey: string; csrfToken: string; canRequestApproval: boolean}

function DistributionManager({serviceKey, csrfToken, canRequestApproval}: ServiceDistributionProps) {
  const url = `/api/services/${encodeURIComponent(serviceKey)}/distributions`;
  const [catalog, setCatalog] = useState<DistributionCatalog | null>(null), [reload, setReload] = useState(0);
  const [editing, setEditing] = useState<Distribution | 'new' | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [scan, setScan] = useState<{name: string; job: string} | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    requestJson<DistributionCatalog>(url, {signal: controller.signal}).then(value => {
      if (!controller.signal.aborted) {setCatalog(value); setError('');}
    }).catch(cause => {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load distributions.');});
    return () => controller.abort();
  }, [url, reload]);
  async function mutate<T>(target: string, payload: object) {
    return requestJson<T>(target, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: csrfToken, ...payload})});
  }
  async function save(name: string, confirmationId: string, enabled: string[]) {
    setBusy(true); setError(''); setNotice(''); setScan(null);
    try {
      const {distribution} = await mutate<{distribution: Distribution}>(url, {name, confirmation_id: confirmationId, enabled_chart_ids: enabled});
      setCatalog(current => current && {...current, distributions: [distribution, ...current.distributions.filter(item => item.id !== distribution.id)]});
      setEditing(null); setNotice(`Saved distribution ${distribution.name}.`);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not save distribution.');}
    finally {setBusy(false);}
  }
  async function scanDistribution(item: Distribution) {
    setBusy(true); setError(''); setNotice(''); setScan(null);
    try {
      const result = await mutate<{job_id: string}>(`${url}/${encodeURIComponent(item.id)}/scan`, {});
      setScan({name: item.name, job: result.job_id});
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not scan distribution.');}
    finally {setBusy(false);}
  }
  return <div>
    {error && <p role="alert">{error} {!catalog && <button onClick={() => setReload(value => value + 1)}>Retry</button>}</p>}
    {notice && <p role="status">{notice}</p>}
    {scan && <p role="status">Scan submitted for {scan.name}. <a href={`/scan?job_id=${encodeURIComponent(scan.job)}`}>View scan progress</a></p>}
    {!catalog ? !error && <p>Loading distributions…</p> : <>
      {catalog.distributions.length ? catalog.distributions.map(item => <article key={item.id} aria-label={item.name}>
        <h3>{item.name}</h3><details><summary>Review selection · {item.enabled_chart_ids.length} enabled · {item.disabled_chart_ids.length} disabled · {item.images.length} images</summary>
          <DistributionDetails selection={item}/></details>
        {catalog.can_manage && catalog.confirmations.some(c => c.id === item.confirmation_id) && <button className="secondary-button" disabled={busy || Boolean(editing)} onClick={() => {setEditing(item); setError(''); setNotice('');}}>Edit as new distribution</button>}{' '}
        {catalog.can_scan && <button className="secondary-button" disabled={busy || !item.images.length} onClick={() => void scanDistribution(item)}>Scan distribution</button>}{' '}
        {canRequestApproval && <a href={`/cyber-approvals?service=${encodeURIComponent(serviceKey)}&distribution_id=${encodeURIComponent(item.id)}`}>Request Cyber approval for this distribution</a>}
      </article>) : <p>No distributions saved for this service.</p>}
      {!catalog.confirmations.length && <p>Confirm an inventory for this service in <a href="/discovery">Discovery</a> to create a distribution.</p>}
      {catalog.can_manage && catalog.confirmations.length > 0 && (editing ?
        <DistributionEditor key={editing === 'new' ? 'new' : editing.id} confirmations={catalog.confirmations} original={editing === 'new' ? null : editing} busy={busy} close={() => {setEditing(null); setError('');}} save={save}/> :
        <button disabled={busy} onClick={() => {setEditing('new'); setError(''); setNotice('');}}>Create distribution</button>)}
    </>}
  </div>;
}

export function ServiceDistributions(props: ServiceDistributionProps) {
  const replica = useServiceReadOnly();
  const [expanded, setExpanded] = useState(window.location.hash === '#service-distributions');
  const [opened, setOpened] = useState(expanded);
  return <section id="service-distributions" className="panel padded service-distributions"><h2>Service distributions</h2>
    <p>{replica ? 'Review chart selections captured with the approved service evidence.' : 'Choose which charts from a confirmed inventory are enabled for a distribution. Each saved selection can be scanned and submitted for Cyber review.'}</p>
    <button type="button" className="secondary-button" aria-expanded={expanded} aria-controls="service-distribution-list" onClick={() => {
      setExpanded(!expanded); setOpened(true);
    }}>{expanded ? 'Hide distributions' : 'View distributions and chart selections'}</button>
    <div id="service-distribution-list" hidden={!expanded}>{opened && <DistributionManager {...props}/>}</div>
  </section>;
}
