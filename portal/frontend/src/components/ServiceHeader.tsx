import { useEffect, useRef, useState } from 'react';
import { can, type PageData } from '../api';
import { Icon, StatusBadge } from './ui';

/** Tabs whose page data is a bounded summary; prefetched on deliberate hover/focus.
 * Architecture (graph) and Deployment Validation (evidence) load only on visit. */
const PREFETCH_TABS = new Set(['overview', 'artifacts', 'dependencies', 'findings', 'remediations', 'activity']);
export function ServiceTabs({ serviceKey, active = 'findings' }: { serviceKey: string; active?: string }) {
  const root = `/services/${encodeURIComponent(serviceKey)}`;
  return <nav className="service-tabs" aria-label="Service views">{[['overview', 'Overview'], ['architecture', 'Architecture'], ['artifacts', 'Artifacts'], ['dependencies', 'Dependencies'], ['validation', 'Deployment Validation'], ['findings', 'Findings'], ['remediations', 'Remediations'], ['activity', 'Activity']].map(([key, label]) => <a key={key} className={active === key ? 'active' : ''} aria-current={active === key ? 'page' : undefined} data-prefetch={PREFETCH_TABS.has(key) && active !== key ? 'true' : undefined} href={`${root}?${key}=true${key === 'findings' ? '&findings_view=simplified' : key === 'remediations' ? '&tab=pipeline' : ''}`}>{label}</a>)}</nav>;
}

function useDismissibleMenu() {
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const dismissOutside = (event: MouseEvent) => {
      if (menu.current?.open && event.target instanceof Node && !menu.current.contains(event.target)) {
        menu.current.open = false;
      }
    };
    const dismissOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && menu.current?.open) {
        const focusInside = menu.current.contains(document.activeElement);
        menu.current.open = false;
        if (focusInside) menu.current.querySelector('summary')?.focus();
      }
    };
    document.addEventListener('click', dismissOutside, true);
    document.addEventListener('keydown', dismissOnEscape);
    return () => {
      document.removeEventListener('click', dismissOutside, true);
      document.removeEventListener('keydown', dismissOnEscape);
    };
  }, []);
  return menu;
}

function ServiceExportMenu({root, includeBundle}: {root: string; includeBundle: boolean}) {
  const menu = useDismissibleMenu();
  const exports = [
    ['diagrams.zip', 'Diagrams', 'ZIP'], ['ppsm.xlsx', 'PPSM', 'XLSX'],
    ['poam.xlsx', 'POA&M', 'XLSX'], ['mitigations.xlsx', 'Mitigations', 'XLSX'],
    ['asset_list.xlsx', 'Asset List', 'XLSX'], ['findings.xlsx', 'Findings', 'XLSX'],
    ['sbom.json', 'SBOM components', 'JSON'],
  ];
  return <details ref={menu} className="actions-menu service-export-menu">
    <summary className="secondary-button">Export<Icon name="chevron"/></summary>
    <div className="actions-menu-popover">
      <a className="service-export-all" href={`${root}/exports/all.zip`}>
        <span><strong>All</strong><small>Individual exports in one download</small></span>
        <span className="export-file-type" aria-hidden="true">ZIP</span>
      </a>
      <div className="service-export-label">Individual downloads</div>
      {exports.map(([path, label, type]) => <a href={`${root}/exports/${path}`} key={path}>
        <span>{label}</span><span className="export-file-type" aria-hidden="true">{type}</span>
      </a>)}
      {includeBundle && <a className="service-export-bundle" href={`${root}/bundle.zip`}>
        <span>Portable Service Bundle</span><span className="export-file-type" aria-hidden="true">ZIP</span>
      </a>}
    </div>
  </details>;
}

export function ServiceHeader({ data }: { data: PageData }) {
  const view = data.view;
  const service = view.service;
  const root = `/services/${encodeURIComponent(service.service_key)}`;
  const actions = useDismissibleMenu();
  const edit = useRef<HTMLDialogElement>(null);
  const archive = useRef<HTMLDialogElement>(null);
  const deletion = useRef<HTMLDialogElement>(null);
  const [confirmation, setConfirmation] = useState('');
  const deleteAllowed = can(data, 'service.delete', service.id);
  const deletePhrase = `delete ${service.name}`;
  const editAllowed = can(data, 'service.edit', service.id);
  const archiveAllowed = !view.archive && can(data, 'archive.request', service.id);
  const csrf = <input type="hidden" name="csrf_token" value={data.csrf_token || ''} />;
  return <><a className="back" href="/"><Icon name="arrowLeft"/>All services</a><section className="heading"><div><p className="eyebrow eyebrow-key">{service.service_key}</p><div className="service-title-row"><h1>{service.name}</h1><span className="service-poc">POC: {service.poc || 'No POC recorded'}</span></div><div className="service-meta"><span className="service-version">Version: {view.version && view.version !== 'Unknown' ? <details className="actions-menu version-menu"><summary aria-label={`View historical versions for ${service.name}`}>{view.version}</summary><div className="actions-menu-popover">{(data.history_versions || []).filter((version: string) => version !== 'Unknown').map((version: string) => <a key={version} href={`${root}/history?version=${encodeURIComponent(version)}`}>{version}</a>)}</div></details> : <span className="version-unknown">Unknown</span>}</span><span>Owner: {service.owner || 'No owner recorded'}</span><span>Groups: {(service.groups || []).map((group: any) => group.name).join(', ') || 'Unassigned'}</span></div>{service.description && <p className="service-description">{service.description}</p>}</div><div className="service-page-actions"><StatusBadge size="lg" value={service.assessment_status !== 'assessed' ? 'assessment_pending' : view.compliant ? 'compliant' : 'non_compliant'} label={service.assessment_status !== 'assessed' ? 'Assessment Pending' : view.compliant ? 'Compliant' : 'Non-Compliant'}/><span className="latest-evidence">Latest Evidence: <strong>{view.last_execution || 'None received'}</strong></span>{can(data, 'service.export', service.id) && <ServiceExportMenu root={root} includeBundle={can(data, 'bundle.export', service.id)}/>}{(editAllowed || archiveAllowed || deleteAllowed) && <>{data.archive_pending && <StatusBadge value="archival_pending" label="Archival pending"/>}<details ref={actions} className="actions-menu"><summary className="secondary-button">Actions<Icon name="chevron"/></summary><div className="actions-menu-popover">{editAllowed && <button type="button" onClick={() => edit.current?.showModal()}>Edit</button>}{archiveAllowed && <button type="button" onClick={() => archive.current?.showModal()}>Archive</button>}{deleteAllowed && <button type="button" className="danger-button" onClick={() => {setConfirmation(''); deletion.current?.showModal();}}>Delete service</button>}</div></details></>}</div></section>
    {deleteAllowed && <dialog ref={deletion} className="review-dialog" aria-labelledby="delete-service-title"><form method="post" action={`${root}/delete`}>{csrf}<h3 id="delete-service-title">Permanently delete {service.name}</h3><p>This removes the service, its versions, findings, evidence, inventory, artifacts, validation and remediation records, and retained local job output. This cannot be undone. A deletion audit is retained.</p><label>Reason<textarea name="reason" minLength={3} required/></label><label>Type <strong>{deletePhrase}</strong> to confirm<input name="confirmation" autoComplete="off" value={confirmation} onChange={event => setConfirmation(event.target.value)} required/></label><div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => deletion.current?.close()}>Cancel</button><button className="danger-button" disabled={confirmation !== deletePhrase}>Permanently delete service</button></div></form></dialog>}
    {archiveAllowed && <dialog ref={archive} className="review-dialog" aria-labelledby="archive-title"><form method="post" action={`${root}/archive`}>{csrf}<h3 id="archive-title">Request service archival</h3><p>Archiving removes this service from active governance while preserving its historical evidence and records. Cybersecurity approval is required.</p>{data.archive_pending ? <><p className="muted">An archival request is already pending.</p><button type="button" className="secondary-button" onClick={() => archive.current?.close()}>Close</button></> : <><label>Reason *<textarea name="reason" minLength={3} required /></label><label>Ticket<input name="ticket" /></label><div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => archive.current?.close()}>Cancel</button><button>Request Archival</button></div></>}</form></dialog>}
    {editAllowed && <><dialog ref={edit} className="review-dialog" aria-labelledby="edit-title"><form method="post" action={`/admin/services/${encodeURIComponent(service.service_key)}`}>{csrf}<input type="hidden" name="return_to" value={data.next_path || root} /><h3 id="edit-title">Edit service information</h3><label>Service name<input name="name" defaultValue={service.name} required /></label><label>Description<textarea name="description" maxLength={2000} defaultValue={service.description || ''} /></label><label>Owner<input name="owner" defaultValue={service.owner || ''} /></label><label>POC<input name="poc" defaultValue={service.poc || ''} /></label><label>Version override<input name="manual_version" defaultValue={service.manual_version || ''} placeholder="Pipeline version" /></label><label>Groups<select name="group_ids" multiple defaultValue={(service.groups || []).map((group: any) => String(group.id))}>{(data.groups || []).map((group: any) => <option value={group.id} key={group.id}>{group.name}</option>)}</select></label><div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => edit.current?.close()}>Cancel</button><button>Save service</button></div></form></dialog><span className="sr-only">Edit service information</span></>}
  </>;
}
