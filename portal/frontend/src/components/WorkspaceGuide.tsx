import type {ReactNode} from 'react';
import {Icon, type IconName} from './ui';

/**
 * Side panel for task workspaces (Scan, SBOM, Patch): the steps the workflow already
 * follows and links to related existing pages. Static presentation only.
 */
export function WorkspaceGuide({title, steps, links = [], note}: {
  title: string; steps: {title: string; detail: ReactNode}[]; links?: {href: string; label: string; icon: IconName}[]; note?: ReactNode;
}) {
  return <aside className="workspace-guide" aria-label={title}>
    <section className="panel workspace-guide-card"><h2>{title}</h2>
      <ol className="workspace-steps">{steps.map((step, index) => <li key={step.title}><span className="workspace-step-index" aria-hidden="true">{index + 1}</span>
        <div><strong>{step.title}</strong><p>{step.detail}</p></div></li>)}</ol>
      {note && <p className="workspace-guide-note"><Icon name="info"/><span>{note}</span></p>}
    </section>
    {links.length > 0 && <nav className="panel workspace-guide-card workspace-links" aria-label="Related pages">
      <h2>Related</h2>{links.map(link => <a key={link.href} href={link.href}><Icon name={link.icon}/><span>{link.label}</span><Icon name="chevronRight" className="workspace-link-end"/></a>)}</nav>}
  </aside>;
}
