import {useEffect, useRef, type KeyboardEvent, type ReactNode} from 'react';
import {can, type PageData} from '../api';
import {Icon, type IconName} from './ui';

export const PRODUCT_NAME = 'Continuous Assessment & Tracking System';

type NavItem = [string, string, (path: string) => boolean, IconName?, string?];
type NavSection = {label?: string; items: NavItem[]};
const primaryNav: NavItem[] = [
  ['/', 'Services', path => path === '/' || path.startsWith('/services/')],
  ['/discovery', 'Discovery', path => path === '/discovery'],
  ['/scan', 'Scan', path => path === '/scan' || path.startsWith('/api/public/jobs/')],
  ['/patch', 'Patch', path => path === '/patch' || path === '/patch-campaigns' || path.startsWith('/api/public/patch-jobs/')],
];
const cyberNav: NavSection[] = [{items: [
  ['/cybersecurity', 'Dashboard', path => path.startsWith('/cybersecurity'), 'gauge', 'Portfolio posture and scan trends'],
  ['/cyber-approvals', 'Approvals', path => path.startsWith('/cyber-approvals'), 'shieldCheck', 'Cyber review queue and decisions'],
  ['/approved-releases', 'Approved Releases', path => path.startsWith('/approved-releases'), 'package', 'Signed snapshots and publication'],
]}];
const moreNav: NavSection[] = [
  {label: 'Governance', items: [
    ['/remediations', 'Remediate', path => path === '/remediations' || path.startsWith('/poam'), 'wrench', 'POA&Ms, exceptions and mitigations'],
    ['/requests', 'Requests', path => path === '/requests', 'inbox', 'Approvals awaiting review'],
  ]},
  {label: 'Inventory', items: [
    ['/artifact-catalog', 'Artifact catalog', path => path === '/artifact-catalog', 'layers', 'Immutable artifact identities'],
    ['/sbom', 'SBOM', path => path === '/sbom', 'file', 'Generate SBOM documents'],
  ]},
  {label: 'Operations', items: [
    ['/jobs', 'Jobs', path => path === '/jobs', 'history', 'Scans, exports and background work'],
  ]},
];

/** Arrow-key movement between the links of an open navigation menu. */
function menuKeys(event: KeyboardEvent<HTMLElement>) {
  const menu = (event.target as Element).closest('details');
  if (!menu) return;
  const links = Array.from(menu.querySelectorAll<HTMLElement>(':scope > .menu-popover a, :scope > .menu-popover button, :scope > .menu-popover summary'));
  const summary = menu.querySelector<HTMLElement>(':scope > summary');
  const index = links.indexOf(document.activeElement as HTMLElement);
  const focus = (target?: HTMLElement) => {if (target) {event.preventDefault(); target.focus();}};
  if (event.key === 'ArrowDown') {
    if (document.activeElement === summary) {
      if (!(menu as HTMLDetailsElement).open) (menu as HTMLDetailsElement).open = true;
      // Links render on open; focus on the next frame.
      event.preventDefault();
      window.requestAnimationFrame?.(() => menu.querySelector<HTMLElement>(':scope > .menu-popover a, :scope > .menu-popover button')?.focus());
      return;
    }
    focus(links[(index + 1) % links.length]);
  } else if (event.key === 'ArrowUp') {
    if (index >= 0) focus(links[(index - 1 + links.length) % links.length]);
  } else if (event.key === 'Home' && index >= 0) focus(links[0]);
  else if (event.key === 'End' && index >= 0) focus(links[links.length - 1]);
}

function NavigationGroup({label, sections, path}: {label: string; sections: NavSection[]; path: string}) {
  const active = sections.some(section => section.items.some(([, , matches]) => matches(path)));
  return <details className="navigation-menu" data-active={active || undefined} onKeyDown={menuKeys}>
    <summary aria-haspopup="true">{label}<Icon name="chevron"/></summary>
    <div className="menu-popover navigation-popover">{sections.map((section, index) =>
      <div key={section.label || index} className="navigation-section" role="group" aria-label={section.label || label}>
        {section.label && <span className="navigation-section-label" aria-hidden="true">{section.label}</span>}
        {section.items.map(([href, name, matches, icon, hint]) => {
          // The link's accessible name stays the destination name; the hint is its description.
          const id = `nav-${href.replace(/[^a-z0-9]+/gi, '-')}`;
          return <a key={href} href={href} className="menu-item" aria-current={matches(path) ? 'page' : undefined} aria-labelledby={`${id}-label`} aria-describedby={hint ? `${id}-hint` : undefined}>
            {icon && <span className="menu-item-icon"><Icon name={icon}/></span>}
            <span className="menu-item-text"><span id={`${id}-label`} className="menu-item-label">{name}</span>{hint && <span id={`${id}-hint`} className="menu-item-hint">{hint}</span>}</span></a>;
        })}
      </div>)}</div>
  </details>;
}
const publicNav: [string, string][] = [['/home', 'Overview'], ['/scan', 'Scan'], ['/sbom', 'SBOM'], ['/patch', 'Patch'], ['/login', 'Login']];

const initials = (name: string) => name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map(part => part[0]?.toUpperCase()).join('') || '?';

export function Shell({data, children}: {data: PageData; children: ReactNode}) {
  const header = useRef<HTMLElement>(null);
  const about = useRef<HTMLDialogElement>(null);
  const user = data.current_user;
  const theme = user?.theme || 'cats';
  useEffect(() => {document.body.dataset.theme = theme;}, [theme]);
  useEffect(() => {
    const close = (event: Event) => {
      if (event instanceof KeyboardEvent && event.key !== 'Escape') return;
      if (event.type === 'click' && header.current?.contains(event.target as Node) && !(event.target as Element).closest('a')) return;
      if (event instanceof KeyboardEvent) {
        const menu = (document.activeElement as Element | null)?.closest('details[open]');
        (menu?.querySelector(':scope > summary') as HTMLElement | null)?.focus();
      }
      header.current?.querySelectorAll('details[open]').forEach(menu => menu.removeAttribute('open'));
    };
    // Only one header menu is open at a time.
    const exclusive = (event: Event) => {
      const opened = event.target as HTMLDetailsElement;
      if (!opened.open || !header.current?.contains(opened) || opened.parentElement?.closest('details')) return;
      header.current.querySelectorAll<HTMLDetailsElement>('details[open]').forEach(menu => {
        if (menu !== opened && !menu.contains(opened)) menu.open = false;
      });
    };
    const node = header.current;
    document.addEventListener('click', close); document.addEventListener('keydown', close);
    node?.addEventListener('toggle', exclusive, true);
    return () => {document.removeEventListener('click', close); document.removeEventListener('keydown', close); node?.removeEventListener('toggle', exclusive, true);};
  }, []);
  const path = window.location.pathname;
  const icon = ['blue', 'red', 'gray', 'light'].includes(theme) ? `/static/cats-icon-${theme}.png` : '/static/cats-icon.png';
  const version = data.cats_deployed_version;
  const pending = Number(data.pending_request_count || 0);
  const adminHref = data.may_manage_accounts || can(data, 'user.manage') ? '/admin' : can(data, 'config.manage') ? '/admin/configuration'
    : can(data, 'audit.view') ? '/admin/general-policy' : data.may_manage_risk_policy ? '/admin/risk-policy' : '/admin/approved-release-destinations';
  const mayAdminister = data.may_manage_accounts || can(data, 'user.manage') || can(data, 'config.manage') || can(data, 'audit.view') || can(data, 'release.destination.manage') || data.may_manage_risk_policy;
  return <><a className="skip-link" href="#main-content">Skip to main content</a><header ref={header} className="app-header">
    <a className="brand" href={user ? '/' : '/home'} title={`CATS — ${PRODUCT_NAME}${version ? ` · ${version}` : ''}`}>
      <img className="brand-icon" src={icon} alt=""/><span className="brand-name">CATS</span><span className="sr-only">, {PRODUCT_NAME}</span>
      {version && <small className="cats-version"><span className="sr-only">version </span>{version}</small>}</a>
    {user ? <nav className="account-nav" aria-label="Primary navigation">
      {primaryNav.map(([href, label, matches]) => <a key={href} href={href} aria-current={matches(path) ? 'page' : undefined}>{label}</a>)}
      <NavigationGroup label="Cybersecurity" sections={cyberNav} path={path}/>
      <NavigationGroup label="More" sections={moreNav} path={path}/>
      <span className="header-utilities">
        <details className="notification-menu"><summary aria-label={pending ? `Notifications (${pending} pending)` : 'Notifications'} title="Notifications"><Icon name="bell"/>
          {!!pending && <span className="notification-badge" aria-hidden="true">{pending > 99 ? '99+' : pending}</span>}
        </summary><div className="notification-popover"><div className="notification-head"><strong>Notifications</strong>{!!pending && <span className="count-pill">{pending} pending</span>}</div>
          {data.actionable_notifications?.length ? <>{data.actionable_notifications.map((item, index) =>
            <a key={index} className="notification-item" href={item.href || "/requests"}><span className="notification-dot" aria-hidden="true"/><span className="notification-text"><span>{item.label}</span><small>{item.service}</small></span></a>)}
            <a className="notification-all" href="/requests">View all requests</a></> : <span className="muted notification-empty">No action required.</span>}
        </div></details>
        {mayAdminister && <a className="admin-entry" aria-label="Administration" title="Administration" href={adminHref} aria-current={path.startsWith('/admin') ? 'page' : undefined}><Icon name="gear"/></a>}
        <details className="user-menu"><summary title={user.display_name}><span className="user-avatar" aria-hidden="true">{initials(user.display_name)}</span><span className="user-name">{user.display_name}</span><Icon name="chevron"/></summary><div className="menu-popover">
          <div className="user-menu-identity"><strong>{user.display_name}</strong>{version && <small>CATS {version}</small>}</div>
          <details className="appearance-menu"><summary className="menu-row"><Icon name="palette"/><span>Appearance</span><Icon name="chevron" className="menu-row-end"/></summary><form method="post" action="/account/appearance">
            <input type="hidden" name="csrf_token" value={data.csrf_token}/><input type="hidden" name="next_path" value={window.location.pathname + window.location.search}/>
            <div className="appearance-theme-grid">{Object.entries(data.themes || {}).map(([key, label]) =>
              <label key={key} className={`theme-option theme-preview-${key}`}><input type="radio" name="theme" value={key} defaultChecked={theme === key}/>
                <span><strong>{label}</strong></span></label>)}</div><button className="appearance-apply">Apply theme</button>
          </form></details><a className="menu-row" href="/account/password"><Icon name="key"/><span>Change password</span></a>
          <button type="button" className="link-button menu-row" onClick={() => {
            const dialog = about.current;
            if (dialog && typeof dialog.showModal === 'function') dialog.showModal(); else dialog?.setAttribute('open', '');
          }}><Icon name="info"/><span>About CATS</span></button>
          <form method="post" action="/logout" onSubmit={() => window.dispatchEvent(new Event('cats:session-ending'))}><input type="hidden" name="csrf_token" value={data.csrf_token}/>
            <button className="link-button menu-row menu-row-signout"><Icon name="logout"/><span>Sign out</span></button></form>
        </div></details>
      </span>
    </nav> : <nav className="public-nav" aria-label="Primary navigation">{publicNav.map(([href, label]) =>
      <a key={href} href={href} aria-current={path === href ? 'page' : undefined}>{label}</a>)}</nav>}
  </header>
  <dialog ref={about} className="review-dialog about-dialog" aria-labelledby="about-cats-title">
    <h3 id="about-cats-title">CATS</h3><p>{PRODUCT_NAME}</p>
    <dl className="kv-grid kv-cols-1"><div><dt>Deployed version</dt><dd>{version || <span className="muted">Not reported</span>}</dd></div></dl>
    <div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => about.current?.close?.()}>Close</button></div>
  </dialog>
  <main id="main-content" tabIndex={-1}>{children}</main></>;
}
