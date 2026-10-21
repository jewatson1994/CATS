import {useEffect, useRef, type ReactNode} from 'react';
import {can, type PageData} from '../api';
import {Icon} from './ui';

type NavItem = [string, string, (path: string) => boolean];
const primaryNav: NavItem[] = [
  ['/', 'Services', path => path === '/' || path.startsWith('/services/')],
  ['/discovery', 'Discovery', path => path === '/discovery'],
  ['/scan', 'Scan', path => path === '/scan' || path.startsWith('/api/public/jobs/')],
  ['/patch', 'Patch', path => path === '/patch' || path === '/patch-campaigns' || path.startsWith('/api/public/patch-jobs/')],
];
const cyberNav: NavItem[] = [
  ['/cybersecurity', 'Cybersecurity overview', path => path.startsWith('/cybersecurity')],
  ['/cyber-approvals', 'Approvals', path => path.startsWith('/cyber-approvals')],
  ['/approved-releases', 'Approved Releases', path => path.startsWith('/approved-releases')],
];
const moreNav: NavItem[] = [
  ['/artifact-catalog', 'Artifact catalog', path => path === '/artifact-catalog'],
  ['/remediations', 'Remediate', path => path === '/remediations' || path.startsWith('/poam')],
  ['/sbom', 'SBOM', path => path === '/sbom'],
  ['/jobs', 'Jobs', path => path === '/jobs'],
  ['/requests', 'Requests', path => path === '/requests'],
];

function NavigationGroup({label, items, path}: {label: string; items: NavItem[]; path: string}) {
  return <details className="navigation-menu" data-active={items.some(([, , matches]) => matches(path)) || undefined}>
    <summary>{label}<Icon name="chevron"/></summary>
    <div className="menu-popover navigation-popover">{items.map(([href, name, matches]) =>
      <a key={href} href={href} aria-current={matches(path) ? 'page' : undefined}>{name}</a>)}</div>
  </details>;
}
const publicNav: [string, string][] = [['/home', 'Overview'], ['/scan', 'Scan'], ['/sbom', 'SBOM'], ['/patch', 'Patch'], ['/login', 'Login']];

export function Shell({data, children}: {data: PageData; children: ReactNode}) {
  const header = useRef<HTMLElement>(null);
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
    document.addEventListener('click', close); document.addEventListener('keydown', close);
    return () => {document.removeEventListener('click', close); document.removeEventListener('keydown', close);};
  }, []);
  const path = window.location.pathname;
  const icon = ['blue', 'red', 'gray', 'light'].includes(theme) ? `/static/cats-icon-${theme}.png` : '/static/cats-icon.png';
  return <><header ref={header}>
    <a className="brand" href={user ? '/' : '/home'}><img className="brand-icon" src={icon} alt=""/>CATS
      {data.cats_deployed_version && <small className="cats-version">{data.cats_deployed_version}</small>}
      <span>Continuous Assessment &amp; Tracking System</span></a>
    {user ? <nav className="account-nav" aria-label="Primary navigation">
      {primaryNav.map(([href, label, matches]) => <a key={href} href={href} aria-current={matches(path) ? 'page' : undefined}>{label}</a>)}
      <NavigationGroup label="Cybersecurity" items={cyberNav} path={path}/>
      <NavigationGroup label="More" items={moreNav} path={path}/>
      <details className="notification-menu"><summary aria-label={data.pending_request_count ? `Notifications (${data.pending_request_count} pending)` : 'Notifications'}><Icon name="bell"/>
        {!!data.pending_request_count && <span className="notification-badge">{data.pending_request_count}</span>}
      </summary><div className="notification-popover"><strong>Notifications</strong>
        {data.actionable_notifications?.length ? <>{data.actionable_notifications.map((item, index) =>
          <a key={index} href={item.href || "/requests"}>{item.label}<small>{item.service}</small></a>)}
          <a className="notification-all" href="/requests">View all requests</a></> : <span className="muted">No action required.</span>}
      </div></details>
      {(data.may_manage_accounts || can(data, 'user.manage') || can(data, 'config.manage') || can(data, 'audit.view') || can(data, 'release.destination.manage') || data.may_manage_risk_policy) &&
        <a className="admin-entry" aria-label="Administration" title="Administration" href={data.may_manage_accounts || can(data, 'user.manage') ? '/admin' : can(data, 'config.manage') ? '/admin/configuration' : can(data, 'audit.view') ? '/admin/general-policy' : data.may_manage_risk_policy ? '/admin/risk-policy' : '/admin/approved-release-destinations'}><Icon name="gear"/></a>}
      <details className="user-menu"><summary>{user.display_name}<Icon name="chevron"/></summary><div className="menu-popover">
        <details className="appearance-menu"><summary>Appearance</summary><form method="post" action="/account/appearance">
          <input type="hidden" name="csrf_token" value={data.csrf_token}/><input type="hidden" name="next_path" value={window.location.pathname + window.location.search}/>
          <div className="appearance-theme-grid">{Object.entries(data.themes || {}).map(([key, label]) =>
            <label key={key} className={`theme-option theme-preview-${key}`}><input type="radio" name="theme" value={key} defaultChecked={theme === key}/>
              <span><strong>{label}</strong></span></label>)}</div><button className="appearance-apply">Apply theme</button>
        </form></details><a href="/account/password">Change password</a><form method="post" action="/logout" onSubmit={() => window.dispatchEvent(new Event('cats:session-ending'))}><input type="hidden" name="csrf_token" value={data.csrf_token}/>
          <button className="link-button">Sign out</button></form>
      </div></details>
    </nav> : <nav className="public-nav" aria-label="Primary navigation">{publicNav.map(([href, label]) =>
      <a key={href} href={href} aria-current={path === href ? 'page' : undefined}>{label}</a>)}</nav>}
  </header><main>{children}</main></>;
}
