import {useEffect, useRef, type ReactNode} from 'react';
import {can, type PageData} from '../api';

export function Shell({data, children}: {data: PageData; children: ReactNode}) {
  const header = useRef<HTMLElement>(null);
  const user = data.current_user;
  const theme = user?.theme || 'cats';
  useEffect(() => {document.body.dataset.theme = theme;}, [theme]);
  useEffect(() => {
    const close = (event: Event) => {
      if (event instanceof KeyboardEvent && event.key !== 'Escape') return;
      if (event.type === 'click' && header.current?.contains(event.target as Node)) return;
      header.current?.querySelectorAll('details[open]').forEach(menu => menu.removeAttribute('open'));
    };
    document.addEventListener('click', close); document.addEventListener('keydown', close);
    return () => {document.removeEventListener('click', close); document.removeEventListener('keydown', close);};
  }, []);
  const icon = ['blue', 'red', 'gray', 'light'].includes(theme) ? `/static/cats-icon-${theme}.png` : '/static/cats-icon.png';
  return <><header ref={header}>
    <a className="brand" href={user ? '/' : '/home'}><img className="brand-icon" src={icon} alt=""/>CATS
      {data.cats_deployed_version && <small className="cats-version">{data.cats_deployed_version}</small>}
      <span>Continuous Assessment &amp; Tracking System</span></a>
    {user ? <nav className="account-nav" aria-label="Primary navigation">
      <a href="/">Services</a><a href="/cybersecurity">Cybersecurity</a><a href="/scan">Scan</a>
      <a href="/sbom">SBOM</a><a href="/patch">Patch</a><a href="/remediations">Remediations</a>
      <details className="notification-menu"><summary aria-label="Notifications">🔔
        {!!data.pending_request_count && <span className="notification-badge">{data.pending_request_count}</span>}
      </summary><div className="notification-popover"><strong>Notifications</strong>
        {data.actionable_notifications?.length ? <>{data.actionable_notifications.map((item, index) =>
          <a key={index} href="/requests">{item.label}<small>{item.service}</small></a>)}
          <a className="notification-all" href="/requests">View all requests</a></> : <span className="muted">No action required.</span>}
      </div></details>
      {(can(data, 'user.manage') || can(data, 'config.manage') || can(data, 'audit.view')) &&
        <details className="admin-menu"><summary aria-label="Administration">⚙</summary><div className="menu-popover">
          <a href={can(data, 'user.manage') ? '/admin' : can(data, 'audit.view') ? '/admin/general-policy' : '/admin/configuration'}>Administration</a>
          {can(data, 'config.manage') && <a href="/admin/configuration">Configuration</a>}
        </div></details>}
      <details className="user-menu"><summary>{user.display_name}</summary><div className="menu-popover">
        <details className="appearance-menu"><summary>Appearance</summary><form method="post" action="/account/appearance">
          <input type="hidden" name="csrf_token" value={data.csrf_token}/><input type="hidden" name="next_path" value={window.location.pathname + window.location.search}/>
          <div className="appearance-theme-grid">{Object.entries(data.themes || {}).map(([key, label]) =>
            <label key={key} className={`theme-option theme-preview-${key}`}><input type="radio" name="theme" value={key} defaultChecked={theme === key}/>
              <span><strong>{label}</strong></span></label>)}</div><button className="appearance-apply">Apply theme</button>
        </form></details><a href="/account/password">Change password</a><form method="post" action="/logout"><input type="hidden" name="csrf_token" value={data.csrf_token}/>
          <button className="link-button">Sign out</button></form>
      </div></details>
    </nav> : <nav className="public-nav" aria-label="Primary navigation"><a href="/home">Overview</a><a href="/scan">Scan</a>
      <a href="/sbom">SBOM</a><a href="/patch">Patch</a><a href="/login">Login</a></nav>}
  </header><main>{children}</main></>;
}
