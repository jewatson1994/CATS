import {Icon, type IconName} from '../components/ui';

/** Account section navigation (same console layout as administration). */
export function AccountNav({selected}: {selected: 'password' | 'appearance'}) {
  const items: [string, string, string, IconName][] = [['password', '/account/password', 'Change password', 'key'], ['appearance', '/account/appearance', 'Appearance', 'palette']];
  return <nav className="admin-tabs admin-sidenav" aria-label="Account sections"><div className="admin-sidenav-group" role="group" aria-label="Account">
    <span className="admin-sidenav-label" aria-hidden="true">Account</span>
    {items.map(([key, href, label, icon]) => <a key={key} href={href} className={selected === key ? 'selected' : ''} aria-current={selected === key ? 'page' : undefined}><Icon name={icon}/><span>{label}</span></a>)}
  </div></nav>;
}
