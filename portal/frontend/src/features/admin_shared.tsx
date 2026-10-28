import type {ReactNode} from 'react';
import {can, type PageData} from '../api';
import {Csrf} from '../components/Form';
import {Icon, type IconName} from '../components/ui';

export interface AdminNavItem {key: string; href: string; label: string; allowed: boolean}

/** Section and icon for each administration destination (presentation only). */
const sections: [string, string[]][] = [
  ['Access', ['accounts']],
  ['Platform', ['configuration']],
  ['Policy', ['general', 'compliance', 'vulnerability', 'risk', 'watchlist']],
  ['Delivery', ['release-destinations']],
];
const icons: Record<string, IconName> = {accounts: 'users', configuration: 'sliders', general: 'file', compliance: 'shieldCheck',
  vulnerability: 'shield', risk: 'target', watchlist: 'eye', 'release-destinations': 'package'};

/**
 * Grouped administration console navigation. Items, destinations and permission checks
 * are supplied by the caller; this only arranges them. Rendered beside the page content
 * on wide screens and as a scrollable strip on narrow ones.
 */
export function AdminNav({items, selected}: {items: AdminNavItem[]; selected: string}) {
  const allowed = items.filter(item => item.allowed);
  const placed = new Set(sections.flatMap(([, keys]) => keys));
  const groups = [...sections.map(([label, keys]) => [label, allowed.filter(item => keys.includes(item.key))] as const),
    ['Other', allowed.filter(item => !placed.has(item.key))] as const].filter(([, entries]) => entries.length);
  return <nav className="admin-tabs admin-sidenav" aria-label="Administration sections">{groups.map(([label, entries]) =>
    <div className="admin-sidenav-group" key={label} role="group" aria-label={label}>
      <span className="admin-sidenav-label" aria-hidden="true">{label}</span>
      {entries.map(item => <a key={item.key} href={item.href} className={selected === item.key ? 'selected' : ''} aria-current={selected === item.key ? 'page' : undefined}>
        <Icon name={icons[item.key] || 'circle'}/><span>{item.label}</span></a>)}
    </div>)}</nav>;
}

export function AdminTabs({data, selected}: {data: PageData; selected: string}) {
  const group = data.selected_group_id ? `?group_id=${data.selected_group_id}` : '';
  const items: AdminNavItem[] = [
    {key: 'accounts', href: '/admin', label: 'Accounts & roles', allowed: can(data, 'user.manage') || can(data, 'role.manage') || data.may_assign_roles === true || data.may_manage_accounts === true},
    {key: 'configuration', href: '/admin/configuration', label: 'Settings', allowed: can(data, 'config.manage')},
    {key: 'general', href: `/admin/general-policy${group}`, label: 'General Policy', allowed: can(data, 'audit.view') || can(data, 'config.manage')},
    {key: 'compliance', href: '/admin/compliance-frameworks', label: 'Hardening Policy', allowed: can(data, 'config.manage')},
    {key: 'vulnerability', href: `/admin/compliance${group}`, label: 'Vulnerability Policy', allowed: can(data, 'config.manage')},
    {key: 'risk', href: `/admin/risk-policy${group}`, label: 'Risk Policy', allowed: Boolean(data.may_manage_risk_policy) || can(data, 'config.manage')},
    {key: 'watchlist', href: '/admin/dependency-watchlist', label: 'Dependency Watchlist', allowed: can(data, 'config.manage')},
    {key: 'release-destinations', href: '/admin/approved-release-destinations', label: 'Release Destinations', allowed: can(data, 'release.destination.manage')},
  ];
  return <AdminNav items={items} selected={selected}/>;
}
export function Heading({title, description}: {title: string; description?: string}) {
  return <section className="heading page-header admin-heading"><div className="page-header-main"><p className="eyebrow">Administration</p><div className="page-header-title"><h1>{title}</h1></div>{description && <p className="page-header-description">{description}</p>}</div></section>;
}
export function Post({data, action, children, upload = false, className}: {data: PageData; action: string; children: ReactNode; upload?: boolean; className?: string}) {
  return <form method="post" action={action} encType={upload ? 'multipart/form-data' : undefined} className={className}><Csrf data={data}/>{children}</form>;
}
export function Hidden({name, value}: {name: string; value: any}) {return <input type="hidden" name={name} value={value ?? ''}/>;}
export function SelectRows({label, name, rows, empty, multiple}: {label: string; name: string; rows: any[]; empty?: string; multiple?: boolean}) {return <label>{label}<select name={name} multiple={multiple} size={multiple ? 5 : undefined}>{empty != null && <option value="">{empty}</option>}{(rows || []).map(row => <option key={row.id} value={row.id}>{row.name || row.username}</option>)}</select></label>;}
export function Saved({data, message}: {data: PageData; message: string}) {
  return <>{data.saved && <div className="save-confirmation callout callout-success" role="status"><Icon name="check"/><div className="callout-body">{message}</div></div>}
    {data.error && <div className="callout callout-danger" role="alert"><Icon name="x"/><div className="callout-body">{data.error}</div></div>}</>;
}
