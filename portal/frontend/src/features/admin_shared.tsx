import type {ReactNode} from 'react';
import {can, type PageData} from '../api';
import {Csrf} from '../components/Form';

export function AdminTabs({data, selected}: {data: PageData; selected: string}) {
  const group = data.selected_group_id ? `?group_id=${data.selected_group_id}` : '';
  const items = [['accounts', '/admin', 'Accounts & roles', can(data, 'user.manage')], ['configuration', '/admin/configuration', 'Settings', can(data, 'config.manage')],
    ['general', `/admin/general-policy${group}`, 'General Policy', can(data, 'audit.view') || can(data, 'config.manage')],
    ['compliance', '/admin/compliance-frameworks', 'Hardening Policy', can(data, 'config.manage')], ['vulnerability', `/admin/compliance${group}`, 'Vulnerability Policy', can(data, 'config.manage')],
    ['watchlist', '/admin/dependency-watchlist', 'Dependency Watchlist', can(data, 'config.manage')]];
  return <nav className="admin-tabs" aria-label="Administration sections">{items.filter(item => item[3]).map(([key, href, label]) => <a key={String(key)} href={String(href)} className={selected === key ? 'selected' : ''} aria-current={selected === key ? 'page' : undefined}>{label}</a>)}</nav>;
}
export function Heading({title, description}: {title: string; description: string}) {return <section className="heading"><div><p className="eyebrow">ADMINISTRATION</p><h1>{title}</h1><p>{description}</p></div></section>;}
export function Post({data, action, children, upload = false, className}: {data: PageData; action: string; children: ReactNode; upload?: boolean; className?: string}) {
  return <form method="post" action={action} encType={upload ? 'multipart/form-data' : undefined} className={className}><Csrf data={data}/>{children}</form>;
}
export function Hidden({name, value}: {name: string; value: any}) {return <input type="hidden" name={name} value={value ?? ''}/>;}
export function SelectRows({label, name, rows, empty, multiple}: {label: string; name: string; rows: any[]; empty?: string; multiple?: boolean}) {return <label>{label}<select name={name} multiple={multiple} size={multiple ? 5 : undefined}>{empty != null && <option value="">{empty}</option>}{(rows || []).map(row => <option key={row.id} value={row.id}>{row.name || row.username}</option>)}</select></label>;}
export function Saved({data, message}: {data: PageData; message: string}) {return <>{data.saved && <div className="save-confirmation" role="status">{message}</div>}{data.error && <p role="alert">{data.error}</p>}</>;}
