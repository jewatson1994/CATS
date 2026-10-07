/**
 * CATS shared presentation components.
 *
 * These components are purely presentational: they never fetch data, never
 * change workflow state and never interpret security semantics beyond mapping
 * an already-computed backend value to a visual tone. Raw backend values are
 * preserved (as `title` / `data-value`) so no technical information is lost.
 */
import {useId, useRef, type FormEvent, type ReactNode} from 'react';

export type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'accent';

/* ---------------------------------------------------------------- icons */

const iconPaths: Record<string, ReactNode> = {
  bell: <path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0"/>,
  gear: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>,
  check: <path d="M20 6 9 17l-5-5"/>,
  alert: <><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></>,
  x: <path d="M18 6 6 18M6 6l12 12"/>,
  info: <><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></>,
  minus: <path d="M5 12h14"/>,
  circle: <circle cx="12" cy="12" r="9"/>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  chevron: <path d="m6 9 6 6 6-6"/>,
  arrowLeft: <path d="M19 12H5M12 19l-7-7 7-7"/>,
  arrowDown: <path d="M12 5v14M19 12l-7 7-7-7"/>,
  arrowUp: <path d="M12 19V5M5 12l7-7 7 7"/>,
  spinner: <path d="M21 12a9 9 0 1 1-6.2-8.56"/>,
};
export type IconName = keyof typeof iconPaths;

/** Locally drawn SVG icon (no icon fonts, no CDN). Decorative unless `label` is given. */
export function Icon({name, label, className = ''}: {name: IconName; label?: string; className?: string}) {
  return <svg className={`icon ${className}`.trim()} viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden={label ? undefined : true} role={label ? 'img' : undefined} aria-label={label} focusable="false">{iconPaths[name]}</svg>;
}

const toneIcon: Record<Tone, IconName> = {success: 'check', warning: 'alert', danger: 'x', info: 'info', neutral: 'minus', accent: 'circle'};

/* ------------------------------------------------------------ text helpers */

const acronyms = new Set(['CVE', 'CVSS', 'EPSS', 'KEV', 'SBOM', 'POA&M', 'OCI', 'SSH', 'TLS', 'MTLS', 'OIDC', 'CA', 'ID', 'URL', 'API', 'CPU', 'OS', 'PPSM', 'NA', 'N/A', 'IP', 'DNS', 'UTC']);

/** Turns backend enum values (NOT_ATTEMPTED, partially_verified, GREEN) into readable labels. */
export function humanize(value: unknown): string {
  if (value === null || value === undefined || value === '') return '';
  const text = String(value).trim();
  if (!/[_]/.test(text) && !/^[A-Z0-9]+$/.test(text) && /[a-z]/.test(text) && /\s|^[A-Z]/.test(text)) return text;
  return text.replace(/[_]+/g, ' ').toLowerCase().split(/\s+/).map((word, index) => {
    const upper = word.toUpperCase();
    if (acronyms.has(upper)) return upper;
    return index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word;
  }).join(' ');
}

const toneWords: [Tone, RegExp][] = [
  ['danger', /^(red|bad|fail|failed|failure|error|errored|non[-_ ]?compliant|noncompliant|blocked|rejected|denied|overdue|critical|unhealthy|invalid|unsafe|missing|revoked|expired|crash\w*|degraded)$/],
  ['warning', /^(yellow|amber|warn|warning|warnings|partial|partially[-_ ]?verified|partially[-_ ]?validated|unverified|could[-_ ]?not[-_ ]?validate|not[-_ ]?verified|pending|pending[-_ ]?approval|awaiting\w*|stale|excepted|exception|needs[-_ ]?review|requested|assessment[-_ ]?pending|high|medium|incomplete|limited|inferred|unsigned|draft|approval[-_ ]?required|archival[-_ ]?pending)$/],
  ['success', /^(green|ok|pass|passed|success|succeeded|successful|complete|completed|compliant|verified|validated|healthy|approved|signed|delivered|ready|resolved|closed|connected|online|installed|current|fixed|accepted|available|enabled)$/],
  ['info', /^(running|in[-_ ]?progress|queued|scheduled|processing|provisioning|validating|deploying|starting|submitted|selected|new|open|static|declared|derived)$/],
  ['neutral', /^(unknown|not[-_ ]?run|not[-_ ]?attempted|not[-_ ]?applicable|n\/?a|none|skipped|unavailable|disabled|inactive|archived|staged|cancelled|canceled|withdrawn|superseded|not[-_ ]?configured|not[-_ ]?started|low|negligible|informational|original)$/],
];

/** Maps an already-computed backend status value to a presentation tone. Unknown values stay neutral. */
export function toneFor(value: unknown): Tone {
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) return 'neutral';
  for (const [tone, pattern] of toneWords) if (pattern.test(text)) return tone;
  return 'neutral';
}

/* ------------------------------------------------------------------ badges */

/**
 * Status badge. Always carries a text label and a shape icon, so meaning never relies on colour alone.
 * The raw backend value is kept in `data-value` and `title`.
 */
export function StatusBadge({value, label, tone, size = 'md', icon = true, className = ''}: {value: unknown; label?: ReactNode; tone?: Tone; size?: 'sm' | 'md' | 'lg'; icon?: boolean; className?: string}) {
  const resolved = tone || toneFor(value);
  const text = label ?? (humanize(value) || 'Unknown');
  return <span className={`badge badge-${resolved} badge-${size} ${className}`.trim()} data-value={value == null ? undefined : String(value)} title={value == null ? undefined : String(value)}>
    {icon && <Icon name={toneIcon[resolved]}/>}<span>{text}</span></span>;
}

const severityRank: Record<string, number> = {critical: 5, high: 4, medium: 3, moderate: 3, low: 2, negligible: 1, informational: 1, unknown: 0};
/** Severity badge with a numeric bar cue (filled segments) in addition to the label. */
export function SeverityBadge({severity, className = ''}: {severity: unknown; className?: string}) {
  const key = String(severity || 'unknown').toLowerCase();
  const rank = severityRank[key] ?? 0;
  return <span className={`severity-badge severity-${key in severityRank ? key : 'unknown'} ${className}`.trim()} title={String(severity ?? 'Unknown')}>
    <span className="severity-pips" aria-hidden="true">{[1, 2, 3, 4, 5].map(step => <i key={step} className={step <= rank ? 'on' : ''}/>)}</span>
    <span>{humanize(severity) || 'Unknown'}</span></span>;
}

/* ------------------------------------------------------------------ layout */

export function PageHeader({eyebrow, title, description, meta, actions, status, back}: {
  eyebrow?: ReactNode; title: ReactNode; description?: ReactNode; meta?: ReactNode; actions?: ReactNode; status?: ReactNode; back?: {href: string; label: string};
}) {
  return <>{back && <a className="back" href={back.href}><Icon name="arrowLeft"/>{back.label}</a>}
    <section className="heading page-header"><div className="page-header-main">{eyebrow && <p className="eyebrow">{eyebrow}</p>}
      <div className="page-header-title"><h1>{title}</h1>{status}</div>
      {description && <p className="page-header-description">{description}</p>}{meta && <div className="page-header-meta">{meta}</div>}</div>
      {actions && <div className="heading-actions page-header-actions">{actions}</div>}</section></>;
}

export function SectionHeader({title, description, actions, level = 2, id}: {title: ReactNode; description?: ReactNode; actions?: ReactNode; level?: 2 | 3; id?: string}) {
  const Heading = level === 2 ? 'h2' : 'h3';
  return <div className="panel-head section-header"><div><Heading id={id}>{title}</Heading>{description && <p>{description}</p>}</div>
    {actions && <div className="panel-actions">{actions}</div>}</div>;
}

export function ActionBar({children, label, className = ''}: {children: ReactNode; label?: string; className?: string}) {
  return <div className={`action-bar ${className}`.trim()} role={label ? 'group' : undefined} aria-label={label}>{children}</div>;
}

export function FilterBar({children, onSubmit, method = 'get', action, label = 'Filters', className = ''}: {children: ReactNode; onSubmit?: (event: FormEvent<HTMLFormElement>) => void; method?: string; action?: string; label?: string; className?: string}) {
  return <form className={`filter-bar ${className}`.trim()} method={method} action={action} onSubmit={onSubmit} aria-label={label} role="search">{children}</form>;
}

export function FormSection({title, description, children, className = ''}: {title: ReactNode; description?: ReactNode; children: ReactNode; className?: string}) {
  return <fieldset className={`form-section ${className}`.trim()}><legend>{title}</legend>{description && <p className="form-section-description">{description}</p>}{children}</fieldset>;
}

export function SettingsSection({id, title, description, status, actions, children}: {id?: string; title: ReactNode; description?: ReactNode; status?: ReactNode; actions?: ReactNode; children: ReactNode}) {
  return <section className="panel settings-section" id={id}><div className="panel-head"><div><h2>{title}{status && <> {status}</>}</h2>{description && <p>{description}</p>}</div>{actions && <div className="panel-actions">{actions}</div>}</div>
    <div className="settings-section-body">{children}</div></section>;
}

/* ----------------------------------------------------------------- metrics */

export function MetricCard({label, value, hint, tone, href, selected, unavailable = 'Not available', className = '', onClick}: {
  label: ReactNode; value: ReactNode; hint?: ReactNode; tone?: Tone; href?: string; selected?: boolean; unavailable?: string; className?: string; onClick?: () => void;
}) {
  const missing = value === null || value === undefined || value === '' || value === 'Unavailable';
  const body = <><span className="metric-label">{label}</span>
    {missing ? <strong className="metric-value metric-value-missing">{unavailable}</strong> : <strong className="metric-value">{value}</strong>}
    {hint && <small className="metric-hint">{hint}</small>}</>;
  const classes = `metric ${tone ? `metric-${tone}` : ''} ${selected ? 'selected' : ''} ${className}`.replace(/\s+/g, ' ').trim();
  if (href) return <a className={`${classes} metric-link`} href={href} aria-current={selected ? 'true' : undefined}>{body}</a>;
  if (onClick) return <button type="button" className={`${classes} metric-link`} aria-pressed={selected} onClick={onClick}>{body}</button>;
  return <article className={classes}>{body}</article>;
}

export function MetricGrid({children, label, className = ''}: {children: ReactNode; label?: string; className?: string}) {
  return <section className={`metric-grid ${className}`.trim()} aria-label={label}>{children}</section>;
}

type Direction = 'lower' | 'higher' | 'neutral';
/** Before → after metric. Direction tells which way is an improvement; change is described in text, not only colour. */
export function BeforeAfterMetric({label, before, after, better = 'lower', format = (value: number) => String(value)}: {
  label: ReactNode; before: number | null | undefined; after: number | null | undefined; better?: Direction; format?: (value: number) => string;
}) {
  const known = typeof before === 'number' && typeof after === 'number';
  const delta = known ? (after as number) - (before as number) : 0;
  const improved = known && delta !== 0 && better !== 'neutral' && ((better === 'lower' && delta < 0) || (better === 'higher' && delta > 0));
  const worsened = known && delta !== 0 && better !== 'neutral' && !improved;
  const tone: Tone = !known ? 'neutral' : improved ? 'success' : worsened ? 'danger' : 'neutral';
  const description = !known ? 'Not available' : delta === 0 ? 'No change' : `${delta > 0 ? '+' : '−'}${format(Math.abs(delta))} ${improved ? '(improved)' : worsened ? '(worse)' : ''}`.trim();
  return <div className={`before-after before-after-${tone}`}>
    <span className="before-after-label">{label}</span>
    <span className="before-after-values"><span><small>Before</small><strong>{typeof before === 'number' ? format(before) : '—'}</strong></span>
      <Icon name="arrowLeft" className="before-after-arrow"/>
      <span><small>After</small><strong>{typeof after === 'number' ? format(after) : '—'}</strong></span></span>
    <span className="before-after-delta">{known && delta !== 0 && <Icon name={delta < 0 ? 'arrowDown' : 'arrowUp'}/>}{description}</span>
  </div>;
}

/* ------------------------------------------------------------ key / values */

export type KeyValueItem = [ReactNode, ReactNode] | {label: ReactNode; value: ReactNode; wide?: boolean};
export function KeyValueGrid({items, columns = 2, className = ''}: {items: KeyValueItem[]; columns?: 1 | 2 | 3; className?: string}) {
  return <dl className={`kv-grid kv-cols-${columns} ${className}`.trim()}>{items.map((item, index) => {
    const {label, value, wide} = Array.isArray(item) ? {label: item[0], value: item[1], wide: false} : item;
    return <div key={index} className={wide ? 'kv-wide' : undefined}><dt>{label}</dt><dd>{value === null || value === undefined || value === '' ? <span className="muted">—</span> : value}</dd></div>;
  })}</dl>;
}

/* ------------------------------------------------------------------ states */

export function EmptyState({title, children, action, kind = 'empty'}: {title: ReactNode; children?: ReactNode; action?: ReactNode; kind?: 'empty' | 'not-run' | 'not-applicable' | 'filtered'}) {
  return <div className={`empty-state empty-state-${kind}`}><Icon name={kind === 'not-run' ? 'clock' : kind === 'filtered' ? 'minus' : 'circle'}/><div><strong>{title}</strong>{children && <p>{children}</p>}{action}</div></div>;
}

export function ErrorState({title = 'Something went wrong', children, onRetry, retryLabel = 'Retry'}: {title?: ReactNode; children?: ReactNode; onRetry?: () => void; retryLabel?: string}) {
  return <div className="error-state" role="alert"><Icon name="x"/><div><strong>{title}</strong>{children && <p>{children}</p>}{onRetry && <button type="button" className="secondary-button" onClick={onRetry}>{retryLabel}</button>}</div></div>;
}

export function Loading({label = 'Loading…', inline = false}: {label?: ReactNode; inline?: boolean}) {
  return <div className={`loading-state ${inline ? 'loading-inline' : ''}`.trim()} role="status" aria-live="polite"><Icon name="spinner" className="spin"/><span>{label}</span></div>;
}

export function Callout({tone = 'info', title, children, actions, className = ''}: {tone?: Tone; title?: ReactNode; children?: ReactNode; actions?: ReactNode; className?: string}) {
  return <div className={`callout callout-${tone} ${className}`.trim()} role={tone === 'danger' ? 'alert' : undefined}><Icon name={toneIcon[tone]}/>
    <div className="callout-body">{title && <strong>{title}</strong>}{children && <div>{children}</div>}</div>{actions && <div className="callout-actions">{actions}</div>}</div>;
}

/* -------------------------------------------------------------- progress */

export type StageState = 'complete' | 'current' | 'failed' | 'pending' | 'skipped' | 'warning';
export type Stage = {key: string; label: ReactNode; state: StageState; detail?: ReactNode};
const stageIcon: Record<StageState, IconName> = {complete: 'check', current: 'spinner', failed: 'x', pending: 'circle', skipped: 'minus', warning: 'alert'};
const stageText: Record<StageState, string> = {complete: 'Complete', current: 'In progress', failed: 'Failed', pending: 'Not started', skipped: 'Skipped', warning: 'Needs attention'};

/** Ordered stage indicator. Each stage announces its state in text for assistive technology. */
export function StageProgress({stages, label = 'Progress', orientation = 'horizontal', className = ''}: {stages: Stage[]; label?: string; orientation?: 'horizontal' | 'vertical'; className?: string}) {
  return <ol className={`stage-progress stage-${orientation} ${className}`.trim()} aria-label={label}>{stages.map(stage =>
    <li key={stage.key} className={`stage stage-${stage.state}`} data-status={stage.state} aria-current={stage.state === 'current' ? 'step' : undefined}>
      <span className="stage-marker"><Icon name={stageIcon[stage.state]} className={stage.state === 'current' ? 'spin' : ''}/></span>
      <span className="stage-text"><strong>{stage.label}</strong><span className="sr-only"> — {stageText[stage.state]}</span>{stage.detail && <small>{stage.detail}</small>}</span>
    </li>)}</ol>;
}

/* ------------------------------------------------------------- navigation */

export function TabNavigation({tabs, label, className = ''}: {tabs: {key: string; label: ReactNode; href: string; active?: boolean; count?: number}[]; label: string; className?: string}) {
  return <nav className={`tab-nav ${className}`.trim()} aria-label={label}>{tabs.map(tab =>
    <a key={tab.key} href={tab.href} className={tab.active ? 'active' : ''} aria-current={tab.active ? 'page' : undefined}>{tab.label}{tab.count !== undefined && <span className="tab-count">{tab.count}</span>}</a>)}</nav>;
}

export function Pagination({page, pageCount, total, pageSize, hrefFor, onPage, label = 'Pagination', unit = 'items'}: {
  page: number; pageCount: number; total?: number; pageSize?: number; hrefFor?: (page: number) => string; onPage?: (page: number) => void; label?: string; unit?: string;
}) {
  if (pageCount <= 1) return null;
  const control = (target: number, text: string, enabled: boolean) => !enabled ? <button type="button" className="secondary-button" disabled>{text}</button>
    : hrefFor ? <a className="secondary-button" href={hrefFor(target)}>{text}</a> : <button type="button" className="secondary-button" onClick={() => onPage?.(target)}>{text}</button>;
  const range = total !== undefined && pageSize ? `${total ? (page - 1) * pageSize + 1 : 0}–${Math.min(page * pageSize, total)} of ${total} ${unit}` : total !== undefined ? `${total} ${unit}` : '';
  return <nav className="pagination" aria-label={label}><span>{range && <>{range} · </>}<span aria-current="page">Page {page} of {pageCount}</span></span>
    <span className="pagination-controls">{control(page - 1, 'Previous', page > 1)}{control(page + 1, 'Next', page < pageCount)}</span></nav>;
}

/* ---------------------------------------------------------------- content */

export function Timeline({items, empty = 'No activity recorded.'}: {items: {key: string | number; time: ReactNode; dateTime?: string; title: ReactNode; actor?: ReactNode; detail?: ReactNode; tone?: Tone}[]; empty?: ReactNode}) {
  if (!items.length) return <EmptyState title={empty}/>;
  return <ol className="timeline">{items.map(item => <li key={item.key} className={`timeline-item timeline-${item.tone || 'neutral'}`}>
    <span className="timeline-dot" aria-hidden="true"/><div className="timeline-content"><div className="timeline-head"><strong>{item.title}</strong><time dateTime={item.dateTime}>{item.time}</time></div>
      {item.actor && <span className="timeline-actor">{item.actor}</span>}{item.detail && <div className="timeline-detail">{item.detail}</div>}</div></li>)}</ol>;
}

/** Progressive disclosure for large technical evidence. Nothing is removed; it is collapsed by default. */
export function ExpandableEvidence({summary, count, children, defaultOpen = false, className = ''}: {summary: ReactNode; count?: number; children: ReactNode; defaultOpen?: boolean; className?: string}) {
  return <details className={`expandable-evidence ${className}`.trim()} open={defaultOpen || undefined}><summary><Icon name="chevron" className="expandable-chevron"/><span>{summary}</span>{count !== undefined && <span className="count-pill">{count}</span>}</summary>
    <div className="expandable-body">{children}</div></details>;
}

export function EvidenceCard({title, source, status, children, footer}: {title: ReactNode; source?: ReactNode; status?: ReactNode; children?: ReactNode; footer?: ReactNode}) {
  return <article className="evidence-card"><header><div><h3>{title}</h3>{source && <p className="evidence-source">{source}</p>}</div>{status}</header>{children && <div className="evidence-body">{children}</div>}{footer && <footer>{footer}</footer>}</article>;
}

export type Column<Row> = {key: string; header: ReactNode; render: (row: Row) => ReactNode; className?: string};
export function DataTable<Row>({columns, rows, rowKey, empty = 'No records.', caption, className = ''}: {columns: Column<Row>[]; rows: Row[]; rowKey: (row: Row, index: number) => string | number; empty?: ReactNode; caption?: ReactNode; className?: string}) {
  return <div className={`table-wrap data-table ${className}`.trim()}><table>{caption && <caption className="sr-only">{caption}</caption>}
    <thead><tr>{columns.map(column => <th scope="col" key={column.key} className={column.className}>{column.header}</th>)}</tr></thead>
    <tbody>{rows.length ? rows.map((row, index) => <tr key={rowKey(row, index)}>{columns.map(column => <td key={column.key} className={column.className}>{column.render(row)}</td>)}</tr>)
      : <tr><td colSpan={columns.length} className="empty">{empty}</td></tr>}</tbody></table></div>;
}

/** Accessible native-dialog modal with a labelled title. Children supply the form and actions. */
export function Modal({trigger, triggerClassName = 'secondary-button', title, description, children, className = ''}: {trigger: ReactNode; triggerClassName?: string; title: ReactNode; description?: ReactNode; children: (close: () => void) => ReactNode; className?: string}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const id = useId();
  const close = () => dialog.current?.close();
  return <><button type="button" className={triggerClassName} onClick={() => dialog.current?.showModal()}>{trigger}</button>
    <dialog ref={dialog} className={`review-dialog modal ${className}`.trim()} aria-labelledby={`${id}-title`} aria-describedby={description ? `${id}-desc` : undefined}>
      <h3 id={`${id}-title`}>{title}</h3>{description && <p id={`${id}-desc`}>{description}</p>}{children(close)}</dialog></>;
}
