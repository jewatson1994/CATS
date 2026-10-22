/**
 * Collapsible filter drawer, active-filter chips and a quick-search field.
 *
 * The drawer wraps the page's existing filter form: the same field names, the
 * same method and action, so the backend receives exactly the parameters it
 * did before. Only where the fields are shown changes. It is a native modal
 * <dialog>, which traps focus while open, closes on Escape and restores focus
 * to the Filters button.
 */
import {useEffect, useRef, useState, type FormEvent, type ReactNode} from 'react';
import {Icon} from './ui';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export interface ActiveFilter {
  /** Stable key (usually the parameter name, plus the value for multi-value filters). */
  key: string;
  label: string;
  value: ReactNode;
  /** URL that shows the same results without this one filter. */
  removeHref: string;
}

/** Current URL without the given parameters (and without `page`, which a filter change resets). */
export function hrefWithout(remove: Record<string, string | null>, location: {pathname: string; search: string} = window.location): string {
  const params = new URLSearchParams(location.search);
  for (const [name, value] of Object.entries(remove)) {
    if (value === null) params.delete(name);
    else {
      const kept = params.getAll(name).filter(item => item !== value);
      params.delete(name);
      kept.forEach(item => params.append(name, item));
    }
  }
  params.delete('page');
  const query = params.toString();
  return query ? `${location.pathname}?${query}` : location.pathname;
}

export function FilterDrawer({id, title = 'Filters', description, action, method = 'get', hidden = [], activeCount = 0, resetHref, applyLabel = 'Apply filters',
  onSubmit, children, triggerLabel = 'Filters'}: {
  id: string; title?: string; description?: ReactNode; action?: string; method?: string; hidden?: [string, string | number][];
  activeCount?: number; resetHref?: string; applyLabel?: string; onSubmit?: (event: FormEvent<HTMLFormElement>) => void; children: ReactNode; triggerLabel?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const show = () => {
    const node = dialog.current;
    if (!node) return;
    if (typeof node.showModal === 'function') node.showModal(); else node.setAttribute('open', '');
    setOpen(true);
  };
  const close = () => {
    const node = dialog.current;
    if (!node) return;
    if (typeof node.close === 'function' && node.open) node.close(); else {node.removeAttribute('open'); finish();}
  };
  const finish = () => {setOpen(false); trigger.current?.focus();};
  useEffect(() => {
    if (!open) return;
    // Focus the first field rather than the close button so filtering starts immediately.
    dialog.current?.querySelector<HTMLElement>('.filter-drawer-body input:not([type="hidden"]), .filter-drawer-body select, .filter-drawer-body textarea, .filter-drawer-body button')?.focus();
  }, [open]);
  return <>
    <button ref={trigger} type="button" className={`secondary-button filter-trigger${activeCount ? ' filter-trigger-active' : ''}`} aria-haspopup="dialog" aria-expanded={open}
      aria-controls={`${id}-drawer`} onClick={show}>
      <Icon name="filter"/><span>{triggerLabel}</span>{activeCount > 0 && <span className="filter-count"><span aria-hidden="true">{activeCount}</span><span className="sr-only">({activeCount} active)</span></span>}
    </button>
    <dialog ref={dialog} id={`${id}-drawer`} className="filter-drawer" aria-labelledby={`${id}-title`}
      onClose={finish} onCancel={event => {event.preventDefault(); close();}}
      onClick={event => {if (event.target === event.currentTarget) close();}}
      onKeyDown={event => {
        // Keep Tab focus cycling inside the open drawer (the page behind is inert).
        if (event.key !== 'Tab') return;
        const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(element => !element.closest('[hidden]'));
        if (!focusable.length) return;
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus();}
        else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus();}
      }}>
      <form id={id} className="filter-drawer-form" method={method} action={action} onSubmit={onSubmit} role="search" aria-labelledby={`${id}-title`}>
        {hidden.map(([name, value]) => <input key={name} type="hidden" name={name} value={value}/>)}
        <header className="filter-drawer-head">
          <div><h2 id={`${id}-title`}>{title}</h2>{description && <p>{description}</p>}</div>
          <button type="button" className="icon-button" aria-label="Close filters" onClick={close}><Icon name="x"/></button>
        </header>
        <div className="filter-drawer-body">{children}</div>
        <footer className="filter-drawer-foot">
          {resetHref && <a className="secondary-button" href={resetHref}>Reset</a>}
          <button type="button" className="secondary-button" onClick={close}>Cancel</button>
          <button type="submit">{applyLabel}</button>
        </footer>
      </form>
    </dialog>
  </>;
}

export function FilterChips({filters, clearHref, label = 'Active filters'}: {filters: ActiveFilter[]; clearHref?: string; label?: string}) {
  if (!filters.length) return null;
  return <div className="filter-chips">
    <span className="filter-chips-label" aria-hidden="true">Filtered by</span>
    <ul aria-label={label}>{filters.map(filter => <li key={filter.key} className="filter-chip">
      <span className="filter-chip-text"><span className="filter-chip-name">{filter.label}:</span> <strong>{filter.value}</strong></span>
      <a className="filter-chip-remove" href={filter.removeHref} aria-label={`Remove filter ${filter.label}: ${typeof filter.value === 'string' ? filter.value : ''}`.trim()}><Icon name="x"/></a>
    </li>)}</ul>
    {clearHref && <a className="link-button filter-chips-clear" href={clearHref}>Clear all</a>}
  </div>;
}

/** Search box shown in a toolbar but submitted with the filter form it names. */
export function QuickSearch({form, name, defaultValue, label, placeholder}: {form: string; name: string; defaultValue?: string; label: string; placeholder?: string}) {
  return <label className="quick-search"><span className="sr-only">{label}</span><Icon name="search"/>
    <input type="search" name={name} form={form} defaultValue={defaultValue} placeholder={placeholder}
      onKeyDown={event => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        const target = document.getElementById(form) as HTMLFormElement | null;
        if (target?.requestSubmit) target.requestSubmit(); else target?.submit();
      }}/></label>;
}
