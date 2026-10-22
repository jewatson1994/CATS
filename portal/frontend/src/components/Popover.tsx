import {useEffect, useId, useRef, useState, type ReactNode} from 'react';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Non-modal popover anchored to a button (column chooser, density, small menus).
 * Keyboard: the button toggles it, focus moves into the panel, Escape closes it
 * and returns focus to the button, and focus or a pointer leaving it closes it.
 */
export function Popover({label, button, children, align = 'end', className = '', buttonClassName = 'secondary-button', title}: {
  label: string; button: ReactNode; children: ReactNode | ((close: () => void) => ReactNode); align?: 'start' | 'end';
  className?: string; buttonClassName?: string; title?: string;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const id = useId();
  const close = (restore = true) => {
    setOpen(false);
    if (restore) trigger.current?.focus();
  };
  useEffect(() => {
    if (!open) return;
    panel.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
    const outside = (event: Event) => {
      const target = event.target;
      if (!root.current || !(target instanceof Node) || root.current.contains(target)) return;
      // Pressing on non-focusable content inside the panel (an option's label text)
      // moves focus to the nearest focusable ancestor, such as <main>. That is not
      // leaving the popover, so focus landing on an ancestor never closes it.
      if (event.type === 'focusin' && target.contains(root.current)) return;
      setOpen(false);
    };
    document.addEventListener('pointerdown', outside);
    document.addEventListener('focusin', outside);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('focusin', outside);
    };
  }, [open]);
  return <div ref={root} className={`popover ${className}`.trim()} onKeyDown={event => {
    if (event.key === 'Escape' && open) {event.stopPropagation(); close();}
  }}>
    <button ref={trigger} type="button" className={buttonClassName} aria-expanded={open} aria-controls={open ? `${id}-panel` : undefined}
      aria-haspopup="dialog" title={title} onClick={() => setOpen(value => !value)}>{button}</button>
    {open && <div ref={panel} id={`${id}-panel`} className={`popover-panel popover-${align}`} role="dialog" aria-label={label}>
      {typeof children === 'function' ? children(() => close()) : children}
    </div>}
  </div>;
}
