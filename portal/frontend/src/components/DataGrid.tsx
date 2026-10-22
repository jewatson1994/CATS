/**
 * CATS enterprise data grid.
 *
 * A semantic <table> with professional grid interactions: drag or keyboard
 * column resizing, double-click auto-fit, column reordering and visibility,
 * density, sticky headers, an optional pinned identifier column, and sorting.
 *
 * Presentation only. Rows are rendered exactly as supplied; the grid never
 * filters them, never changes their values and never requests data. Sorting
 * follows the dataset's real scope:
 *   - `client`  every row of the dataset is present, so sorting the rows here
 *               sorts the whole dataset;
 *   - `server`  the backend owns ordering; headers are links to its sort URL;
 *   - `none`    the dataset is paginated without server sorting, so headers
 *               are not sortable (sorting one page would mislead).
 * Layout preferences persist per table identity (see gridPreferences.ts).
 */
import {useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type DragEvent, type KeyboardEvent, type PointerEvent, type ReactNode} from 'react';
import {Icon} from './ui';
import {Popover} from './Popover';
import {clearLayout, DENSITIES, readLayout, reconcileOrder, writeLayout, type Density, type GridLayout} from './gridPreferences';

export type ColumnType = 'text' | 'number' | 'date' | 'severity';
export type SortDirection = 'asc' | 'desc';

export interface GridColumn<Row> {
  key: string;
  /** Plain-text header, used in the column chooser and accessible labels. */
  header: string;
  /** Optional rich header content (defaults to `header`). */
  headerContent?: ReactNode;
  render: (row: Row, index: number) => ReactNode;
  /** Raw value used for sorting. Columns without one are not sortable. */
  value?: (row: Row) => unknown;
  type?: ColumnType;
  align?: 'start' | 'end' | 'center';
  width?: number;
  minWidth?: number;
  maxWidth?: number;
  /** Security-critical columns set this to false: they cannot be hidden. */
  hideable?: boolean;
  /** Identifier column that may be pinned while scrolling horizontally. */
  identifier?: boolean;
  /** Allow cell text to wrap instead of truncating with an ellipsis. */
  wrap?: boolean;
  /** Hidden until the user chooses to show it. */
  defaultHidden?: boolean;
  className?: string;
  /** Explanation shown as the header tooltip. */
  description?: string;
}

export type GridSort =
  | {mode: 'client'}
  | {mode: 'server'; key?: string; direction?: SortDirection; href: (key: string, direction: SortDirection) => string; sortable?: string[]}
  | {mode: 'none'};

export const SEVERITY_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, moderate: 3, low: 2, negligible: 1, informational: 1, info: 1, unknown: 0, none: 0,
};

const missing = (value: unknown) => value === null || value === undefined || value === '' || (typeof value === 'number' && Number.isNaN(value));

function numeric(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'boolean') return value ? 1 : 0;
  const parsed = Number(String(value).replace(/[,\s]/g, ''));
  return Number.isFinite(parsed) ? parsed : NaN;
}

function timestamp(value: unknown): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value;
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : NaN;
}

/** Ascending comparison of two present values of a column type. */
export function compareValues(a: unknown, b: unknown, type: ColumnType = 'text'): number {
  if (type === 'number') return numeric(a) - numeric(b);
  if (type === 'date') return timestamp(a) - timestamp(b);
  if (type === 'severity') {
    const rank = (value: unknown) => SEVERITY_RANK[String(value).trim().toLowerCase()] ?? 0;
    return rank(a) - rank(b);
  }
  return String(a).localeCompare(String(b), undefined, {numeric: true, sensitivity: 'base'});
}

/** Stable sort; missing values always sort last regardless of direction. */
export function sortRows<Row>(rows: Row[], column: GridColumn<Row>, direction: SortDirection): Row[] {
  const read = column.value;
  if (!read) return rows;
  const type = column.type || 'text';
  return rows.map((row, index) => ({row, index, value: read(row)})).sort((left, right) => {
    const leftMissing = missing(left.value) || (type === 'number' && Number.isNaN(numeric(left.value))) || (type === 'date' && Number.isNaN(timestamp(left.value)));
    const rightMissing = missing(right.value) || (type === 'number' && Number.isNaN(numeric(right.value))) || (type === 'date' && Number.isNaN(timestamp(right.value)));
    if (leftMissing || rightMissing) return leftMissing === rightMissing ? left.index - right.index : leftMissing ? 1 : -1;
    const result = compareValues(left.value, right.value, type);
    return (direction === 'asc' ? result : -result) || left.index - right.index;
  }).map(item => item.row);
}

/** First-click direction: largest/most severe/newest first for analyst columns. */
export const initialDirection = (type: ColumnType = 'text'): SortDirection => type === 'text' ? 'asc' : 'desc';

const MIN_WIDTH = 56;
const MAX_WIDTH = 720;
const KEY_STEP = 16;
/** Extra pixels added to measured widths so sub-pixel rounding never truncates. */
const MEASURE_HEADROOM = 10;
/** Auto-fit measures at most this many rendered rows: never an unbounded scan. */
const AUTOFIT_ROW_LIMIT = 200;

/** Attribute-selector-safe value for column keys. */
const selectorValue = (value: string) => value.replace(/["\\]/g, '\\$&');
const clamp = (value: number, min: number, max: number) => Math.round(Math.min(max, Math.max(min, value)));
const limits = (column: GridColumn<unknown>) => ({min: column.minWidth ?? MIN_WIDTH, max: column.maxWidth ?? (column.wrap ? 520 : MAX_WIDTH)});
const densityLabel: Record<Density, string> = {compact: 'Compact', comfortable: 'Comfortable', spacious: 'Spacious'};

function defaults(columns: GridColumn<any>[], density: Density): GridLayout {
  return {widths: {}, order: columns.map(column => column.key), hidden: columns.filter(column => column.defaultHidden && column.hideable !== false).map(column => column.key), density, pinned: true};
}

export interface DataGridProps<Row> {
  /** Stable identity used to scope saved layout preferences. */
  id: string;
  /** Accessible name of the table. */
  label: string;
  columns: GridColumn<Row>[];
  rows: Row[];
  rowKey: (row: Row, index: number) => string | number;
  sort?: GridSort;
  empty?: ReactNode;
  loading?: boolean;
  title?: ReactNode;
  description?: ReactNode;
  /** Content at the start of the toolbar (for example a quick search). */
  toolbar?: ReactNode;
  /** Actions before the built-in Columns and Density controls (for example Filters). */
  actions?: ReactNode;
  /** Actions after the built-in controls (for example Export). */
  trailingActions?: ReactNode;
  /** Content between the toolbar and the table (for example active filter chips). */
  above?: ReactNode;
  footer?: ReactNode;
  /** Hide the built-in Columns and Density controls (tiny tables). */
  controls?: boolean;
  defaultDensity?: Density;
  /** Maximum height of the scroll frame, which keeps the header in view. */
  maxHeight?: string;
  rowClassName?: (row: Row) => string | undefined;
  /** Extra full-width row rendered after a row (expanded detail). */
  rowDetail?: (row: Row) => ReactNode;
  className?: string;
}

export function DataGrid<Row>(props: DataGridProps<Row>) {
  const {id, label, columns, rows, rowKey, sort = {mode: 'none'}, empty = 'No records.', loading = false, title, description,
    toolbar, actions, trailingActions, above, footer, controls = true, defaultDensity = 'comfortable', maxHeight, rowClassName,
    rowDetail, className = ''} = props;
  const byKey = useMemo(() => new Map(columns.map(column => [column.key, column])), [columns]);
  const keys = useMemo(() => columns.map(column => column.key), [columns]);
  const [layout, setLayout] = useState<GridLayout>(() => {
    const stored = readLayout(id);
    const base = defaults(columns, defaultDensity);
    return {...base, ...stored, order: reconcileOrder(stored.order, base.order), widths: stored.widths || {}, hidden: stored.hidden ?? base.hidden};
  });
  const [measured, setMeasured] = useState<Record<string, number>>({});
  const [clientSort, setClientSort] = useState<{key: string; direction: SortDirection} | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const [dragKey, setDragKey] = useState<string | null>(null);
  const [dropKey, setDropKey] = useState<string | null>(null);
  const [current, setCurrent] = useState<string | number | null>(null);
  const table = useRef<HTMLTableElement>(null);
  const resizing = useRef<{key: string; startX: number; startWidth: number} | null>(null);

  const commit = useCallback((update: (previous: GridLayout) => GridLayout) => {
    setLayout(previous => {
      const next = update(previous);
      writeLayout(id, {widths: next.widths, order: next.order, hidden: next.hidden, density: next.density, pinned: next.pinned});
      return next;
    });
  }, [id]);

  const order = useMemo(() => reconcileOrder(layout.order, keys), [layout.order, keys]);
  const hidden = useMemo(() => new Set(layout.hidden.filter(key => byKey.get(key)?.hideable !== false)), [layout.hidden, byKey]);
  const visible = useMemo(() => order.map(key => byKey.get(key)!).filter(column => column && !hidden.has(column.key)), [order, byKey, hidden]);
  // User-set widths win, then widths measured from the rendered content. A
  // column's declared `width` is only a fallback when nothing can be measured.
  const sizedOf = useCallback((key: string) => layout.widths[key] ?? measured[key], [layout.widths, measured]);
  const widthOf = useCallback((key: string) => sizedOf(key) ?? byKey.get(key)?.width, [sizedOf, byKey]);
  const fixed = visible.length > 0 && visible.every(column => sizedOf(column.key));
  const totalWidth = fixed ? visible.reduce((sum, column) => sum + (sizedOf(column.key) || 0), 0) : undefined;

  // Measure natural widths once real rows exist, then switch to a fixed layout so
  // later resizing is exact. Measurement reads only the rendered header cells.
  const visibleSignature = visible.map(column => column.key).join('|');
  useLayoutEffect(() => {
    if (fixed || !table.current || (!rows.length && !loading)) return;
    const next: Record<string, number> = {};
    table.current.querySelectorAll<HTMLTableCellElement>('thead th[data-col]').forEach(cell => {
      const key = cell.dataset.col!;
      const column = byKey.get(key);
      if (!column || sizedOf(key)) return;
      const width = cell.getBoundingClientRect().width;
      if (width > 0) {
        const {min, max} = limits(column as GridColumn<unknown>);
        // Widest rendered content (bounded to the rendered rows) plus headroom, so
        // switching to the fixed layout never clips what was fully visible.
        let content = 0;
        table.current!.querySelectorAll<HTMLElement>(`tbody td[data-col="${selectorValue(key)}"] > .dg-cell:not(.dg-cell-wrap)`).forEach((node, index) => {
          if (index < AUTOFIT_ROW_LIMIT) content = Math.max(content, node.scrollWidth);
        });
        const padding = (parseFloat(window.getComputedStyle(cell).paddingLeft) || 0) + (parseFloat(window.getComputedStyle(cell).paddingRight) || 0);
        next[key] = clamp(Math.max(width, content + padding) + MEASURE_HEADROOM, min, max);
      }
    });
    if (Object.keys(next).length) setMeasured(previous => ({...previous, ...next}));
  }, [fixed, visibleSignature, rows.length, loading, byKey, sizedOf]);

  const autofit = useCallback((key: string) => {
    const column = byKey.get(key);
    const node = table.current;
    if (!column || !node) return;
    node.classList.add('dg-measuring');
    let widest = 0;
    const header = node.querySelector<HTMLElement>(`thead th[data-col="${selectorValue(key)}"]`);
    const headerLabel = header?.querySelector<HTMLElement>('.dg-head-label');
    const padding = (element: Element | null | undefined) => {
      if (!element) return 24;
      const style = window.getComputedStyle(element);
      return (parseFloat(style.paddingLeft) || 0) + (parseFloat(style.paddingRight) || 0);
    };
    // In measuring mode cell content is laid out at its intrinsic (max-content)
    // width, independent of the column's current width.
    const intrinsic = (element: HTMLElement) => element.getBoundingClientRect().width;
    if (headerLabel) widest = intrinsic(headerLabel) + padding(header) + (header?.querySelector('.dg-sort-icon') ? 22 : 6);
    const cells = Array.from(node.querySelectorAll<HTMLElement>(`tbody td[data-col="${selectorValue(key)}"]`)).slice(0, AUTOFIT_ROW_LIMIT);
    for (const cell of cells) {
      const content = cell.querySelector<HTMLElement>('.dg-cell');
      if (content) widest = Math.max(widest, intrinsic(content) + padding(cell) + 2);
    }
    node.classList.remove('dg-measuring');
    const {min, max} = limits(column as GridColumn<unknown>);
    const width = clamp(widest ? widest + MEASURE_HEADROOM : column.width || min, min, max);
    commit(previous => ({...previous, widths: {...frozenWidths(previous), [key]: width}}));
    setAnnouncement(`${column.header} column fitted to ${width} pixels`);
    // frozenWidths keeps every other column exactly where the user sees it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [byKey, commit]);

  /** Current on-screen widths of every visible column, so one change never shifts the others. */
  function frozenWidths(previous: GridLayout): Record<string, number> {
    const widths = {...previous.widths};
    table.current?.querySelectorAll<HTMLTableCellElement>('thead th[data-col]').forEach(cell => {
      const key = cell.dataset.col!;
      const width = cell.getBoundingClientRect().width;
      if (width > 0) widths[key] = Math.round(width);
      else if (!widths[key]) {
        const fallback = measured[key] ?? byKey.get(key)?.width;
        if (fallback) widths[key] = fallback;
      }
    });
    return widths;
  }

  function startResize(event: PointerEvent<HTMLSpanElement>, key: string) {
    if (event.button > 0) return;
    event.preventDefault();
    event.stopPropagation();
    const cell = (event.currentTarget.closest('th') as HTMLElement | null);
    const startWidth = Math.round(cell?.getBoundingClientRect().width || widthOf(key) || byKey.get(key)?.minWidth || 120);
    setLayout(previous => ({...previous, widths: {...frozenWidths(previous), [key]: startWidth}}));
    resizing.current = {key, startX: event.clientX, startWidth};
    document.body.classList.add('dg-resizing');
    const onMove = (moveEvent: globalThis.PointerEvent) => {
      const active = resizing.current;
      if (!active) return;
      const column = byKey.get(active.key);
      if (!column) return;
      const {min, max} = limits(column as GridColumn<unknown>);
      const width = clamp(active.startWidth + moveEvent.clientX - active.startX, min, max);
      setLayout(previous => previous.widths[active.key] === width ? previous : {...previous, widths: {...previous.widths, [active.key]: width}});
    };
    const stop = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', stop);
      window.removeEventListener('pointercancel', stop);
      document.body.classList.remove('dg-resizing');
      if (resizing.current) commit(previous => previous);
      resizing.current = null;
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', stop);
    window.addEventListener('pointercancel', stop);
  }

  function keyResize(event: KeyboardEvent<HTMLSpanElement>, key: string) {
    const column = byKey.get(key);
    if (!column) return;
    const {min, max} = limits(column as GridColumn<unknown>);
    const currentWidth = widthOf(key) || min;
    let width: number | null = null;
    if (event.key === 'ArrowLeft') width = currentWidth - (event.shiftKey ? KEY_STEP * 4 : KEY_STEP);
    else if (event.key === 'ArrowRight') width = currentWidth + (event.shiftKey ? KEY_STEP * 4 : KEY_STEP);
    else if (event.key === 'Home') width = min;
    else if (event.key === 'End') width = max;
    else if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); autofit(key); return;}
    if (width === null) return;
    event.preventDefault();
    const next = clamp(width, min, max);
    commit(previous => ({...previous, widths: {...frozenWidths(previous), [key]: next}}));
    setAnnouncement(`${column.header} column ${next} pixels`);
  }

  function move(key: string, offset: number) {
    commit(previous => {
      const list = reconcileOrder(previous.order, keys).filter(item => !hidden.has(item) || item === key);
      const from = list.indexOf(key);
      const to = from + offset;
      if (from < 0 || to < 0 || to >= list.length) return previous;
      const target = list[to];
      const full = reconcileOrder(previous.order, keys).filter(item => item !== key);
      full.splice(full.indexOf(target) + (offset > 0 ? 1 : 0), 0, key);
      return {...previous, order: full};
    });
    const column = byKey.get(key);
    if (column) setAnnouncement(`${column.header} moved ${offset < 0 ? 'left' : 'right'}`);
  }

  function dropOn(target: string, after: boolean) {
    const source = dragKey;
    setDragKey(null); setDropKey(null);
    if (!source || source === target) return;
    commit(previous => {
      const full = reconcileOrder(previous.order, keys).filter(item => item !== source);
      full.splice(full.indexOf(target) + (after ? 1 : 0), 0, source);
      return {...previous, order: full};
    });
  }

  function toggle(key: string) {
    const column = byKey.get(key);
    if (!column || column.hideable === false) return;
    commit(previous => {
      const set = new Set(previous.hidden);
      if (set.has(key)) set.delete(key); else set.add(key);
      return {...previous, hidden: [...set]};
    });
  }

  function reset() {
    clearLayout(id);
    setLayout(defaults(columns, defaultDensity));
    setMeasured({});
    setClientSort(null);
    setAnnouncement('Column layout reset');
  }

  // Sorting -------------------------------------------------------------------------------------
  const sortableKey = (column: GridColumn<Row>) => sort.mode === 'client' ? Boolean(column.value)
    : sort.mode === 'server' ? (sort.sortable ? sort.sortable.includes(column.key) : Boolean(column.value)) : false;
  const active = sort.mode === 'client' ? clientSort : sort.mode === 'server' && sort.key ? {key: sort.key, direction: sort.direction || 'asc'} : null;
  const shownRows = useMemo(() => {
    if (sort.mode !== 'client' || !clientSort) return rows;
    const column = byKey.get(clientSort.key);
    return column ? sortRows(rows, column, clientSort.direction) : rows;
  }, [rows, sort.mode, clientSort, byKey]);

  function clickSort(column: GridColumn<Row>) {
    const first = initialDirection(column.type);
    const next = !clientSort || clientSort.key !== column.key ? {key: column.key, direction: first}
      : clientSort.direction === first ? {key: column.key, direction: (first === 'asc' ? 'desc' : 'asc') as SortDirection} : null;
    setClientSort(next);
    setAnnouncement(next ? `Sorted by ${column.header}, ${next.direction === 'asc' ? 'ascending' : 'descending'}` : 'Sorting cleared; original order restored');
  }

  useEffect(() => () => document.body.classList.remove('dg-resizing'), []);

  const pinnedKey = layout.pinned && visible[0]?.identifier ? visible[0].key : null;
  const hiddenCount = columns.filter(column => hidden.has(column.key)).length;
  const alignClass = (column: GridColumn<Row>) => {
    const align = column.align || (column.type === 'number' ? 'end' : 'start');
    return align === 'end' ? 'dg-align-end' : align === 'center' ? 'dg-align-center' : '';
  };

  const columnChooser = <Popover label="Columns" className="dg-columns" title="Choose, reorder and reset columns"
    button={<><Icon name="columns"/><span>Columns</span>{hiddenCount > 0 && <span className="count-pill dg-hidden-count" aria-label={`${hiddenCount} hidden`}>{hiddenCount} hidden</span>}</>}>
    <div className="dg-menu">
      <p className="dg-menu-title" id={`${id}-columns-title`}>Columns</p>
      <ul className="dg-column-list" aria-labelledby={`${id}-columns-title`}>{order.map((key, index) => {
        const column = byKey.get(key)!;
        const locked = column.hideable === false;
        return <li key={key} className={hidden.has(key) ? 'is-hidden' : undefined}>
          <label title={locked ? 'Always shown: required to interpret security status' : undefined}>
            <input type="checkbox" checked={!hidden.has(key)} disabled={locked} onChange={() => toggle(key)}/>
            <span>{column.header}</span>{locked && <span className="dg-locked">Required</span>}
          </label>
          <span className="dg-move">
            <button type="button" className="icon-button" aria-label={`Move ${column.header} left`} disabled={index === 0} onClick={() => move(key, -1)}><Icon name="chevronLeft"/></button>
            <button type="button" className="icon-button" aria-label={`Move ${column.header} right`} disabled={index === order.length - 1} onClick={() => move(key, 1)}><Icon name="chevronRight"/></button>
          </span>
        </li>;
      })}</ul>
      {columns.some(column => column.identifier) && <label className="dg-pin"><input type="checkbox" checked={layout.pinned} onChange={() => commit(previous => ({...previous, pinned: !previous.pinned}))}/>
        Pin identifier column while scrolling</label>}
      <p className="dg-menu-hint">Drag a header edge to resize; double-click it to fit the content. Drag headers to reorder.</p>
      <button type="button" className="secondary-button dg-reset" onClick={reset}>Reset column layout</button>
    </div>
  </Popover>;

  const densityChooser = <Popover label="Row density" className="dg-density-menu" title="Row density"
    button={<><Icon name="rows"/><span>Density</span><span className="sr-only">: {densityLabel[layout.density]}</span></>}>
    <fieldset className="dg-menu dg-density-options"><legend className="dg-menu-title">Row density</legend>
      {DENSITIES.map(value => <label key={value}><input type="radio" name={`${id}-density`} value={value} checked={layout.density === value}
        onChange={() => commit(previous => ({...previous, density: value}))}/>{densityLabel[value]}</label>)}
    </fieldset>
  </Popover>;

  const hasToolbar = title || description || toolbar || actions || trailingActions || controls;
  return <div className={`data-grid dg-density-${layout.density} ${className}`.trim()} data-grid-id={id}>
    {hasToolbar && <div className="dg-toolbar">
      <div className="dg-toolbar-start">{(title || description) && <div className="dg-title">{title && <h2>{title}</h2>}{description && <p>{description}</p>}</div>}{toolbar}</div>
      <div className="dg-toolbar-end" role="group" aria-label={`${label} controls`}>{actions}{controls && <>{columnChooser}{densityChooser}</>}{trailingActions}</div>
    </div>}
    {above}
    <div className="dg-scroll" role="region" aria-label={`${label} table`} tabIndex={0} style={maxHeight ? {maxHeight} : undefined}>
      <table ref={table} className={`dg-table${fixed ? ' dg-fixed' : ''}`} style={totalWidth ? {width: totalWidth} : undefined} aria-busy={loading || undefined}>
        <caption className="sr-only">{label}</caption>
        <colgroup>{visible.map(column => <col key={column.key} style={sizedOf(column.key) ? {width: sizedOf(column.key)} : undefined}/>)}</colgroup>
        <thead><tr>{visible.map(column => {
          const sortable = sortableKey(column);
          const sorted = active?.key === column.key ? active.direction : null;
          const ariaSort = sorted ? (sorted === 'asc' ? 'ascending' : 'descending') : sortable ? 'none' : undefined;
          const width = widthOf(column.key);
          const {min, max} = limits(column as GridColumn<unknown>);
          const labelContent = <span className="dg-head-label">{column.headerContent ?? column.header}</span>;
          const icon = <Icon name={sorted === 'asc' ? 'sortAsc' : sorted === 'desc' ? 'sortDesc' : 'sort'} className="dg-sort-icon"/>;
          const nextServer = sort.mode === 'server' ? (sorted ? (sorted === 'asc' ? 'desc' : 'asc') : initialDirection(column.type)) : 'asc';
          return <th key={column.key} scope="col" data-col={column.key} aria-sort={ariaSort} title={column.description}
            style={!fixed && column.minWidth ? {minWidth: column.minWidth} : undefined}
            className={[alignClass(column), column.className, pinnedKey === column.key ? 'dg-sticky' : '', dropKey === column.key ? 'dg-drop-target' : '', dragKey === column.key ? 'dg-dragging' : ''].filter(Boolean).join(' ') || undefined}
            draggable={controls}
            onDragStart={(event: DragEvent<HTMLTableCellElement>) => {
              if ((event.target as Element).closest?.('.dg-resizer')) {event.preventDefault(); return;}
              setDragKey(column.key);
              event.dataTransfer.effectAllowed = 'move';
              try {event.dataTransfer.setData('text/plain', column.header);} catch { /* some browsers restrict drag data */ }
            }}
            onDragOver={event => {if (dragKey && dragKey !== column.key) {event.preventDefault(); setDropKey(column.key);}}}
            onDragLeave={() => setDropKey(value => value === column.key ? null : value)}
            onDrop={event => {
              event.preventDefault();
              const box = event.currentTarget.getBoundingClientRect();
              dropOn(column.key, box.width > 0 && event.clientX > box.left + box.width / 2);
            }}
            onDragEnd={() => {setDragKey(null); setDropKey(null);}}>
            <div className="dg-th">{sortable ? sort.mode === 'server'
              ? <a className="dg-sort" href={sort.href(column.key, nextServer)} draggable={false}>{labelContent}{icon}</a>
              : <button type="button" className="dg-sort" onClick={() => clickSort(column)}>{labelContent}{icon}</button>
              : labelContent}</div>
            {controls && <span className="dg-resizer" role="separator" aria-orientation="vertical" tabIndex={0}
              aria-label={`Resize ${column.header} column`} aria-valuenow={width ? Math.round(width) : undefined} aria-valuemin={min} aria-valuemax={max}
              title="Drag to resize · double-click to fit content"
              onPointerDown={event => startResize(event, column.key)} onDoubleClick={event => {event.stopPropagation(); autofit(column.key);}}
              onKeyDown={event => keyResize(event, column.key)} onClick={event => event.stopPropagation()}/>}
          </th>;
        })}</tr></thead>
        <tbody>{loading && !rows.length ? Array.from({length: 6}, (_, index) => <tr key={`skeleton-${index}`} className="dg-skeleton-row" aria-hidden="true">
          {visible.map(column => <td key={column.key}><span className="skeleton-bar"/></td>)}</tr>)
          : shownRows.length ? shownRows.map((row, index) => {
            const key = rowKey(row, index);
            const detail = rowDetail?.(row);
            return [<tr key={key} className={[rowClassName?.(row), current === key ? 'dg-row-current' : ''].filter(Boolean).join(' ') || undefined}
              onClick={() => setCurrent(key)}>
              {visible.map(column => {
                const content = column.render(row, index);
                const plain = typeof content === 'string' || typeof content === 'number' ? String(content) : undefined;
                return <td key={column.key} data-col={column.key} className={[alignClass(column), column.className, column.type === 'number' && (column.align ?? 'end') === 'end' ? 'num' : '', pinnedKey === column.key ? 'dg-sticky' : ''].filter(Boolean).join(' ') || undefined}>
                  <div className={column.wrap ? 'dg-cell dg-cell-wrap' : 'dg-cell'} title={plain}>{content}</div></td>;
              })}</tr>,
              detail ? <tr key={`${key}-detail`} className="dg-detail-row"><td colSpan={visible.length}>{detail}</td></tr> : null];
          })
          : <tr><td colSpan={visible.length || 1} className="empty dg-empty">{loading ? 'Loading…' : empty}</td></tr>}</tbody>
      </table>
    </div>
    <p className="sr-only" role="status" aria-live="polite">{announcement}</p>
    {footer}
  </div>;
}
