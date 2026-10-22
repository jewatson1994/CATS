/**
 * Per-table layout preferences (column widths, order, visibility, density).
 *
 * Only presentation state is stored, keyed by a stable table identity. No row
 * data, filter values, identifiers or other application content is ever
 * written, so browser storage cannot expose security information. Storage may
 * be unavailable (private windows, blocked site data); every access is guarded
 * and the grid works without it.
 */
export type Density = 'compact' | 'comfortable' | 'spacious';
export const DENSITIES: Density[] = ['compact', 'comfortable', 'spacious'];

export interface GridLayout {
  widths: Record<string, number>;
  order: string[];
  hidden: string[];
  density: Density;
  pinned: boolean;
}

const VERSION = 1;
const PREFIX = 'cats.grid.';
export const storageKey = (id: string) => `${PREFIX}${id}.v${VERSION}`;

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' && window.localStorage ? window.localStorage : null;
  } catch {
    return null;
  }
}

const finiteWidth = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value > 0 && value < 4000;

/** Reads a stored layout, dropping anything malformed. */
export function readLayout(id: string): Partial<GridLayout> {
  const store = storage();
  if (!store) return {};
  try {
    const raw = store.getItem(storageKey(id));
    if (!raw) return {};
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object') return {};
    const layout: Partial<GridLayout> = {};
    if (value.widths && typeof value.widths === 'object') {
      layout.widths = Object.fromEntries(Object.entries(value.widths).filter(([key, width]) => typeof key === 'string' && finiteWidth(width))) as Record<string, number>;
    }
    if (Array.isArray(value.order)) layout.order = value.order.filter((key: unknown) => typeof key === 'string');
    if (Array.isArray(value.hidden)) layout.hidden = value.hidden.filter((key: unknown) => typeof key === 'string');
    if (DENSITIES.includes(value.density)) layout.density = value.density;
    if (typeof value.pinned === 'boolean') layout.pinned = value.pinned;
    return layout;
  } catch {
    return {};
  }
}

export function writeLayout(id: string, layout: Partial<GridLayout>) {
  const store = storage();
  if (!store) return;
  try {
    store.setItem(storageKey(id), JSON.stringify({
      widths: layout.widths || {}, order: layout.order || [], hidden: layout.hidden || [],
      density: layout.density, pinned: layout.pinned,
    }));
  } catch {
    /* quota or blocked storage: preferences simply do not persist */
  }
}

export function clearLayout(id: string) {
  const store = storage();
  if (!store) return;
  try {store.removeItem(storageKey(id));} catch { /* ignored */ }
}

/** Reconciles a stored column order with the columns a table currently offers. */
export function reconcileOrder(stored: string[] | undefined, keys: string[]): string[] {
  const known = new Set(keys);
  const order = (stored || []).filter((key, index, all) => known.has(key) && all.indexOf(key) === index);
  // Columns introduced after the layout was saved take their natural place
  // (after their natural predecessor) instead of collecting at the end.
  keys.forEach((key, index) => {
    if (order.includes(key)) return;
    const previous = index > 0 ? order.indexOf(keys[index - 1]) : -1;
    order.splice(previous + 1, 0, key);
  });
  return order;
}
