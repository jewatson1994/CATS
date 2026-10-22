import {act, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {compareValues, DataGrid, sortRows, type GridColumn} from './DataGrid';
import {readLayout, reconcileOrder, storageKey} from './gridPreferences';

interface Row {id: number; name: string; count: number | null; seen: string | null; severity: string}
const rows: Row[] = [
  {id: 1, name: 'alpha', count: 10, seen: '2026-01-05T00:00:00Z', severity: 'Low'},
  {id: 2, name: 'Bravo', count: 2, seen: null, severity: 'Critical'},
  {id: 3, name: 'charlie', count: null, seen: '2026-03-01T00:00:00Z', severity: 'High'},
  {id: 4, name: 'delta', count: 2, seen: '2025-12-31T00:00:00Z', severity: 'Medium'},
];
const columns: GridColumn<Row>[] = [
  {key: 'name', header: 'Name', identifier: true, hideable: false, width: 120, value: row => row.name, render: row => row.name},
  {key: 'count', header: 'Count', type: 'number', width: 80, value: row => row.count, render: row => row.count ?? '—'},
  {key: 'seen', header: 'Last seen', type: 'date', width: 140, value: row => row.seen, render: row => row.seen ?? '—'},
  {key: 'severity', header: 'Severity', type: 'severity', width: 100, value: row => row.severity, render: row => row.severity},
];
const grid = (props: Partial<Parameters<typeof DataGrid<Row>>[0]> = {}) =>
  render(<DataGrid<Row> id="test-grid" label="Test records" columns={columns} rows={rows} rowKey={row => row.id} sort={{mode: 'client'}} {...props}/>);
const headers = () => screen.getAllByRole('columnheader').map(cell => cell.getAttribute('data-col'));
const column = (key: string) => within(screen.getByRole('table')).getAllByRole('cell').filter(cell => cell.getAttribute('data-col') === key).map(cell => cell.textContent);
const colWidth = (index: number) => (screen.getByRole('table').querySelectorAll('col')[index] as HTMLElement).style.width;

// jsdom has no PointerEvent; a MouseEvent subclass carries clientX and button like the real one.
if (typeof window.PointerEvent !== 'function') {
  (window as any).PointerEvent = class PointerEvent extends MouseEvent {};
}
beforeEach(() => window.localStorage.clear());
afterEach(() => vi.restoreAllMocks());

describe('sorting helpers', () => {
  it('compares numbers, dates, severities and text with the right semantics', () => {
    expect(compareValues('10', '9', 'number')).toBeGreaterThan(0);
    expect(compareValues('1,200', '950', 'number')).toBeGreaterThan(0);
    expect(compareValues('2026-01-02', '2025-12-31', 'date')).toBeGreaterThan(0);
    expect(compareValues('Critical', 'high', 'severity')).toBeGreaterThan(0);
    expect(compareValues('Medium', 'moderate', 'severity')).toBe(0);
    expect(compareValues('item 10', 'item 9', 'text')).toBeGreaterThan(0);
    expect(compareValues('alpha', 'Bravo', 'text')).toBeLessThan(0);
  });
  it('is stable and keeps missing values last in both directions', () => {
    const count = columns[1];
    expect(sortRows(rows, count, 'asc').map(row => row.id)).toEqual([2, 4, 1, 3]);
    expect(sortRows(rows, count, 'desc').map(row => row.id)).toEqual([1, 2, 4, 3]);
    expect(sortRows(rows, columns[2], 'desc').map(row => row.id)).toEqual([3, 1, 4, 2]);
    expect(sortRows(rows, columns[3], 'desc').map(row => row.id)).toEqual([2, 3, 4, 1]);
  });
});

describe('DataGrid', () => {
  it('renders a captioned semantic table with sortable headers that announce their state', () => {
    grid();
    const table = screen.getByRole('table', {name: 'Test records'});
    expect(table).toBeInTheDocument();
    expect(headers()).toEqual(['name', 'count', 'seen', 'severity']);
    const severity = screen.getByRole('columnheader', {name: /Severity/});
    expect(severity).toHaveAttribute('aria-sort', 'none');
    fireEvent.click(within(severity).getByRole('button'));
    expect(severity).toHaveAttribute('aria-sort', 'descending');
    expect(column('severity')).toEqual(['Critical', 'High', 'Medium', 'Low']);
    expect(screen.getByRole('status')).toHaveTextContent('Sorted by Severity, descending');
    fireEvent.click(within(screen.getByRole('columnheader', {name: /Name/})).getByRole('button'));
    expect(column('name')).toEqual(['alpha', 'Bravo', 'charlie', 'delta']);
    expect(screen.getByRole('columnheader', {name: /Severity/})).toHaveAttribute('aria-sort', 'none');
  });

  it('uses server sort links for server-ordered datasets and no sort controls when sorting would only cover one page', () => {
    const {unmount} = grid({sort: {mode: 'server', key: 'count', direction: 'desc', href: (key, direction) => `/records?sort=${key}&direction=${direction}`}});
    const count = screen.getByRole('columnheader', {name: /Count/});
    expect(count).toHaveAttribute('aria-sort', 'descending');
    expect(within(count).getByRole('link')).toHaveAttribute('href', '/records?sort=count&direction=asc');
    expect(within(screen.getByRole('columnheader', {name: /Name/})).getByRole('link')).toHaveAttribute('href', '/records?sort=name&direction=asc');
    expect(column('count')).toEqual(['10', '2', '—', '2']);
    unmount();
    grid({sort: {mode: 'none'}});
    expect(within(screen.getByRole('columnheader', {name: /Count/})).queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByRole('columnheader', {name: /Count/})).not.toHaveAttribute('aria-sort');
  });

  it('resizes a column by dragging its boundary and persists only the layout', () => {
    grid();
    const handle = screen.getByRole('separator', {name: 'Resize Count column'});
    fireEvent.pointerDown(handle, {button: 0, clientX: 100});
    act(() => {window.dispatchEvent(new MouseEvent('pointermove', {clientX: 160}));});
    expect(document.body).toHaveClass('dg-resizing');
    act(() => {window.dispatchEvent(new MouseEvent('pointerup', {clientX: 160}));});
    expect(document.body).not.toHaveClass('dg-resizing');
    expect(colWidth(1)).toBe('140px');
    const stored = readLayout('test-grid');
    expect(stored.widths?.count).toBe(140);
    // Only presentation state is stored: no row values.
    const raw = window.localStorage.getItem(storageKey('test-grid'))!;
    for (const value of ['alpha', 'Bravo', 'Critical', '2026-01-05']) expect(raw).not.toContain(value);
  });

  it('clamps drag and keyboard resizing to sensible minimum and maximum widths', () => {
    grid();
    const handle = screen.getByRole('separator', {name: 'Resize Count column'});
    fireEvent.pointerDown(handle, {button: 0, clientX: 500});
    act(() => {window.dispatchEvent(new MouseEvent('pointermove', {clientX: 0}));});
    act(() => {window.dispatchEvent(new MouseEvent('pointerup'));});
    expect(colWidth(1)).toBe('56px');
    fireEvent.keyDown(handle, {key: 'ArrowRight'});
    expect(colWidth(1)).toBe('72px');
    fireEvent.keyDown(handle, {key: 'ArrowRight', shiftKey: true});
    expect(colWidth(1)).toBe('136px');
    fireEvent.keyDown(handle, {key: 'End'});
    expect(colWidth(1)).toBe('720px');
    expect(handle).toHaveAttribute('aria-valuemax', '720');
    fireEvent.keyDown(handle, {key: 'Home'});
    expect(colWidth(1)).toBe('56px');
  });

  it('auto-fits a column to its header and displayed content on double-click', () => {
    grid();
    // jsdom has no layout: report intrinsic widths for the measured elements.
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      const width = this.classList.contains('dg-head-label') ? 60 : this.classList.contains('dg-cell') ? (this.textContent || '').length * 30 : 0;
      return {width, height: 20, top: 0, left: 0, right: width, bottom: 20, x: 0, y: 0, toJSON: () => ({})} as DOMRect;
    });
    fireEvent.doubleClick(screen.getByRole('separator', {name: 'Resize Name column'}));
    // widest cell "charlie" = 7 × 30 = 210, + 2 + 10 headroom (jsdom computes no padding).
    expect(colWidth(0)).toBe('222px');
    expect(screen.getByRole('status')).toHaveTextContent('Name column fitted to 222 pixels');
    fireEvent.keyDown(screen.getByRole('separator', {name: 'Resize Severity column'}), {key: 'Enter'});
    expect(colWidth(3)).toBe('252px');
  });

  it('reorders columns from the column menu and by dragging headers', () => {
    grid();
    fireEvent.click(screen.getByRole('button', {name: /Columns/}));
    fireEvent.click(screen.getByRole('button', {name: 'Move Severity left'}));
    expect(headers()).toEqual(['name', 'count', 'severity', 'seen']);
    expect(screen.getByRole('button', {name: 'Move Name left'})).toBeDisabled();
    const [, count, , seen] = screen.getAllByRole('columnheader');
    fireEvent.dragStart(seen, {dataTransfer: {setData: () => {}, effectAllowed: ''}});
    fireEvent.dragOver(count, {dataTransfer: {}});
    expect(count).toHaveClass('dg-drop-target');
    fireEvent.drop(count, {clientX: 0, dataTransfer: {}});
    expect(headers()).toEqual(['name', 'seen', 'count', 'severity']);
    expect(readLayout('test-grid').order).toEqual(['name', 'seen', 'count', 'severity']);
  });

  it('hides and shows columns, keeps required columns visible, and resets the layout', () => {
    grid();
    fireEvent.click(screen.getByRole('button', {name: /Columns/}));
    expect(screen.getByRole('checkbox', {name: /^Name/})).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox', {name: 'Last seen'}));
    expect(headers()).toEqual(['name', 'count', 'severity']);
    expect(screen.getByRole('button', {name: /Columns/})).toHaveTextContent('1 hidden');
    expect(readLayout('test-grid').hidden).toEqual(['seen']);
    fireEvent.click(screen.getByRole('checkbox', {name: 'Last seen'}));
    expect(headers()).toEqual(['name', 'count', 'seen', 'severity']);
    fireEvent.click(screen.getByRole('checkbox', {name: 'Count'}));
    fireEvent.click(screen.getByRole('button', {name: 'Reset column layout'}));
    expect(headers()).toEqual(['name', 'count', 'seen', 'severity']);
    expect(window.localStorage.getItem(storageKey('test-grid'))).toBeNull();
  });

  it('restores saved widths, order, visibility and density per table identity', () => {
    window.localStorage.setItem(storageKey('test-grid'), JSON.stringify({widths: {count: 222, name: 'wide'}, order: ['severity', 'unknown', 'name'], hidden: ['seen', 'name'], density: 'compact', pinned: false}));
    const {container, unmount} = grid();
    // Unknown and malformed entries are ignored; required columns cannot be hidden.
    expect(headers()).toEqual(['severity', 'name', 'count']);
    expect(colWidth(2)).toBe('222px');
    expect(container.querySelector('.data-grid')).toHaveClass('dg-density-compact');
    unmount();
    render(<DataGrid<Row> id="other-grid" label="Other" columns={columns} rows={rows} rowKey={row => row.id}/>);
    expect(headers()).toEqual(['name', 'count', 'seen', 'severity']);
  });

  it('switches density from an accessible radio group', () => {
    const {container} = grid();
    expect(container.querySelector('.data-grid')).toHaveClass('dg-density-comfortable');
    fireEvent.click(screen.getByRole('button', {name: /Density/}));
    const group = screen.getByRole('group', {name: 'Row density'});
    fireEvent.click(within(group).getByRole('radio', {name: 'Spacious'}));
    expect(container.querySelector('.data-grid')).toHaveClass('dg-density-spacious');
    expect(readLayout('test-grid').density).toBe('spacious');
  });

  it('closes menus with Escape and returns focus to their button', () => {
    grid();
    const button = screen.getByRole('button', {name: /Columns/});
    fireEvent.click(button);
    expect(button).toHaveAttribute('aria-expanded', 'true');
    const dialog = screen.getByRole('dialog', {name: 'Columns'});
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    fireEvent.keyDown(document.activeElement!, {key: 'Escape'});
    expect(screen.queryByRole('dialog', {name: 'Columns'})).not.toBeInTheDocument();
    expect(button).toHaveFocus();
  });

  it('pins the identifier column, shows loading skeletons and empty states', () => {
    const {rerender} = grid();
    expect(screen.getAllByRole('columnheader')[0]).toHaveClass('dg-sticky');
    rerender(<DataGrid<Row> id="test-grid" label="Test records" columns={columns} rows={[]} rowKey={row => row.id} loading/>);
    expect(screen.getByRole('table')).toHaveAttribute('aria-busy', 'true');
    expect(document.querySelectorAll('.dg-skeleton-row')).toHaveLength(6);
    rerender(<DataGrid<Row> id="test-grid" label="Test records" columns={columns} rows={[]} rowKey={row => row.id} empty="Nothing here."/>);
    expect(screen.getByText('Nothing here.').closest('td')).toHaveAttribute('colspan', '4');
  });

  it('works when browser storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {throw new Error('blocked');});
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {throw new Error('blocked');});
    grid();
    fireEvent.keyDown(screen.getByRole('separator', {name: 'Resize Count column'}), {key: 'ArrowRight'});
    expect(colWidth(1)).toBe('96px');
  });

  it('reconciles saved column order with columns added later', () => {
    // d follows its natural predecessor c; b follows a.
    expect(reconcileOrder(['c', 'a'], ['a', 'b', 'c', 'd'])).toEqual(['c', 'd', 'a', 'b']);
    expect(reconcileOrder(undefined, ['a', 'b'])).toEqual(['a', 'b']);
  });
});
