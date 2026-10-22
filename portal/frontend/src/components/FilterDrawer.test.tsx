import {fireEvent, render, screen, within} from '@testing-library/react';
import {describe, expect, it, vi} from 'vitest';
import {FilterChips, FilterDrawer, hrefWithout, QuickSearch} from './FilterDrawer';

function Drawer({onSubmit}: {onSubmit?: (event: any) => void}) {
  return <>
    <QuickSearch form="records" name="q" defaultValue="api" label="Search records"/>
    <FilterDrawer id="records" action="/records" title="Filter records" activeCount={2} hidden={[['tab', 'poams']]} resetHref="/records?tab=poams"
      onSubmit={event => {event.preventDefault(); onSubmit?.(event);}}>
      <label>Owner<input name="owner" defaultValue="ops"/></label>
      <label>Status<select name="status_filter" defaultValue="overdue"><option value="all">All</option><option value="overdue">Overdue</option></select></label>
    </FilterDrawer>
  </>;
}

describe('FilterDrawer', () => {
  it('opens as a labelled dialog, focuses the first field and restores focus when closed', () => {
    render(<Drawer/>);
    const trigger = screen.getByRole('button', {name: /Filters/});
    expect(trigger).toHaveAttribute('aria-haspopup', 'dialog');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger).toHaveTextContent('2');
    expect(trigger).toHaveTextContent('(2 active)');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog', {name: 'Filter records'});
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByLabelText('Owner')).toHaveFocus();
    fireEvent.click(within(dialog).getByRole('button', {name: 'Close filters'}));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
  });

  it('closes on Escape (dialog cancel) and on a backdrop click', () => {
    render(<Drawer/>);
    const trigger = screen.getByRole('button', {name: /Filters/});
    fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog');
    const cancel = new Event('cancel', {cancelable: true});
    fireEvent(dialog, cancel);
    expect(cancel.defaultPrevented).toBe(true);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('dialog'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('keeps the existing GET form contract: fields, hidden values, reset and apply', () => {
    const submit = vi.fn();
    render(<Drawer onSubmit={submit}/>);
    fireEvent.click(screen.getByRole('button', {name: /Filters/}));
    const form = screen.getByRole('search', {name: 'Filter records'}) as HTMLFormElement;
    expect(form).toHaveAttribute('method', 'get');
    expect(form).toHaveAttribute('action', '/records');
    const values = new FormData(form);
    expect(values.get('tab')).toBe('poams');
    expect(values.get('owner')).toBe('ops');
    expect(values.get('status_filter')).toBe('overdue');
    // The toolbar search belongs to the same form.
    expect(values.get('q')).toBe('api');
    expect(screen.getByRole('link', {name: 'Reset'})).toHaveAttribute('href', '/records?tab=poams');
    fireEvent.click(screen.getByRole('button', {name: 'Apply filters'}));
    expect(submit).toHaveBeenCalledTimes(1);
  });

  it('submits the filter form when Enter is pressed in the quick search', () => {
    const submit = vi.fn();
    render(<Drawer onSubmit={submit}/>);
    fireEvent.keyDown(screen.getByLabelText('Search records'), {key: 'Enter'});
    expect(submit).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(screen.getByLabelText('Search records'), {key: 'a'});
    expect(submit).toHaveBeenCalledTimes(1);
  });
});

describe('FilterChips', () => {
  it('lists active filters with individual remove links and a clear-all link', () => {
    render(<FilterChips clearHref="/records" filters={[
      {key: 'owner', label: 'Owner', value: 'ops', removeHref: '/records?status_filter=overdue'},
      {key: 'status', label: 'Status', value: 'Overdue', removeHref: '/records?owner=ops'},
    ]}/>);
    const list = screen.getByRole('list', {name: 'Active filters'});
    expect(within(list).getAllByRole('listitem')).toHaveLength(2);
    expect(screen.getByRole('link', {name: 'Remove filter Owner: ops'})).toHaveAttribute('href', '/records?status_filter=overdue');
    expect(screen.getByRole('link', {name: 'Clear all'})).toHaveAttribute('href', '/records');
  });

  it('renders nothing without active filters', () => {
    const {container} = render(<FilterChips filters={[]}/>);
    expect(container).toBeEmptyDOMElement();
  });

  it('removes one parameter (or one value of a repeated parameter) and resets the page', () => {
    const location = {pathname: '/services/api', search: '?q=ssl&severity=High&severity=Critical&page=3&page_size=100'};
    expect(hrefWithout({q: null}, location)).toBe('/services/api?severity=High&severity=Critical&page_size=100');
    expect(hrefWithout({severity: 'High'}, location)).toBe('/services/api?q=ssl&page_size=100&severity=Critical');
    expect(hrefWithout({q: null, severity: null, page_size: null}, location)).toBe('/services/api');
  });
});
