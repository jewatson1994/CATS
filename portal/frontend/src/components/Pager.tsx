import {useId} from 'react';
import {Icon} from './ui';

/**
 * Compact pagination for server-paginated tables. Links are ordinary page
 * links, so the backend keeps owning page boundaries and ordering.
 */
export function Pager({page, pageCount, total, pageSize, hrefFor, label, unit = 'items', pageSizes, pageSizeParam = 'page_size', className = ''}: {
  page: number; pageCount: number; total: number; pageSize: number; hrefFor: (page: number) => string; label: string; unit?: string;
  /** Offer a rows-per-page choice; it navigates to the current URL with the new size (and page 1). */
  pageSizes?: number[]; pageSizeParam?: string; className?: string;
}) {
  const id = useId();
  const start = total ? (page - 1) * pageSize + 1 : 0;
  const end = Math.min(page * pageSize, total);
  const step = (target: number, direction: 'previous' | 'next', enabled: boolean) => {
    const content = <><Icon name={direction === 'previous' ? 'chevronLeft' : 'chevronRight'}/><span className="sr-only">{direction === 'previous' ? 'Previous page' : 'Next page'}</span></>;
    return enabled ? <a className="pager-step" href={hrefFor(target)} rel={direction === 'previous' ? 'prev' : 'next'}>{content}</a>
      : <span className="pager-step" aria-disabled="true">{content}</span>;
  };
  const sizeHref = (size: number) => {
    const url = new URL(window.location.href);
    url.searchParams.set(pageSizeParam, String(size));
    url.searchParams.delete('page');
    return url.pathname + url.search;
  };
  return <nav className={`pager ${className}`.trim()} aria-label={label}>
    <span className="pager-range">{start.toLocaleString()}–{end.toLocaleString()} of {total.toLocaleString()} {unit}</span>
    {pageSizes && <label className="pager-size" htmlFor={`${id}-size`}><span>Rows</span>
      <select id={`${id}-size`} name={pageSizeParam} value={pageSize}
        onChange={event => window.location.assign(sizeHref(Number(event.target.value)))}>
        {(pageSizes.includes(pageSize) ? pageSizes : [...pageSizes, pageSize].sort((a, b) => a - b)).map(size => <option key={size} value={size}>{size}</option>)}
      </select></label>}
    {pageCount > 1 && <span className="pager-controls">{step(page - 1, 'previous', page > 1)}
      <span className="pager-page" aria-current="page">Page {page} of {pageCount}</span>{step(page + 1, 'next', page < pageCount)}</span>}
  </nav>;
}
