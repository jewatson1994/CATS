import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {BeforeAfterMetric, EmptyState, ErrorState, ExpandableEvidence, KeyValueGrid, MetricCard, Pagination, SeverityBadge, StageProgress, StatusBadge, Timeline, humanize, toneFor} from './ui';

afterEach(cleanup);

describe('status presentation', () => {
  it('humanizes backend enums without inventing meaning', () => {
    expect(humanize('NOT_ATTEMPTED')).toBe('Not attempted');
    expect(humanize('PARTIALLY_VERIFIED')).toBe('Partially verified');
    expect(humanize('kev_match')).toBe('KEV match');
    expect(humanize('Already readable')).toBe('Already readable');
    expect(humanize(null)).toBe('');
  });
  it('maps semantic tones and leaves unknown values neutral', () => {
    expect(toneFor('VERIFIED')).toBe('success');
    expect(toneFor('PARTIALLY_VERIFIED')).toBe('warning');
    expect(toneFor('COULD_NOT_VALIDATE')).toBe('warning');
    expect(toneFor('FAILED')).toBe('danger');
    expect(toneFor('running')).toBe('info');
    expect(toneFor('NOT_ATTEMPTED')).toBe('neutral');
    expect(toneFor('something-new')).toBe('neutral');
  });
  it('always renders a text label and icon, and preserves the raw value', () => {
    const {container} = render(<StatusBadge value="NOT_ATTEMPTED"/>);
    const badge = container.querySelector('.badge')!;
    expect(badge).toHaveTextContent('Not attempted');
    expect(badge).toHaveAttribute('data-value', 'NOT_ATTEMPTED');
    expect(badge).toHaveClass('badge-neutral');
    expect(badge.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
  });
  it('renders severity with a non-colour magnitude cue', () => {
    const {container} = render(<SeverityBadge severity="High"/>);
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(container.querySelectorAll('.severity-pips i.on')).toHaveLength(4);
  });
});

describe('metrics', () => {
  it('shows a missing measurement as unavailable, never as zero', () => {
    render(<><MetricCard label="Pods" value={null} unavailable="Not reported"/><MetricCard label="Jobs" value={0}/></>);
    expect(screen.getByText('Not reported')).toBeInTheDocument();
    expect(screen.getByText('0')).toBeInTheDocument();
  });
  it('renders links for filter cards and marks the selection', () => {
    render(<MetricCard label="Warnings" value={3} href="/x" selected/>);
    expect(screen.getByRole('link')).toHaveAttribute('aria-current', 'true');
  });
  it('describes before/after direction in text', () => {
    render(<><BeforeAfterMetric label="Findings" before={10} after={4}/><BeforeAfterMetric label="Images" before={null} after={4}/></>);
    expect(screen.getByText(/6 \(improved\)/)).toBeInTheDocument();
    expect(screen.getByText('Not available')).toBeInTheDocument();
  });
});

describe('structure', () => {
  it('renders key/value pairs with a dash for missing values', () => {
    render(<KeyValueGrid items={[['Engine', 'kind'], {label: 'Artifact', value: null}]}/>);
    expect(screen.getByText('Engine').nextElementSibling).toHaveTextContent('kind');
    expect(screen.getByText('Artifact').nextElementSibling).toHaveTextContent('—');
  });
  it('announces stage state in text, not colour alone', () => {
    render(<StageProgress label="Progress" stages={[{key: 'a', label: 'Plan', state: 'complete'}, {key: 'b', label: 'Run', state: 'current'}, {key: 'c', label: 'Verify', state: 'pending'}]}/>);
    const list = screen.getByRole('list', {name: 'Progress'});
    expect(within(list).getAllByRole('listitem')[0]).toHaveTextContent('Complete');
    expect(within(list).getAllByRole('listitem')[1]).toHaveAttribute('aria-current', 'step');
    expect(within(list).getAllByRole('listitem')[2]).toHaveTextContent('Not started');
  });
  it('keeps large evidence collapsed without removing it', () => {
    const {container} = render(<ExpandableEvidence summary="Observed resources" count={300}><p>row</p></ExpandableEvidence>);
    expect(container.querySelector('details')).not.toHaveAttribute('open');
    expect(screen.getByText('row')).toBeInTheDocument();
    expect(screen.getByText('300')).toBeInTheDocument();
  });
  it('renders timeline entries and an empty state', () => {
    const {rerender} = render(<Timeline items={[{key: 1, time: 'Today', title: 'Finding updated', actor: 'System'}]}/>);
    expect(screen.getByText('Finding updated')).toBeInTheDocument();
    rerender(<Timeline items={[]} empty="Nothing yet"/>);
    expect(screen.getByText('Nothing yet')).toBeInTheDocument();
  });
  it('offers retry from error states and plain empty states', () => {
    const retry = vi.fn();
    render(<><ErrorState title="Failed" onRetry={retry}>Network</ErrorState><EmptyState title="No rows"/></>);
    fireEvent.click(screen.getByRole('button', {name: 'Retry'}));
    expect(retry).toHaveBeenCalledOnce();
    expect(screen.getByRole('alert')).toHaveTextContent('Network');
    expect(screen.getByText('No rows')).toBeInTheDocument();
  });
  it('builds server pagination links and disables unavailable directions', () => {
    render(<Pagination page={1} pageCount={3} total={60} pageSize={25} hrefFor={page => `/x?page=${page}`} label="Rows"/>);
    expect(screen.getByRole('navigation', {name: 'Rows'})).toHaveTextContent('1–25 of 60 items');
    expect(screen.getByRole('button', {name: 'Previous'})).toBeDisabled();
    expect(screen.getByRole('link', {name: 'Next'})).toHaveAttribute('href', '/x?page=2');
  });
});
