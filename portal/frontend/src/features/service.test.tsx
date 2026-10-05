import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { Page } from './service';
import type { PageData } from '../api';

beforeAll(() => {
  HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) { this.setAttribute('open', ''); });
  HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) { this.removeAttribute('open'); });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const fixture = (extra: Partial<PageData> = {}): PageData => ({
  csrf_token: 'csrf-proof', next_path: '/services/sample?findings=true',
  view: { service: { id: 7, service_key: 'sample', name: 'Sample', assessment_status: 'assessed', groups: [] }, version: '1.0', compliant: false, archive: false },
  history_versions: ['1.0', '2.0 beta'], selected_findings_view: 'raw', finding_state: 'active', finding_type: 'all',
  severity: [], severity_options: ['HIGH', 'LOW'], page: 1, page_size: 50, total_items: 1, total_pages: 2,
  pagination_base: '/services/sample?findings_view=raw&severity=HIGH',
  findings: [{ id: 42, cve: 'CVE-2026-42', severity: 'HIGH', active: true, episode_days: 12, due: 'Sep 30, 2026', last_seen: 'Sep 29, 2026', images: ['image:1'], epss: 0.123 }],
  policy_findings: [], can: { 'exception.request': { '7': true }, 'poam.request': { '7': true } }, ...extra,
});

describe('native service finding pages', () => {
  it('preserves CVE identity, CSRF and existing exception action when opening a request', () => {
    render(<Page data={fixture()} />);
    expect(screen.getByRole('link', { name: 'CVE-2026-42' })).toHaveAttribute('href', '/services/sample/findings/42');
    expect(screen.getAllByRole('link', { name: 'Next' })[0]).toHaveAttribute('href', '/services/sample?findings_view=raw&severity=HIGH&page=2');
    expect(screen.getByRole('link', { name: '2.0 beta' })).toHaveAttribute('href', '/services/sample/history?version=2.0%20beta');
    fireEvent.click(screen.getByRole('button', { name: 'Request Exception' }));
    const dialog = screen.getByRole('dialog');
    const form = dialog.querySelector('form')!;
    expect(form).toHaveAttribute('action', '/findings/42/exceptions');
    expect(form).toHaveAttribute('method', 'post');
    expect(form.querySelector('[name="csrf_token"]')).toHaveValue('csrf-proof');
    expect(within(dialog).getByLabelText('Requested expiration')).toBeRequired();
  });

  it('uses policy-specific actions and retains policy mitigation identifiers', () => {
    render(<Page data={fixture({ findings: [], policy_findings: [{ id: 91, finding: 'RULE-91', title: 'Privilege escalation', active: true, severity: 'HIGH', episode_days: 3, target: 'deployment/sample', remediation_classification: 'PATCH' }] })} />);
    fireEvent.click(screen.getByRole('button', { name: 'Add POA&M Entry' }));
    expect(screen.getByRole('dialog').querySelector('form')).toHaveAttribute('action', '/policy-findings/91/poams');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add Mitigation' }));
    const form = screen.getByRole('dialog').querySelector('form')!;
    expect(form).toHaveAttribute('action', '/services/sample/mitigations');
    expect(form.querySelector('[name="policy_finding_id"]')).toHaveValue('91');
    expect(form.querySelector('[name="finding_id"]')).toHaveValue('');
  });

  it('does not expose mutation controls to a user without scoped permission', () => {
    render(<Page data={fixture({ can: { 'exception.request': { '8': true }, 'poam.request': { '*': true } } })} />);
    expect(screen.queryByRole('button', { name: 'Request Exception' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add POA&M Entry' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  });

  it('loads simplified members only on expansion and paginates without losing finding actions', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ id: 12, cve: 'CVE-A', active: true, severity: 'HIGH' }], page: 1, total_pages: 2, total_items: 51 }), { headers: { 'Content-Type': 'application/json' } })).mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ id: 13, cve: 'CVE-B', active: true, severity: 'HIGH' }], page: 2, total_pages: 2, total_items: 51 }), { headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    render(<Page data={fixture({ selected_findings_view: 'simplified', query: 'openssl', severity: ['HIGH'], simplified_findings: [{ group_id: 'group-1', package: 'openssl', remediation: 'Update package', fixed_version: '3.0.2', severity: 'HIGH', image_count: 1, member_count: 51, representative_cve: 'CVE-A' }] })} />);
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'View findings' }));
    expect(await screen.findByRole('link', { name: 'CVE-A' })).toHaveAttribute('href', '/services/sample/findings/12');
    expect(fetchMock.mock.calls[0][0]).toContain('/api/v1/services/sample/findings/simplified/group-1/members?page=1&page_size=50');
    expect(fetchMock.mock.calls[0][0]).toContain('q=openssl');
    expect(fetchMock.mock.calls[0][0]).toContain('severity=HIGH');
    fireEvent.click(screen.getByRole('button', { name: 'Next findings' }));
    expect(await screen.findByRole('link', { name: 'CVE-B' })).toHaveAttribute('href', '/services/sample/findings/13');
    expect(screen.queryByRole('link', { name: 'CVE-A' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Add POA&M Entry' }));
    expect(screen.getByRole('dialog').querySelector('form')).toHaveAttribute('action', '/findings/13/poams');
  });

  it('allows retry after a simplified member request fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('Temporary failure')).mockResolvedValueOnce(new Response(JSON.stringify({ items: [], page: 1, total_pages: 1, total_items: 0 }), { headers: { 'Content-Type': 'application/json' } })));
    render(<Page data={fixture({ selected_findings_view: 'simplified', simplified_findings: [{ group_id: 'g', package: 'openssl', member_count: 1 }] })} />);
    fireEvent.click(screen.getByRole('button', { name: 'View findings' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Temporary failure');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('navigation', { name: 'Member pages for openssl' })).toBeInTheDocument();
  });

  it('retains missing evidence POAM scope and prefilled details', () => {
    render(<Page data={fixture({ finding_state: 'noncompliant', noncompliance_items: [{ type: 'Evidence', item: 'Missing scan', images: ['image:missing'], reason: 'No evidence' }] })} />);
    fireEvent.click(screen.getByRole('button', { name: 'Add POA&M Entry' }));
    const form = screen.getByRole('dialog').querySelector('form')!;
    expect(form).toHaveAttribute('action', '/poam');
    expect(form.querySelector('[name="service_id"]')).toHaveValue('7');
    expect(form.querySelector('[name="item_type"]')).toHaveValue('missing_evidence');
    expect(within(form).getByLabelText('Evidence details')).toHaveValue('No evidence: image:missing');
  });

  it('retains policy exception revocation without exposing request controls for accepted findings', () => {
    render(<Page data={fixture({ findings: [], policy_findings: [{ id: 91, finding: 'RULE-91', active: true, exception: { id: 27, expires_at: 'Oct 1, 2026' } }], can: { 'exception.request': { '7': true }, 'exception.revoke': { '7': true } } })} />);
    const revoke = screen.getByRole('button', { name: 'Revoke' }).closest('form')!;
    expect(revoke).toHaveAttribute('action', '/policy-exceptions/27/revoke');
    expect(revoke.querySelector('[name="csrf_token"]')).toHaveValue('csrf-proof');
    expect(screen.queryByRole('button', { name: 'Request Exception' })).not.toBeInTheDocument();
  });
});
