import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, describe, expect, it} from 'vitest';
import {Page} from './patch_results';
afterEach(cleanup);
describe('patch result parity', () => {
  it('filters observations and preserves fallback counts and failed publication download', () => {
    render(<Page data={{job:{job_id:'test'},result:{delivery_status:'failed',vulnerabilities_remaining:1,vulnerabilities_removed:1,vulnerabilities_after:1,vulnerability_results:[{id:'CVE-2026-1',result:'Remediated',fixed_versions:['2','3']},{id:'CVE-2026-2',result:'Unresolved'}]}}}/>);
    expect(screen.getByRole('link',{name:'Download patched image (.tar)'})).toHaveAttribute('href','/api/public/patch-jobs/test/patched-image.tar');
    expect(screen.getByText('Completed with unresolved vulnerabilities')).toBeInTheDocument();
    expect(screen.getByText('2, 3')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Unresolved 1'}));
    expect(screen.getByText('CVE-2026-1').closest('tr')).not.toBeVisible();
    expect(screen.getByText('CVE-2026-2').closest('tr')).toBeVisible();
    expect(screen.getByRole('button',{name:'Unresolved 1'})).toHaveAttribute('aria-pressed','true');
  });
  it('never offers unavailable archives and renders signing metadata and failure', () => {
    render(<Page data={{job:{job_id:'test',started_at:'2026-01-01T00:00:00Z',finished_at:'2026-01-01T00:01:02Z'},result:{status:'failed',output_mode:'download',artifact_available:false,signature:{key_fingerprint:'fingerprint',verified_at:'verified',generator:'tool',generator_version:'1'}}}}/>);
    expect(screen.queryByRole('link',{name:'Download patched image (.tar)'})).not.toBeInTheDocument();
    expect(screen.getByText('Patched artifact unavailable')).toBeInTheDocument();
    expect(screen.getByText('fingerprint')).toBeInTheDocument();
    expect(screen.getByText('· 00:01:02')).toBeInTheDocument();
    expect(screen.getByText('No vulnerability observations were reported.')).toHaveAttribute('colspan','7');
  });
});
