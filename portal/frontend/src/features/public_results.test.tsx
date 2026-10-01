import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {Page} from './public_results';
afterEach(cleanup);
const finding = {type:'Vulnerability',finding:'cve-2026-1234',scanner:'Grype',severity:'High',state:'Active',image:'app:1',target:'openssl',kev:'No',epss:0.125,details:'<script>alert(1)</script>',remediation:'Upgrade'};
const base = {job:{job_id:'test'},service:{name:'Example'},vulnerability_count:1,configuration_count:1,rows:[finding,{...finding,type:'Configuration',finding:'CFG-1'}],simplified_rows:[{type:'Vulnerability',finding_ids:[finding.finding],finding_indices:[0],count:1,severity:'High',image:'app:1',remediation:'Upgrade'}],overview_data:{source:'Submitted scan evidence'}};
describe('public scan results', () => {
  it('preserves exports, raw/simplified filters and safe finding detail references', () => {
    const previous = HTMLDialogElement.prototype.showModal;
    HTMLDialogElement.prototype.showModal = vi.fn(function(this:HTMLDialogElement) {this.setAttribute('open','');});
    render(<Page data={{...base,missing_evidence:true}}/>);
    expect(screen.getByRole('link',{name:'Export to Excel'})).toHaveAttribute('href','/api/public/jobs/test/export.xlsx');
    expect(screen.getByText('Completed with missing evidence')).toHaveClass('bad');
    fireEvent.click(screen.getByRole('button',{name:'Raw Findings'}));
    expect(screen.getAllByText('0.13')[0]).toBeVisible();
    fireEvent.change(screen.getByLabelText('Type'),{target:{value:'Vulnerability'}});
    expect(screen.getByRole('button',{name:'CFG-1',hidden:true}).closest('tr')).not.toBeVisible();
    fireEvent.click(screen.getByRole('button',{name:'Simplified Findings'}));
    fireEvent.click(screen.getByRole('button',{name:finding.finding}));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText(finding.details)).toBeInTheDocument();
    expect(dialog.querySelector('script')).toBeNull();
    expect(within(dialog).getByRole('link',{name:'NVD reference'})).toHaveAttribute('href','https://nvd.nist.gov/vuln/detail/CVE-2026-1234');
    HTMLDialogElement.prototype.showModal = previous;
  });
  it('paginates static overview evidence and exposes diagnostics without policy actions', () => {
    render(<Page data={{...base,overview_data:{source:'Helm',warnings:[{message:'Warning',original_error:'diagnostic',unrecognized_images:['unknown:1']}],ports:Array.from({length:11},(_,i)=>({port:String(i+1),protocol:'TCP',service:'app',declared_by:'chart'}))}}}/>);
    const pages = screen.getByLabelText('Ports & Protocols pages');
    expect(within(pages).getByText('1–10 of 11')).toBeInTheDocument();
    fireEvent.click(within(pages).getByRole('button',{name:'Next'}));
    expect(within(pages).getByText('11–11 of 11')).toBeInTheDocument();
    expect(screen.getByText('Helm diagnostic')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Remove'})).not.toBeInTheDocument();
  });
});
