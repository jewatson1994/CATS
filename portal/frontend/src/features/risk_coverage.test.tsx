import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {IntelligenceCoverage, ObservationIntelligence} from './risk_coverage';
import {requestJson} from '../api';
vi.mock('../api', async () => ({...await vi.importActual('../api'), requestJson: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});
const counts = {authoritative_vex: 3, applicable_vex: 2, advisory_only: 1, kev: 2, epss: 4, no_intelligence: 0, unresolved_identity: 1, stale_or_conflicting: 1};
const coverage = {denominator: 'unique_findings', total_findings: 4, counts, images: [
  {image: 'ubuntu:24.04', image_digest: 'sha256:ubuntu', total_findings: 3, counts: {...counts, authoritative_vex: 2, epss: 3}},
  {image: 'python:3.12', image_digest: 'sha256:python', total_findings: 2, counts: {...counts, authoritative_vex: 1, epss: 2}},
]};
const assessment = {id: 7, source_execution_id: 9, as_of: '2026-10-20T00:00:00Z', summary: {coverage}};
it('uses the saved unique-finding denominator separately for service and image coverage', () => {
  render(<IntelligenceCoverage assessment={assessment}/>);
  const service = screen.getByRole('table', {name: 'Service coverage — 4 unique findings'});
  const row = within(service).getByRole('row', {name: /Exact VEX candidate evidence/});
  expect(within(row).getByText('3 / 4')).toBeInTheDocument();
  expect(within(row).getByText('75.0%')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Image: ubuntu:24.04 · sha256:ubuntu'));
  const ubuntu = screen.getByRole('table', {name: 'Coverage for ubuntu:24.04 — 3 unique findings'});
  const imageRow = within(ubuntu).getByRole('row', {name: /Exact VEX candidate evidence/});
  expect(within(imageRow).getByText('2 / 3')).toBeInTheDocument();
  expect(within(imageRow).getByText('66.7%')).toBeInTheDocument();
  expect(screen.getByText(/Categories overlap and must not be added together/)).toBeInTheDocument();
  expect(screen.getByText(/Image totals must not be added/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Reproducible coverage data'));
  expect(screen.getByText(/"source_execution_id": 9/)).toBeInTheDocument();
  expect(requestJson).not.toHaveBeenCalled();
});
it('does not show missing historical coverage or absent metrics as zero', () => {
  const view = render(<IntelligenceCoverage assessment={{id: 6, summary: {}}}/>);
  expect(screen.getByText(/coverage was not recorded/)).toBeInTheDocument();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  view.rerender(<IntelligenceCoverage assessment={{...assessment, summary: {coverage: {...coverage, counts: {authoritative_vex: 1}, images: []}}}}/>);
  const row = screen.getByRole('row', {name: /Verified applicable VEX/});
  expect(within(row).getAllByText('Not recorded')).toHaveLength(2);
});
it('does not invent percentages when there are no findings', () => {
  render(<IntelligenceCoverage assessment={{...assessment, summary: {coverage: {total_findings: 0, counts: Object.fromEntries(Object.keys(counts).map(key => [key, 0]))}}}}/>);
  expect(screen.getAllByText('Not applicable (no findings)')).toHaveLength(8);
  expect(screen.queryByText(/NaN|Infinity|0\.0%/)).not.toBeInTheDocument();
});
it('distinguishes missing CVEs from rejected identities when recorded', () => {
  render(<IntelligenceCoverage assessment={{...assessment, summary: {coverage: {...coverage, counts: {...counts, cve_absent: 1, identity_rejected: 2}, images: [], definitions: {cve_absent: 'No CVE candidate exists'}}}}}/>);
  expect(screen.getByRole('row', {name: 'No matching CVE in VEX 1 / 4 25.0%'})).toBeInTheDocument();
  expect(screen.getByRole('row', {name: 'Rejected identity matches 2 / 4 50.0%'})).toBeInTheDocument();
});
it('shows accepted and rejected identifiers, reasons and source references without fetching originals until asked', async () => {
  vi.mocked(requestJson).mockResolvedValue({id: 4, raw_text: '<script>unsafe()</script>'});
  render(<ObservationIntelligence assessmentId={7} observation={{identity: {purl: 'pkg:deb/ubuntu/openssl@3?arch=amd64'}, vex: {
    status: 'under_investigation', reasons: ['missing_product_context'],
    statements: [{id: 3, document_id: 4, source_id: 5, source: 'Ubuntu', status: 'affected', accepted: true, reason: null, sha256: 'digest-123', identity: {product_id: 'pkg:deb/ubuntu/openssl@3?arch=amd64'}}],
    rejected_candidates: [{id: 8, document_id: 9, source_id: 10, source: 'Red Hat', status: 'not_affected', reason: 'wrong_containing_product', identity: {csaf_product_context: 'rhel-9-server'}}],
  }}}/>);
  fireEvent.click(screen.getByText('VEX acceptance and rejection evidence (2 retained)'));
  expect(screen.getByText('Accepted for applicability · Ubuntu')).toBeInTheDocument();
  expect(screen.getByText('Not accepted for applicability · Red Hat')).toBeInTheDocument();
  expect(screen.getByText('Reason: wrong containing product.')).toBeInTheDocument();
  expect(screen.getByText(/Statement #3 · document #4 · source #5/)).toBeInTheDocument();
  expect(screen.getByText('digest-123')).toBeInTheDocument();
  expect(requestJson).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', {name: 'Inspect original VEX document #4'}));
  expect(await screen.findByText(/<script>unsafe\(\)<\/script>/)).toBeInTheDocument();
  expect(requestJson).toHaveBeenCalledWith('/api/risk/assessments/7/documents/4');
  expect(document.querySelector('script')).toBeNull();
});
it('keeps advisory evidence distinct from VEX acceptance and exposes the original local record', async () => {
  vi.mocked(requestJson).mockResolvedValue({id: 22, data: {id: 'GHSA-real-id'}});
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'no_vex', statements: []}, advisory: {
    records: [{id: 22, record_id: 'GHSA-real-id', source: {name: 'GitHub'}, kind: 'advisory', match_reason: 'cve_alias', product: 'pkg:npm/package'}],
  }}}/>);
  expect(screen.getByText('VEX: No VEX')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Supplemental advisory evidence (1)'));
  expect(screen.getByText(/They do not establish authoritative VEX applicability/)).toBeInTheDocument();
  expect(screen.getByText('Correlation: cve alias')).toBeInTheDocument();
  expect(screen.queryByText(/Accepted for applicability/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Inspect original advisory record #22'}));
  expect(await screen.findByRole('button', {name: 'Close original advisory record #22'})).toBeInTheDocument();
  expect(requestJson).toHaveBeenCalledWith('/api/risk/records/22');
});
it('retains the unresolved-finding explanation for a verified Fixed statement', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'fixed', statements: []}}}/>);
  expect(screen.getByText('VEX: Verified Fixed')).toBeInTheDocument();
  expect(screen.getByText('A Fixed statement does not resolve the original scanner finding.')).toBeInTheDocument();
});
it('shows failed evidence retrieval as an error without replacing the evaluation', async () => {
  vi.mocked(requestJson).mockRejectedValue(new Error('Evidence exceeds the response limit'));
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'stale', statements: [{id: 1, document_id: 2, source: 'Vendor', reason: 'stale'}]}}}/>);
  fireEvent.click(screen.getByText('VEX acceptance and rejection evidence (1 retained)'));
  fireEvent.click(screen.getByRole('button', {name: 'Inspect original VEX document #2'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Evidence exceeds the response limit');
  expect(screen.getByText('VEX: Stale VEX')).toBeInTheDocument();
});
it('does not present absent or explicitly rejected acceptance as verified', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'under_investigation', statements: [
    {id: 1, source: 'Incomplete record'}, {id: 2, source: 'Rejected record', accepted: false, reason: null},
  ], rejected_candidates: [{id: 3, source: 'Rejected candidate', accepted: true, reason: 'wrong_version'}]}}}/>);
  fireEvent.click(screen.getByText('VEX acceptance and rejection evidence (3 retained)'));
  expect(screen.getByText('Not accepted for applicability · Incomplete record')).toBeInTheDocument();
  expect(screen.getByText('Not accepted for applicability · Rejected record')).toBeInTheDocument();
  expect(screen.getByText('Not accepted for applicability · Rejected candidate')).toBeInTheDocument();
  expect(screen.queryByText(/^Accepted for applicability/)).not.toBeInTheDocument();
});

it('labels presence samples and bounded rejection evidence without claiming full rejection coverage', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'no_vex', applicability_state: 'missing_context',
    rejected_candidates_truncated: true, rejected_candidates: [{id: 3, document_id: 4, source: 'Vendor', accepted: true, sample_only: true, reason: 'different_product_identity_sample'}],
  }}}/>);
  expect(screen.getByText('VEX: Unresolved product identity')).toBeInTheDocument();
  fireEvent.click(screen.getByText('VEX acceptance and rejection evidence (1 retained)'));
  expect(screen.getByText('CVE presence sample · Vendor')).toBeInTheDocument();
  expect(screen.getByText(/does not represent all rejected candidates/)).toBeInTheDocument();
  expect(screen.getByText(/This list is incomplete/)).toBeInTheDocument();
  expect(screen.queryByText(/^Accepted for applicability/)).not.toBeInTheDocument();
});
it('explains advisory range and fixed-version comparisons that have not been evaluated', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'no_vex'}, advisory: {truncated: true, records: [
    {id: 1, source: 'OSV', match_reason: 'package_reference_ranges_not_evaluated', current: true},
    {id: 2, source: 'Alpine', match_reason: 'package_reference_secdb_fix_not_evaluated', current: false, reason: 'advisory_stale'},
  ]}}}/>);
  fireEvent.click(screen.getByText('Supplemental advisory evidence (2)'));
  expect(screen.getByText(/affected version ranges have not been evaluated/)).toBeInTheDocument();
  expect(screen.getByText(/the fixed-version comparison has not been evaluated/)).toBeInTheDocument();
  expect(screen.getByText('Current source evidence.')).toBeInTheDocument();
  expect(screen.getByText(/Source evidence does not pass current trust and freshness checks: advisory stale/)).toBeInTheDocument();
  expect(screen.getByText(/The advisory evidence list is limited/)).toBeInTheDocument();
});

it('separates original and resolved identities with provenance and direct versus resolved coverage', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{identity: {
    raw_purl: 'pkg:deb/ubuntu/libssl3@3?distro=ubuntu-22.04', raw_installed_version: '3',
    resolution: {resolver_version: 'cats-package-identity/v1', outcome: 'authoritatively_resolved_identity',
      candidates: [{kind: 'authoritative_resolved', eligible: true, relationship: 'installed_binary_to_source',
        context: {purl: 'pkg:deb/ubuntu/openssl@3?arch=source&distro=jammy'}, valid_until: '2026-10-21',
        provenance_chain: [{relation: 'installed_binary_to_source', source: 'Debian package metadata',
          evidence_path: 'sbom_artifact.metadata', source_version: {name:'syft',version:'1.31.0'}, observed_at:'2026-10-20',
          details: {source_name: 'openssl'}}]}]},
  }, vex: {status:'not_affected', statements:[]}}}/>);
  expect(screen.getByRole('region', {name:'Package identity resolution'})).toBeInTheDocument();
  expect(screen.getByText('pkg:deb/ubuntu/libssl3@3?distro=ubuntu-22.04')).toBeInTheDocument();
  expect(screen.getByText('pkg:deb/ubuntu/openssl@3?arch=source&distro=jammy')).toBeInTheDocument();
  expect(screen.getByText(/Source version: syft 1.31.0/)).toHaveTextContent('Observed: 2026-10-20');
  expect(screen.getByText(/applicability still requires trusted, current evidence/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Supporting evidence: sbom_artifact.metadata'));
  expect(within(screen.getByRole('region', {name: 'Package identity resolution'})).getByText(/"source_name": "openssl"/)).toBeInTheDocument();
  expect(requestJson).not.toHaveBeenCalled();
});
it('shows unresolved mapping warnings without presenting invented identities', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{identity:{resolution:{
    outcome:'no_verified_relationship', reasons:['source_rpm_epoch_and_vendor_product_context_unverified'],
    candidates:[{kind:'exact_observed',context:{purl:'pkg:rpm/redhat/bash@5'}}],
    relationships:[{relation:'installed_binary_to_source_rpm',details:{source_epoch:null}}],
  }}, vex:{status:'no_vex'}}}/>);
  expect(screen.getByText(/Unresolved evidence: source rpm epoch and vendor product context unverified/)).toBeInTheDocument();
  expect(screen.getByText('No additional authoritative identity is eligible for VEX matching.')).toBeInTheDocument();
  expect(screen.queryByText('Derived identity 1')).not.toBeInTheDocument();
});
it('records separate direct and derived coverage without adding absent historical metrics', () => {
  render(<IntelligenceCoverage assessment={{...assessment,summary:{coverage:{...coverage,images:[],counts:{...counts,
    direct_vex_candidates:1,resolved_identity:3,resolved_vex_candidates:2,direct_applicable_vex:1,resolved_applicable_vex:1}}}}}/>);
  expect(screen.getByRole('row',{name:'Authoritatively resolved package identities 3 / 4 75.0%'})).toBeInTheDocument();
  expect(screen.getByRole('row',{name:'Applicable VEX through resolved identities 1 / 4 25.0%'})).toBeInTheDocument();
});
it('keeps a missing scanner identity distinct from a verified SBOM identity and its provenance', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{identity: {
    raw_purl: null, raw_installed_version: '3', context: {purl: 'pkg:deb/ubuntu/libssl3@3', version: '3'},
    scanner_identity: {raw_purl: null, raw_installed_version: null, context: {}, reasons: ['missing_package_identity']},
    sbom_artifact: {id: 'artifact-7', name: 'libssl3', version: '3'},
    sbom_binding: {status: 'matched', reasons: [], component_id: 41, provenance: {execution_id: 9,
      component_ref: 'artifact-7', binding_kind: 'artifact_id', image: 'ubuntu', digest: 'sha256:image',
      platform: 'linux/amd64', sbom_digest: 'sha256:sbom'}},
    resolution: {outcome: 'no_verified_relationship', candidates: []},
  }, vex: {status: 'no_vex', cve_present: true, exact_candidate_count: 0, direct_applicable_count: 0, resolved_applicable_count: 0}}}/>);
  const identity = within(screen.getByRole('region', {name: 'Package identity resolution'}));
  expect(identity.getByText('Original scanner identity').nextElementSibling).toHaveTextContent('Not recorded');
  expect(identity.getByText('Installed version').nextElementSibling).toHaveTextContent('Not recorded');
  expect(identity.getByText('SBOM component identity used for lookup').nextElementSibling).toHaveTextContent('pkg:deb/ubuntu/libssl3@3');
  expect(identity.getByText('Verified component binding')).toBeInTheDocument();
  expect(identity.getByText(/It does not establish VEX applicability/)).toBeInTheDocument();
  fireEvent.click(identity.getByText('SBOM binding provenance and original records'));
  expect(identity.getByText('Scan execution').nextElementSibling).toHaveTextContent('9');
  expect(identity.getByText('Component reference').nextElementSibling).toHaveTextContent('artifact-7');
  expect(identity.getByText('sha256:sbom')).toBeInTheDocument();
  expect(identity.getByText('Original scanner record').nextElementSibling).toHaveTextContent('"raw_purl": null');
  const lookup = within(screen.getByRole('region', {name: 'VEX lookup and applicability'}));
  expect(lookup.getByText('CVE or alias present in VEX').nextElementSibling).toHaveTextContent('Present');
  expect(lookup.getByText('Exact identity candidates').nextElementSibling).toHaveTextContent('0');
  expect(lookup.getByText('Statements passing applicability checks').nextElementSibling).toHaveTextContent('0');
  expect(requestJson).not.toHaveBeenCalled();
});
it.each([
  ['missing', 'No matching component'], ['ambiguous', 'Multiple components match'],
  ['conflict', 'Conflicting component evidence'], ['scope_missing', 'Scan or image scope is missing'],
])('shows a failed %s binding without promoting a correlated identity', (status, label) => {
  render(<ObservationIntelligence assessmentId={7} observation={{identity: {
    scanner_identity: {raw_purl: 'pkg:npm/original@1', raw_installed_version: '1'},
    context: {purl: 'pkg:npm/unaccepted@1'}, sbom_binding: {status, reasons: ['sbom_binding_unverified']},
  }, vex: {status: 'under_investigation', cve_present: true, exact_candidate_count: 1,
    direct_applicable_count: 0, resolved_applicable_count: 0}}}/>);
  expect(screen.getByText(label)).toBeInTheDocument();
  expect(screen.getByText('Binding reasons: sbom binding unverified.')).toBeInTheDocument();
  expect(screen.getByText('pkg:npm/original@1')).toBeInTheDocument();
  expect(screen.queryByText('SBOM component identity used for lookup')).not.toBeInTheDocument();
  const lookup = within(screen.getByRole('region', {name: 'VEX lookup and applicability'}));
  expect(lookup.getByText('Exact identity candidates').nextElementSibling).toHaveTextContent('1');
  expect(lookup.getByText('Statements passing applicability checks').nextElementSibling).toHaveTextContent('0');
});
it('does not interpret absent historical lookup metrics as an empty corpus or zero candidates', () => {
  render(<ObservationIntelligence assessmentId={7} observation={{vex: {status: 'under_investigation'}}}/>);
  const lookup = within(screen.getByRole('region', {name: 'VEX lookup and applicability'}));
  expect(lookup.getByText('Not established')).toBeInTheDocument();
  expect(lookup.getAllByText('Not recorded')).toHaveLength(2);
  expect(lookup.queryByText('0')).not.toBeInTheDocument();
});
