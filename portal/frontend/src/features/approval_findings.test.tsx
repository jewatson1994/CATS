import {cleanup, fireEvent, render, screen, within} from '@testing-library/react';
import {afterEach, expect, it} from 'vitest';
import {ApprovalFindings, reviewFindings} from './approval_findings';

afterEach(cleanup);
it('filters by the exact selected container, combines filters and resets pagination', () => {
  const image = 'harbor.example/team/app:1';
  render(<ApprovalFindings findings={[
    ...Array.from({length:30}, (_, i) => ({cve:`CVE-APP-${i}`, image, severity:'High', kev:i === 0})),
    {cve:'CVE-SIMILAR', image:`${image}0`, severity:'High', kev:true},
    {cve:'CVE-LOW', image, severity:'Low', kev:true},
  ]}/>);
  const table = within(screen.getByRole('table'));
  fireEvent.click(screen.getByRole('button', {name:'high: 31 observations'}));
  fireEvent.click(screen.getByRole('button', {name:'Next'}));
  expect(screen.getByRole('status')).toHaveTextContent('26–31 of 31');
  fireEvent.click(screen.getByRole('button', {name:`Filter container ${image}`}));
  expect(screen.getByRole('button', {name:`Filter container ${image}`})).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByRole('status')).toHaveTextContent('1–25 of 30');
  fireEvent.change(screen.getByLabelText('Risk signal'), {target:{value:'kev'}});
  expect(table.getByText('CVE-APP-0')).toBeInTheDocument();
  expect(table.queryByText('CVE-SIMILAR')).not.toBeInTheDocument();
  expect(table.queryByText('CVE-LOW')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Search findings'), {target:{value:'no match'}});
  expect(table.getByText('No findings match these filters.')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Search findings'), {target:{value:''}});
  fireEvent.click(screen.getByRole('button', {name:`Filter container ${image}`}));
  expect(table.getByText('CVE-SIMILAR')).toBeInTheDocument();
  expect(screen.queryByRole('button', {name:'Clear container filter'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name:`Filter container ${image}`}));
  fireEvent.change(screen.getByLabelText('Severity'), {target:{value:'all'}});
  expect(table.getByText('CVE-LOW')).toBeInTheDocument();
  expect(table.queryByText('CVE-SIMILAR')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name:'Clear container filter'}));
  expect(table.getByText('CVE-SIMILAR')).toBeInTheDocument();
});

it('reads retained pipeline intelligence without treating missing scores or flags as zero or false', () => {
  const rows = reviewFindings({vulnerabilities:[
    {cve:'CVE-A', severity:'HIGH', package:'openssl', evidence:{epss:'0.92', kev:'Yes'}, fixed_version:'3.1'},
    {cve:'CVE-B', epss:0, kev:false}, {cve:'CVE-C'}, {cve:'CVE-D', epss:5, kev:'unknown'},
  ]});
  expect(rows[0]).toMatchObject({id:'CVE-A', severity:'high', package:'openssl', epss:.92, kev:true, fixed:'3.1'});
  expect(rows[1]).toMatchObject({epss:0, kev:false});
  expect(rows[2]).toMatchObject({epss:null, kev:null});
  expect(rows[3]).toMatchObject({epss:null, kev:null});
});

it('flattens retained Grype and Trivy candidate scans with image and package attribution', () => {
  const rows = reviewFindings({vulnerability_scans:{'api:patched':{matches:[{vulnerability:{id:'CVE-G', severity:'Critical', epss:[{epss:.96}], knownExploited:[{cve:'CVE-G'}], fix:{versions:['2.0']}},artifact:{name:'lib',version:'1.0'}}]},
    trivy:{ArtifactName:'db:patched',Results:[{Vulnerabilities:[{VulnerabilityID:'CVE-T',Severity:'Low',PkgName:'db-lib',InstalledVersion:'1',FixedVersion:'2'}]}]}}});
  expect(rows).toHaveLength(2);
  expect(rows[0]).toMatchObject({id:'CVE-G',image:'api:patched',package:'lib',version:'1.0',epss:.96,kev:true,fixed:'2.0',scanner:'Grype'});
  expect(rows[1]).toMatchObject({id:'CVE-T',image:'db:patched',package:'db-lib',version:'1',fixed:'2',scanner:'Trivy',epss:null,kev:null});
});

it('filters using severity bars, KEV, EPSS cutoff and search while keeping raw evidence available', () => {
  render(<ApprovalFindings findings={[
    {cve:'CVE-KEV',severity:'High',image:'api:1',package:'lib-a',kev:true,epss:.3},
    {cve:'CVE-EPSS',severity:'Critical',image:'db:1',epss:.95,kev:false},
    {cve:'CVE-UNKNOWN',severity:'Low',evidence:{description:'retained detail'}},
  ]}/>);
  const table = within(screen.getByRole('table'));
  expect(table.getAllByRole('row')).toHaveLength(4);
  fireEvent.change(screen.getByLabelText('Risk signal'),{target:{value:'kev'}});
  expect(table.getByText('CVE-KEV')).toBeInTheDocument();
  expect(table.queryByText('CVE-EPSS')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Risk signal'),{target:{value:'epss'}});
  expect(table.getByText('95.00%')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('EPSS review cutoff (%)'),{target:{value:'96'}});
  expect(table.getByText('No findings match these filters.')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Risk signal'),{target:{value:'all'}});
  fireEvent.click(screen.getByRole('button',{name:'low: 1 observations'}));
  expect(table.getAllByRole('row')).toHaveLength(2);
  fireEvent.click(table.getByRole('button',{name:'CVE-UNKNOWN'}));
  expect(table.getByText(/retained detail/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'low: 1 observations'}));
  fireEvent.change(screen.getByLabelText('Search findings'),{target:{value:'lib-a'}});
  expect(table.getAllByRole('row')).toHaveLength(2);
});

it('paginates a large snapshot and resets paging when filters change', () => {
  render(<ApprovalFindings findings={Array.from({length:2000},(_,i) => ({cve:`CVE-${i}`,severity:'High',image:`image:${i}`}))}/>);
  expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(26);
  expect(screen.getByRole('status')).toHaveTextContent('1–25 of 2,000');
  fireEvent.click(screen.getByRole('button',{name:'Next'}));
  expect(screen.getByRole('status')).toHaveTextContent('26–50 of 2,000');
  fireEvent.change(screen.getByLabelText('Search findings'),{target:{value:'image:1999'}});
  expect(screen.getByRole('status')).toHaveTextContent('1–1 of 1');
  expect(screen.getByRole('button',{name:'Previous'})).toBeDisabled();
});

it('does not claim a clean scan when observations are absent', () => {
  render(<ApprovalFindings findings={{summary:{total:7}}}/>);
  expect(screen.getByText(/No vulnerability observations were retained/)).toBeInTheDocument();
});

it('ranks the top five images for the selected severity and reports unattributed observations', () => {
  const findings = ['z:1','a:1','b:1','c:1','d:1','e:1'].flatMap((image, i) =>
    Array.from({length:i < 2 ? 8 : 7 - i}, () => ({cve:'CVE-REPEATED',image,severity:'High'})));
  render(<ApprovalFindings findings={[...findings,{cve:'CVE-MISSING',severity:'High'}, {image:'low:1',severity:'Low'}]}/>);
  fireEvent.click(screen.getByRole('button',{name:`high: ${findings.length + 1} observations`}));
  const ranking = within(screen.getByRole('region',{name:'Top containers for high'}));
  const items = ranking.getAllByRole('listitem');
  expect(items).toHaveLength(5);
  expect(items[0]).toHaveTextContent('a:1');
  expect(items[0]).toHaveTextContent('8 observations');
  expect(items[1]).toHaveTextContent('z:1');
  expect(ranking.queryByText('e:1')).not.toBeInTheDocument();
  expect(ranking.getByText(/1 observations have no recorded image/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Search findings'),{target:{value:'no match'}});
  expect(ranking.getAllByRole('listitem')).toHaveLength(5);
  fireEvent.click(screen.getByRole('button',{name:'low: 1 observations'}));
  expect(within(screen.getByRole('region',{name:'Top containers for low'})).getByText('low:1')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'critical: 0 observations'}));
  expect(screen.getByText('No container images recorded for this severity.')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'critical: 0 observations'}));
  expect(screen.queryByRole('region',{name:/Top containers/})).not.toBeInTheDocument();
});

it('shows frozen feed versions and uses only the corresponding review lookups', () => {
  const intelligence = {basis:'approval-request',captured_at:'2026-10-15T15:00:00+00:00',
    kev:{state:'LOADED',metadata:{catalog_version:'2026.10.14',date_released:'2026-10-14T10:00:00Z'}},
    epss:{state:'LOADED',metadata:{model_version:'v2026.06.15',score_date:'2026-10-15'}},
    findings:{'CVE-A':{kev:true,epss:.75},'CVE-B':{kev:null,epss:null}}};
  const findings = [{cve:'CVE-A',kev:false,epss:0},{cve:'CVE-B',kev:true,epss:.99}];
  expect(reviewFindings(findings,intelligence)[1]).toMatchObject({kev:null,epss:null});
  expect(findings[0]).toMatchObject({kev:false,epss:0});
  render(<ApprovalFindings findings={findings} intelligence={intelligence}/>);
  for (const value of ['2026.10.14','2026-10-14T10:00:00Z','v2026.06.15','2026-10-15']) expect(screen.getByText(value)).toBeInTheDocument();
  expect(screen.getByText(/Captured at request/)).toBeInTheDocument();
  expect(within(screen.getByRole('table')).getByText('75.00%')).toBeInTheDocument();
  expect(within(screen.getByRole('table')).getByText('KEV hit')).toBeInTheDocument();
});

it('does not invent dataset dates for older snapshots', () => {
  render(<ApprovalFindings findings={[{cve:'CVE-OLD',kev:true,epss:.9}]}/>);
  expect(screen.getByText(/Dataset provenance was not retained/)).toBeInTheDocument();
  expect(screen.getAllByText('Not recorded')).toHaveLength(5);
  expect(screen.getByText('90.00%')).toBeInTheDocument();
});
