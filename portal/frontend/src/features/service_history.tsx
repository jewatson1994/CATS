import {useState} from 'react';
import type {PageData} from '../api';
import {EmptyState, Icon, MetricCard, MetricGrid, SeverityBadge, StatusBadge} from '../components/ui';

const tabs = ['Overview', 'Dependencies', 'Findings', 'Releases'] as const;
type Row = Record<string, string | number | null | undefined>;
type Column = [field: string, label: string];
type ScanOption = {scan_id: string; key: string; at?: string; name?: string; source: 'native' | 'imported'};
type Snapshot = {
  scan_id: string; key: string; at?: string; scope?: string; complete?: boolean; source_files?: string[];
  data: {
    service: Row; service_overview: {description?: string; artifacts?: Row[]; ports?: Row[]; accounts?: Row[]; compose?: {services?: Row[]};
      helm_chart_graph?: {charts?: Row[]}; missing_evidence?: Row[]; dependencies?: Row[]; warnings?: Row[]};
    findings: Row[]; policy_findings: Row[]; sbom_components: Row[];
  };
};

function EvidenceTable({title, rows, columns, empty, heading: Heading = 'h3'}: {
  title: string; rows: Row[]; columns: Column[]; empty: string; heading?: 'h2' | 'h3';
}) {
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const needle = query.trim().toLowerCase();
  const filtered = needle ? rows.filter(row => columns.some(([field]) =>
    String(row[field] ?? '').toLowerCase().includes(needle))) : rows;
  const size = 25;
  const pages = Math.ceil(filtered.length / size);
  return <section className="panel padded">
    <div className="panel-head"><Heading>{title}</Heading>{rows.length > size &&
      <label>Search {title.toLowerCase()}<input type="search" value={query} onChange={event => {
        setQuery(event.target.value); setPage(0);
      }}/></label>}</div>
    {filtered.length ? <div className="table-wrap"><table><thead><tr>{columns.map(([field, label]) =>
      <th scope="col" key={field}>{label}</th>)}</tr></thead><tbody>
      {filtered.slice(page * size, (page + 1) * size).map((row, index) => <tr key={index}>
        {columns.map(([field]) => <td key={field}>{field === 'severity' ? <SeverityBadge severity={row[field]}/> : row[field] ?? '—'}</td>)}
      </tr>)}
    </tbody></table></div> : <p>{rows.length ? 'No matching entries.' : empty}</p>}
    {pages > 1 && <nav className="pagination" aria-label={title + ' pages'}>
      <button className="secondary-button" type="button" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button>
      <span>Page {page + 1} of {pages}</span>
      <button className="secondary-button" type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
    </nav>}
  </section>;
}

function Overview({snapshot}: {snapshot: Snapshot}) {
  const evidence = snapshot.data, inventory = evidence.service_overview || {};
  const artifacts = inventory.artifacts || [], files = snapshot.source_files || [];
  return <>
    {(evidence.service?.description || inventory.description) && <p>{evidence.service?.description || inventory.description}</p>}
    <MetricGrid label="Captured inventory">
      <MetricCard label="Artifacts" value={artifacts.length}/>
      <MetricCard label="SBOM components" value={evidence.sbom_components?.length || 0}/>
      <MetricCard label="Vulnerability findings" value={evidence.findings?.length || 0}/>
      <MetricCard label="Policy findings" value={evidence.policy_findings?.length || 0}/>
    </MetricGrid>
    <EvidenceTable title="Artifact inventory" rows={artifacts}
      columns={[['type','Type'],['artifact','Artifact'],['version','Version'],['registry','Registry'],
        ['repository','Repository'],['digest','Digest']]} empty="No artifacts were retained in this scan."/>
    {Boolean(inventory.compose?.services?.length) && <EvidenceTable title="Compose services" rows={inventory.compose!.services!}
      columns={[['name','Service'],['image','Image'],['status','Status']]} empty="No Compose services retained."/>}
    {Boolean(inventory.helm_chart_graph?.charts?.length) && <EvidenceTable title="Helm chart hierarchy"
      rows={inventory.helm_chart_graph!.charts!} columns={[['chart','Chart'],['version','Version'],['parent_chart_name','Parent chart'],
        ['resource_count','Resources'],['image_count','Images']]} empty="No Helm chart hierarchy retained."/>}
    {Boolean(inventory.ports?.length) && <EvidenceTable title="Ports" rows={inventory.ports!}
      columns={[['port','Port'],['protocol','Protocol'],['service','Service'],['declared_by','Declared by']]} empty="No ports retained."/>}
    {Boolean(inventory.accounts?.length) && <EvidenceTable title="Accounts" rows={inventory.accounts!}
      columns={[['name','Name'],['scope','Scope'],['relationships','Relationships']]} empty="No accounts retained."/>}
    {Boolean(inventory.missing_evidence?.length) && <EvidenceTable title="Missing evidence" rows={inventory.missing_evidence!}
      columns={[['item','Item'],['reason','Reason'],['source_file','Source file']]} empty="No missing evidence recorded."/>}
    {Boolean(inventory.warnings?.length) && <EvidenceTable title="Scan warnings" rows={inventory.warnings!}
      columns={[['message','Warning'],['chart','Chart'],['source','Source']]} empty="No warnings recorded."/>}
    {files.length > 0 && <details className="panel padded"><summary>Retained source files ({files.length})</summary>
      <EvidenceTable title="File inventory" rows={files.map(path => ({path}))} columns={[['path','Path']]} empty="No files retained."/>
    </details>}
  </>;
}

function SnapshotContent({snapshot, tab}: {snapshot: Snapshot; tab: string}) {
  const evidence = snapshot.data;
  if (tab === 'dependencies') return <>
    {Boolean(evidence.service_overview?.dependencies?.length) && <EvidenceTable title="Deployment dependencies"
      rows={evidence.service_overview.dependencies!} columns={[['dependency','Dependency'],['used_by','Used by'],['provides','Provides'],['images','Images']]}
      empty="No deployment dependencies were retained."/>}
    <EvidenceTable title="SBOM components" rows={evidence.sbom_components || []}
      columns={[['name','Component'],['version','Version'],['ecosystem','Ecosystem'],['purl','Package URL'],['image','Image'],['license_expression','License']]}
      empty="No SBOM components were retained in this scan."/>
  </>;
  if (tab === 'findings') return <>
    <EvidenceTable title="Vulnerability findings" rows={evidence.findings || []}
      columns={[['cve','Identifier'],['severity','Severity'],['package','Package'],['installed_version','Installed'],['fixed_version','Fixed in'],['image','Image']]}
      empty="No vulnerability findings were retained in this scan."/>
    <EvidenceTable title="Policy findings" rows={evidence.policy_findings || []}
      columns={[['finding','Identifier'],['title','Finding'],['severity','Severity'],['target','Target'],['scanner','Scanner']]}
      empty="No policy findings were retained in this scan."/>
  </>;
  return <Overview snapshot={snapshot}/>;
}

function pageLink(data: PageData, replacements: Record<string, string>) {
  const params = new URLSearchParams({version: data.version, tab: data.history_tab || 'overview',
    page: String(data.page || 1), imported_page: String(data.imported_page || 1),
    page_size: String(data.page_size || 10), scan: data.selected_scan || '', ...replacements});
  if (!params.get('scan')) params.delete('scan');
  return '/services/' + encodeURIComponent(data.service.service_key) + '/history?' + params;
}

function Pagination({data, imported = false}: {data: PageData; imported?: boolean}) {
  const page = imported ? data.imported_page : data.page;
  const pages = imported ? data.imported_total_pages : data.total_pages;
  if (!(pages > 1)) return null;
  const link = (next: number) => pageLink(data, {scan: '', source: imported ? 'imported' : 'native',
    [imported ? 'imported_page' : 'page']: String(next)});
  const label = imported ? 'Imported scans' : 'Retained scans';
  return <nav className="pagination" aria-label={label + ' pages'}>
    {page > 1 && <a href={link(page - 1)}>Previous</a>}<span>{label} · Page {page} of {pages}</span>
    {page < pages && <a href={link(page + 1)}>Next</a>}
  </nav>;
}

export function Page({data}: {data: PageData}) {
  const root = '/services/' + encodeURIComponent(data.service.service_key);
  const tab = data.history_tab || 'overview';
  const native: Snapshot[] = data.snapshots || [], imported: Snapshot[] = data.imported_snapshots || [];
  const snapshots = [...native, ...imported];
  const snapshot = snapshots.find(row => row.scan_id === data.selected_scan) || snapshots[0];
  const options: ScanOption[] = data.scan_options || [];
  const selected = options.find(row => row.scan_id === data.selected_scan);
  const historicalName = snapshot?.data.service?.name || selected?.name || data.service.service_key;
  const releases: Row[] = data.releases || [];
  return <>
    <a className="back" href={root + '?overview=true'}><Icon name="arrowLeft"/>Current service workspace</a>
    <section className="heading"><div><p className="eyebrow">{data.service.service_key}</p>
      <h1>{historicalName}</h1><p>Historical evidence · Version {data.version}</p></div>
      {data.versions?.length > 1 && <form action={root + '/history'} method="get" className="filter-bar">
        <input type="hidden" name="tab" value={tab}/><label>Version<select name="version" key={data.version} defaultValue={data.version}>
          {data.versions.map((version: string) => <option key={version}>{version}</option>)}</select></label><button className="secondary-button">View version</button>
      </form>}
    </section>
    <nav className="service-tabs" aria-label="Historical service views">{tabs.map(label => {
      const id = label.toLowerCase();
      return <a key={id} href={pageLink(data, {tab: id})} className={tab === id ? 'active' : ''} aria-current={tab === id ? 'page' : undefined}>{label}</a>;
    })}</nav>
    {tab === 'releases' ? <EvidenceTable key={data.version} heading="h2" title="Releases" rows={releases}
      columns={[['release_key','Release'],['approved_at','Approved'],['source','Source'],['scan','Source scan'],['digest','Evidence digest']]}
      empty={'No approved release evidence is linked to version ' + data.version + '.'}/> : <>
      {snapshot ? <>
        <section className="section-intro"><div>
          <h2>{tabs.find(label => label.toLowerCase() === tab)}</h2>
          <p>{snapshot.at || 'Date unavailable'} · {snapshot.scope || 'Unknown scope'} scan · <code>{snapshot.key}</code></p>
          {imported.includes(snapshot) ? <StatusBadge value="imported" label="Imported evidence"/> :
            <StatusBadge value={snapshot.complete ? 'complete' : 'incomplete'} label={snapshot.complete ? 'Complete scan' : 'Incomplete scan'}/>}
        </div>
        {options.length > 1 && <form action={root + '/history'} method="get" className="filter-bar">
          <input type="hidden" name="version" value={data.version}/><input type="hidden" name="tab" value={tab}/>
          <input type="hidden" name="page_size" value={String(data.page_size || 10)}/>
          <label>Retained scan<select name="scan" key={snapshot.scan_id} defaultValue={snapshot.scan_id}>
            {(['native', 'imported'] as const).map(source => {
              const rows = options.filter(row => row.source === source);
              return rows.length > 0 && <optgroup key={source} label={source === 'native' ? 'Service scans' : 'Imported scans'}>
                {rows.map(row => <option key={row.scan_id} value={row.scan_id}>{row.at || 'Undated'} · {row.key}</option>)}</optgroup>;
            })}
          </select></label><button className="secondary-button">View scan</button>
        </form>}
        </section>
        <SnapshotContent key={snapshot.scan_id + tab} snapshot={snapshot} tab={tab}/>
      </> : <EmptyState title="No retained scans">No scan evidence is available for version {data.version}.</EmptyState>}
      <Pagination data={data}/><Pagination data={data} imported/>
    </>}
  </>;
}
