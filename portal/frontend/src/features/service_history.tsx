import {type PageData} from '../api';

function Snapshot({snapshot, imported = false}: {snapshot: any; imported?: boolean}) {
  return <section className="panel padded"><h2>{snapshot.key}</h2><p>{snapshot.at} · {snapshot.scope}{!imported && ` · ${snapshot.complete ? 'Complete' : 'Incomplete'}`}</p>{Object.entries(snapshot.data || {}).map(([key, value]) => <details key={key}><summary>{key.replaceAll('_', ' ').replace(/\b\w/g, char => char.toUpperCase())}</summary><pre>{JSON.stringify(value, null, 2)}</pre></details>)}<details><summary>Retained source file inventory</summary><pre>{(snapshot.source_files || []).join('\n')}</pre></details></section>;
}
export function Page({data}: {data: PageData}) {
  const root = `/services/${encodeURIComponent(data.service.service_key)}`;
  return <><a href={root}>Current service workspace</a><h1>Historical evidence — {data.version}</h1><form method="get"><label>Version<select name="version" defaultValue={data.version}>{(data.versions || []).map((version: string) => <option key={version}>{version}</option>)}</select></label><button>View version</button></form><p>This read-only view contains only retained scans for the selected version. Current approvals, remediation state and editable workspaces are not historical snapshots and are not mixed into this view.</p><a href={`${root}/exchange?version=${encodeURIComponent(data.version || '')}`}>Export / import selected version</a><Pagination data={data}/>{data.snapshots?.length ? data.snapshots.map((snapshot: any, index: number) => <Snapshot snapshot={snapshot} key={index}/>) : <p>No scan evidence exists for this version.</p>}{data.imported_snapshots?.length > 0 && <><h2>Imported historical evidence (informational only)</h2><p>These results were produced elsewhere. They do not populate current findings, approvals, or compliance.</p><Pagination data={data} imported/>{data.imported_snapshots.map((snapshot: any, index: number) => <Snapshot snapshot={snapshot} imported key={index}/>)}</>}</>;
}

function Pagination({data, imported = false}: {data: PageData; imported?: boolean}) {
  const page = imported ? data.imported_page : data.page;
  const pages = imported ? data.imported_total_pages : data.total_pages;
  if (!(pages > 1)) return null;
  const link = (next: number) => {
    const params = new URLSearchParams({version: data.version || '', page_size: String(data.page_size || 10),
      page: String(imported ? data.page || 1 : next), imported_page: String(imported ? next : data.imported_page || 1)});
    return `/services/${encodeURIComponent(data.service.service_key)}/history?${params}`;
  };
  return <nav className="pagination" aria-label={imported ? 'Imported history pages' : 'Scan history pages'}>
    {page > 1 && <a href={link(page - 1)}>Previous</a>}<span>Page {page} of {pages}</span>
    {page < pages && <a href={link(page + 1)}>Next</a>}
  </nav>;
}
