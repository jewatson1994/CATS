export interface ComposeModel {
  services: { name: string; image?: string | null; configuration?: unknown; source_files?: string[]; status?: string; image_scan?: string }[];
  images?: string[];
  issues?: { code: string; message: string; service?: string; source?: string; blocking?: boolean }[];
  complete: boolean;
  coverage?: {services?: number; unique_images?: number; scanned_images?: number; preview?: boolean};
}
export function ComposeInventory({ model, preview = false }: { model: ComposeModel; preview?: boolean }) {
  return <section aria-label="Compose inventory" className="normalized-overview">
    <h3>{preview ? 'Compose preview' : 'Compose inventory'}</h3>
    <p className="muted">{model.complete ? 'Compose discovery complete.' : 'Compose discovery is incomplete; review the issues below.'} No images were built and no containers were started.{preview && ' No vulnerability or configuration scans were run.'}</p>
    <p><strong>Unique images:</strong> {model.images?.length ? model.images.join(', ') : 'None discovered'}</p>
    {model.coverage && !preview && <p><strong>Image scan coverage:</strong> {model.coverage.scanned_images ?? 0} / {model.coverage.unique_images ?? model.images?.length ?? 0} unique images scanned.</p>}
    <div className="overview-table-wrap"><table className="overview-table"><thead><tr><th>Service</th><th>Image</th><th>Status</th><th>Image scan</th><th>Source files</th><th>Configuration</th></tr></thead><tbody>
      {model.services?.length ? model.services.map((service, index) => <tr key={index}><td>{service.name}</td><td><code>{service.image || 'No image declared'}</code></td><td>{service.status?.replaceAll('_', ' ') || 'Discovered'}</td><td>{service.image_scan?.replaceAll('_', ' ') || (preview ? 'Not scanned' : 'Not reported')}</td><td>{service.source_files?.join(', ') || '—'}</td><td>{service.configuration != null ? <details><summary>Declared configuration</summary><pre>{typeof service.configuration === 'string' ? service.configuration : JSON.stringify(service.configuration, null, 2)}</pre></details> : '—'}</td></tr>) : <tr><td colSpan={6}>No Compose services discovered.</td></tr>}
    </tbody></table></div>
    {!!model.issues?.length && <div className="overview-render-warning"><h4>Compose issues</h4><ul>{model.issues.map((issue, index) => <li key={index}><strong>{issue.blocking ? 'Blocking' : 'Warning'} · {issue.code}</strong>: {issue.message}{issue.service && <> · Service: {issue.service}</>}{issue.source && <> · Source: {issue.source}</>}</li>)}</ul></div>}
  </section>;
}
