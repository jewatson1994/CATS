import {useReplicaResource} from '../hooks/useReplicaResource';

export function OverrideIndicator({serviceKey, releaseId}: {serviceKey: string; releaseId?: number}) {
  const {value, error} = useReplicaResource<{overrides: {status: string; release_id?: number}[]}>(
    `/api/services/${encodeURIComponent(serviceKey)}/local-overrides`, 15000);
  const count = error ? 0 : value?.overrides?.filter(row => row.status === 'active' && (releaseId == null || row.release_id === releaseId)).length || 0;
  const href = `/services/${encodeURIComponent(serviceKey)}/cyber-overrides`;
  return count ? <aside className="panel padded" role="status"><strong>Mission-continuity exception active</strong><p>{count} local Cyber override{count === 1 ? '' : 's'} recorded for specifically scoped artifacts. Distribution still checks trust and the current denial condition. Imported release status and compliance are unchanged.</p><a href={href}>Review local Cyber overrides</a></aside> : error ? <p role="status">Local override status unavailable. <a href={href}>Review enforcement status</a></p> : null;
}
