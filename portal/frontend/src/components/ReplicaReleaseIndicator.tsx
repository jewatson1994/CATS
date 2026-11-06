import {useReplicaResource} from '../hooks/useReplicaResource';
import {StatusBadge} from './ui';

/** Assessment posture is captured evidence; distribution status comes from local policy. */
export function ReplicaReleaseIndicator({serviceKey}: {serviceKey: string}) {
  const {value, error} = useReplicaResource<{releases: {id: number; sequence: number; status: string; expires_at?: string}[]}>(
    `/api/replica/releases?service_key=${encodeURIComponent(serviceKey)}`, 15000);
  const latest = value?.releases?.reduce<(NonNullable<typeof value>['releases'][number]) | undefined>(
    (current, row) => !current || row.sequence > current.sequence ? row : current, undefined);
  return <aside className="panel padded" aria-label="Local release enforcement">
    <strong>OCI release enforcement</strong>
    {error ? <p role="status">Current release status unavailable. Previously displayed status is not an authorization decision.</p>
      : latest ? <p>Latest imported release {latest.sequence} · <StatusBadge value={latest.status} label={latest.status === 'active' ? 'Approved release active' : undefined}/>{latest.expires_at && <> · Expires {new Date(latest.expires_at).toLocaleString()}</>}</p>
        : <p role="status">{value ? 'No verified release is available.' : 'Checking local release status…'}</p>}
    <p>Captured assessment results describe the publisher’s evidence. Each pull also checks current release validity, trust and any separately recorded local Cyber override.</p>
    <a href={`/approved-releases?service=${encodeURIComponent(serviceKey)}`}>Review release history and captured evidence</a>
  </aside>;
}
