import {useEffect, useState} from 'react';
import {requestJson} from '../api';

export function OverrideIndicator({serviceKey, releaseId}: {serviceKey: string; releaseId?: number}) {
  const [count, setCount] = useState(0), [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    requestJson<{overrides: {status: string; release_id?: number}[]}>(`/api/services/${encodeURIComponent(serviceKey)}/local-overrides`, {signal: controller.signal})
      .then(value => {if (!controller.signal.aborted) {setCount(value.overrides.filter(row => row.status === 'active' && (releaseId == null || row.release_id === releaseId)).length); setFailed(false);}})
      .catch(() => {if (!controller.signal.aborted) setFailed(true);});
    return () => controller.abort();
  }, [serviceKey, releaseId]);
  const href = `/services/${encodeURIComponent(serviceKey)}/cyber-overrides`;
  return count ? <aside className="panel padded" role="status"><strong>Mission-continuity exception active</strong><p>{count} local Cyber override{count === 1 ? '' : 's'} recorded for specifically scoped artifacts. Distribution still checks trust and the current denial condition. Imported release status and compliance are unchanged.</p><a href={href}>Review local Cyber overrides</a></aside> : failed ? <p role="status">Local override status unavailable. <a href={href}>Review enforcement status</a></p> : null;
}
