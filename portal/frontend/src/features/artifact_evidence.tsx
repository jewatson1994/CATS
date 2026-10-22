export type VulnerabilityEvidence = {before: number; after: number; source_digest: string; target_digest: string; scope: string};

export function ArtifactEvidence({value}: {value?: VulnerabilityEvidence | null}) {
  if (!value || value.scope !== 'retained_image_patch' || !Number.isInteger(value.before) || !Number.isInteger(value.after) || value.before < 0 || value.after < 0) return <p>Verified image vulnerability comparison unavailable.</p>;
  return <section aria-label="Retained image vulnerability evidence"><h3>Verified image scan findings</h3><dl><dt>Before patch</dt><dd>{value.before}</dd><dt>After patch</dt><dd>{value.after}</dd><dt>Source digest</dt><dd><code>{value.source_digest}</code></dd><dt>Patched digest</dt><dd><code>{value.target_digest}</code></dd></dl><p>Counts come from the retained image patch evidence. A fresh assessment of the proposed service inventory is still required.</p></section>;
}
