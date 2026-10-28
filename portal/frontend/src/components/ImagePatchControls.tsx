import './image-patch-controls.css';

export type ImagePatchHistory = {original_image: string; patched_at: string; job_id: string; result_image: string};
export type PatchableImage = {
  id: number;
  image_reference: string;
  image_digest?: string;
  lifecycle_status?: string;
  patch_history?: ImagePatchHistory[];
};

export function hasImmutableImageDigest(image: PatchableImage) {
  const referenceDigest = image.image_reference.split('@')[1]?.toLowerCase();
  const digest = image.image_digest?.toLowerCase() || referenceDigest || '';
  return /^sha256:[a-f0-9]{64}$/.test(digest) && (!referenceDigest || referenceDigest === digest);
}

export function ImagePatchAction({image, serviceKey, allowed}: {image: PatchableImage; serviceKey: string; allowed: boolean}) {
  if (!allowed || image.lifecycle_status !== 'active') return null;
  const label = `Patch ${image.image_reference}`;
  if (!hasImmutableImageDigest(image)) return <span className="image-patch-unavailable"><button type="button" className="secondary-button" disabled aria-label={label}>Patch</button><small>Scan this image to record its digest before patching.</small></span>;
  return <a className="secondary-button" aria-label={label} href={`/patch-campaigns?${new URLSearchParams({service_id: serviceKey, image_id: String(image.id)})}`}>Patch</a>;
}

export function ImagePatchHistory({image}: {image: PatchableImage}) {
  if (!image.patch_history?.length) return null;
  return <details className="image-patch-history"><summary aria-label={`Patch history for ${image.image_reference}`} title="Show original image and patch time"><span aria-hidden="true">✦</span> Patched</summary><div className="image-patch-history-content">{image.patch_history.map((entry, index) => {
    const date = new Date(entry.patched_at);
    return <section key={`${entry.job_id}-${index}`} aria-label={`Patch ${index + 1}`}><dl><dt>Patched</dt><dd><time dateTime={entry.patched_at}>{Number.isNaN(date.getTime()) ? entry.patched_at : date.toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'long'})}</time></dd><dt>Original image</dt><dd><code>{entry.original_image}</code></dd><dt>Patched image</dt><dd><code>{entry.result_image}</code></dd></dl>{entry.job_id && <a href={`/api/public/patch-jobs/${encodeURIComponent(entry.job_id)}/results`}>View patch results</a>}</section>;
  })}</div></details>;
}
