import {useEffect, useId, useRef, useState} from 'react';
import {requestJson} from '../api';
import type {PatchableImage} from './ImagePatchControls';

interface PullRoute {
  repository: string;
  digest: string;
  reference: string;
  command: string;
  login_command: string | null;
  login_required?: boolean;
  anonymous_pull?: boolean;
}
interface PullInstructions {
  service_id: number;
  image_id: number;
  image_reference: string;
  registry: string | null;
  status: 'available' | 'unavailable';
  reason: string | null;
  routes: PullRoute[];
}

export function ImagePullInstructions({image, serviceKey}: {image: PatchableImage; serviceKey: string}) {
  const [open, setOpen] = useState(false), [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<PullInstructions | null>(null);
  const [error, setError] = useState(''), [copyNotice, setCopyNotice] = useState('');
  const dialog = useRef<HTMLDialogElement>(null), trigger = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  useEffect(() => {
    if (!open) return;
    const node = dialog.current;
    if (node && !node.open) {
      if (typeof node.showModal === 'function') node.showModal();
      else node.setAttribute('open', '');
    }
    const controller = new AbortController();
    setResult(null); setError(''); setCopyNotice('');
    requestJson<PullInstructions>(`/api/services/${encodeURIComponent(serviceKey)}/artifacts/images/${image.id}/pull`, {signal: controller.signal})
      .then(value => {if (!controller.signal.aborted) setResult(value);})
      .catch(cause => {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load pull instructions.');});
    return () => controller.abort();
  }, [open, attempt, serviceKey, image.id]);
  function close() {
    if (typeof dialog.current?.close === 'function') dialog.current.close();
    setOpen(false); trigger.current?.focus();
  }
  async function copy(value: string, label: string) {
    try {await window.navigator.clipboard.writeText(value); setCopyNotice(`${label} copied.`);}
    catch {setCopyNotice('Could not copy automatically. Select and copy the command below.');}
  }
  const routes = result?.status === 'available' ? result.routes : [];
  return <><button ref={trigger} type="button" className="secondary-button" aria-label={`Pull ${image.image_reference} from CATS`} onClick={() => setOpen(true)}>Pull from CATS</button>
    {open && <dialog ref={dialog} className="review-dialog modal" aria-labelledby={titleId} onCancel={() => setOpen(false)} onClose={() => setOpen(false)}>
      <h3 id={titleId}>Pull image from CATS</h3><p><code className="image-ref">{image.image_reference}</code></p>
      {!result && !error && <p role="status">Checking this service's approved image and pull route…</p>}
      {error && <div role="alert"><p>{error}</p><button type="button" onClick={() => setAttempt(value => value + 1)}>Retry</button></div>}
      {result && <><p>Service ID: <strong>{result.service_id}</strong>{result.registry && <> · Registry: <code>{result.registry}</code></>}</p>
        {!routes.length ? <p role="status">{result.reason || 'No approved pull route is currently available for this image.'}</p> : <>
          {routes.map((route, index) => {
            const loginRequired = route.login_required ?? Boolean(route.login_command);
            const login = route.login_command;
            return <section key={`${route.repository}-${route.digest}`} aria-label={`Pull route ${index + 1}`}>
              <h4>{routes.length > 1 ? `Pull route ${index + 1}` : 'Pull the approved image'}</h4>
              {loginRequired ? <div><h5>Sign in to CATS</h5><p>Use a CATS machine account granted access to this route.</p>
                {login && <><pre><code>{login}</code></pre><button type="button" className="secondary-button" onClick={() => void copy(login, 'Login command')}>{routes.length > 1 ? `Copy login command ${index + 1}` : 'Copy login command'}</button></>}
              </div> : <p>No sign-in required. This service allows anonymous pulls.</p>}
              <pre><code>{route.command}</code></pre><button type="button" className="secondary-button" onClick={() => void copy(route.command, 'Pull command')}>{routes.length > 1 ? `Copy pull command ${index + 1}` : 'Copy pull command'}</button>
            </section>;
          })}
          <p>CATS checks this service's approval again when the image is pulled.</p>
        </>}</>}
      {copyNotice && <p role="status">{copyNotice}</p>}
      <div className="dialog-actions"><button type="button" className="secondary-button" onClick={close}>Close</button></div>
    </dialog>}
  </>;
}
