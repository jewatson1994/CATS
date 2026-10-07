import {useRef, type ReactNode} from 'react';
import type {PageData} from '../api';
import {toneFor} from './ui';

export function Csrf({data}: {data: PageData}) {return <input type="hidden" name="csrf_token" value={data.csrf_token || ''}/>;}
export function Dialog({button, title, children, className = 'review-dialog', buttonClass = ''}: {button: string; title: string; children: ReactNode; className?: string; buttonClass?: string}) {
  const dialog = useRef<HTMLDialogElement>(null);
  return <><button type="button" className={buttonClass} onClick={() => dialog.current?.showModal()}>{button}</button>
    <dialog ref={dialog} className={className} aria-label={title}><h3>{title}</h3>{children}<button type="button" className="secondary-button" onClick={() => dialog.current?.close()}>Cancel</button></dialog></>;
}
/** Legacy status pill. Text is unchanged; tone comes from the shared design-system mapping so colour is consistent everywhere. */
export function Status({value, bad = false}: {value: string; bad?: boolean}) {
  const tone = bad ? 'danger' : ['completed', 'compliant', 'pass', 'verified', 'validated'].includes(value.toLowerCase()) ? 'success' : toneFor(value);
  const legacy = tone === 'danger' ? 'bad' : tone === 'success' ? 'ok' : tone;
  return <span className={`status ${legacy}`} title={value}>{value.replaceAll('_', ' ')}</span>;
}
export function safeReference(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {const parsed = new URL(url, window.location.origin); return ['https:', 'http:'].includes(parsed.protocol) ? parsed.href : undefined;} catch {return undefined;}
}
