import {useRef, type ReactNode} from 'react';
import type {PageData} from '../api';

export function Csrf({data}: {data: PageData}) {return <input type="hidden" name="csrf_token" value={data.csrf_token || ''}/>;}
export function Dialog({button, title, children, className = 'review-dialog', buttonClass = ''}: {button: string; title: string; children: ReactNode; className?: string; buttonClass?: string}) {
  const dialog = useRef<HTMLDialogElement>(null);
  return <><button type="button" className={buttonClass} onClick={() => dialog.current?.showModal()}>{button}</button>
    <dialog ref={dialog} className={className} aria-label={title}><h3>{title}</h3>{children}<button type="button" className="secondary-button" onClick={() => dialog.current?.close()}>Cancel</button></dialog></>;
}
export function Status({value, bad = false}: {value: string; bad?: boolean}) {return <span className={`status ${bad ? 'bad' : ['completed', 'compliant', 'pass', 'verified', 'validated'].includes(value.toLowerCase()) ? 'ok' : ''}`}>{value.replaceAll('_', ' ')}</span>;}
export function safeReference(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {const parsed = new URL(url, window.location.origin); return ['https:', 'http:'].includes(parsed.protocol) ? parsed.href : undefined;} catch {return undefined;}
}
