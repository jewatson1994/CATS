import {useEffect, useRef, useState} from 'react';
import {requestJson, type Announcement, type PageData} from '../api';
import {Icon} from './ui';

export function NotificationBell({data}: {data: PageData}) {
  const [notice, setNotice] = useState(data.announcement || null);
  const [marking, setMarking] = useState(false);
  const menu = useRef<HTMLDetailsElement>(null);
  const generation = useRef(0);
  useEffect(() => {
    const controller = new AbortController();
    let loading = false;
    const refresh = async () => {
      if (document.hidden || loading) return;
      loading = true;
      const revision = generation.current;
      try {
        const response = await fetch('/api/announcements/current', {
          credentials: 'same-origin', cache: 'no-store', headers: {Accept: 'application/json'}, signal: controller.signal,
        });
        if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) return;
        const current: Announcement | null = await response.json();
        if (!controller.signal.aborted && revision === generation.current) setNotice(current);
      } catch {
        // Retain the last confirmed notice when a background refresh is unavailable.
      } finally {loading = false;}
    };
    const node = menu.current;
    const onToggle = () => {if (node?.open) void refresh();};
    const timer = window.setInterval(refresh, 60_000);
    node?.addEventListener('toggle', onToggle);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      node?.removeEventListener('toggle', onToggle);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, []);
  async function markRead() {
    if (!notice || marking) return;
    setMarking(true);
    try {
      const result = await requestJson<Announcement | null>(`/account/announcements/${notice.id}/read`, {
        method: 'POST', body: new URLSearchParams({csrf_token: data.csrf_token || ''}),
      });
      generation.current++;
      setNotice(result);
    } catch { /* requestJson publishes the error in the notification panel. */ }
    finally {setMarking(false);}
  }
  const pending = Number(data.pending_request_count || 0);
  const visible = notice && (!notice.expires_at || Date.parse(notice.expires_at) > Date.now()) ? notice : null;
  const count = pending + Number(Boolean(visible?.unread));
  const label = [pending ? `${pending} pending` : '', visible?.unread ? '1 unread announcement' : ''].filter(Boolean).join(', ');
  return <details ref={menu} className="notification-menu">
    <summary aria-label={label ? `Notifications (${label})` : 'Notifications'} title="Notifications"><Icon name="bell"/>
      {count > 0 && <span className="notification-badge" aria-hidden="true">{count > 99 ? '99+' : count}</span>}
    </summary>
    <div className="notification-popover">
      <div className="notification-head"><strong>Notifications</strong>{pending > 0 && <span className="count-pill">{pending} pending</span>}</div>
      {visible && <section className="bell-announcement" aria-label="Portal announcement">
        <strong>{visible.title}</strong><p>{visible.message}</p>
        {visible.unread && <button type="button" className="link-button" disabled={marking} onClick={markRead}>Mark as read</button>}
      </section>}
      {data.actionable_notifications?.length ? <>{data.actionable_notifications.map((item, index) =>
        <a key={index} className="notification-item" href={item.href || '/requests'}><span className="notification-dot" aria-hidden="true"/><span className="notification-text"><span>{item.label}</span><small>{item.service}</small></span></a>)}
        <a className="notification-all" href="/requests">View all requests</a></>
        : !visible && <span className="muted notification-empty">No action required.</span>}
    </div>
  </details>;
}
