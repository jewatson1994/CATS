import {type PageData} from '../api';
import {ServiceHeader, ServiceTabs} from '../components/ServiceHeader';

const label = (value: string) => value.replaceAll('_', ' ').replaceAll('.', ' · ').replace(/\b\w/g, char => char.toUpperCase());
export function Page({data}: {data: PageData}) {
  const service = data.view.service;
  return <><ServiceHeader data={data}/><ServiceTabs serviceKey={service.service_key} active="activity"/><section className="panel service-activity"><div className="panel-heading"><div><h2>Service activity</h2><p>Chronological history for {service.name} from the existing audit trail.</p></div></div><ol className="activity-list">{data.events?.length ? data.events.map((event: any, index: number) => <li key={index}><time dateTime={event.created_at}>{event.created_at_display}</time><div><strong>{label(event.action || '')}</strong><span>{event.actor_name || 'System'}</span>{Object.keys(event.detail || {}).length > 0 && <small>{Object.entries(event.detail).map(([key, value]) => `${label(key)}: ${String(value)}`).join(' · ')}</small>}</div></li>) : <li className="empty">No activity has been recorded for this service.</li>}</ol></section></>;
}
