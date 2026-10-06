import {type PageData} from '../api';
import {ServiceHeader, ServiceTabs} from '../components/ServiceHeader';
import {SectionHeader, Timeline, toneFor} from '../components/ui';

const label = (value: string) => value.replaceAll('_', ' ').replaceAll('.', ' · ').replace(/\b\w/g, char => char.toUpperCase());
export function Page({data}: {data: PageData}) {
  const service = data.view.service;
  return <><ServiceHeader data={data}/><ServiceTabs serviceKey={service.service_key} active="activity"/><section className="panel service-activity"><SectionHeader title="Service activity" description={`Chronological history for ${service.name} from the existing audit trail.`}/><Timeline empty="No activity has been recorded for this service." items={(data.events || []).map((event: any, index: number) => ({key: event.id ?? index, time: event.created_at_display, dateTime: event.created_at, title: label(event.action || ''), actor: event.actor_name || 'System', tone: toneFor(String(event.action || '').split(/[._]/).pop()),
      detail: Object.keys(event.detail || {}).length > 0 && <dl>{Object.entries(event.detail).map(([key, value]) => <div key={key}><dt>{label(key)}</dt><dd>{String(value)}</dd></div>)}</dl>}))}/>{data.page_count > 1 && <nav className="pagination" aria-label="Activity pages"><span>Page {data.page} of {data.page_count} · {data.total_items} events</span><span className="pagination-controls">{data.page > 1 && <a href={`${data.pagination_base}&page=${data.page - 1}`}>Previous</a>}{data.page < data.page_count && <a href={`${data.pagination_base}&page=${data.page + 1}`}>Next</a>}</span></nav>}</section></>;
}
