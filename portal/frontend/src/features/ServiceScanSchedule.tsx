import {useId, useState} from 'react';
import type {PageData} from '../api';
import {Csrf} from '../components/Form';
import {StatusBadge} from '../components/ui';
import '../components/service-controls.css';
import {useServiceReadOnly} from '../operatingMode';

const weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const timezones = ['UTC', ...(Intl.supportedValuesOf?.('timeZone') || [])];

function localTime(value: string, timezone: string) {
  const date = new Date(value);
  try {
    return new Intl.DateTimeFormat(undefined, {
      timeZone: timezone, weekday: 'short', month: 'short', day: 'numeric',
      hour: 'numeric', minute: '2-digit', timeZoneName: 'short',
    }).format(date);
  } catch {
    return date.toUTCString();
  }
}

export function ServiceScanSchedule({data, root}: {data: PageData; root: string}) {
  const replica = useServiceReadOnly(Boolean(data.imported_service || data.read_only));
  const schedule = data.scan_schedule;
  const [cadence, setCadence] = useState(schedule?.cadence || 'off');
  const [editing, setEditing] = useState(false);
  const editorId = useId();
  if (replica || !schedule || (!data.can_schedule_scans && schedule.cadence === 'off')) return null;
  const timezone = schedule.timezone || 'UTC';
  const label = schedule.cadence === 'weekly' ? `Weekly on ${weekdays[schedule.weekday]}`
    : schedule.cadence === 'daily' ? 'Nightly' : 'Off';
  const cancel = () => {setCadence(schedule.cadence || 'off'); setEditing(false);};
  return <section id="scan-schedule" className="panel service-control-card" aria-label="Scheduled scans">
    <div className="service-control-heading"><div className="service-control-title"><h2>Scheduled scans</h2>
      <StatusBadge value={schedule.cadence === 'off' ? 'off' : 'scheduled'} label={label} tone="neutral"/>
    </div>{data.can_schedule_scans && <button type="button" className="secondary-button" aria-expanded={editing} aria-controls={editorId}
      onClick={() => {if (editing) cancel(); else setEditing(true);}}>Edit scan schedule</button>}</div>
    {data.schedule_saved && <p role="status">Scan schedule saved.</p>}
    <p className="service-control-description">{schedule.cadence === 'off' ? 'Automatic scans are off. Start scans manually or set an overnight schedule.' : `Scans start between 9 p.m. and 5 a.m. (${timezone}).`}</p>
    {schedule.cadence !== 'off' && schedule.next_run_at && <p className="service-control-help">Next scheduled start · {localTime(schedule.next_run_at, timezone)}</p>}
    {schedule.last_result && <details className="service-control-history"><summary>Last scheduling activity</summary><p>{schedule.last_run_at && <>{localTime(schedule.last_run_at, timezone)} · </>}{schedule.last_result}</p></details>}
    {data.can_schedule_scans && editing && <form id={editorId} className="service-control-editor" method="post" action={`${root}/scan-schedule`}>
        <Csrf data={data}/>
        <p className="service-control-help">Scan active images and update this service’s findings. Scans start as capacity allows and may finish after 5 a.m.</p>
        <div className="service-control-fields">
        <label>Frequency<select name="cadence" value={cadence} onChange={event => setCadence(event.target.value)}>
          <option value="off">Off</option><option value="daily">Nightly</option><option value="weekly">Weekly</option>
        </select></label>
        {cadence === 'weekly' && <label>Night beginning on<select name="weekday" defaultValue={schedule.weekday ?? 0}>
          {weekdays.map((day, index) => <option key={day} value={index}>{day}</option>)}
        </select></label>}
        {cadence !== 'off' && <><label>Time zone<input name="timezone" list="scan-timezones" required defaultValue={timezone} placeholder="America/New_York"/>
          <small>Use an IANA time zone such as America/New_York or UTC.</small></label>
          <datalist id="scan-timezones">{timezones.map(zone => <option key={zone} value={zone}/>)}</datalist></>}
        </div><div className="service-control-actions"><button>Save schedule</button><button type="button" className="secondary-button" onClick={cancel}>Cancel</button></div>
      </form>}
    {!data.can_schedule_scans && data.can_disable_scan_schedule && schedule.cadence !== 'off' && <form className="service-control-editor" method="post" action={`${root}/scan-schedule`}>
      <Csrf data={data}/><input type="hidden" name="cadence" value="off"/><button>Turn off scheduled scans</button>
    </form>}
  </section>;
}
