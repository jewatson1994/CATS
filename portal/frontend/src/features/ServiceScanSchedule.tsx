import {useState} from 'react';
import type {PageData} from '../api';
import {Csrf} from '../components/Form';

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
  const schedule = data.scan_schedule;
  const [cadence, setCadence] = useState(schedule?.cadence || 'off');
  if (!schedule || (!data.can_schedule_scans && schedule.cadence === 'off')) return null;
  const timezone = schedule.timezone || 'UTC';
  const label = schedule.cadence === 'weekly' ? `Weekly on ${weekdays[schedule.weekday]}`
    : schedule.cadence === 'daily' ? 'Nightly' : 'Off';
  return <section id="scan-schedule" className="panel padded" aria-label="Scheduled scans">
    <h2>Scheduled scans</h2>
    {data.schedule_saved && <p role="status">Scan schedule saved.</p>}
    <p><strong>{label}</strong>{schedule.cadence !== 'off' && <> · 9 p.m. to 5 a.m. ({timezone})</>}</p>
    {schedule.cadence !== 'off' && schedule.next_run_at && <p>Next scheduled start · {localTime(schedule.next_run_at, timezone)}</p>}
    {schedule.last_result && <p>Last scheduling activity{schedule.last_run_at && <> · {localTime(schedule.last_run_at, timezone)}</>} · {schedule.last_result}</p>}
    {data.can_schedule_scans && <details><summary>Edit scan schedule</summary>
      <form method="post" action={`${root}/scan-schedule`}>
        <Csrf data={data}/>
        <p>Scan this service’s active images and add the results to its findings. CATS starts scans during the overnight window as capacity allows. A scan already running can finish after 5 a.m.</p>
        <label>Frequency<select name="cadence" value={cadence} onChange={event => setCadence(event.target.value)}>
          <option value="off">Off</option><option value="daily">Nightly</option><option value="weekly">Weekly</option>
        </select></label>
        {cadence === 'weekly' && <label>Night beginning on<select name="weekday" defaultValue={schedule.weekday ?? 0}>
          {weekdays.map((day, index) => <option key={day} value={index}>{day}</option>)}
        </select></label>}
        {cadence !== 'off' && <><label>Time zone<input name="timezone" list="scan-timezones" required defaultValue={timezone} placeholder="America/New_York"/>
          <small>Use an IANA time zone such as America/New_York or UTC.</small></label>
          <datalist id="scan-timezones">{timezones.map(zone => <option key={zone} value={zone}/>)}</datalist></>}
        <button>Save schedule</button>
      </form>
    </details>}
    {!data.can_schedule_scans && data.can_disable_scan_schedule && schedule.cadence !== 'off' && <form method="post" action={`${root}/scan-schedule`}>
      <Csrf data={data}/><input type="hidden" name="cadence" value="off"/><button>Turn off scheduled scans</button>
    </form>}
  </section>;
}
