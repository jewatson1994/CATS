import {useEffect, useId, useRef, useState} from 'react';
import type {PageData} from '../api';
import {Csrf} from '../components/Form';
import {useServiceReadOnly} from '../operatingMode';
import '../components/service-controls.css';

const weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const ordinals: Record<number, string> = {1: 'first', 2: 'second', 3: 'third', 4: 'fourth', 5: 'fifth', [-1]: 'last'};
const timezones = ['UTC', ...(Intl.supportedValuesOf?.('timeZone') || [])];

type Cadence = 'off' | 'daily' | 'weekly' | 'monthly';
interface Schedule {
  cadence: Cadence;
  timezone?: string;
  time_of_day?: string | null;
  weekdays?: number[];
  weekday?: number;
  monthly_mode?: 'weekday' | 'date';
  day_of_month?: number;
  week_of_month?: number;
  next_run_at?: string;
  last_run_at?: string;
  last_result?: string;
}

function selectedDays(schedule: Schedule) {
  return schedule.weekdays?.length ? schedule.weekdays : [schedule.weekday ?? 0];
}

function scheduleLabel(schedule: Schedule) {
  if (schedule.cadence === 'off') return 'Off';
  let frequency = 'Daily';
  if (schedule.cadence === 'weekly') {
    const days = selectedDays(schedule);
    frequency = 'Weekly · ' + days.map(day => days.length === 1 ? weekdays[day] : weekdays[day].slice(0, 3)).join(', ');
  } else if (schedule.cadence === 'monthly') {
    frequency = schedule.monthly_mode === 'date' ? 'Monthly · day ' + schedule.day_of_month
      : 'Monthly · ' + ordinals[schedule.week_of_month ?? 1] + ' ' + weekdays[schedule.weekday ?? 0];
  }
  return [frequency, schedule.time_of_day || '21:00–05:00', schedule.timezone || 'UTC'].join(' · ');
}

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

function ScheduleEditor({data, root, schedule, cancel}: {
  data: PageData; root: string; schedule: Schedule; cancel: () => void;
}) {
  const [cadence, setCadence] = useState(schedule.cadence);
  const [days, setDays] = useState(selectedDays(schedule));
  const [monthlyMode, setMonthlyMode] = useState(schedule.monthly_mode || 'weekday');
  const zonesId = useId();
  return <form className="service-control-editor" method="post" action={`${root}/scan-schedule`}>
    <Csrf data={data}/>
    <div className="service-control-fields">
      <label>Frequency<select name="cadence" value={cadence} onChange={event => setCadence(event.target.value as Cadence)}>
        <option value="off">Off</option><option value="daily">Daily</option>
        <option value="weekly">Weekly</option><option value="monthly">Monthly</option>
      </select></label>
      {cadence === 'monthly' && <label>Repeat by<select name="monthly_mode" value={monthlyMode} onChange={event => setMonthlyMode(event.target.value === 'date' ? 'date' : 'weekday')}>
        <option value="weekday">Weekday of the month</option><option value="date">Day of the month</option>
      </select></label>}
      {cadence === 'weekly' && <fieldset className="schedule-weekdays">
        <legend>Repeat on</legend><div>{weekdays.map((day, index) =>
          <label key={day}><input type="checkbox" name="weekdays" value={index} checked={days.includes(index)}
            required={!days.length && index === 0} onChange={event => {
              setDays(event.target.checked ? [...days, index] : days.filter(value => value !== index));
            }}/>{day}</label>)}</div>
        {!days.length && <small>Select at least one day.</small>}
      </fieldset>}
      {cadence === 'monthly' && (monthlyMode === 'date' ?
        <label>Day of month<select name="day_of_month" defaultValue={schedule.day_of_month ?? 1}>
          {Array.from({length: 31}, (_, index) => <option key={index} value={index + 1}>{index + 1}</option>)}
        </select></label> : <>
          <label>Occurrence<select name="week_of_month" defaultValue={schedule.week_of_month ?? 1}>
            {[1, 2, 3, 4, 5, -1].map(value => <option key={value} value={value}>{ordinals[value][0].toUpperCase() + ordinals[value].slice(1)}</option>)}
          </select></label>
          <label>Weekday<select name="weekday" defaultValue={schedule.weekday ?? 0}>
            {weekdays.map((day, index) => <option key={day} value={index}>{day}</option>)}
          </select></label>
        </>)}
      {cadence !== 'off' && <>
        <label>Start time<input required name="time_of_day" type="time" defaultValue={schedule.time_of_day || ''}/></label>
        <label>Time zone<input name="timezone" list={zonesId} required defaultValue={schedule.timezone || 'UTC'} placeholder="America/New_York"/></label>
        <datalist id={zonesId}>{timezones.map(zone => <option key={zone} value={zone}/>)}</datalist>
      </>}
    </div>
    {cadence === 'monthly' && <p className="service-control-help">Months without the selected day are skipped.</p>}
    <div className="service-control-actions"><button>Save schedule</button><button type="button" className="secondary-button" onClick={cancel}>Cancel</button></div>
  </form>;
}

export function ServiceScanSchedule({data, root}: {data: PageData; root: string}) {
  const replica = useServiceReadOnly(Boolean(data.imported_service || data.read_only));
  const schedule: Schedule | undefined = data.scan_schedule;
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const selector = useRef<HTMLButtonElement>(null);
  const container = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!open) return;
    function outside(event: PointerEvent) {
      if (event.target instanceof Node && !container.current?.contains(event.target)) setOpen(false);
    }
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [open]);
  if (replica || !schedule || (!data.can_schedule_scans && schedule.cadence === 'off')) return null;
  const timezone = schedule.timezone || 'UTC';
  const summary = scheduleLabel(schedule);
  function close() {
    setOpen(false);
    selector.current?.focus();
  }
  return <section ref={container} id="scan-schedule" className="service-setting" aria-label="Scan schedule"
    onBlur={event => {
      if (event.relatedTarget instanceof Node && !event.currentTarget.contains(event.relatedTarget)) setOpen(false);
    }}
    onKeyDown={event => {
      if (open && event.key === 'Escape') { event.preventDefault(); close(); }
    }}>
    <div className="service-setting-row">
      <span>Scan schedule:</span>
      <button ref={selector} type="button" className="service-setting-trigger" aria-expanded={open} aria-controls={panelId}
        title={summary} aria-label={`Scan schedule: ${summary}`} onClick={() => setOpen(!open)}>
        {schedule.cadence[0].toUpperCase() + schedule.cadence.slice(1)}
      </button>
      {data.schedule_saved && <small role="status" className="service-setting-saved">Scan schedule saved.</small>}
    </div>
    <div id={panelId} className="service-setting-popover" hidden={!open}>
      {open && <>
        <strong>{summary}</strong>
        {schedule.cadence !== 'off' && schedule.next_run_at && <p className="service-control-help">Next scheduled start · {localTime(schedule.next_run_at, timezone)}</p>}
        {schedule.last_result && <p className="service-control-help">Last scheduling activity · {schedule.last_run_at && <>{localTime(schedule.last_run_at, timezone)} · </>}{schedule.last_result}</p>}
        {data.can_schedule_scans && <ScheduleEditor data={data} root={root} schedule={schedule} cancel={close}/>}
        {!data.can_schedule_scans && data.can_disable_scan_schedule && schedule.cadence !== 'off' && <form className="service-control-editor" method="post" action={`${root}/scan-schedule`}>
          <Csrf data={data}/><input type="hidden" name="cadence" value="off"/><button>Turn off scheduled scans</button>
        </form>}
      </>}
    </div>
  </section>;
}
