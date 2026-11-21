import {expect, it} from 'vitest';
import {fireEvent, render, screen} from '@testing-library/react';
import {ServiceScanSchedule} from './ServiceScanSchedule';

function renderSchedule(scan_schedule: Record<string, unknown>) {
  render(<ServiceScanSchedule root="/services/calendar" data={{can_schedule_scans: true, csrf_token: 'proof', scan_schedule}}/>);
  fireEvent.click(screen.getByRole('button', {name: /Scan schedule:/}));
}

function fields() {
  return new FormData(screen.getByRole('button', {name: 'Save schedule'}).closest('form')!);
}

it('edits the third Saturday each month at a selected local time', () => {
  renderSchedule({cadence: 'off', timezone: 'UTC'});
  fireEvent.change(screen.getByLabelText('Frequency'), {target: {value: 'monthly'}});
  fireEvent.change(screen.getByLabelText('Occurrence'), {target: {value: '3'}});
  fireEvent.change(screen.getByLabelText('Weekday'), {target: {value: '5'}});
  fireEvent.change(screen.getByLabelText('Start time'), {target: {value: '14:35'}});
  fireEvent.change(screen.getByLabelText('Time zone'), {target: {value: 'America/New_York'}});
  expect(Object.fromEntries(fields())).toEqual({
    cadence: 'monthly', monthly_mode: 'weekday', week_of_month: '3', weekday: '5',
    time_of_day: '14:35', timezone: 'America/New_York', csrf_token: 'proof',
  });
});

it('shows a saved monthly schedule on the selector and supports last weekday and numbered dates', () => {
  renderSchedule({cadence: 'monthly', monthly_mode: 'weekday', week_of_month: -1, weekday: 4,
    time_of_day: '09:15', timezone: 'Asia/Tokyo'});
  expect(screen.getByRole('button', {name: /Monthly · last Friday · 09:15 · Asia\/Tokyo/})).toBeInTheDocument();
  expect(screen.getByLabelText('Occurrence')).toHaveValue('-1');
  fireEvent.change(screen.getByLabelText('Repeat by'), {target: {value: 'date'}});
  fireEvent.change(screen.getByLabelText('Day of month'), {target: {value: '31'}});
  const values = fields();
  expect(Object.fromEntries(values)).toMatchObject({cadence: 'monthly', monthly_mode: 'date', day_of_month: '31', time_of_day: '09:15'});
  expect(values.has('weekday')).toBe(false);
  expect(screen.getByText('Months without the selected day are skipped.')).toBeInTheDocument();
});

it('posts daily recurrence without hidden monthly or weekly filters', () => {
  renderSchedule({cadence: 'monthly', monthly_mode: 'date', day_of_month: 7, time_of_day: '16:20', timezone: 'UTC'});
  fireEvent.change(screen.getByLabelText('Frequency'), {target: {value: 'daily'}});
  fireEvent.change(screen.getByLabelText('Start time'), {target: {value: '00:00'}});
  expect(Object.fromEntries(fields())).toEqual({cadence: 'daily', time_of_day: '00:00', timezone: 'UTC', csrf_token: 'proof'});
});

it('requires at least one weekday for a weekly schedule', () => {
  renderSchedule({cadence: 'weekly', weekdays: [5], time_of_day: '18:30', timezone: 'UTC'});
  fireEvent.click(screen.getByRole('checkbox', {name: 'Saturday'}));
  expect(screen.getByText('Select at least one day.')).toBeInTheDocument();
  const form = screen.getByRole('button', {name: 'Save schedule'}).closest('form')!;
  expect(form.checkValidity()).toBe(false);
  fireEvent.click(screen.getByRole('checkbox', {name: 'Sunday'}));
  expect(form.checkValidity()).toBe(true);
  expect(fields().getAll('weekdays')).toEqual(['6']);
});
