'use strict';

const assert = require('node:assert/strict');
const elapsed = require('../app/static/elapsed-time.js');

assert.equal(elapsed.formatElapsedDuration(7), '00:00:07');
assert.equal(elapsed.formatElapsedDuration(272), '00:04:32');
assert.equal(elapsed.formatElapsedDuration(4665), '01:17:45');
assert.equal(elapsed.formatElapsedDuration(43699), '12:08:19');

const origin = Date.parse('2026-09-15T12:00:00Z');
assert.equal(elapsed.elapsedSeconds(origin, null, origin + 7000), 7);
assert.equal(elapsed.elapsedSeconds(origin, origin + 272000, origin + 999999), 272);

function runningTimer() {
  let clock = origin;
  let callback = null;
  let schedules = 0;
  let clears = 0;
  const element = {textContent: ''};
  const controller = elapsed.createElapsedTimer(element, {
    startedAt: new Date(origin).toISOString(),
    status: 'running',
    now: () => clock,
    setInterval: (fn, milliseconds) => {
      assert.equal(milliseconds, 1000);
      callback = fn;
      schedules += 1;
      return schedules;
    },
    clearInterval: () => { clears += 1; }
  });
  return {
    controller, element,
    advance(milliseconds) { clock += milliseconds; callback(); },
    setClock(milliseconds) { clock = origin + milliseconds; callback(); },
    schedules: () => schedules,
    clears: () => clears,
    now: () => clock
  };
}

// One timestamp-derived timer continues across every Scan stage, including SBOM.
const scan = runningTimer();
scan.advance(12000);
assert.match(scan.element.textContent, /00:00:12$/);
scan.controller.update({status: 'running', startedAt: new Date(origin).toISOString()}); // SBOM stage
scan.setClock(108000);
assert.match(scan.element.textContent, /00:01:48$/);
scan.controller.update({status: 'running', startedAt: new Date(origin).toISOString()}); // vulnerability stage
scan.setClock(267000);
assert.match(scan.element.textContent, /00:04:27$/);
assert.equal(scan.schedules(), 1, 'stage changes must not create duplicate intervals');

// A Patch job likewise keeps one total clock while work moves between images.
const patch = runningTimer();
patch.setClock(60000);
patch.controller.update({status: 'running', startedAt: new Date(origin).toISOString()});
patch.setClock(121000);
assert.match(patch.element.textContent, /00:02:01$/);
assert.equal(patch.schedules(), 1);

// Ticks derive from timestamps, so throttled callbacks do not accumulate drift.
const drift = runningTimer();
drift.setClock(605000);
assert.match(drift.element.textContent, /00:10:05$/);

for (const status of ['complete', 'incomplete', 'error', 'failed', 'cancelled']) {
  const terminal = runningTimer();
  terminal.setClock(10000);
  terminal.controller.update({
    status,
    finishedAt: new Date(origin + 41000).toISOString()
  });
  assert.match(terminal.element.textContent, /00:00:41$/);
  assert.equal(terminal.controller.isRunning(), false);
  assert.equal(terminal.clears(), 1);
}

// Refresh/remount reconstructs the same value from authoritative timestamps.
const first = runningTimer();
first.setClock(83000);
const second = runningTimer();
second.setClock(83000);
assert.equal(first.element.textContent, second.element.textContent);

const cleanup = runningTimer();
cleanup.controller.destroy();
assert.equal(cleanup.controller.isRunning(), false);
assert.equal(cleanup.clears(), 1);
assert.equal(cleanup.element.textContent, '');

// Reusing or replacing an attached job never creates a second interval.
let attachSchedules = 0;
let attachClears = 0;
const attachedElement = {textContent: '', dataset: {startedAt: new Date(origin).toISOString(), finishedAt: '', status: 'running'}};
const attached = elapsed.attach(attachedElement, undefined, {
  now: () => origin,
  setInterval: () => { attachSchedules += 1; return attachSchedules; },
  clearInterval: () => { attachClears += 1; }
});
assert.strictEqual(elapsed.attach(attachedElement), attached);
assert.equal(attachSchedules, 1);
attached.update({startedAt: null, finishedAt: null, status: 'queued'});
assert.equal(attachClears, 1);

console.log('elapsed-time tests passed');
