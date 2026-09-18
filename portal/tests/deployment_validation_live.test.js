'use strict';

const assert = require('node:assert/strict');
const live = require('../app/static/deployment-validation-live.js');

assert.equal(live.badgeLabel({status: 'CREATING_CLUSTER', phase: 'CREATING_CLUSTER'}), 'Creating Cluster');
assert.equal(live.badgeLabel({status: 'COULD_NOT_VALIDATE', phase: 'COMPLETE', reason_category: 'SECURITY_POLICY_VIOLATION'}), 'BLOCKED BY PREFLIGHT');
assert.equal(live.badgeLabel({status: 'VERIFIED', phase: 'COMPLETE'}), 'Verified');
assert.equal(live.isTerminal({status: 'VERIFIED', phase: 'CLEANING_UP', cleanup_status: 'RUNNING'}), false);
assert.equal(live.isTerminal({status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE'}), true);

const originalFetch = global.fetch;
const originalAbort = global.AbortController;
const originalSetTimeout = global.setTimeout;
const originalClearTimeout = global.clearTimeout;

async function flush() { await new Promise(resolve => originalSetTimeout(resolve, 0)); }

(async () => {
  try {
    let requests = [];
    global.AbortController = class {
      constructor() { this.signal = {}; this.aborted = false; }
      abort() { this.aborted = true; }
    };
    global.fetch = (url, options) => new Promise((resolve, reject) => requests.push({url, options, resolve, reject}));

    const rendered = [];
    const status = {textContent: ''};
    const root = {dataset: {}};
    const controller = live.create({
      url: '/api/run-one', runKey: 'run-one', active: true, interval: 100000,
      statusElement: status, root, render: state => rendered.push(state),
    });
    assert.equal(requests.length, 1, 'active run starts one request');
    controller.poll();
    assert.equal(requests.length, 1, 'requests do not overlap');
    requests.shift().resolve({ok: true, json: async () => ({run_key: 'run-one', status: 'CREATING_CLUSTER', phase: 'CREATING_CLUSTER', cleanup_status: 'RUNNING'})});
    await flush();
    assert.equal(rendered.at(-1).phase, 'CREATING_CLUSTER');
    assert.equal(controller.isPolling(), true, 'non-terminal state remains live');

    controller.destroy();
    const failureRendered = [];
    const failureStatus = {textContent: ''};
    const failureController = live.create({url: '/api/failure', runKey: 'failure', active: true, interval: 100000, statusElement: failureStatus, root: {dataset: {}}, render: state => failureRendered.push(state)});
    requests.shift().reject(new Error('temporary network failure'));
    await flush();
    assert.match(failureStatus.textContent, /unavailable/i, 'poll failures are announced');
    assert.equal(failureRendered.length, 0, 'poll failure preserves the last rendered state');
    failureController.destroy();

    requests = [];
    const switched = [];
    const rerun = live.create({url: '/api/old', runKey: 'old', active: false, interval: 100000, statusElement: {textContent: ''}, root: {dataset: {}}, render: state => switched.push(state.run_key)});
    rerun.poll();
    assert.equal(requests.length, 1);
    rerun.switchRun({url: '/api/new', runKey: 'new', state: {run_key: 'new', status: 'QUEUED', phase: 'QUEUED', cleanup_status: 'PENDING'}});
    assert.equal(requests.length, 2, 'switching runs starts the new run immediately');
    requests[0].resolve({ok: true, json: async () => ({run_key: 'old', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE'})});
    await flush();
    assert.deepEqual(switched, ['new'], 'stale response from the prior run is ignored');
    requests[1].resolve({ok: true, json: async () => ({run_key: 'new', status: 'VERIFIED', phase: 'COMPLETE', cleanup_status: 'COMPLETE'})});
    await flush();
    assert.deepEqual(switched, ['new', 'new']);
    assert.equal(rerun.isPolling(), false, 'terminal status after cleanup stops polling');
    rerun.destroy();

    console.log('deployment validation live tests passed');
  } finally {
    global.fetch = originalFetch;
    global.AbortController = originalAbort;
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
