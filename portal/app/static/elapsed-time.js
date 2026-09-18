(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.CatsElapsedTime = api;
})(typeof window !== 'undefined' ? window : undefined, function () {
  'use strict';

  const TERMINAL_STATUSES = new Set([
    'complete', 'completed', 'incomplete', 'error', 'failed', 'cancelled',
    'validated', 'review_required', 'not_remediable', 'verified',
    'partially_verified', 'could_not_validate', 'not_attempted'
  ]);
  const controllers = new WeakMap();

  function timestampMilliseconds(value) {
    if (value === null || value === undefined || value === '') return null;
    if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : null;
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    const parsed = Date.parse(String(value));
    return Number.isFinite(parsed) ? parsed : null;
  }

  function formatElapsedDuration(totalSeconds) {
    const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainder = seconds % 60;
    return [hours, minutes, remainder].map((value) => String(value).padStart(2, '0')).join(':');
  }

  function elapsedSeconds(startedAt, finishedAt, nowMilliseconds) {
    const start = timestampMilliseconds(startedAt);
    if (start === null) return null;
    const finish = timestampMilliseconds(finishedAt);
    const end = finish === null ? nowMilliseconds : finish;
    return Math.max(0, Math.floor((end - start) / 1000));
  }

  function createElapsedTimer(element, options) {
    const settings = options || {};
    const now = settings.now || Date.now;
    const schedule = settings.setInterval || setInterval;
    const cancel = settings.clearInterval || clearInterval;
    const intervalMilliseconds = settings.intervalMilliseconds || 1000;
    let intervalId = null;
    let fallbackFinishedAt = null;
    let state = {
      startedAt: settings.startedAt || null,
      finishedAt: settings.finishedAt || null,
      status: String(settings.status || '').toLowerCase()
    };

    function isTerminal() {
      return TERMINAL_STATUSES.has(state.status);
    }

    function stop() {
      if (intervalId !== null) {
        cancel(intervalId);
        intervalId = null;
      }
    }

    function render() {
      const start = timestampMilliseconds(state.startedAt);
      if (start === null) {
        element.textContent = '';
        return null;
      }
      let finish = state.finishedAt;
      if (isTerminal() && timestampMilliseconds(finish) === null) {
        fallbackFinishedAt = fallbackFinishedAt === null ? now() : fallbackFinishedAt;
        finish = fallbackFinishedAt;
      }
      const seconds = elapsedSeconds(start, finish, now());
      element.textContent = formatElapsedDuration(seconds);
      return seconds;
    }

    function reconcileInterval() {
      const shouldRun = timestampMilliseconds(state.startedAt) !== null &&
        timestampMilliseconds(state.finishedAt) === null && !isTerminal();
      if (shouldRun && intervalId === null) intervalId = schedule(render, intervalMilliseconds);
      if (!shouldRun) stop();
    }

    function update(values) {
      const next = values || {};
      if (Object.prototype.hasOwnProperty.call(next, 'startedAt')) state.startedAt = next.startedAt;
      if (Object.prototype.hasOwnProperty.call(next, 'finishedAt')) state.finishedAt = next.finishedAt;
      if (Object.prototype.hasOwnProperty.call(next, 'status')) state.status = String(next.status || '').toLowerCase();
      if (!isTerminal()) fallbackFinishedAt = null;
      render();
      reconcileInterval();
    }

    function destroy() {
      stop();
      element.textContent = '';
    }

    update(state);
    return {update, render, destroy, isRunning: () => intervalId !== null};
  }

  function attach(element, values, options) {
    if (!element) return null;
    let controller = controllers.get(element);
    if (controller && values === undefined) return controller;
    const initial = values || {
      startedAt: element.dataset.startedAt || null,
      finishedAt: element.dataset.finishedAt || null,
      status: element.dataset.status || ''
    };
    if (!controller) {
      controller = createElapsedTimer(element, {...(options || {}), ...initial});
      controllers.set(element, controller);
    } else {
      controller.update(initial);
    }
    return controller;
  }

  function initialize(scope) {
    const container = scope || document;
    container.querySelectorAll('[data-elapsed-time]').forEach((element) => attach(element));
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => initialize(document), {once: true});
    } else {
      initialize(document);
    }
  }

  return {attach, createElapsedTimer, elapsedSeconds, formatElapsedDuration, initialize, timestampMilliseconds};
});
