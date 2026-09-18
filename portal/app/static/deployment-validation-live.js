(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.CatsDeploymentLive = api;
})(typeof window !== 'undefined' ? window : undefined, function (window) {
  'use strict';

  const TERMINAL = new Set(['VERIFIED', 'PARTIALLY_VERIFIED', 'COULD_NOT_VALIDATE', 'NOT_ATTEMPTED']);
  const CLEANUP_TERMINAL = new Set(['COMPLETE', 'FAILED', 'NOT_REQUIRED', 'NOT_ATTEMPTED', 'UNKNOWN']);
  const PHASE_LABELS = { QUEUED: 'Queued', PREFLIGHT: 'Preparing Validation', RENDERING: 'Rendering Helm', CREATING_CLUSTER: 'Creating Cluster', INSTALLING: 'Installing Helm', WAITING_FOR_READY: 'Observing Runtime', COLLECTING: 'Collecting Evidence', COMPARING: 'Reconciling Evidence', CLEANING_UP: 'Cleaning Up', COMPLETE: '' };

  function text(value, fallback) { return value === null || value === undefined || value === '' ? (fallback || '—') : String(value); }
  function title(value) { return text(value, '—').toLowerCase().replace(/(^|[_ -])([a-z])/g, (_, p, c) => p + c.toUpperCase()).replace(/_/g, ' '); }
  function escape(value) { return text(value, '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function date(value) { if (!value) return '—'; const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? text(value) : parsed.toLocaleString(); }
  function isTerminal(state) { return TERMINAL.has(text(state && state.status).toUpperCase()) && text(state.phase).toUpperCase() === 'COMPLETE' && CLEANUP_TERMINAL.has(text(state.cleanup_status).toUpperCase()); }
  function badgeLabel(state) {
    const phase = text(state && state.phase).toUpperCase();
    const status = text(state && state.status).toUpperCase();
    if (state && (state.preflight_blocked || status === 'BLOCKED_BY_PREFLIGHT' || state.reason_category === 'SECURITY_POLICY_VIOLATION')) return 'BLOCKED BY PREFLIGHT';
    return phase !== 'COMPLETE' ? (PHASE_LABELS[phase] || title(phase)) : title(status);
  }

  function setStatusClass(element, value) {
    if (!element) return;
    [...element.classList].filter(item => item.indexOf('validation-status-') === 0).forEach(item => element.classList.remove(item));
    const normalized = text(value, 'not-attempted').toLowerCase().replace(/_/g, '-');
    element.classList.add('validation-status-' + normalized);
    if (normalized !== 'verified' && normalized !== 'partially-verified' && normalized !== 'could-not-validate' && normalized !== 'not-attempted') element.classList.add('validation-status-in-progress');
  }

  function renderCapabilities(section, rows) {
    if (!section) return;
    const allItems = Array.isArray(rows) ? rows : [];
    const items = allItems.filter(item => {
      const status = text(item.status, 'NOT_REQUIRED').toUpperCase();
      return status !== 'NOT_REQUIRED' && text(item.capability) !== 'Configuration dependencies';
    });
    section.hidden = allItems.length === 0;
    const grid = section.querySelector('[data-live-capability-evidence-grid]');
    if (!grid) return;
    grid.innerHTML = items.map(item => {
      const status = text(item.status, 'NOT_REQUIRED').toUpperCase();
      const ok = ['AVAILABLE', 'PROVISIONED', 'VERIFIED', 'BOUND'].includes(status);
      const details = item.evidence || {};
      const provider = details.provider || {};
      const providerLine = Object.keys(provider).length ? `<p class="muted">Provider: ${escape(provider.provider || provider.provider_id || 'Detected environment')} ${escape(provider.version || '')}</p><small class="muted">Bootstrap: ${escape(title(provider.bootstrap_status || 'NOT_ATTEMPTED'))} · Readiness: ${escape(title(provider.readiness_status || 'NOT_CHECKED'))} · Reconciliation: ${escape(title(details.reconciliation || provider.reconciliation_result || 'NOT_ATTEMPTED'))}</small>${provider.verification_method ? `<p class="muted">Verification: ${escape(provider.verification_method)}</p>` : ''}${provider.failure_reason ? `<p class="warning">${escape(provider.failure_reason)}</p>` : ''}` : (details.reconciliation ? `<p class="muted">Reconciliation: ${escape(title(details.reconciliation))}</p>` : '');
      const evidence = Object.keys(details).length ? `${providerLine}<details><summary>Capability technical evidence</summary><pre>${escape(JSON.stringify(details, null, 2))}</pre></details>` : '';
      return `<div><strong>${escape(item.capability)}</strong><br><span class="status ${ok ? 'ok' : (item.required ? 'warning' : '')}">${escape(title(status))}</span>${item.required ? `<small><br>Required by <code>${escape(item.source_resource || 'artifact')}</code></small>` : ''}${item.explanation ? `<p class="muted">${escape(item.explanation)}</p>` : ''}${item.provisioned_by_cats ? '<small class="muted">Provisioned by CATS</small>' : ''}${evidence}</div>`;
    }).join('');
  }

  function renderCapabilityGroups(section, groups) {
    if (!section) return;
    const grid = section.querySelector('.capability-summary-grid');
    if (!grid) return;
    const items = Array.isArray(groups) ? groups : [];
    grid.innerHTML = items.map(item => {
      const status = text(item.status, 'NOT_REQUIRED').toUpperCase();
      const ok = ['AVAILABLE', 'PROVISIONED', 'VERIFIED', 'BOUND'].includes(status);
      return `<div><strong>${escape(item.capability)}</strong><br><span class="status ${ok ? 'ok' : (item.required ? 'warning' : '')}">${escape(title(status))}</span><p class="muted">${escape(item.verified_count || 0)} verified · ${escape(item.available_count || 0)} available · ${escape(item.required_count || 0)} required</p></div>`;
    }).join('');
    grid.querySelectorAll(':scope > div').forEach(node => node.classList.add('capability-summary-card'));
    const dependencyCard = section.querySelector('[data-live-capability-dependencies]');
    const dependencyGroup = items.find(item => text(item.capability) === 'Configuration dependencies');
    if (dependencyCard) {
      dependencyCard.hidden = !dependencyGroup || !Array.isArray(dependencyGroup.dependency_rows) || !dependencyGroup.dependency_rows.length;
      if (dependencyGroup && !dependencyCard.hidden) {
        const dependencyStatus = text(dependencyGroup.status, 'NOT_REQUIRED').toUpperCase();
        const statusNode = dependencyCard.querySelector('[data-live-capability-dependency-status]');
        if (statusNode) {
          statusNode.textContent = title(dependencyStatus);
          statusNode.className = 'status ' + (['AVAILABLE', 'PROVISIONED', 'VERIFIED', 'BOUND'].includes(dependencyStatus) ? 'ok' : 'warning');
        }
        const dependencies = dependencyGroup.dependency_rows;
        const countNode = dependencyCard.querySelector('[data-live-capability-dependency-count]');
        if (countNode) countNode.textContent = (dependencyGroup.dependency_available || 0) + ' / ' + (dependencyGroup.dependency_total || dependencies.length) + ' dependencies resolved';
        const breakdownNode = dependencyCard.querySelector('[data-live-capability-dependency-breakdown]');
        if (breakdownNode) breakdownNode.textContent = ['ConfigMap', 'Secret'].map(kind => {
          const matching = dependencies.filter(item => item.kind === kind);
          if (!matching.length) return '';
          const available = matching.filter(item => ['AVAILABLE', 'PROVISIONED', 'VERIFIED', 'BOUND'].includes(String(item.status || '').toUpperCase())).length;
          return kind + ' ' + available + ' / ' + matching.length;
        }).filter(Boolean).join(' · ');
        const body = dependencyCard.querySelector('[data-live-capability-dependency-body]');
        if (body) body.innerHTML = dependencies.map(item => '<div class="capability-dependency-row"><code>' + escape(item.kind + '/' + item.name) + '</code><small>Required by: ' + (item.required_by || []).map(source => '<code>' + escape(source) + '</code>').join(', ') + '</small><small>Status: ' + escape(title(item.status || 'NOT_REQUIRED')) + '</small></div>').join('');
      }
    }
  }

  function renderReasons(state) {
    const section = document.querySelector('[data-live-reasons]');
    if (!section) return;
    const reasons = Array.isArray(state.classification_reasons) ? state.classification_reasons : [];
    const summary = state.classification_summary || {};
    section.hidden = !reasons.length && text(state.status).toUpperCase() === 'VERIFIED';
    const values = [summary.expected_resources || 0, summary.observed_expected || 0, summary.expected_only || 0, summary.runtime_generated || 0, summary.failed || 0];
    ['total','observed','missing','generated','failed'].forEach((name, index) => { const node = section.querySelector(`[data-reason-${name}]`); if (node) node.textContent = values[index]; });
    const ratio = section.querySelector('[data-live-reason-ratio]');
    if (ratio) ratio.textContent = summary.expected_resources ? `${summary.observed_expected || 0} / ${summary.expected_resources} expected resources observed` : 'No resource comparison was available.';
    const body = section.querySelector('[data-live-reason-body]');
    if (body) body.innerHTML = reasons.length ? reasons.map(item => { const resource = item.resource || {}; const identity = resource.kind ? `${resource.kind}/${resource.namespace || ''}/${resource.name || ''}` : '—'; return `<tr><td><code>${escape(item.code || 'VALIDATION_REASON')}</code></td><td><code>${escape(identity)}</code></td><td>${escape(item.expected_state || '—')}</td><td>${escape(item.observed_state || '—')}</td><td>${escape(item.explanation || '—')}</td></tr>`; }).join('') : '<tr><td colspan="5" class="empty">No blocking reasons recorded.</td></tr>';
  }

  function renderListSection(section, values, renderer) {
    if (!section) return;
    const items = Array.isArray(values) ? values : [];
    section.hidden = items.length === 0;
    renderer(items);
  }

  function renderState(state, root, timer) {
    const status = text(state.status, 'NOT_ATTEMPTED').toUpperCase();
    const badge = document.querySelector('[data-live-validation-badge]');
    if (badge) { const label = badgeLabel(state); badge.textContent = label; setStatusClass(badge, label === 'BLOCKED BY PREFLIGHT' ? 'blocked-by-preflight' : (state.phase === 'COMPLETE' ? status : state.phase)); }
    const field = name => document.querySelector(`[data-live-field="${name}"]`);
    if (field('status')) field('status').textContent = badgeLabel(state);
    if (field('phase')) field('phase').textContent = title(state.phase || 'COMPLETE');
    if (field('started_at')) field('started_at').textContent = date(state.started_at);
    if (field('completed_at')) field('completed_at').textContent = date(state.completed_at);
    if (field('cleanup_status')) field('cleanup_status').textContent = title(state.cleanup_status || 'PENDING');
    const reason = field('reason');
    if (reason) reason.textContent = text(state.reason, isTerminal(state) ? 'Validation completed.' : 'Validation is queued or currently running.');
    const explanation = document.querySelector('[data-live-explanation]');
    if (explanation) {
      const old = explanation.querySelector('[data-live-classification]');
      if (state.reason_category) {
        if (old) old.innerHTML = `<strong>Classification:</strong> <code>${escape(state.reason_category)}</code>`;
        else explanation.insertAdjacentHTML('afterbegin', `<p data-live-classification><strong>Classification:</strong> <code>${escape(state.reason_category)}</code></p>`);
      } else if (old) old.remove();
    }
    if (timer) timer.update({startedAt: state.started_at, finishedAt: state.completed_at, status: state.phase === 'COMPLETE' ? status : state.phase});
    renderReasons(state);
    renderCapabilities(document.querySelector('[data-live-capabilities]'), state.capability_preflight);
    renderCapabilityGroups(document.querySelector('[data-live-capabilities]'), state.capability_assessment);
    const warnings = document.querySelector('[data-live-warnings]');
    if (warnings) { const values = state.warnings || []; warnings.hidden = !values.length; const list = warnings.querySelector('ul'); if (list) list.innerHTML = values.map(item => `<li class="warning">${escape(item)}</li>`).join(''); }
    const resources = state.resource_summary || {};
    document.querySelectorAll('[data-live-resources] [data-resource-key]').forEach(card => { const key = card.dataset.resourceKey; const item = resources[key] || {}; const ready = key === 'pvcs' ? (item.bound || 0) : (item.ready || 0); const expected = item.expected || 0; const target = card.querySelector('strong'); if (target) target.textContent = `${ready} / ${expected}`; });
    const helm = state.helm_result || {};
    const helmValues = [helm.template || (isTerminal(state) ? 'NOT_ATTEMPTED' : 'PENDING'), helm.template_duration_ms ? `${helm.template_duration_ms}ms` : '—', helm.install || (isTerminal(state) ? 'NOT_ATTEMPTED' : 'PENDING'), helm.install_duration_ms ? `${helm.install_duration_ms}ms` : '—', helm.release_status || (isTerminal(state) ? 'NOT_ATTEMPTED' : 'PENDING'), helm.rendered_resource_count === undefined ? 0 : helm.rendered_resource_count];
    document.querySelectorAll('[data-live-helm] dd').forEach((node, index) => { if (helmValues[index] !== undefined) node.textContent = helmValues[index]; });
    const conditions = document.querySelector('[data-live-conditions] dl');
    if (conditions) conditions.innerHTML = Object.keys(state.conditions || {}).length ? Object.entries(state.conditions).map(([key, value]) => `<dt>${escape(title(key))}</dt><dd>${escape(value)}</dd>`).join('') : '<dt>Status</dt><dd>No runtime conditions recorded.</dd>';
    const dependencies = state.dependencies || {};
    const dependencySection = document.querySelector('[data-live-dependencies]');
    if (dependencySection) {
      const groups = [['Missing CRDs', dependencies.missing_crds], ['Missing StorageClasses', dependencies.missing_storage_classes], ['Unavailable images', dependencies.unavailable_images]];
      const hasValues = groups.some(([, values]) => Array.isArray(values) && values.length);
      dependencySection.hidden = !hasValues;
      const grid = dependencySection.querySelector('.validation-list-grid');
      if (grid) grid.innerHTML = groups.map(([label, values]) => `<div><h3>${escape(label)}</h3><ul>${(Array.isArray(values) && values.length ? values.map(item => `<li><code>${escape(item)}</code></li>`).join('') : '<li class="muted">None</li>')}</ul></div>`).join('');
    }
    const isolation = state.resource_isolation || {};
    const isolationSection = document.querySelector('[data-live-isolation]');
    if (isolationSection) {
      isolationSection.hidden = !isolation.overall || isolation.overall === 'NOT_ATTEMPTED';
      const overall = isolationSection.querySelector('[data-live-isolation-overall]');
      if (overall) { overall.textContent = title(isolation.overall || 'NOT_ATTEMPTED'); overall.className = `status ${isolation.overall === 'ENFORCED' ? 'ok' : 'warning'}`; }
      const items = isolationSection.querySelector('[data-live-isolation-items]');
      if (items) items.innerHTML = [['cpu','CPU'],['memory','MEMORY'],['pids','PROCESS']].map(([key, label]) => { const item = isolation[key]; if (!item) return ''; const enforced = item.status === 'ENFORCED'; return `<div><strong>${label}</strong><br><span class="status ${enforced ? 'ok' : 'warning'}">${enforced ? 'ENFORCED' : 'NOT ENFORCED'}</span><br><small>Configured: <code>${escape(item.configured_limit)}</code></small>${!enforced ? '<p class="muted">Validation continued.</p>' : ''}${item.reason ? `<details><summary>Technical details</summary><p class="muted">${escape(item.reason)}</p></details>` : ''}</div>`; }).join('');
    }
    const unhealthy = document.querySelector('[data-live-unhealthy]');
    if (unhealthy) { const rows = state.unhealthy_resources || []; unhealthy.hidden = !rows.length; const body = unhealthy.querySelector('tbody'); if (body) body.innerHTML = rows.map(item => `<tr><td><code>${escape(item.resource)}</code></td><td>${escape(item.state || item.reason || 'Unknown')}</td><td>${escape(item.detail || item.reason || '—')}</td></tr>`).join(''); }
    const policy = document.querySelector('[data-live-policy]');
    const sensitive = root.querySelector('[data-live-sandbox-sensitive]'); if (sensitive) { const rows = state.sandbox_sensitive_behaviors || []; sensitive.hidden = !rows.length; const heading = sensitive.querySelector('[data-live-sandbox-heading]'); if (heading) heading.textContent = `Sandbox-sensitive behaviors${rows.length ? ` (${rows.length})` : ''}`; const body = sensitive.querySelector('[data-live-sandbox-body]'); if (body) body.innerHTML = rows.map(item => `<tr><td><code>${escape(item.resource || '—')}</code>${item.container ? `<br><span class="muted">container: ${escape(item.container)}</span>` : ''}</td><td><code>${escape(item.field_path || '—')}</code><br><span class="muted">${escape(item.value)}</span></td><td><code>${escape(item.classification || '—')}</code></td><td>${escape(item.reason || '—')}</td><td>${escape(item.isolation_control || '—')}</td><td>${item.template ? `<code>${escape(item.template)}</code>` : '<span class="muted">Source not retained</span>'}</td></tr>`).join(''); }
    if (policy) { const rows = state.security_policy_violations || []; policy.hidden = !(rows.length || state.reason_category === 'SECURITY_POLICY_VIOLATION'); const heading = policy.querySelector('[data-live-policy-heading]'); if (heading) heading.textContent = `Validation Sandbox Policy: Sandbox Boundary Violations${rows.length ? ` (${rows.length})` : ''}`; const body = policy.querySelector('[data-live-policy-body]'); if (body) body.innerHTML = rows.map(item => `<tr><td><code>${escape(item.rule_id || 'SECURITY_POLICY')}</code><br>${escape(item.rule_name || 'Sandbox boundary policy')}</td><td><code>${escape((item.kind || '—') + '/' + (item.name || '—'))}</code>${item.namespace ? `<br><span class="muted">${escape(item.namespace)}</span>` : ''}${item.container ? `<br><span class="muted">container: ${escape(item.container)}</span>` : ''}</td><td><code>${escape(item.field_path || '—')}</code>${item.value !== undefined && item.value !== null ? `<br><span class="muted">value: ${escape(item.value)}</span>` : ''}</td><td>${escape(item.reason || '—')}</td><td>${item.source_template ? `<code>${escape(item.source_template)}</code>${item.source_line ? `:${escape(item.source_line)}` : ''}` : '<span class="muted">Source not retained</span>'}</td></tr>`).join(''); const empty = policy.querySelector('[data-live-policy-empty]'); if (empty) empty.hidden = Boolean(rows.length); }
    const topology = state.observed_topology || {};
    const topologySection = document.querySelector('[data-live-topology]');
    if (topologySection) { const nodes = topology.nodes || []; const edges = topology.edges || []; const summary = topologySection.querySelector('[data-live-topology-summary]'); if (summary) summary.textContent = `${nodes.length} resources and ${edges.length} observed relationships from the Kubernetes API.`; const body = topologySection.querySelector('tbody'); if (body) body.innerHTML = nodes.length ? nodes.map(node => `<tr><td>${escape(node.kind)}</td><td><code>${escape(node.name)}</code></td><td>${escape(node.namespace || '—')}</td></tr>`).join('') : '<tr><td class="empty" colspan="3">Observed topology was not available for this run.</td></tr>'; }
    const comparison = state.comparison || {};
    document.querySelectorAll('[data-live-comparison] [data-comparison-key]').forEach(card => { const key = card.dataset.comparisonKey; const values = comparison[key] || []; const count = card.querySelector('[data-comparison-count]'); if (count) count.textContent = values.length; const summary = card.querySelector('summary'); if (summary) summary.textContent = `View ${title(key)} (${values.length})`; const items = card.querySelector('[data-comparison-items]'); if (items) items.innerHTML = values.length ? values.map(item => `<li><code>${escape(item)}</code></li>`).join('') : '<li class="muted">None</li>'; });
    const events = document.querySelector('[data-live-events]');
    if (events) { const rows = state.events || []; events.hidden = !rows.length; const body = events.querySelector('tbody'); if (body) body.innerHTML = rows.map(item => `<tr><td>${escape(item.type || '—')}</td><td>${escape(item.reason || '—')}</td><td><code>${escape(item.condition || '—')}</code></td><td><code>${escape(((item.involvedObject || {}).kind || '') + '/' + ((item.involvedObject || {}).name || ''))}</code></td><td>${escape(item.message || '—')}</td></tr>`).join(''); }
    const diagnostics = document.querySelector('[data-live-diagnostics]');
    if (diagnostics) { const values = state.diagnostics || {}; diagnostics.hidden = !Object.keys(values).length; diagnostics.querySelectorAll('h3,pre').forEach(node => node.remove()); Object.entries(values).forEach(([key, value]) => diagnostics.insertAdjacentHTML('beforeend', `<h3>${escape(title(key))}</h3><pre>${escape(JSON.stringify(value, null, 2))}</pre>`)); }
    root.dataset.activeRun = isTerminal(state) ? 'false' : 'true';
  }

  function create(options) {
    const settings = options || {};
    let url = settings.url; let runKey = settings.runKey; let timer = settings.timer || null; let sequence = 0; let request = null; let timerId = null; let stopped = false;
    const statusElement = settings.statusElement || document.querySelector('[data-live-polling-status]');
    function announce(value) { if (statusElement) statusElement.textContent = value || ''; }
    function stopRequest() { if (request) { request.abort(); request = null; } }
    function schedule() { if (!stopped && timerId === null) timerId = setTimeout(() => { timerId = null; poll(); }, settings.interval || 2000); }
    async function poll() {
      if (stopped || request || !url) return;
      const current = ++sequence; const controller = new AbortController(); request = controller;
      try {
        const response = await fetch(url, {credentials: 'same-origin', headers: {Accept: 'application/json'}, signal: request.signal, cache: 'no-store'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const state = await response.json();
        if (current !== sequence || state.run_key !== runKey) return;
        (settings.render || renderState)(state, settings.root, timer); announce('');
        if (!isTerminal(state)) schedule(); else announce('');
      } catch (error) { if (error.name !== 'AbortError') { announce('Live update unavailable; retrying.'); schedule(); } }
      finally { if (request === controller) request = null; }
    }
    function switchRun(next) { sequence += 1; stopRequest(); if (timerId !== null) { clearTimeout(timerId); timerId = null; } url = next.url; runKey = next.runKey; stopped = false; (settings.render || renderState)(next.state, settings.root, timer); poll(); }
    function destroy() { stopped = true; sequence += 1; stopRequest(); if (timerId !== null) clearTimeout(timerId); timerId = null; }
    if (settings.active) poll();
    return {poll, switchRun, destroy, isPolling: () => Boolean(request || timerId)};
  }

  function initialize() {
    const root = document.querySelector('[data-validation-live-root]');
    if (!root || !root.dataset.runKey) return null;
    const elapsed = document.querySelector('[data-validation-elapsed]');
    const timer = window && window.CatsElapsedTime && elapsed ? window.CatsElapsedTime.attach(elapsed) : null;
    const controller = create({root, url: root.dataset.apiUrl, runKey: root.dataset.runKey, active: root.dataset.activeRun === 'true', timer});
    const rerun = document.querySelector('[data-validation-rerun]');
    if (rerun) rerun.addEventListener('submit', async event => {
      event.preventDefault();
      const button = rerun.querySelector('button'); if (button) button.disabled = true;
      try {
        const response = await fetch(rerun.action, {method: 'POST', body: new FormData(rerun), credentials: 'same-origin', headers: {Accept: 'application/json'}});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json(); const state = payload.run; const nextUrl = `/api/v1/services/${encodeURIComponent(root.dataset.serviceKey)}/deployment-validations/${encodeURIComponent(payload.run_id)}`;
        history.replaceState({}, '', payload.url || location.href); root.dataset.runKey = payload.run_id; root.dataset.apiUrl = nextUrl; controller.switchRun({url: nextUrl, runKey: payload.run_id, state});
      } catch (error) { if (button) button.disabled = false; }
    });
    return controller;
  }
  if (typeof document !== 'undefined') { if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, {once: true}); else initialize(); }
  return {create, initialize, isTerminal, badgeLabel, renderState};
});
