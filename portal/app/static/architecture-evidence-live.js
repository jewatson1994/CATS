(() => {
  const root = document.querySelector("[data-architecture-summary]");
  if (!root?.dataset.evidenceUrl) return;
  let timer;
  const statusClass = (state) => `status validation-status-${String(state || "N/A").toLowerCase().replaceAll("_", "-")}`;
  async function poll() {
    if (!document.hidden) {
      try {
        const response = await fetch(root.dataset.evidenceUrl, {credentials: "same-origin", headers: {Accept: "application/json"}, cache: "no-store"});
        if (response.ok) {
          const payload = await response.json();
          const evidence = payload.architecture || {};
          const badge = root.querySelector("[data-architecture-summary-badge]");
          if (badge) { badge.textContent = evidence.label || "N/A"; badge.className = statusClass(evidence.state); }
          const declared = root.querySelector("[data-architecture-declared]");
          const observed = root.querySelector("[data-architecture-observed]");
          const differences = root.querySelector("[data-architecture-differences]");
          if (declared) declared.textContent = payload.graph?.summary?.declared ?? evidence.expected ?? 0;
          if (observed) observed.textContent = evidence.observed ?? 0;
          if (differences) differences.textContent = evidence.missing ?? payload.graph?.summary?.differences ?? 0;
        }
      } catch (_) { /* Keep the last persisted summary visible. */ }
    }
    timer = setTimeout(poll, 5000);
  }
  timer = setTimeout(poll, 5000);
  window.addEventListener("pagehide", () => clearTimeout(timer), {once: true});
})();
