(() => {
  const root = document.querySelector("[data-architecture]");
  if (!root) return;

  let graph = JSON.parse(root.dataset.graph);
  const svg = root.querySelector("svg");
  const scene = root.querySelector("[data-architecture-scene]");
  const panel = root.querySelector(".architecture-details");
  const detail = root.querySelector("[data-architecture-details]");
  const empty = root.querySelector("[data-architecture-empty]");
  const emptyView = root.querySelector("[data-architecture-empty-view]");
  const layer = document.querySelector("[data-architecture-layer]");
  const close = root.querySelector("[data-architecture-close]");
  const level = root.querySelector("[data-zoom-level]");
  const viewport = root.querySelector(".architecture-canvas");
  let nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  let renderedEdges = [];
  let selected = null;
  let scale = 1;
  let panX = 0;
  let panY = 0;
  let dragging = false;
  let lastX = 0;
  let lastY = 0;
  let canvasWidth = 1200;
  let canvasHeight = 620;

  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
  }[character]));

  function currentLayout() {
    return graph.layouts[layer.value] || graph.layouts.flow;
  }

  function pathData(points) {
    return points.map((point, index) => `${index ? "L" : "M"} ${point.x} ${point.y}`).join(" ");
  }

  function show(item) {
    if (!item) return;
    selected = item.id;
    panel.hidden = false;
    empty.hidden = true;
    detail.hidden = false;
    const source = nodeById.get(item.source);
    const target = nodeById.get(item.target);
    const ports = (item.network || {}).ports || [];
    const mappings = ports.length
      ? `<dt>Port mappings</dt><dd>${ports.map((port) => `${escapeHtml(port.servicePort ?? "—")} → ${escapeHtml(port.targetPort ?? "—")}/${escapeHtml(port.protocol || "TCP")}`).join("<br>")}</dd>`
      : "";
    const classifications = item.classifications || (item.classification ? [item.classification] : []);
    const evidence = (item.evidence || []).map((entry) => `${escapeHtml(entry.detail || "Evidence")} · ${escapeHtml(entry.source || "—")}`).join("<br>") || "—";
    const chart = item.chart_provenance || {};
    const chartDetails = chart.chart
      ? `<dt>Chart</dt><dd>${escapeHtml(chart.chart)}${chart.version ? ` @ ${escapeHtml(chart.version)}` : ""}</dd>`
        + `<dt>Chart parent</dt><dd>${escapeHtml(chart.parent_chart_name || chart.parent_chart || "Root")}</dd>`
        + `<dt>Discovered from</dt><dd>${escapeHtml(chart.discovery_source_file || chart.source || "—")}${chart.yaml_path ? `#${escapeHtml(chart.yaml_path)}` : ""}</dd>`
        + (chart.reference ? `<dt>YAML reference</dt><dd>${escapeHtml(chart.reference)}</dd>` : "")
      : "";
    detail.innerHTML = `<h3>${escapeHtml(item.label || item.id || item.classification)}</h3><dl>`
      + `<dt>Source</dt><dd>${escapeHtml(source?.label || item.source || "—")}</dd>`
      + `<dt>Destination</dt><dd>${escapeHtml(target?.label || item.target || "—")}</dd>`
      + `<dt>Classification</dt><dd>${escapeHtml(classifications.join(" + ") || item.kind || "—")}</dd>`
      + `<dt>Evidence provenance</dt><dd>${escapeHtml(titleCase(item.provenance || "DECLARED"))}</dd>`
      + mappings
      + chartDetails
      + `<dt>Evidence</dt><dd>${evidence}</dd>`
      + (item.confidence ? `<dt>Confidence</dt><dd>${escapeHtml(item.confidence)}</dd>` : "")
      + "</dl>";
    draw();
  }

  function relatedIds() {
    if (!selected) return new Set();
    const related = new Set([selected]);
    const selectedEdge = renderedEdges.find((edge) => edge.id === selected);
    if (selectedEdge) {
      related.add(selectedEdge.source);
      related.add(selectedEdge.target);
    } else {
      renderedEdges.forEach((edge) => {
        if (edge.source === selected || edge.target === selected) {
          related.add(edge.id);
          related.add(edge.source);
          related.add(edge.target);
        }
      });
    }
    return related;
  }

  function applyTransform() {
    scene.setAttribute("transform", `translate(${panX} ${panY}) scale(${scale})`);
    level.textContent = `${Math.round(scale * 100)}%`;
    scene.querySelectorAll(".architecture-edge").forEach((edge) => {
      edge.setAttribute("marker-end", "url(#architecture-arrow)");
    });
  }

  function draw() {
    const layout = currentLayout();
    renderedEdges = layout.edges || [];
    const visibleNodes = (layout.node_ids || []).map((id) => nodeById.get(id)).filter(Boolean);
    const related = relatedIds();
    scene.replaceChildren();
    emptyView.hidden = visibleNodes.length > 0;
    if (!visibleNodes.length) {
      emptyView.textContent = `No resources applicable to the ${layer.options[layer.selectedIndex].text} view were discovered.`;
      return;
    }

    renderedEdges.forEach((edge) => {
      const dim = selected && !related.has(edge.id);
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", pathData(edge.points));
      path.setAttribute("class", `architecture-edge ${String(edge.classification || "derived").toLowerCase()} provenance-${String(edge.provenance || "declared").toLowerCase().replaceAll("_", "-")}${dim ? " is-dim" : ""}`);
      path.dataset.id = edge.id;
      path.addEventListener("click", () => show(edge));
      scene.appendChild(path);
      if (edge.label_position) {
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", edge.label_position.x);
        text.setAttribute("y", edge.label_position.y);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("class", `architecture-edge-label${dim ? " is-dim" : ""}`);
        text.dataset.edgeId = edge.id;
        const lines = edge.label_lines || [edge.label];
        lines.forEach((line, index) => {
          const span = document.createElementNS("http://www.w3.org/2000/svg", "tspan");
          span.setAttribute("x", edge.label_position.x);
          span.setAttribute("y", edge.label_position.y + (index - (lines.length - 1) / 2) * 16 + 4);
          span.textContent = line;
          text.appendChild(span);
        });
        scene.appendChild(text);
      }
    });

    visibleNodes.forEach((node) => {
      const point = layout.positions[node.id];
      const dim = selected && !related.has(node.id);
      const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
      group.setAttribute("class", `architecture-node provenance-${String(node.provenance || "declared").toLowerCase().replaceAll("_", "-")}${dim ? " is-dim" : ""}`);
      group.dataset.id = node.id;
      group.innerHTML = `<rect x="${point.x - 92}" y="${point.y - 28}" width="184" height="56" rx="8"></rect>`
        + `<text x="${point.x}" y="${point.y - 3}" text-anchor="middle">${escapeHtml(node.kind || node.type)}</text>`
        + `<text x="${point.x}" y="${point.y + 16}" text-anchor="middle" class="architecture-node-name">${escapeHtml(node.name.length > 25 ? node.name.slice(0, 24) + "…" : node.name)}</text>`
        + `<title>${escapeHtml(node.kind + " · " + node.name + " · " + node.namespace)}</title>`;
      group.addEventListener("click", () => show(node));
      scene.appendChild(group);
    });
    applyTransform();
  }

  function zoom(next, centerX = canvasWidth / 2, centerY = canvasHeight / 2) {
    const previous = scale;
    scale = Math.max(0.25, Math.min(3, next));
    panX = centerX - (centerX - panX) * (scale / previous);
    panY = centerY - (centerY - panY) * (scale / previous);
    applyTransform();
  }

  function fit() {
    const bounds = currentLayout().bounds;
    if (!bounds || !bounds.width || !bounds.height) return;
    scale = 1;
    panX = Math.max(0, (canvasWidth - bounds.width) / 2) - bounds.x;
    panY = Math.max(0, (canvasHeight - bounds.height) / 2) - bounds.y;
    applyTransform();
  }

  root.querySelector("[data-zoom-in]").addEventListener("click", () => zoom(scale + 0.25));
  root.querySelector("[data-zoom-out]").addEventListener("click", () => zoom(scale - 0.25));
  root.querySelector("[data-zoom-reset]").addEventListener("click", () => {
    scale = 1;
    panX = 0;
    panY = 0;
    applyTransform();
  });
  root.querySelector("[data-zoom-fit]").addEventListener("click", fit);
  close.addEventListener("click", () => {
    selected = null;
    panel.hidden = true;
    draw();
  });
  layer.addEventListener("change", () => {
    selected = null;
    panel.hidden = true;
    draw();
    fit();
  });
  viewport.addEventListener("wheel", (event) => {
    event.preventDefault();
    const box = svg.getBoundingClientRect();
    zoom(scale + (event.deltaY < 0 ? 0.15 : -0.15), (event.clientX - box.left) / box.width * canvasWidth, (event.clientY - box.top) / box.height * canvasHeight);
  }, { passive: false });
  viewport.addEventListener("pointerdown", (event) => {
    if (event.target.closest(".architecture-node,.architecture-edge")) return;
    dragging = true;
    lastX = event.clientX;
    lastY = event.clientY;
    viewport.setPointerCapture(event.pointerId);
    viewport.classList.add("is-panning");
  });
  viewport.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    panX += event.clientX - lastX;
    panY += event.clientY - lastY;
    lastX = event.clientX;
    lastY = event.clientY;
    applyTransform();
  });
  viewport.addEventListener("pointerup", () => {
    dragging = false;
    viewport.classList.remove("is-panning");
  });

  let resizeTimer;
  let requestNumber = 0;
  let requestedWidth = 0;
  let pendingRequest;
  async function reflow() {
    const box = svg.getBoundingClientRect();
    const width = Math.max(240, Math.min(10000, Math.floor(box.width / 16) * 16));
    canvasWidth = box.width;
    canvasHeight = box.height;
    svg.setAttribute("viewBox", `0 0 ${canvasWidth} ${canvasHeight}`);
    if (width === requestedWidth) return;
    requestedWidth = width;
    const number = ++requestNumber;
    pendingRequest?.abort();
    pendingRequest = new AbortController();
    const url = new URL(window.location.href);
    url.searchParams.set("architecture", "true");
    url.searchParams.set("layout_width", width);
    try {
      const response = await fetch(url, { signal: pendingRequest.signal });
      if (!response.ok) throw new Error("Layout request failed");
      const layouts = await response.json();
      if (number !== requestNumber) return;
      graph.layouts = layouts;
      draw();
      fit();
    } catch (error) {
      if (error.name !== "AbortError" && number === requestNumber) {
        requestedWidth = 0;
        emptyView.hidden = false;
        emptyView.textContent = "Could not refresh the layout. Resize or reload to retry.";
      }
    }
  }
  new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(reflow, 180);
  }).observe(svg);
  function titleCase(value) { return String(value || "").toLowerCase().replace(/(^|[_ -])([a-z])/g, (_, p, c) => p + c.toUpperCase()).replaceAll("_", " "); }
  function updateGraph(nextGraph) {
    const selectedView = layer.value;
    graph = nextGraph;
    nodeById = new Map((graph.nodes || []).map((node) => [node.id, node]));
    if (!graph.layouts[selectedView]) layer.value = "all";
    if (selected && !nodeById.has(selected) && !(graph.relationships || []).some(edge => edge.id === selected)) selected = null;
    draw();
    fit();
  }
  const verification = document.querySelector("[data-architecture-verification]");
  if (verification?.dataset.evidenceUrl) {
    let evidenceTimer;
    let graphKey = JSON.stringify(graph);
    const refreshEvidence = async () => {
      if (document.hidden) { evidenceTimer = setTimeout(refreshEvidence, 5000); return; }
      try {
        const response = await fetch(verification.dataset.evidenceUrl, {credentials: "same-origin", headers: {Accept: "application/json"}, cache: "no-store"});
        if (response.ok) {
          const state = await response.json();
          const badge = verification.querySelector("[data-architecture-badge]");
          if (badge && state.architecture) {
            badge.textContent = `${state.architecture.state === "VERIFIED" ? "✓ " : ""}${state.architecture.label}`;
            badge.className = `status validation-status-${state.architecture.state.toLowerCase().replaceAll("_", "-")}`;
          }
          const evidence = state.architecture || {};
          const popover = verification.querySelector("[data-architecture-popover]");
          if (popover) {
            const verified = ["VERIFIED", "PARTIALLY_VERIFIED"].includes(evidence.state);
            const metrics = verified
              ? `<p><strong>${escapeHtml(evidence.observed ?? 0)} / ${escapeHtml(evidence.expected ?? 0)}</strong> declared resources observed<br>${escapeHtml(evidence.missing ?? 0)} expected resources missing<br>${escapeHtml(evidence.failed ?? 0)} failed</p>`
                + `<p>Validation completed: ${escapeHtml(evidence.completed_at ? new Date(evidence.completed_at).toLocaleString() : "—")}</p><p>Engine: <strong>${escapeHtml(evidence.engine || "kind")}</strong></p>`
              : `<p>${escapeHtml(evidence.reason || "No persisted runtime verification applies to this artifact revision.")}</p>`;
            const action = evidence.run_key
              ? `<a href="${escapeHtml(window.location.pathname)}?validation=true&amp;validation_run=${encodeURIComponent(evidence.run_key)}">View Deployment Validation →</a>`
              : evidence.state === "DECLARED" ? `<a href="${escapeHtml(window.location.pathname)}?validation=true">Run Deployment Validation →</a>` : "";
            popover.innerHTML = `<h3>${escapeHtml(evidence.label || "N/A")} Architecture</h3>${metrics}${action}`;
          }
          const nextGraphKey = state.graph ? JSON.stringify(state.graph) : graphKey;
          if (state.graph && nextGraphKey !== graphKey) {
            graphKey = nextGraphKey;
            updateGraph(state.graph);
          }
        }
      } catch (_) { /* Persisted evidence remains visible while polling recovers. */ }
      evidenceTimer = setTimeout(refreshEvidence, 5000);
    };
    evidenceTimer = setTimeout(refreshEvidence, 5000);
    window.addEventListener("pagehide", () => clearTimeout(evidenceTimer), {once: true});
  }
  draw();
  reflow();
})();
