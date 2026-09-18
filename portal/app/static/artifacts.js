(() => {
  document.querySelectorAll('[data-filter-bar="images"] option').forEach(option => {
    if (option.value === 'running') { option.value = 'scanning'; option.textContent = 'Scanning'; }
    if (option.value === 'complete') { option.value = 'scanned'; option.textContent = 'Scanned'; }
  });
  const dialog = document.getElementById('add-artifact-dialog');
  if (dialog) {
    const form = dialog.querySelector('form');
    const types = [...form.querySelectorAll('[name="artifact_type"]')];
    const panels = [...form.querySelectorAll('[data-artifact-panel]')];
    const syncType = () => {
      const selected = types.find(input => input.checked)?.value || 'helm_repository';
      panels.forEach(panel => {
        const active = panel.dataset.artifactPanel === selected;
        panel.hidden = !active;
        panel.querySelectorAll('input,select').forEach(control => control.disabled = !active);
      });
      const repositoryReference = form.querySelector('[data-artifact-panel="helm_repository"] [name="source_reference"]');
      if (repositoryReference) repositoryReference.required = selected === 'helm_repository';
      syncChartSource();
    };
    const syncChartSource = () => {
      const panel = form.querySelector('[data-artifact-panel="helm_chart"]');
      const method = panel?.querySelector('[name="source_method"]:checked')?.value;
      const reference = panel?.querySelector('[data-helm-reference]');
      const upload = panel?.querySelector('[data-helm-upload]');
      if (!panel || panel.hidden) return;
      if (reference) { reference.hidden = method !== 'oci'; reference.querySelector('input').required = method === 'oci'; }
      if (upload) { upload.hidden = method === 'oci'; upload.querySelector('input').required = method !== 'oci'; }
    };
    types.forEach(input => input.addEventListener('change', syncType));
    form.querySelectorAll('[data-artifact-panel="helm_chart"] [name="source_method"]').forEach(input => input.addEventListener('change', syncChartSource));
    document.querySelectorAll('[data-open-artifact-dialog]').forEach(button => button.addEventListener('click', () => {
      const requested = button.dataset.artifactType;
      if (requested) { const input = form.querySelector(`[name="artifact_type"][value="${requested}"]`); if (input) input.checked = true; }
      syncType(); dialog.showModal();
    }));
    form.querySelector('[data-close-artifact-dialog]')?.addEventListener('click', () => dialog.close());
    syncType();
  }

  const pageSize = 25;
  document.querySelectorAll('[data-artifact-table]').forEach(table => {
    const kind = table.dataset.artifactTable;
    const bar = document.querySelector(`[data-filter-bar="${kind}"]`);
    const pager = document.querySelector(`[data-artifact-pagination="${kind}"]`);
    const empty = document.querySelector(`[data-filter-empty="${kind}"]`);
    const body = table.tBodies[0];
    const rows = [...body.querySelectorAll('[data-artifact-row]')];
    let page = 1;
    const update = () => {
      const query = (bar?.querySelector('[data-filter-search]')?.value || '').trim().toLowerCase();
      const source = bar?.querySelector('[data-filter-source]')?.value || '';
      const state = bar?.querySelector('[data-filter-state]')?.value || '';
      const validation = bar?.querySelector('[data-filter-validation]')?.value || '';
      const sort = bar?.querySelector('[data-filter-sort]')?.value;
      const filtered = rows.filter(row => (!query || row.dataset.name.includes(query)) && (!source || row.dataset.source === source) && (!state || row.dataset.state === state) && (!validation || row.dataset.validation === validation));
      if (sort) filtered.sort((a, b) => sort === 'files' ? Number(a.dataset.files) - Number(b.dataset.files) : (a.dataset[sort] || '').localeCompare(b.dataset[sort] || '', undefined, {numeric: true}));
      filtered.forEach(row => body.appendChild(row));
      const pages = Math.max(1, Math.ceil(filtered.length / pageSize)); page = Math.min(page, pages);
      rows.forEach(row => row.hidden = true);
      filtered.slice((page - 1) * pageSize, page * pageSize).forEach(row => row.hidden = false);
      if (empty) empty.hidden = filtered.length !== 0;
      if (pager) {
        pager.hidden = filtered.length <= pageSize;
        pager.querySelector('[data-page-summary]').textContent = `${filtered.length ? (page - 1) * pageSize + 1 : 0}–${Math.min(page * pageSize, filtered.length)} of ${filtered.length}`;
        pager.querySelector('[data-page-prev]').disabled = page === 1;
        pager.querySelector('[data-page-next]').disabled = page === pages;
      }
    };
    bar?.querySelectorAll('input,select').forEach(control => control.addEventListener(control.matches('input') ? 'input' : 'change', () => { page = 1; update(); }));
    pager?.querySelector('[data-page-prev]')?.addEventListener('click', () => { page--; update(); });
    pager?.querySelector('[data-page-next]')?.addEventListener('click', () => { page++; update(); });
    update();
  });

  const statuses = [...document.querySelectorAll('[data-image-status]')];
  if (statuses.some(node => ['Queued', 'Scanning'].includes(node.textContent.trim()))) {
    const serviceKey = location.pathname.split('/')[2];
    const poll = async () => {
      try {
        const response = await fetch(`/api/services/${encodeURIComponent(serviceKey)}/artifacts/images/status`);
        if (!response.ok) return;
        const payload = await response.json();
        payload.images.forEach(image => { const node = document.querySelector(`[data-image-status="${image.id}"]`); if (node) node.textContent = String(image.status || '').replaceAll('_', ' '); });
        if (payload.images.some(image => ['queued', 'scanning'].includes(image.status))) setTimeout(poll, 3000);
      } catch (_) { setTimeout(poll, 5000); }
    };
    setTimeout(poll, 1500);
  }
})();
