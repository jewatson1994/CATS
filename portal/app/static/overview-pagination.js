(() => {
  const init = () => {
    document.querySelectorAll('table.overview-paginated').forEach((table) => {
      const card = table.closest('.overview-dashboard-card');
      const footer = card && card.querySelector('[data-overview-pagination]');
      const rows = Array.from(table.tBodies[0]?.rows || []);
      const pageSize = Math.max(1, Number.parseInt(table.dataset.pageSize || '10', 10) || 10);
      if (!footer || rows.length <= pageSize) {
        rows.forEach((row) => { row.hidden = false; });
        if (footer) footer.hidden = true;
        return;
      }
      const tableWrap = table.closest('.overview-table-wrap');
      const top = footer.cloneNode(true);
      top.hidden = true;
      top.dataset.overviewPaginationTop = 'true';
      tableWrap?.before(top);
      const mounts = [top, footer];
      const totalPages = Math.ceil(rows.length / pageSize);
      let page = 1;
      const render = () => {
        const start = (page - 1) * pageSize;
        const end = Math.min(start + pageSize, rows.length);
        rows.forEach((row, index) => { row.hidden = index < start || index >= end; });
        mounts.forEach((mount) => {
          mount.hidden = false;
          const summary = mount.querySelector('[data-pagination-summary]');
          const numbers = mount.querySelector('[data-page-numbers]');
          const previous = mount.querySelector('[data-page-prev]');
          const next = mount.querySelector('[data-page-next]');
          if (summary) summary.textContent = `Showing ${start + 1}\u2013${end} of ${rows.length}`;
          if (previous) previous.disabled = page === 1;
          if (next) next.disabled = page === totalPages;
          if (!numbers) return;
          numbers.replaceChildren();
          const pages = [];
          if (totalPages <= 5) {
            for (let value = 1; value <= totalPages; value += 1) pages.push(value);
          } else {
            pages.push(1);
            const low = Math.max(2, page - 1);
            const high = Math.min(totalPages - 1, page + 1);
            if (low > 2) pages.push('\u2026');
            for (let value = low; value <= high; value += 1) pages.push(value);
            if (high < totalPages - 1) pages.push('\u2026');
            pages.push(totalPages);
          }
          pages.forEach((value) => {
            if (value === '\u2026') {
              const ellipsis = document.createElement('span');
              ellipsis.className = 'overview-pagination-ellipsis';
              ellipsis.textContent = value;
              numbers.append(ellipsis);
              return;
            }
            const button = document.createElement('button');
            button.type = 'button';
            button.textContent = value;
            button.setAttribute('aria-label', `Page ${value}`);
            if (value === page) button.setAttribute('aria-current', 'page');
            button.addEventListener('click', () => { page = value; render(); });
            numbers.append(button);
          });
        });
      };
      mounts.forEach((mount) => {
        mount.querySelector('[data-page-prev]')?.addEventListener('click', () => { if (page > 1) { page -= 1; render(); } });
        mount.querySelector('[data-page-next]')?.addEventListener('click', () => { if (page < totalPages) { page += 1; render(); } });
      });
      render();
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
