/* Secondary SPA pages (inventory and audit). Loaded before app.js. */
'use strict';

(function () {
  async function renderInventory(view, h) {
    const { $, get, esc, num, fmtShort, statusPill, emptyHtml, loadingHtml, queryString, toast, errorText, openModal, sevBadge } = h;
    let customers = [];
    try { customers = await get('/customers'); } catch (ignore) { customers = []; }
    const customerOptions = customers.map(function (item) {
      return '<option value="' + item.id + '">' + esc(item.name) + '</option>';
    }).join('');

    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Inventory</h1>' +
        '<div class="page-sub">Hosts and services discovered by network scans, with device and OS hints.</div></div>' +
        '<div class="page-actions"><button class="btn" id="inventory-refresh">Refresh</button></div></div>' +
      '<section class="panel"><div class="panel-head"><h2>Discovered hosts</h2><span class="spacer"></span>' +
        '<span class="muted small" id="inventory-count"></span></div>' +
        '<div class="panel-body">' +
        '<div class="filter-bar">' +
          '<select class="select" id="inventory-customer"><option value="">All customers</option>' + customerOptions + '</select>' +
          '<input class="input" id="inventory-query" placeholder="Search IP, hostname, OS, MAC" style="max-width:300px">' +
          '<button class="btn" id="inventory-filter">Filter</button>' +
        '</div>' +
        '<div id="inventory-summary" class="muted small" style="margin:8px 0"></div>' +
        '<div class="table-wrap" id="inventory-table">' + loadingHtml('Loading inventory…') + '</div>' +
        '</div></section>';

    async function load() {
      const params = {
        customer_id: $('#inventory-customer').value,
        q: $('#inventory-query').value.trim(),
        limit: 500
      };
      const data = await get('/inventory' + queryString(params));
      $('#inventory-count').textContent = num(data.total) + ' entr' + (num(data.total) === 1 ? 'y' : 'ies');
      $('#inventory-summary').textContent = (data.device_types || []).map(function (item) {
        return (item.device_type || 'Unknown') + ': ' + num(item.count);
      }).join(' · ') || 'No devices discovered yet.';
      const rows = data.entries || [];
      if (!rows.length) {
        $('#inventory-table').innerHTML = emptyHtml('No inventory entries', 'Run a network scan against a customer to populate host and service inventory.');
        return;
      }
      $('#inventory-table').innerHTML =
        '<table class="data-table"><thead><tr><th>Host</th><th>Device / OS</th><th>Ports</th>' +
        '<th>Customer</th><th>First seen</th><th>Last seen</th><th>Status</th></tr></thead><tbody>' +
        rows.map(function (row) {
          const ports = (row.ports || []).slice(0, 12).map(function (port) {
            return '<span class="tag">' + num(port) + '</span>';
          }).join(' ') + ((row.ports || []).length > 12 ? ' <span class="muted small">+' + (row.ports.length - 12) + '</span>' : '');
          return '<tr' + (row.asset_id ? ' class="clickable" data-asset-id="' + num(row.asset_id) + '"' : '') + '>' +
            '<td><div class="cell-main mono">' + esc(row.ip_address || row.hostname || '—') + '</div>' +
              '<div class="cell-sub">' + esc(row.hostname && row.hostname !== row.ip_address ? row.hostname : '') + '</div></td>' +
            '<td>' + esc(row.device_type || 'Unknown') + '<div class="cell-sub">' + esc(row.os_guess || '') + '</div></td>' +
            '<td>' + (ports || '<span class="muted small">none</span>') + '</td>' +
            '<td>' + esc(row.customer_name || '—') + '<div class="cell-sub">' + esc(row.asset_name || '') + '</div></td>' +
            '<td class="nowrap">' + esc(fmtShort(row.first_seen)) + '</td>' +
            '<td class="nowrap">' + esc(fmtShort(row.last_seen)) + '</td>' +
            '<td>' + statusPill(row.status || 'active') + '</td></tr>';
        }).join('') + '</tbody></table>';
    }

    $('#inventory-filter').addEventListener('click', function () {
      load().catch(function (error) { toast(errorText(error), 'error'); });
    });
    $('#inventory-query').addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { event.preventDefault(); load().catch(function (error) { toast(errorText(error), 'error'); }); }
    });
    $('#inventory-refresh').addEventListener('click', function () {
      load().catch(function (error) { toast(errorText(error), 'error'); });
    });
    $('#inventory-table').addEventListener('click', async function (event) {
      const row = event.target.closest('[data-asset-id]');
      if (!row) return;
      try {
        const history = await get('/assets/' + row.getAttribute('data-asset-id') + '/history');
        const inventoryRows = (history.inventory || []).map(function (item) {
          return '<div class="kv"><span class="mono">' + esc(item.ip_address || item.hostname) + '</span>' +
            '<span>' + esc(item.device_type || 'Unknown') + ' · ' + esc((item.ports || []).join(', ') || 'no ports') + '</span></div>';
        }).join('');
        const historyRows = (history.history || []).slice(0, 100).map(function (item) {
          return '<tr><td class="mono">' + esc(item.fingerprint) + '</td><td>' + sevBadge(item.severity_at_last) + '</td>' +
            '<td>' + esc(item.status_at_last || '') + '</td><td>' + num(item.count) + '</td>' +
            '<td class="nowrap">' + esc(fmtShort(item.first_seen)) + '</td><td class="nowrap">' + esc(fmtShort(item.last_seen)) + '</td></tr>';
        }).join('');
        openModal({
          title: 'Asset history · ' + (history.asset.name || ''),
          size: 'wide',
          content:
            '<div class="kv"><span>Asset</span><span class="mono">' + esc(history.asset.identifier || history.asset.name || '') + '</span></div>' +
            '<div class="kv"><span>Customer</span><span>' + esc(history.asset.customer_name || '—') + '</span></div>' +
            '<h3 style="margin-top:16px">Inventory</h3>' + (inventoryRows || '<p class="muted small">No inventory records.</p>') +
            '<h3 style="margin-top:16px">Finding history</h3>' +
            (historyRows ? '<div class="table-wrap"><table class="data-table"><thead><tr><th>Fingerprint</th><th>Severity</th><th>Status</th><th>Seen</th><th>First</th><th>Last</th></tr></thead><tbody>' + historyRows + '</tbody></table></div>' : '<p class="muted small">No finding history yet.</p>')
        });
      } catch (error) { toast(errorText(error), 'error'); }
    });
    await load();
  }

  async function renderAudit(view, h) {
    const { $, get, esc, num, fmtDate, emptyHtml, loadingHtml, queryString, toast, errorText, openModal } = h;
    let summary = { total: 0, failures: 0, last_24h: 0 };
    try { summary = await get('/audit/summary'); } catch (ignore) { /* keep defaults */ }
    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Audit trail</h1>' +
        '<div class="page-sub">Authentication, configuration, maintenance and API changes recorded by the server.</div></div>' +
        '<div class="page-actions"><a class="btn" id="audit-export" href="/api/audit/export">Export CSV</a>' +
        '<button class="btn" id="audit-refresh">Refresh</button></div></div>' +
      '<div class="stat-grid">' +
        '<div class="stat-card"><div class="stat-label">Events</div><div class="stat-value">' + num(summary.total) + '</div><div class="stat-foot">all time</div></div>' +
        '<div class="stat-card"><div class="stat-label">Last 24 hours</div><div class="stat-value">' + num(summary.last_24h) + '</div><div class="stat-foot">recorded events</div></div>' +
        '<div class="stat-card ' + (num(summary.failures) ? 'stat-warn' : '') + '"><div class="stat-label">Failures</div><div class="stat-value">' + num(summary.failures) + '</div><div class="stat-foot">denied or failed actions</div></div>' +
      '</div>' +
      '<section class="panel"><div class="panel-head"><h2>Events</h2><span class="spacer"></span><span class="muted small" id="audit-count"></span></div><div class="panel-body">' +
        '<div class="filter-bar">' +
          '<select class="select" id="audit-category"><option value="">All categories</option>' +
            ['auth', 'settings', 'maintenance', 'api'].map(function (item) { return '<option value="' + item + '">' + item + '</option>'; }).join('') +
          '</select>' +
          '<select class="select" id="audit-outcome"><option value="">Any outcome</option><option value="success">success</option><option value="failure">failure</option></select>' +
          '<input class="input" id="audit-query" placeholder="Search action, actor, target or detail" style="max-width:340px">' +
          '<button class="btn" id="audit-filter">Filter</button>' +
        '</div>' +
        '<div class="table-wrap" id="audit-table">' + loadingHtml('Loading audit trail…') + '</div>' +
      '</div></section>';

    function filterParams() {
      return {
        category: $('#audit-category').value,
        outcome: $('#audit-outcome').value,
        q: $('#audit-query').value.trim(),
        limit: 500
      };
    }

    async function load() {
      const params = filterParams();
      const data = await get('/audit' + queryString(params));
      $('#audit-count').textContent = num(data.total) + ' matching event' + (num(data.total) === 1 ? '' : 's');
      $('#audit-export').setAttribute('href', '/api/audit/export' + queryString(params));
      const rows = data.entries || [];
      if (!rows.length) {
        $('#audit-table').innerHTML = emptyHtml('No audit events', 'Security-sensitive actions and API changes will appear here.');
        return;
      }
      $('#audit-table').innerHTML =
        '<table class="data-table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Category</th><th>Target</th><th>Outcome</th><th>IP</th></tr></thead><tbody>' +
        rows.map(function (row) {
          return '<tr class="clickable" data-audit-id="' + num(row.id) + '">' +
            '<td class="nowrap">' + esc(fmtDate(row.created_at)) + '</td>' +
            '<td>' + esc(row.actor || '—') + '</td>' +
            '<td class="mono">' + esc(row.action || '') + '</td>' +
            '<td>' + esc(row.category || '') + '</td>' +
            '<td class="truncate" title="' + esc(row.target || '') + '">' + esc(row.target || '—') + '</td>' +
            '<td><span class="badge ' + (row.outcome === 'failure' ? 'sev-critical' : 'sev-info') + '">' + esc(row.outcome || '') + '</span></td>' +
            '<td class="mono">' + esc(row.ip || '') + '</td></tr>';
        }).join('') + '</tbody></table>';
      $('#audit-table').dataset.entries = JSON.stringify(rows);
    }

    $('#audit-filter').addEventListener('click', function () { load().catch(function (error) { toast(errorText(error), 'error'); }); });
    $('#audit-query').addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { event.preventDefault(); load().catch(function (error) { toast(errorText(error), 'error'); }); }
    });
    $('#audit-refresh').addEventListener('click', function () { load().catch(function (error) { toast(errorText(error), 'error'); }); });
    $('#audit-table').addEventListener('click', function (event) {
      const row = event.target.closest('[data-audit-id]');
      if (!row) return;
      let entries = [];
      try { entries = JSON.parse($('#audit-table').dataset.entries || '[]'); } catch (ignore) { entries = []; }
      const entry = entries.find(function (item) { return String(item.id) === row.getAttribute('data-audit-id'); });
      if (!entry) return;
      openModal({
        title: 'Audit event #' + entry.id,
        content:
          '<div class="kv"><span>Time</span><span>' + esc(fmtDate(entry.created_at)) + '</span></div>' +
          '<div class="kv"><span>Actor</span><span>' + esc(entry.actor || '—') + '</span></div>' +
          '<div class="kv"><span>Action</span><span class="mono">' + esc(entry.action || '') + '</span></div>' +
          '<div class="kv"><span>Category</span><span>' + esc(entry.category || '') + '</span></div>' +
          '<div class="kv"><span>Outcome</span><span>' + esc(entry.outcome || '') + '</span></div>' +
          '<div class="kv"><span>Target</span><span class="mono">' + esc(entry.target || '—') + '</span></div>' +
          '<div class="kv"><span>Source IP</span><span class="mono">' + esc(entry.ip || '—') + '</span></div>' +
          '<div class="kv"><span>User agent</span><span class="small">' + esc(entry.user_agent || '—') + '</span></div>' +
          '<h3 style="margin-top:16px">Detail</h3><pre class="audit-detail">' + esc(entry.detail || '—') + '</pre>'
      });
    });
    await load();
  }

  window.VSPages = { inventory: renderInventory, audit: renderAudit };
})();
