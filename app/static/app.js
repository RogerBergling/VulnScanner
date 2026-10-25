/* VulnScanner single-page UI. Dependency-free, CSP-friendly, no inline handlers. */
'use strict';

(function () {
  // ---------------------------------------------------------------------------
  // Constants and helpers
  // ---------------------------------------------------------------------------
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_COLOR = {
    critical: '#c62828',
    high: '#d95d13',
    medium: '#b08300',
    low: '#2563a8',
    info: '#68778a'
  };
  const SCAN_TYPES = {
    web: { label: 'Website / web app', placeholder: 'https://example.com or 192.168.1.20:8080' },
    network: { label: 'Server / network', placeholder: '192.168.1.0/24, hostname or IP address' },
    repo: { label: 'Local repository', placeholder: '/path/to/repository (on this server)' },
    github: { label: 'GitHub repository', placeholder: 'https://github.com/owner/repo or owner/repo' },
    ad: { label: 'AD report file', placeholder: '/path/to/ad-report.json (on this server)' }
  };
  const ASSET_TYPE = {
    web: 'web', github: 'github', repo: 'repo', host: 'network', domain: 'network',
    agent: 'network', other: 'network'
  };
  const ACTIVE_STATUSES = ['queued', 'running', 'waiting_agent'];
  const state = {
    pollTimer: null, activeTimer: null, manualCache: null, meta: null,
    scanDetailClick: null, scanDetailChange: null
  };

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

  function esc(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function num(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  function pad(value) { return String(value).padStart(2, '0'); }
  function fmtDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
    });
  }
  function fmtShort(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }
  function relTime(value) {
    if (!value) return 'never';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    const seconds = Math.round((Date.now() - date.getTime()) / 1000);
    if (seconds < 45) return 'just now';
    if (seconds < 3600) return Math.max(1, Math.round(seconds / 60)) + 'm ago';
    if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
    if (seconds < 2592000) return Math.round(seconds / 86400) + 'd ago';
    return fmtShort(value);
  }
  function duration(start, end) {
    if (!start) return '—';
    const from = new Date(start).getTime();
    const to = end ? new Date(end).getTime() : Date.now();
    if (Number.isNaN(from) || Number.isNaN(to) || to < from) return '—';
    const seconds = Math.round((to - from) / 1000);
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
    return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
  }
  function bytes(value) {
    const size = num(value);
    if (size < 1024) return size + ' B';
    if (size < 1048576) return (size / 1024).toFixed(1) + ' KiB';
    if (size < 1073741824) return (size / 1048576).toFixed(1) + ' MiB';
    return (size / 1073741824).toFixed(2) + ' GiB';
  }
  function sev(value) {
    const key = String(value || '').toLowerCase();
    return SEVERITIES.includes(key) ? key : 'info';
  }
  function sevBadge(value, label) {
    const key = sev(value);
    return '<span class="badge sev-' + key + '">' + esc(label || key) + '</span>';
  }
  function riskBadge(summary) {
    const data = summary || {};
    const top = SEVERITIES.find(function (key) { return num(data[key]) > 0; });
    if (!top) return '<span class="badge sev-info">clean</span>';
    return sevBadge(top, num(data[top]) + ' ' + top);
  }
  function statusPill(status) {
    const key = String(status || 'unknown').toLowerCase();
    return '<span class="status-pill status-' + esc(key) + '"><span class="dot"></span>' +
      esc(key.replace(/_/g, ' ')) + '</span>';
  }
  function severityChips(summary) {
    const data = summary || {};
    const parts = SEVERITIES.map(function (key) {
      const count = num(data[key]);
      return count ? '<span class="badge sev-' + key + '" title="' + key + '">' + count + '</span>' : '';
    }).filter(Boolean);
    return parts.length ? '<span class="sev-row">' + parts.join('') + '</span>' : '<span class="muted small">none</span>';
  }
  function riskColor(label) {
    const key = String(label || '').toLowerCase();
    if (key === 'critical') return 'var(--critical)';
    if (key === 'high') return 'var(--high)';
    if (key === 'medium') return 'var(--medium)';
    if (key === 'low') return 'var(--low)';
    return 'var(--ok)';
  }
  function errorText(error) {
    if (!error) return 'Unexpected error';
    const message = String(error.message || error);
    return message === '[object Object]' ? 'Unexpected error' : message;
  }
  function loadingHtml(message) {
    return '<div class="loading-block"><span class="spinner dark"></span> ' + esc(message || 'Loading…') + '</div>';
  }
  function emptyHtml(title, detail, action) {
    return '<div class="empty"><strong>' + esc(title) + '</strong>' +
      (detail ? '<div>' + esc(detail) + '</div>' : '') + (action || '') + '</div>';
  }
  function queryString(params) {
    const search = new URLSearchParams();
    Object.keys(params || {}).forEach(function (key) {
      const value = params[key];
      if (value !== undefined && value !== null && value !== '') search.set(key, value);
    });
    const text = search.toString();
    return text ? '?' + text : '';
  }

  // ---------------------------------------------------------------------------
  // API client
  // ---------------------------------------------------------------------------
  async function api(path, options) {
    const opts = Object.assign({}, options || {});
    const headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
    if (opts.body && typeof opts.body !== 'string') {
      opts.body = JSON.stringify(opts.body);
      headers['Content-Type'] = 'application/json';
    }
    opts.headers = headers;
    let response;
    try {
      response = await fetch('/api' + path, opts);
    } catch (networkError) {
      throw new Error('Cannot reach the VulnScanner server. Is it still running?');
    }
    const type = response.headers.get('content-type') || '';
    let body = null;
    if (type.indexOf('application/json') !== -1) {
      try { body = await response.json(); } catch (ignore) { body = null; }
    } else {
      body = await response.text();
    }
    if (!response.ok) {
      let message = 'Request failed (' + response.status + ')';
      if (body && typeof body === 'object' && body.detail) {
        if (Array.isArray(body.detail)) {
          message = body.detail.map(function (item) { return item.msg || String(item); }).join('; ');
        } else {
          message = String(body.detail);
        }
      } else if (typeof body === 'string' && body.trim()) {
        message = body.trim().slice(0, 300);
      }
      throw new Error(message);
    }
    return body;
  }
  const get = (path) => api(path);
  const post = (path, body) => api(path, { method: 'POST', body: body || {} });
  const patch = (path, body) => api(path, { method: 'PATCH', body: body || {} });
  const del = (path) => api(path, { method: 'DELETE' });

  // ---------------------------------------------------------------------------
  // Toasts and modals
  // ---------------------------------------------------------------------------
  function toast(message, kind) {
    const root = $('#toast-root');
    if (!root) return;
    const node = document.createElement('div');
    node.className = 'toast ' + (kind || '');
    node.textContent = message;
    root.appendChild(node);
    setTimeout(function () {
      node.style.opacity = '0';
      node.style.transition = 'opacity .25s ease';
      setTimeout(function () { node.remove(); }, 280);
    }, kind === 'error' ? 7000 : 4200);
  }
  function formError(container, message) {
    const box = $('.form-error', container);
    if (!box) return;
    box.textContent = message;
    box.classList.add('show');
  }
  function clearFormError(container) {
    const box = $('.form-error', container);
    if (box) box.classList.remove('show');
  }

  function openModal(options) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    const size = options.size ? ' ' + options.size : '';
    overlay.innerHTML =
      '<div class="modal' + size + '" role="dialog" aria-modal="true" aria-label="' + esc(options.title) + '">' +
        '<div class="modal-head"><h2>' + esc(options.title) + '</h2>' +
          '<button class="icon-btn" data-close type="button" aria-label="Close">' +
            '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18" stroke-linecap="round"/></svg>' +
          '</button></div>' +
        '<div class="modal-body">' + (options.content || '') + '</div>' +
        (options.actions && options.actions.length ? '<div class="modal-foot"></div>' : '') +
      '</div>';
    $('#modal-root').appendChild(overlay);
    const card = $('.modal', overlay);
    function close() { overlay.remove(); }
    overlay.addEventListener('click', function (event) {
      if (event.target === overlay || event.target.closest('[data-close]')) close();
    });
    const actions = options.actions || [];
    if (actions.length) {
      const foot = $('.modal-foot', overlay);
      actions.forEach(function (action) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn ' + (action.class || '');
        button.textContent = action.label;
        if (action.disabled) button.disabled = true;
        button.addEventListener('click', function () {
          action.onClick({ overlay: overlay, close: close, button: button, card: card });
        });
        foot.appendChild(button);
      });
    }
    overlay.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') close();
    });
    if (options.onMount) options.onMount(overlay, close);
    setTimeout(function () {
      const focusable = $('input:not([type=hidden]), select, textarea, button.btn-primary', card);
      if (focusable) focusable.focus();
    }, 30);
    return { overlay: overlay, card: card, close: close };
  }

  function confirmAction(message, label, danger) {
    return new Promise(function (resolve) {
      let settled = false;
      const done = function (value) {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      const modal = openModal({
        title: 'Please confirm',
        content: '<p style="margin:0;color:var(--text-2)">' + esc(message) + '</p>',
        actions: [
          { label: 'Cancel', onClick: function (ctx) { ctx.close(); done(false); } },
          {
            label: label || 'Delete',
            class: danger === false ? 'btn-primary' : 'btn-danger',
            onClick: function (ctx) { ctx.close(); done(true); }
          }
        ]
      });
      modal.overlay.addEventListener('click', function (event) {
        if (event.target === modal.overlay) done(false);
      });
    });
  }

  async function runWithButton(button, task) {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = 'Working…';
    try {
      await task();
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  }

  function optionsHtml(list, selected, placeholder) {
    const items = (list || []).map(function (item) {
      const value = String(item.value);
      return '<option value="' + esc(value) + '"' + (String(selected) === value ? ' selected' : '') + '>' +
        esc(item.label) + '</option>';
    });
    if (placeholder) items.unshift('<option value="">' + esc(placeholder) + '</option>');
    return items.join('');
  }

  // ---------------------------------------------------------------------------
  // Routing and shell
  // ---------------------------------------------------------------------------
  function setActiveNav(page) {
    let target = page;
    if (page === 'customers' || page === 'customer') target = 'customers';
    if (page === 'scans' || page === 'scan') target = 'scans';
    $$('.nav-link').forEach(function (link) {
      link.classList.toggle('active', link.getAttribute('data-nav') === target);
    });
  }

  async function router() {
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
    const raw = (location.hash || '').replace(/^#\/?/, '');
    const parts = raw.split('/').filter(Boolean);
    const page = parts[0] || 'dashboard';
    const rawId = parts[1] ? decodeURIComponent(parts[1]) : null;
    const id = rawId && /^\d+$/.test(rawId) ? Number(rawId) : rawId;
    setActiveNav(page);
    // Replace the view element on every navigation so delegated listeners from
    // the previous page are discarded cleanly.
    const oldView = $('#view');
    const view = document.createElement('main');
    view.id = 'view';
    view.className = 'view';
    view.tabIndex = -1;
    view.setAttribute('aria-live', 'polite');
    oldView.replaceWith(view);
    view.innerHTML = loadingHtml();
    try {
      if (page === 'dashboard') await renderDashboard(view);
      else if (page === 'customers' && id) await renderCustomerDetail(view, id);
      else if (page === 'customers') await renderCustomers(view);
      else if (page === 'scans' && id) await renderScanDetail(view, id);
      else if (page === 'scans') await renderScans(view);
      else if (page === 'agents' && id) await renderAgentDetail(view, id);
      else if (page === 'agents') await renderAgents(view);
      else if (page === 'ad') await renderAd(view);
      else if (page === 'server') await renderServer(view);
      else if (page === 'settings') await renderSettings(view);
      else if (page === 'help') await renderHelp(view);
      else {
        view.innerHTML = emptyHtml('Page not found', 'The requested page does not exist.', '<a class="btn" href="#/dashboard">Back to dashboard</a>');
      }
    } catch (error) {
      view.innerHTML = '<div class="card" style="border-color:#f0c4c4">' +
        '<div class="panel-body"><h2 style="color:var(--critical)">Could not load this page</h2>' +
        '<p class="muted">' + esc(errorText(error)) + '</p>' +
        '<a class="btn" href="#/dashboard">Back to dashboard</a></div></div>';
    }
    window.scrollTo(0, 0);
  }

  async function refreshActiveBadge() {
    try {
      const data = await get('/scans?active=true&limit=1');
      const badge = $('#active-badge');
      const count = num(data.total);
      if (!badge) return;
      badge.classList.toggle('hidden', count === 0);
      const label = $('#active-count');
      if (label) label.textContent = String(count);
    } catch (ignore) { /* the server may be restarting */ }
  }

  async function init() {
    $('#top-new-scan').addEventListener('click', function () { openNewScan({}); });
    window.addEventListener('hashchange', router);
    try {
      const health = await get('/health');
      const version = $('#app-version');
      if (version && health.version) version.textContent = health.version;
    } catch (ignore) { /* non-fatal */ }
    try { state.meta = await get('/meta'); } catch (ignore) { state.meta = null; }
    await router();
    refreshActiveBadge();
    state.activeTimer = setInterval(refreshActiveBadge, 20000);
  }

  // ---------------------------------------------------------------------------
  // Dashboard
  // ---------------------------------------------------------------------------
  function trendChart(rows) {
    const byDay = {};
    (rows || []).forEach(function (row) { byDay[row.date] = row; });
    const days = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    for (let i = 13; i >= 0; i -= 1) {
      const day = new Date(today.getTime() - i * 86400000);
      const key = day.getFullYear() + '-' + pad(day.getMonth() + 1) + '-' + pad(day.getDate());
      days.push({ key: key, date: day, counts: byDay[key] || {} });
    }
    const totals = days.map(function (day) {
      return SEVERITIES.reduce(function (sum, key) { return sum + num(day.counts[key]); }, 0);
    });
    const max = Math.max(1, Math.max.apply(null, totals));
    const width = 660, height = 160, left = 6, right = 6, top = 8, bottom = 24;
    const innerW = width - left - right;
    const innerH = height - top - bottom;
    const slot = innerW / days.length;
    const barW = Math.min(24, slot * 0.58);
    let bars = '';
    days.forEach(function (day, index) {
      const x = left + index * slot + (slot - barW) / 2;
      let y = top + innerH;
      SEVERITIES.forEach(function (key) {
        const value = num(day.counts[key]);
        if (!value) return;
        const h = (value / max) * innerH;
        y -= h;
        bars += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + barW.toFixed(1) +
          '" height="' + h.toFixed(1) + '" rx="2" fill="' + SEV_COLOR[key] + '"><title>' +
          day.key + ': ' + value + ' ' + key + '</title></rect>';
      });
      if (index % 3 === 0 || index === days.length - 1) {
        const label = (day.date.getMonth() + 1) + '/' + day.date.getDate();
        bars += '<text x="' + (x + barW / 2).toFixed(1) + '" y="' + (height - 6) +
          '" font-size="9.5" fill="#7b8a9d" text-anchor="middle">' + label + '</text>';
      }
    });
    if (!bars) return '<div class="chart-empty">No completed scans in the last 14 days.</div>';
    return '<svg class="trend-svg" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Findings trend">' +
      '<line x1="' + left + '" y1="' + (top + innerH) + '" x2="' + (width - right) + '" y2="' + (top + innerH) +
      '" stroke="#e3eaf2" stroke-width="1"/>' + bars + '</svg>';
  }

  async function renderDashboard(view) {
    const data = await get('/dashboard');
    const counts = data.counts || {};
    const severity = data.severity || {};
    const total = num(severity.total);
    const risk = data.risk || { score: 0, label: 'None' };
    const riskLabel = String(risk.label || 'None');
    const sevBars = SEVERITIES.map(function (key) {
      const value = num(severity[key]);
      const pct = total ? Math.round((value / total) * 100) : 0;
      return '<div class="sev-bar"><div class="sev-bar-head"><span class="severity-' + key + '">' +
        esc(key.charAt(0).toUpperCase() + key.slice(1)) + '</span><span class="muted">' + value + '</span></div>' +
        '<div class="sev-bar-track"><div class="sev-bar-fill" style="width:' + pct + '%;background:' + SEV_COLOR[key] + '"></div></div></div>';
    }).join('');

    const recent = (data.recent_scans || []).length
      ? (data.recent_scans || []).map(function (scan) {
          const summary = scan.summary || {};
          return '<a class="recent-item" href="#/scans/' + scan.id + '">' +
            '<div class="recent-main"><div class="recent-title">' + esc(scan.target || 'Untitled target') + '</div>' +
            '<div class="recent-sub">' + esc(scan.customer_name || 'Unassigned') + ' · ' +
            esc(scan.scan_type) + ' · ' + esc(relTime(scan.created_at)) + '</div></div>' +
            '<div style="text-align:right">' + statusPill(scan.status) +
            '<div style="margin-top:3px">' + severityChips(summary) + '</div></div></a>';
        }).join('')
      : emptyHtml('No scans yet', 'Start a scan to populate the dashboard.', '<button class="btn btn-primary" data-action="new-scan">New scan</button>');

    const topFindings = (data.top_findings || []).length
      ? (data.top_findings || []).map(function (finding) {
          return '<a class="top-finding" href="#/scans/' + finding.scan_id + '">' +
            sevBadge(finding.severity) +
            '<div class="top-finding-main"><div class="top-finding-title">' + esc(finding.title) + '</div>' +
            '<div class="top-finding-sub">' + esc(finding.customer_name || 'Unassigned') + ' · ' +
            esc(finding.asset_name || 'Ad-hoc target') + (finding.cve ? ' · ' + esc(finding.cve) : '') +
            '</div></div></a>';
        }).join('')
      : emptyHtml('No critical or high findings', 'The latest results for each asset are shown here.');

    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Security overview</h1>' +
        '<div class="page-sub">Latest results per asset across all customers. Local data, updated as scans complete.</div></div>' +
        '<div class="page-actions"><button class="btn" data-action="import-ad">Import AD report</button>' +
        '<button class="btn btn-primary" data-action="new-scan">' +
          '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14" stroke-linecap="round"/></svg>' +
          'New scan</button></div></div>' +
      '<div class="stat-grid">' +
        '<div class="stat-card"><div class="stat-label">Customers</div><div class="stat-value">' + num(counts.customers) + '</div>' +
          '<div class="stat-foot">' + num(counts.groups) + ' groups · ' + num(counts.assets) + ' assets</div></div>' +
        '<div class="stat-card"><div class="stat-label">Scans stored</div><div class="stat-value">' + num(counts.scans) + '</div>' +
          '<div class="stat-foot">' + num(counts.running_scans) + ' running · ' + num(counts.waiting_agent_scans) + ' waiting for agent</div></div>' +
        '<div class="stat-card stat-ok"><div class="stat-label">Agents online</div><div class="stat-value">' + num(counts.agents_online) + '</div>' +
          '<div class="stat-foot">' + num(counts.agents) + ' enrolled endpoints</div></div>' +
        '<div class="stat-card stat-warn"><div class="stat-label">Assessed assets</div><div class="stat-value">' + num(counts.assessed_assets) + '</div>' +
          '<div class="stat-foot">Assets with at least one completed scan</div></div>' +
      '</div>' +
      '<div class="dash-grid">' +
        '<section class="panel"><div class="panel-head"><h2>Risk posture</h2><span class="spacer"></span>' +
          '<span class="muted small">Latest completed scans</span></div>' +
          '<div class="panel-body"><div class="risk-card">' +
            '<div class="risk-ring" style="--score:' + Math.max(0, Math.min(100, num(risk.score))) + ';--ring-color:' + riskColor(riskLabel) + '">' +
              '<div class="risk-ring-inner"><div class="risk-ring-value">' + num(risk.score) + '</div>' +
              '<div class="risk-ring-label">' + esc(riskLabel) + '</div></div></div>' +
            '<div class="sev-bars">' + sevBars +
              '<div class="muted small" style="margin-top:2px">' + total + ' open finding' + (total === 1 ? '' : 's') +
              ' across latest asset results.</div></div>' +
          '</div></div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Findings trend</h2><span class="spacer"></span>' +
          '<span class="muted small">Last 14 days</span></div>' +
          '<div class="panel-body"><div class="trend-wrap">' + trendChart(data.trend) + '</div>' +
          '<div class="trend-legend">' + SEVERITIES.map(function (key) {
            return '<span><i style="background:' + SEV_COLOR[key] + '"></i>' + key + '</span>';
          }).join('') + '</div></div></section>' +
      '</div>' +
      '<div class="dash-grid-2">' +
        '<section class="panel"><div class="panel-head"><h2>Recent scans</h2><span class="spacer"></span>' +
          '<a class="small" href="#/scans">View all</a></div>' +
          '<div class="recent-list">' + recent + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Priority findings</h2><span class="spacer"></span>' +
          '<span class="muted small">Critical &amp; high</span></div>' +
          '<div>' + topFindings + '</div></section>' +
      '</div>';

    bindCommonActions(view);
  }

  // ---------------------------------------------------------------------------
  // Customers, groups and assets
  // ---------------------------------------------------------------------------
  function customerRow(customer) {
    return '<a class="master-item" href="#/customers/' + customer.id + '">' +
      '<div class="master-item-head"><span class="master-name">' + esc(customer.name) + '</span>' +
      riskBadge(customer.severity) +
      '</div>' +
      '<div class="master-sub"><span>' + num(customer.assets) + ' assets</span><span>' + num(customer.scans) + ' scans</span>' +
      '<span>' + esc(customer.last_scan ? relTime(customer.last_scan) : 'no scans') + '</span></div></a>';
  }

  async function renderCustomers(view) {
    const customers = await get('/customers');
    const master = customers.length ? customers.map(customerRow).join('') : emptyHtml('No customers', 'Create a customer to organize assets and scans.');
    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Customers &amp; assets</h1>' +
        '<div class="page-sub">Organize work by customer, then by groups such as “webserver”, “workstations” or “branch office”.</div></div>' +
        '<div class="page-actions"><button class="btn btn-primary" data-action="add-customer">Add customer</button></div></div>' +
      '<div class="split">' +
        '<section class="panel master-panel"><div class="master-search"><input class="input input-sm search-input" id="customer-filter" placeholder="Filter customers…" aria-label="Filter customers"></div>' +
          '<div class="master-list" id="customer-master">' + master + '</div></section>' +
        '<section class="panel"><div class="panel-body">' +
          emptyHtml('Select a customer', 'Choose a customer on the left to see groups, assets and scan history.', '<button class="btn btn-primary" data-action="add-customer">Add customer</button>') +
        '</div></section>' +
      '</div>';
    $('#customer-filter').addEventListener('input', function (event) {
      const term = event.target.value.trim().toLowerCase();
      $$('#customer-master .master-item').forEach(function (item) {
        item.style.display = item.textContent.toLowerCase().indexOf(term) !== -1 ? '' : 'none';
      });
    });
    bindCommonActions(view);
  }

  async function renderCustomerDetail(view, customerId) {
    const customer = await get('/customers/' + customerId);
    const sevData = customer.severity || {};
    const groups = customer.groups || [];
    const assetTotal = groups.reduce(function (total, group) {
      return total + (group.assets || []).length;
    }, 0);
    const groupHtml = groups.length ? groups.map(function (group) {
      const assets = group.assets || [];
      const assetRows = assets.length ? assets.map(function (asset) {
        const last = asset.last_scan;
        return '<tr>' +
          '<td><div class="cell-main">' + esc(asset.name) + '</div>' +
            (asset.description ? '<div class="cell-sub">' + esc(asset.description) + '</div>' : '') + '</td>' +
          '<td><span class="kind-chip">' + esc(asset.kind) + '</span></td>' +
          '<td><div class="truncate" style="max-width:300px" title="' + esc(asset.identifier) + '">' + esc(asset.identifier || '—') + '</div></td>' +
          '<td>' + (last ? statusPill(last.status) + '<div class="cell-sub">' + esc(relTime(last.created_at)) + '</div>' :
            '<span class="muted small">never scanned</span>') + '</td>' +
          '<td>' + num(asset.scan_count) + '</td>' +
          '<td class="actions"><div class="row-actions">' +
            '<button class="btn btn-sm" data-action="scan-asset" data-asset="' + asset.id + '">Scan</button>' +
            '<button class="btn btn-sm btn-subtle" data-action="view-asset" data-asset="' + asset.id + '">View</button>' +
            '<button class="btn btn-sm btn-subtle" data-action="edit-asset" data-asset="' + asset.id + '" data-group="' + group.id + '">Edit</button>' +
            '<button class="btn btn-sm btn-subtle danger-text" data-action="delete-asset" data-asset="' + asset.id + '">Delete</button>' +
          '</div></td></tr>';
      }).join('') : '<tr><td colspan="6"><div class="asset-empty">No assets in this group yet. ' +
        '<button class="btn btn-sm" data-action="add-asset" data-group="' + group.id + '">Add the first asset</button></div></td></tr>';

      return '<div class="group" data-group-id="' + group.id + '">' +
        '<div class="group-head"><button class="group-toggle" type="button" data-action="toggle-group">' +
          '<svg class="chev" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
          '<span class="group-name">' + esc(group.name) + '</span>' +
          '<span class="group-count">' + assets.length + ' asset' + (assets.length === 1 ? '' : 's') + ' · ' + num(group.scan_count) + ' scans</span>' +
        '</button><div class="group-actions">' +
          '<button class="btn btn-sm" data-action="add-asset" data-group="' + group.id + '">Add asset</button>' +
          '<button class="btn btn-sm btn-subtle" data-action="edit-group" data-group="' + group.id + '" data-name="' + esc(group.name) + '" data-description="' + esc(group.description) + '">Edit</button>' +
          '<button class="btn btn-sm btn-subtle danger-text" data-action="delete-group" data-group="' + group.id + '" data-name="' + esc(group.name) + '">Delete</button>' +
        '</div></div>' +
        '<div class="group-assets"><div class="table-wrap"><table class="data-table"><thead><tr>' +
          '<th>Asset</th><th>Kind</th><th>Target / identifier</th><th>Last scan</th><th>Scans</th><th></th>' +
        '</tr></thead><tbody>' + assetRows + '</tbody></table></div></div></div>';
    }).join('') : emptyHtml('No groups yet', 'Add a group to start organizing this customer’s assets.', '<button class="btn btn-primary" data-action="add-group">Add group</button>');

    view.innerHTML =
      '<div class="breadcrumb"><a href="#/customers">Customers</a><span class="sep">/</span><span>' + esc(customer.name) + '</span></div>' +
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">' + esc(customer.name) + '</h1>' +
        '<div class="page-sub">' + esc(customer.description || 'No description') + '</div></div>' +
        '<div class="page-actions"><button class="btn" data-action="edit-customer">Edit</button>' +
        '<button class="btn btn-danger" data-action="delete-customer">Delete</button>' +
        '<button class="btn btn-primary" data-action="new-scan">New scan</button></div></div>' +
      '<section class="panel"><div class="customer-head"><div class="customer-head-main">' +
        '<h2>' + esc(customer.name) + '</h2>' +
        '<div class="customer-stats">' +
          '<span class="customer-stat">Risk score <strong>' + num(customer.risk_score) + '</strong></span>' +
          '<span class="customer-stat">Groups <strong>' + groups.length + '</strong></span>' +
          '<span class="customer-stat">Assets <strong>' + num(assetTotal) + '</strong></span>' +
          '<span class="customer-stat">Scans <strong>' + num(customer.scan_count) + '</strong></span>' +
        '</div></div><div style="text-align:right"><div class="muted small" style="margin-bottom:5px">Latest findings</div>' +
        '<div class="sev-row">' + SEVERITIES.map(function (key) {
          return '<span class="badge sev-' + key + '">' + num(sevData[key]) + '</span>';
        }).join('') + '</div></div></div>' +
        '<div class="group-list">' + groupHtml + '</div>' +
        '<div class="panel-body" style="border-top:1px solid var(--border)">' +
        '<button class="btn btn-sm" data-action="add-group">Add group</button></div></section>';

    view.dataset.customerId = String(customer.id);
    bindCommonActions(view);
    bindCustomerActions(view, customer);
  }

  async function addCustomerModal() {
    const modal = openModal({
      title: 'Add customer',
      content: '<form id="customer-form"><div class="form-grid">' +
        '<label class="field full"><span>Customer name</span>' +
          '<input class="input" name="name" required maxlength="120" placeholder="Acme Corporation"></label>' +
        '<label class="field full"><span>Description <span class="muted">(optional)</span></span>' +
          '<textarea class="textarea" name="description" maxlength="2000" rows="3" placeholder="Scope, contacts or notes"></textarea></label>' +
        '</div><div class="form-error"></div></form>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Create customer', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            try {
              const form = $('#customer-form', ctx.overlay);
              const data = Object.fromEntries(new FormData(form).entries());
              const customer = await post('/customers', data);
              ctx.close();
              toast('Customer created');
              if (location.hash.indexOf('#/customers') === 0) router();
              else location.hash = '#/customers/' + customer.id;
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ]
    });
    return modal;
  }

  async function addGroupModal(customerId) {
    openModal({
      title: 'Add asset group',
      content: '<form id="group-form"><div class="form-grid">' +
        '<label class="field full"><span>Group name</span>' +
          '<input class="input" name="name" required maxlength="120" placeholder="webserver"></label>' +
        '<label class="field full"><span>Description <span class="muted">(optional)</span></span>' +
          '<input class="input" name="description" maxlength="2000" placeholder="Internet-facing web servers"></label>' +
        '</div><div class="form-error"></div></form>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Create group', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            try {
              const data = Object.fromEntries(new FormData($('#group-form', ctx.overlay)).entries());
              await post('/customers/' + customerId + '/groups', data);
              ctx.close(); toast('Group created'); router();
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ]
    });
  }

  function editGroupModal(groupId, name, description) {
    openModal({
      title: 'Edit group',
      content: '<form id="group-edit"><div class="form-grid">' +
        '<label class="field full"><span>Group name</span><input class="input" name="name" required maxlength="120" value="' + esc(name) + '"></label>' +
        '<label class="field full"><span>Description</span><input class="input" name="description" maxlength="2000" value="' + esc(description || '') + '"></label>' +
        '</div><div class="form-error"></div></form>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Save group', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            try {
              const data = Object.fromEntries(new FormData($('#group-edit', ctx.overlay)).entries());
              await patch('/groups/' + groupId, data);
              ctx.close(); toast('Group updated'); router();
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ]
    });
  }

  function assetFormHtml(asset) {
    const item = asset || {};
    const kinds = ['host', 'web', 'repo', 'github', 'domain', 'agent', 'other'];
    return '<form id="asset-form"><div class="form-grid">' +
      '<label class="field"><span>Asset name</span><input class="input" name="name" required maxlength="160" value="' + esc(item.name || '') + '" placeholder="web01"></label>' +
      '<label class="field"><span>Kind</span><select class="select" name="kind">' +
        optionsHtml(kinds.map(function (kind) { return { value: kind, label: kind }; }), item.kind || 'host') + '</select></label>' +
      '<label class="field full"><span>Target / identifier</span>' +
        '<input class="input" name="identifier" maxlength="2000" value="' + esc(item.identifier || '') + '" placeholder="https://example.com, 10.0.0.5 or owner/repo">' +
        '<span class="hint">The default target used when you start a scan from this asset.</span></label>' +
      '<label class="field full"><span>Description <span class="muted">(optional)</span></span>' +
        '<input class="input" name="description" maxlength="2000" value="' + esc(item.description || '') + '"></label>' +
      '</div><div class="form-error"></div></form>';
  }

  function addAssetModal(groupId) {
    openModal({
      title: 'Add asset',
      size: 'wide',
      content: assetFormHtml(null),
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Create asset', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            try {
              const data = Object.fromEntries(new FormData($('#asset-form', ctx.overlay)).entries());
              await post('/groups/' + groupId + '/assets', data);
              ctx.close(); toast('Asset created'); router();
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ]
    });
  }

  async function editAssetModal(assetId) {
    try {
      const asset = await get('/assets/' + assetId);
      openModal({
        title: 'Edit asset',
        size: 'wide',
        content: assetFormHtml(asset),
        actions: [
          { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
          { label: 'Save asset', class: 'btn-primary', onClick: function (ctx) {
            runWithButton(ctx.button, async function () {
              try {
                const data = Object.fromEntries(new FormData($('#asset-form', ctx.overlay)).entries());
                await patch('/assets/' + assetId, data);
                ctx.close(); toast('Asset updated'); router();
              } catch (error) { formError(ctx.overlay, errorText(error)); }
            });
          } }
        ]
      });
    } catch (error) { toast(errorText(error), 'error'); }
  }

  async function viewAssetModal(assetId) {
    try {
      const asset = await get('/assets/' + assetId);
      const scans = (asset.scans || []).map(function (scan) {
        return '<a class="recent-item" href="#/scans/' + scan.id + '"><div class="recent-main">' +
          '<div class="recent-title">' + esc(scan.target) + '</div>' +
          '<div class="recent-sub">' + esc(scan.scan_type) + ' · ' + esc(fmtDate(scan.created_at)) + '</div></div>' +
          statusPill(scan.status) + '</a>';
      }).join('') || emptyHtml('No scans for this asset');
      const findings = (asset.latest_findings || []).slice(0, 30).map(function (finding) {
        return '<div class="top-finding"><a href="#/scans/' + finding.scan_id + '">' + sevBadge(finding.severity) + '</a>' +
          '<div class="top-finding-main"><div class="top-finding-title">' + esc(finding.title) + '</div>' +
          '<div class="top-finding-sub">' + esc(finding.category) + (finding.cve ? ' · ' + esc(finding.cve) : '') +
          (finding.location ? ' · ' + esc(finding.location) : '') + '</div></div></div>';
      }).join('') || emptyHtml('No findings in the latest completed scan');
      openModal({
        title: asset.name,
        size: 'xwide',
        content: '<div class="detail-grid" style="border:1px solid var(--border);border-radius:8px;margin-bottom:16px">' +
          '<div class="detail-cell"><div class="detail-label">Kind</div><div class="detail-value">' + esc(asset.kind) + '</div></div>' +
          '<div class="detail-cell"><div class="detail-label">Customer</div><div class="detail-value">' + esc(asset.customer && asset.customer.name) + '</div></div>' +
          '<div class="detail-cell"><div class="detail-label">Group</div><div class="detail-value">' + esc(asset.group && asset.group.name) + '</div></div>' +
          '<div class="detail-cell"><div class="detail-label">Scans</div><div class="detail-value">' + (asset.scans || []).length + '</div></div>' +
          '</div>' +
          '<div class="field full" style="margin-bottom:16px"><span>Identifier</span><div class="meta-json">' + esc(asset.identifier || '—') + '</div></div>' +
          '<h3 style="margin-bottom:6px">Scan history</h3><div class="recent-list" style="border:1px solid var(--border);border-radius:8px;margin-bottom:16px">' + scans + '</div>' +
          '<h3 style="margin-bottom:6px">Latest findings</h3><div style="border:1px solid var(--border);border-radius:8px">' + findings + '</div>',
        actions: [
          { label: 'Close', onClick: function (ctx) { ctx.close(); } },
          { label: 'Scan this asset', class: 'btn-primary', onClick: function (ctx) {
            ctx.close();
            openNewScan({ customerId: asset.customer_id, groupId: asset.group_id, assetId: asset.id });
          } }
        ]
      });
    } catch (error) { toast(errorText(error), 'error'); }
  }

  function editCustomerModal(customer) {
    openModal({
      title: 'Edit customer',
      content: '<form id="customer-edit"><div class="form-grid">' +
        '<label class="field full"><span>Customer name</span><input class="input" name="name" required maxlength="120" value="' + esc(customer.name) + '"></label>' +
        '<label class="field full"><span>Description</span><textarea class="textarea" name="description" rows="3" maxlength="2000">' + esc(customer.description || '') + '</textarea></label>' +
        '</div><div class="form-error"></div></form>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Save customer', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            try {
              const data = Object.fromEntries(new FormData($('#customer-edit', ctx.overlay)).entries());
              await patch('/customers/' + customer.id, data);
              ctx.close(); toast('Customer updated'); router();
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ]
    });
  }

  function bindCommonActions(root) {
    root.addEventListener('click', function (event) {
      const action = event.target.closest('[data-action]');
      if (!action || !root.contains(action)) return;
      const name = action.getAttribute('data-action');
      if (name === 'new-scan') {
        event.preventDefault();
        const customerId = root.dataset.customerId ? Number(root.dataset.customerId) : null;
        openNewScan(customerId ? { customerId: customerId } : {});
      } else if (name === 'import-ad') {
        event.preventDefault(); openAdImport();
      } else if (name === 'add-customer') {
        event.preventDefault(); addCustomerModal();
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Customer detail action binding
  // ---------------------------------------------------------------------------
  function bindCustomerActions(view, customer) {
    view.addEventListener('click', function (event) {
      const button = event.target.closest('[data-action]');
      if (!button || !view.contains(button)) return;
      const action = button.getAttribute('data-action');
      const groupId = button.getAttribute('data-group') ? Number(button.getAttribute('data-group')) : null;
      const assetId = button.getAttribute('data-asset') ? Number(button.getAttribute('data-asset')) : null;

      if (action === 'toggle-group') {
        const group = button.closest('.group');
        if (group) group.classList.toggle('collapsed');
        return;
      }
      if (action === 'add-group') { addGroupModal(customer.id); return; }
      if (action === 'add-asset' && groupId) { addAssetModal(groupId); return; }
      if (action === 'edit-group' && groupId) {
        editGroupModal(groupId, button.getAttribute('data-name'), button.getAttribute('data-description'));
        return;
      }
      if (action === 'delete-group' && groupId) {
        confirmAction('Delete group “' + button.getAttribute('data-name') + '”? Its assets and scans will be removed.', 'Delete group').then(function (ok) {
          if (!ok) return;
          del('/groups/' + groupId).then(function () { toast('Group deleted'); router(); })
            .catch(function (error) { toast(errorText(error), 'error'); });
        });
        return;
      }
      if (action === 'edit-asset' && assetId) { editAssetModal(assetId); return; }
      if (action === 'view-asset' && assetId) { viewAssetModal(assetId); return; }
      if (action === 'delete-asset' && assetId) {
        confirmAction('Delete this asset and its scan history? This cannot be undone.', 'Delete asset').then(function (ok) {
          if (!ok) return;
          del('/assets/' + assetId).then(function () { toast('Asset deleted'); router(); })
            .catch(function (error) { toast(errorText(error), 'error'); });
        });
        return;
      }
      if (action === 'scan-asset' && assetId) {
        get('/assets/' + assetId).then(function (asset) {
          openNewScan({
            customerId: asset.customer_id, groupId: asset.group_id, assetId: asset.id,
            type: ASSET_TYPE[asset.kind] || 'network', target: asset.identifier || ''
          });
        }).catch(function (error) { toast(errorText(error), 'error'); });
        return;
      }
      if (action === 'edit-customer') { editCustomerModal(customer); return; }
      if (action === 'delete-customer') {
        confirmAction('Delete customer “' + customer.name + '” including all groups, assets and scans?', 'Delete customer').then(function (ok) {
          if (!ok) return;
          del('/customers/' + customer.id).then(function () { toast('Customer deleted'); location.hash = '#/customers'; })
            .catch(function (error) { toast(errorText(error), 'error'); });
        });
      }
    });
  }

  // ---------------------------------------------------------------------------
  // New scan dialog
  // ---------------------------------------------------------------------------
  function scanTypeOptionsHtml(type) {
    if (type === 'web') {
      return '<div class="form-section"><h3>Web scan options</h3><div class="checkbox-row">' +
        '<label class="check"><input type="checkbox" id="opt-active" checked><span><strong>Active checks</strong> — test SQL injection, XSS, traversal and common misconfigurations.</span></label>' +
        '<label class="check"><input type="checkbox" id="opt-external"><span><strong>Use Nuclei</strong> — run the optional Nuclei templates if installed.</span></label>' +
        '</div><div class="modal-note" style="margin-top:8px">Only scan applications you are authorized to test. Active checks send real attack payloads.</div></div>';
    }
    if (type === 'network') {
      return '<div class="form-section"><h3>Network scan options</h3><div class="form-grid">' +
        '<label class="field"><span>Port profile</span><select class="select" id="opt-profile">' +
          '<option value="common">Common services</option><option value="web">Web ports</option>' +
          '<option value="top1000">Top 1000 ports</option><option value="all">All ports (slow)</option></select></label>' +
        '<label class="field"><span>Custom ports <span class="muted">(optional)</span></span>' +
          '<input class="input" id="opt-ports" placeholder="22,80,443 or 1-1024"></label></div>' +
        '<div class="checkbox-row" style="margin-top:12px">' +
        '<label class="check"><input type="checkbox" id="opt-external" checked><span><strong>Use Nmap</strong> when available for service detection.</span></label>' +
        '<label class="check"><input type="checkbox" id="opt-vulners"><span>Run the Nmap <span class="mono">vulners</span> NSE script.</span></label></div>' +
        '<div class="modal-note" style="margin-top:8px">CIDR ranges are limited by the server configuration (default 256 hosts).</div></div>';
    }
    if (type === 'repo' || type === 'github') {
      return '<div class="form-section"><h3>Repository options</h3><div class="checkbox-row">' +
        '<label class="check"><input type="checkbox" id="opt-secrets" checked><span><strong>Secrets</strong> — API keys, tokens, private keys and passwords.</span></label>' +
        '<label class="check"><input type="checkbox" id="opt-deps" checked><span><strong>Dependencies</strong> — manifest and lockfile review with OSV.</span></label>' +
        '<label class="check"><input type="checkbox" id="opt-source" checked><span><strong>Source review</strong> — heuristic SAST checks.</span></label>' +
        '<label class="check"><input type="checkbox" id="opt-external"><span><strong>Use Gitleaks, Semgrep and osv-scanner</strong> when installed.</span></label>' +
        '</div><div class="modal-note" style="margin-top:8px">' +
        (type === 'github' ? 'The repository is cloned to the local data directory. Private repositories need a read-only token.' :
          'The path must be readable by the VulnScanner server process.') + '</div></div>';
    }
    return '<div class="form-section"><h3>Active Directory</h3><div class="modal-note">' +
      'This creates a scan from a JSON report already stored on the server. To upload a report from this browser, use ' +
      '<strong>Import AD report</strong> on the Scans page or dashboard. The collector is read-only.</div></div>';
  }

  async function openNewScan(prefill) {
    const initial = prefill || {};
    let customers;
    try { customers = await get('/customers'); }
    catch (error) { toast(errorText(error), 'error'); return; }
    if (!customers.length) {
      openModal({
        title: 'Create a customer first',
        content: '<p style="margin:0;color:var(--text-2)">Scans are stored against a customer. Create one, then add a group and asset.</p>',
        actions: [
          { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
          { label: 'Add customer', class: 'btn-primary', onClick: function (ctx) { ctx.close(); addCustomerModal(); } }
        ]
      });
      return;
    }

    const modal = openModal({
      title: 'New scan',
      size: 'wide',
      content: '<form id="new-scan-form" autocomplete="off"><div class="form-grid">' +
        '<label class="field"><span>Scan type</span><select class="select" id="scan-type" name="scan_type">' +
          Object.keys(SCAN_TYPES).map(function (key) {
            return '<option value="' + key + '">' + esc(SCAN_TYPES[key].label) + '</option>';
          }).join('') + '</select></label>' +
        '<label class="field"><span>Customer</span><select class="select" id="scan-customer" name="customer_id" required>' +
          customers.map(function (customer) {
            return '<option value="' + customer.id + '">' + esc(customer.name) + '</option>';
          }).join('') + '</select></label>' +
        '<label class="field"><span>Group</span><select class="select" id="scan-group" name="group_id"></select></label>' +
        '<label class="field"><span>Asset <span class="muted">(optional)</span></span><select class="select" id="scan-asset" name="asset_id"></select></label>' +
        '<label class="field full"><span>Target</span>' +
          '<input class="input" id="scan-target" name="target" required maxlength="4000" placeholder="">' +
          '<span class="hint" id="target-hint"></span></label>' +
        '<label class="field full hidden" id="github-token-field"><span>GitHub token <span class="muted">(optional, not stored)</span></span>' +
          '<input class="input" id="scan-github-token" type="password" maxlength="500" placeholder="ghp_… (read-only token for private repositories)">' +
          '<span class="hint">The token is used for this clone only and is never written to the database.</span></label>' +
        '<div class="field full" id="scan-type-options"></div>' +
        '</div><div class="form-error"></div></form>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Start scan', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            const form = $('#new-scan-form', ctx.overlay);
            clearFormError(ctx.overlay);
            try {
              const type = $('#scan-type', ctx.overlay).value;
              const customerId = Number($('#scan-customer', ctx.overlay).value);
              const groupValue = $('#scan-group', ctx.overlay).value;
              const assetValue = $('#scan-asset', ctx.overlay).value;
              const target = $('#scan-target', ctx.overlay).value.trim();
              if (!customerId) throw new Error('Choose a customer');
              if (!target) throw new Error('Enter a scan target');
              const payload = {
                customer_id: customerId, scan_type: type, target: target, options: {}
              };
              if (groupValue) payload.group_id = Number(groupValue);
              if (assetValue) payload.asset_id = Number(assetValue);
              if (type === 'web') {
                payload.options.active = !!($('#opt-active', ctx.overlay) || {}).checked;
                payload.options.external_tools = !!($('#opt-external', ctx.overlay) || {}).checked;
              } else if (type === 'network') {
                payload.options.profile = ($('#opt-profile', ctx.overlay) || {}).value || 'common';
                payload.options.external_tools = !!($('#opt-external', ctx.overlay) || {}).checked;
                payload.options.nmap_vulners = !!($('#opt-vulners', ctx.overlay) || {}).checked;
                const ports = ($('#opt-ports', ctx.overlay) || {}).value || '';
                if (ports.trim()) payload.options.ports = ports.trim();
              } else if (type === 'repo' || type === 'github') {
                payload.options.include_secrets = !!($('#opt-secrets', ctx.overlay) || {}).checked;
                payload.options.include_dependencies = !!($('#opt-deps', ctx.overlay) || {}).checked;
                payload.options.include_source = !!($('#opt-source', ctx.overlay) || {}).checked;
                payload.options.external_tools = !!($('#opt-external', ctx.overlay) || {}).checked;
                const token = ($('#scan-github-token', ctx.overlay) || {}).value || '';
                if (type === 'github' && token.trim()) payload.github_token = token.trim();
              }
              const created = await post('/scans', payload);
              ctx.close();
              toast('Scan queued');
              refreshActiveBadge();
              location.hash = '#/scans/' + created.id;
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ],
      onMount: function (overlay) {
        const typeSelect = $('#scan-type', overlay);
        const customerSelect = $('#scan-customer', overlay);
        const groupSelect = $('#scan-group', overlay);
        const assetSelect = $('#scan-asset', overlay);
        const targetInput = $('#scan-target', overlay);
        const tokenField = $('#github-token-field', overlay);
        let detail = null;

        function renderType() {
          const type = typeSelect.value;
          const config = SCAN_TYPES[type];
          targetInput.placeholder = config.placeholder;
          $('#target-hint', overlay).textContent = type === 'github'
            ? 'Public repositories work without a token. The clone is stored locally and deleted after the scan.'
            : (type === 'repo' ? 'Use an absolute path on the server. A relative path is resolved from the server working directory.' :
              (type === 'ad' ? 'The JSON report must already exist on the server.' : 'Only scan systems you own or have written permission to test.'));
          $('#scan-type-options', overlay).innerHTML = scanTypeOptionsHtml(type);
          tokenField.classList.toggle('hidden', type !== 'github');
        }
        function renderAssets() {
          const groupId = groupSelect.value ? Number(groupSelect.value) : null;
          const groups = (detail && detail.groups) || [];
          let assets = [];
          groups.forEach(function (group) {
            if (groupId && group.id !== groupId) return;
            (group.assets || []).forEach(function (asset) {
              assets.push({ asset: asset, groupName: group.name });
            });
          });
          assetSelect.innerHTML = '<option value="">No specific asset</option>' + assets.map(function (entry) {
            return '<option value="' + entry.asset.id + '">' + esc(entry.asset.name) +
              (groupId ? '' : ' — ' + esc(entry.groupName)) + '</option>';
          }).join('');
        }
        async function loadCustomer(keepGroup, keepAsset) {
          const customerId = Number(customerSelect.value);
          const previousGroup = keepGroup ? groupSelect.value : '';
          const previousAsset = keepAsset ? assetSelect.value : '';
          groupSelect.innerHTML = '<option value="">Default group</option>';
          assetSelect.innerHTML = '<option value="">No specific asset</option>';
          detail = null;
          if (!customerId) return;
          try {
            detail = await get('/customers/' + customerId);
            groupSelect.innerHTML = '<option value="">Default group</option>' + (detail.groups || []).map(function (group) {
              return '<option value="' + group.id + '">' + esc(group.name) + '</option>';
            }).join('');
            if (previousGroup) groupSelect.value = previousGroup;
            if (!groupSelect.value && initial.groupId) groupSelect.value = String(initial.groupId);
            renderAssets();
            if (previousAsset) assetSelect.value = previousAsset;
            if (!assetSelect.value && initial.assetId) assetSelect.value = String(initial.assetId);
            if (assetSelect.value) applyAsset(false);
          } catch (error) { formError(overlay, errorText(error)); }
        }
        function applyAsset(setType) {
          if (!assetSelect.value || !detail) return;
          let found = null;
          (detail.groups || []).forEach(function (group) {
            (group.assets || []).forEach(function (asset) { if (String(asset.id) === assetSelect.value) found = asset; });
          });
          if (!found) return;
          if (found.identifier) targetInput.value = found.identifier;
          if (setType) {
            typeSelect.value = ASSET_TYPE[found.kind] || 'network';
            renderType();
          }
          if (found.group_id) groupSelect.value = String(found.group_id);
          renderAssets();
          assetSelect.value = String(found.id);
        }

        typeSelect.addEventListener('change', renderType);
        customerSelect.addEventListener('change', function () { loadCustomer(false, false); });
        groupSelect.addEventListener('change', function () { renderAssets(); assetSelect.value = ''; });
        assetSelect.addEventListener('change', function () { applyAsset(true); });

        if (initial.type && SCAN_TYPES[initial.type]) typeSelect.value = initial.type;
        if (initial.customerId) customerSelect.value = String(initial.customerId);
        renderType();
        loadCustomer(true, true).then(function () {
          if (initial.type) typeSelect.value = initial.type;
          renderType();
          if (initial.target && !targetInput.value) targetInput.value = initial.target;
        });
      }
    });
    return modal;
  }

  // ---------------------------------------------------------------------------
  // Scans list
  // ---------------------------------------------------------------------------
  async function renderScans(view) {
    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Scans</h1>' +
        '<div class="page-sub">Every result is stored locally so you can revisit, compare and export it later.</div></div>' +
        '<div class="page-actions"><button class="btn" data-action="import-ad">Import AD report</button>' +
        '<button class="btn btn-primary" data-action="new-scan">New scan</button></div></div>' +
      '<section class="panel">' +
        '<div class="filter-bar">' +
          '<input class="input input-sm search-input" id="scan-search" placeholder="Search target, customer or asset…" aria-label="Search scans">' +
          '<select class="select select-sm filter-select" id="scan-type-filter" aria-label="Scan type">' +
            '<option value="">All types</option>' +
            Object.keys(SCAN_TYPES).map(function (key) { return '<option value="' + key + '">' + esc(SCAN_TYPES[key].label) + '</option>'; }).join('') +
            '<option value="agent">Agent scan</option></select>' +
          '<select class="select select-sm filter-select" id="scan-status-filter" aria-label="Status">' +
            '<option value="">All statuses</option><option value="queued">Queued</option><option value="running">Running</option>' +
            '<option value="waiting_agent">Waiting for agent</option><option value="completed">Completed</option>' +
            '<option value="failed">Failed</option><option value="cancelled">Cancelled</option></select>' +
          '<span class="spacer"></span><span class="muted small" id="scan-count">Loading…</span>' +
        '</div>' +
        '<div id="scans-table">' + loadingHtml('Loading scans…') + '</div>' +
      '</section>';

    bindCommonActions(view);
    const search = $('#scan-search', view);
    const typeFilter = $('#scan-type-filter', view);
    let timer = null;
    function reload() {
      clearTimeout(timer);
      timer = setTimeout(load, 180);
    }
    async function load() {
      const params = queryString({
        q: search.value.trim(), scan_type: typeFilter.value,
        status: $('#scan-status-filter', view).value, limit: 200
      });
      try {
        const data = await get('/scans' + params);
        $('#scan-count', view).textContent = data.total + ' scan' + (data.total === 1 ? '' : 's');
        $('#scans-table', view).innerHTML = scanTableHtml(data.items);
      } catch (error) {
        $('#scans-table', view).innerHTML = emptyHtml('Could not load scans', errorText(error));
      }
    }
    search.addEventListener('input', reload);
    typeFilter.addEventListener('change', reload);
    $('#scan-status-filter', view).addEventListener('change', reload);
    await load();
    bindScanActions(view);
  }

  function scanTableHtml(items) {
    if (!items || !items.length) {
      return emptyHtml('No scans match these filters', 'Start a new scan or adjust the filters.',
        '<button class="btn btn-primary" data-action="new-scan">New scan</button>');
    }
    return '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      '<th>Scan</th><th>Target</th><th>Status</th><th>Findings</th><th>Created</th><th></th>' +
      '</tr></thead><tbody>' + items.map(function (scan) {
        const active = ACTIVE_STATUSES.indexOf(scan.status) !== -1;
        return '<tr class="clickable" data-href="#/scans/' + scan.id + '">' +
          '<td><div class="cell-main">#' + scan.id + '</div><div class="cell-sub">' + esc(scan.scan_type) + '</div></td>' +
          '<td><div class="table-target cell-main" title="' + esc(scan.target) + '">' + esc(scan.target) + '</div>' +
            '<div class="cell-sub">' + esc(scan.customer_name || 'Unassigned') +
            (scan.asset_name ? ' · ' + esc(scan.asset_name) : (scan.group_name ? ' · ' + esc(scan.group_name) : '')) + '</div></td>' +
          '<td>' + statusPill(scan.status) +
            (active ? '<div class="progress progress-mini" style="margin-top:6px"><div class="progress-bar" style="width:' + num(scan.progress) + '%"></div></div>' +
              '<div class="cell-sub">' + esc(scan.stage) + '</div>' : '') + '</td>' +
          '<td>' + severityChips(scan.summary) + '</td>' +
          '<td><div class="cell-main">' + esc(relTime(scan.created_at)) + '</div>' +
            '<div class="cell-sub">' + esc(fmtShort(scan.created_at)) + '</div></td>' +
          '<td class="actions"><div class="row-actions">' +
            '<a class="btn btn-sm" href="#/scans/' + scan.id + '">View</a>' +
            (active ? '<button class="btn btn-sm btn-subtle" data-cancel="' + scan.id + '">Cancel</button>' : '') +
            (!active ? '<button class="btn btn-sm btn-subtle danger-text" data-delete="' + scan.id + '">Delete</button>' : '') +
          '</div></td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  function bindScanActions(root) {
    root.addEventListener('click', function (event) {
      const cancel = event.target.closest('[data-cancel]');
      const remove = event.target.closest('[data-delete]');
      const row = event.target.closest('tr[data-href]');
      if (cancel) {
        event.preventDefault(); event.stopPropagation();
        const id = cancel.getAttribute('data-cancel');
        confirmAction('Cancel scan #' + id + '? Partial findings may be saved.', 'Cancel scan', false).then(function (ok) {
          if (!ok) return;
          post('/scans/' + id + '/cancel', {}).then(function () { toast('Cancellation requested'); location.hash = '#/scans/' + id; })
            .catch(function (error) { toast(errorText(error), 'error'); });
        });
        return;
      }
      if (remove) {
        event.preventDefault(); event.stopPropagation();
        const id = remove.getAttribute('data-delete');
        confirmAction('Delete scan #' + id + ' and all its findings?', 'Delete scan').then(function (ok) {
          if (!ok) return;
          del('/scans/' + id).then(function () {
            toast('Scan deleted');
            if (location.hash.indexOf('#/scans/') === 0) location.hash = '#/scans'; else router();
          }).catch(function (error) { toast(errorText(error), 'error'); });
        });
        return;
      }
      if (row && !event.target.closest('a,button,select,input')) {
        location.hash = row.getAttribute('data-href');
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Scan detail
  // ---------------------------------------------------------------------------
  function findingDetailHtml(finding) {
    const evidence = finding.evidence
      ? '<div class="full"><h4>Evidence</h4><pre class="evidence-block">' + esc(finding.evidence) + '</pre></div>'
      : '';
    const raw = finding.raw && Object.keys(finding.raw).length
      ? '<div class="full"><h4>Raw data</h4><pre class="meta-json">' + esc(JSON.stringify(finding.raw, null, 2)) + '</pre></div>'
      : '';
    return '<div class="finding-detail">' +
      '<div><h4>Description</h4><p>' + esc(finding.description || 'No description provided.') + '</p></div>' +
      '<div><h4>Remediation</h4><p>' + esc(finding.remediation || 'No remediation provided.') + '</p></div>' +
      (finding.location || finding.resource ? '<div class="full"><h4>Location / resource</h4><p>' +
        esc(finding.location || '') + (finding.resource && finding.resource !== finding.location ? '\n' + esc(finding.resource) : '') + '</p></div>' : '') +
      evidence + raw + '</div>';
  }

  function findingRowHtml(finding) {
    const status = String(finding.status || 'open');
    const statusOptions = ['open', 'acknowledged', 'false_positive', 'accepted', 'fixed'].map(function (value) {
      return '<option value="' + value + '"' + (value === status ? ' selected' : '') + '>' + value.replace(/_/g, ' ') + '</option>';
    }).join('');
    return '<tr class="finding-row" data-severity="' + sev(finding.severity) + '" data-status="' + esc(status) + '">' +
      '<td>' + sevBadge(finding.severity) + '</td>' +
      '<td class="finding-title-cell"><div class="finding-title">' + esc(finding.title) + '</div>' +
        '<div class="finding-meta">' +
          (finding.cve ? '<span class="tag">' + esc(finding.cve) + '</span>' : '') +
          (finding.cwe ? '<span class="tag">' + esc(finding.cwe) + '</span>' : '') +
          (finding.cvss !== null && finding.cvss !== undefined ? '<span class="tag">CVSS ' + esc(finding.cvss) + '</span>' : '') +
        '</div></td>' +
      '<td>' + esc(finding.category) + '</td>' +
      '<td><div class="truncate" style="max-width:240px" title="' + esc(finding.location) + '">' + esc(finding.location || '—') + '</div></td>' +
      '<td><select class="select select-sm finding-status" data-finding-status="' + finding.id + '" aria-label="Finding status">' +
        statusOptions + '</select></td>' +
      '<td class="actions"><button class="btn btn-sm btn-subtle" data-expand="' + finding.id + '">Details</button></td></tr>' +
      '<tr class="finding-expand-row hidden" data-detail-for="' + finding.id + '"><td colspan="6">' + findingDetailHtml(finding) + '</td></tr>';
  }

  function eventsHtml(events) {
    if (!events || !events.length) return '<div class="empty">No events recorded.</div>';
    return events.slice().reverse().map(function (event) {
      return '<div class="event event-' + esc(event.level || 'info') + '">' +
        '<span class="event-time">' + esc(fmtShort(event.created_at)) + '</span>' +
        '<span class="event-msg">' + esc(event.message) + '</span></div>';
    }).join('');
  }

  function scanMeta(scan) {
    return JSON.stringify({
      summary: scan.summary || {}, options: scan.options || {},
      requested_by: scan.requested_by, error: scan.error || ''
    }, null, 2);
  }

  function drawScanDetail(view, scan) {
    const active = ACTIVE_STATUSES.indexOf(scan.status) !== -1;
    const summary = scan.summary || {};
    const findings = scan.findings || [];
    const agent = scan.agent;
    const findingsHtml = findings.length
      ? '<div class="table-wrap findings-table"><table class="data-table"><thead><tr>' +
          '<th>Severity</th><th>Finding</th><th>Category</th><th>Location</th><th>Status</th><th></th>' +
        '</tr></thead><tbody>' + findings.map(findingRowHtml).join('') + '</tbody></table></div>'
      : emptyHtml(active ? 'Scan in progress' : 'No findings recorded',
          active ? 'Findings appear when the scan completes.' : 'This scan did not discover any issues, or the target could not be reached.');

    view.innerHTML =
      '<div class="breadcrumb"><a href="#/customers' + (scan.customer_id ? '/' + scan.customer_id : '') + '">' +
        esc(scan.customer_name || 'Customers') + '</a><span class="sep">/</span><a href="#/scans">Scans</a>' +
        '<span class="sep">/</span><span>#' + scan.id + '</span></div>' +
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Scan #' + scan.id + '</h1>' +
        '<div class="page-sub">' + esc(scan.scan_type) + ' scan · ' + esc(fmtDate(scan.created_at)) + '</div></div>' +
        '<div class="page-actions">' +
          '<a class="btn" href="/api/scans/' + scan.id + '/export?format=html" target="_blank" rel="noopener">HTML report</a>' +
          '<a class="btn" href="/api/scans/' + scan.id + '/export?format=json" download>JSON</a>' +
          '<a class="btn" href="/api/scans/' + scan.id + '/export?format=csv" download>CSV</a>' +
          (scan.scan_type !== 'agent' && !active ? '<button class="btn" data-action="rescan">Rescan</button>' : '') +
          (active ? '<button class="btn btn-danger" data-action="cancel-scan">Cancel</button>' :
            '<button class="btn btn-danger" data-action="delete-scan">Delete</button>') +
        '</div></div>' +
      '<section class="panel" style="margin-bottom:16px"><div class="scan-hero">' +
        '<div class="scan-hero-top"><div class="scan-hero-main"><div class="scan-target">' + esc(scan.target) + '</div>' +
          '<div class="scan-sub"><span data-scan-status>' + statusPill(scan.status) + '</span>' +
          '<span class="tag">' + esc(scan.scan_type) + '</span>' +
          '<span>' + esc(scan.customer_name || 'Unassigned') + '</span>' +
          (scan.group_name ? '<span>· ' + esc(scan.group_name) + '</span>' : '') +
          (scan.asset_name ? '<span>· ' + esc(scan.asset_name) + '</span>' : '') + '</div></div>' +
          '<div class="right"><div class="muted small">Risk score</div>' +
            '<div style="font-size:24px;font-weight:700">' + num(summary.risk_score) + '</div>' +
            '<div class="muted small">' + esc(summary.risk_label || 'None') + '</div></div></div>' +
        '<div class="scan-progress"><div class="progress progress-lg"><div class="progress-bar" data-scan-progress style="width:' + num(scan.progress) + '%"></div></div>' +
          '<div class="scan-progress-meta"><span data-scan-stage>' + esc(scan.stage || '') + '</span><span>' + num(scan.progress) + '%</span></div></div>' +
      '</div>' +
      '<div class="detail-grid">' +
        '<div class="detail-cell"><div class="detail-label">Customer</div><div class="detail-value">' + esc(scan.customer_name || 'Unassigned') + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Group</div><div class="detail-value">' + esc(scan.group_name || '—') + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Asset</div><div class="detail-value">' + esc(scan.asset_name || '—') + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Requested by</div><div class="detail-value">' + esc(scan.requested_by || 'local') + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Created</div><div class="detail-value">' + esc(fmtDate(scan.created_at)) + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Started</div><div class="detail-value">' + esc(fmtDate(scan.started_at)) + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Completed</div><div class="detail-value">' + esc(fmtDate(scan.completed_at)) + '</div></div>' +
        '<div class="detail-cell"><div class="detail-label">Duration</div><div class="detail-value">' + esc(duration(scan.started_at, scan.completed_at)) + '</div></div>' +
      '</div>' +
      '<div class="summary-strip">' + SEVERITIES.map(function (key) {
        return '<span class="badge sev-' + key + '">' + num(summary[key]) + ' ' + key + '</span>';
      }).join('') +
        '<span class="tag">' + num(summary.total) + ' total</span>' +
        '<span class="risk-inline">Risk score ' + num(summary.risk_score) + ' · ' + esc(summary.risk_label || 'None') + '</span></div>' +
      (scan.error ? '<div class="agent-callout" style="background:var(--critical-bg);color:var(--critical)"><strong>Error:</strong> ' + esc(scan.error) + '</div>' : '') +
      (agent ? '<div class="agent-callout"><strong>Agent:</strong> ' + esc(agent.name || agent.id) + ' · ' +
        esc(agent.platform || 'unknown platform') + ' · ' + esc(agent.hostname || '') + ' · seen ' + esc(relTime(agent.last_seen)) + '</div>' : '') +
      '</section>' +
      '<div style="display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,1fr);gap:16px;align-items:start">' +
        '<section class="panel"><div class="panel-head"><h2>Findings</h2><span class="tag">' + findings.length + '</span>' +
          '<span class="spacer"></span>' +
          '<select class="select select-sm filter-select" id="finding-severity-filter" aria-label="Filter findings by severity">' +
            '<option value="">All severities</option>' + SEVERITIES.map(function (key) {
              return '<option value="' + key + '">' + key + '</option>';
            }).join('') + '</select>' +
          '<select class="select select-sm filter-select" id="finding-status-filter" aria-label="Filter findings by status">' +
            '<option value="">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option>' +
            '<option value="accepted">Accepted risk</option><option value="false_positive">False positive</option>' +
            '<option value="fixed">Fixed</option></select></div>' +
          '<div id="findings-body">' + findingsHtml + '</div></section>' +
        '<div style="display:flex;flex-direction:column;gap:16px">' +
          '<section class="panel"><div class="panel-head"><h2>Scan events</h2></div>' +
            '<div class="event-list" data-events>' + eventsHtml(scan.events) + '</div></section>' +
          '<section class="panel"><div class="panel-head"><h2>Scan data</h2></div>' +
            '<div class="panel-body"><pre class="meta-json">' + esc(scanMeta(scan)) + '</pre></div></section>' +
        '</div></div>';

    bindScanDetailActions(view, scan);
    if (active) startScanPolling(view, scan);
  }

  async function renderScanDetail(view, scanId) {
    const scan = await get('/scans/' + scanId);
    view.dataset.scanId = String(scanId);
    drawScanDetail(view, scan);
  }

  function applyFindingFilter(view) {
    const severity = ($('#finding-severity-filter', view) || {}).value || '';
    const status = ($('#finding-status-filter', view) || {}).value || '';
    $$('.finding-row', view).forEach(function (row) {
      const match = (!severity || row.dataset.severity === severity) && (!status || row.dataset.status === status);
      row.classList.toggle('hidden', !match);
      const detail = $('.finding-expand-row[data-detail-for="' + row.querySelector('[data-expand]').getAttribute('data-expand') + '"]', view);
      if (!match && detail) detail.classList.add('hidden');
    });
  }

  function bindScanDetailActions(view, scan) {
    if (state.scanDetailClick) view.removeEventListener('click', state.scanDetailClick);
    if (state.scanDetailChange) view.removeEventListener('change', state.scanDetailChange);
    state.scanDetailClick = function (event) {
      const action = event.target.closest('[data-action]');
      const expand = event.target.closest('[data-expand]');
      if (expand) {
        const row = $('.finding-expand-row[data-detail-for="' + expand.getAttribute('data-expand') + '"]', view);
        if (row) {
          row.classList.toggle('hidden');
          expand.textContent = row.classList.contains('hidden') ? 'Details' : 'Hide';
        }
        return;
      }
      if (!action) return;
      const act = action.getAttribute('data-action');
      if (act === 'cancel-scan') {
        confirmAction('Cancel this scan? Partial findings may be saved.', 'Cancel scan', false).then(function (ok) {
          if (!ok) return;
          post('/scans/' + scan.id + '/cancel', {}).then(function () {
            toast('Cancellation requested'); refreshActiveBadge(); router();
          }).catch(function (error) { toast(errorText(error), 'error'); });
        });
      } else if (act === 'delete-scan') {
        confirmAction('Delete this scan and all its findings?', 'Delete scan').then(function (ok) {
          if (!ok) return;
          del('/scans/' + scan.id).then(function () {
            toast('Scan deleted'); location.hash = '#/scans';
          }).catch(function (error) { toast(errorText(error), 'error'); });
        });
      } else if (act === 'rescan') {
        runWithButton(action, async function () {
          try {
            const created = await post('/scans/' + scan.id + '/rescan', {});
            toast('Rescan queued'); refreshActiveBadge();
            location.hash = '#/scans/' + created.id;
          } catch (error) { toast(errorText(error), 'error'); }
        });
      }
    };

    state.scanDetailChange = function (event) {
      if (event.target.closest('#finding-severity-filter, #finding-status-filter')) {
        applyFindingFilter(view);
        return;
      }
      const select = event.target.closest('[data-finding-status]');
      if (!select) return;
      const findingId = select.getAttribute('data-finding-status');
      const newStatus = select.value;
      select.disabled = true;
      patch('/findings/' + findingId, { status: newStatus }).then(function () {
        toast('Finding marked ' + newStatus.replace(/_/g, ' '));
        const row = select.closest('.finding-row');
        if (row) row.dataset.status = newStatus;
        applyFindingFilter(view);
      }).catch(function (error) {
        toast(errorText(error), 'error'); select.value = select.dataset.previous || 'open';
      }).finally(function () { select.disabled = false; });
    };

    view.addEventListener('click', state.scanDetailClick);
    view.addEventListener('change', state.scanDetailChange);
  }

  function updateScanProgress(view, scan) {
    const statusNode = $('[data-scan-status]', view);
    if (statusNode) statusNode.innerHTML = statusPill(scan.status);
    const bar = $('[data-scan-progress]', view);
    if (bar) bar.style.width = num(scan.progress) + '%';
    const stage = $('[data-scan-stage]', view);
    if (stage) stage.textContent = scan.stage || '';
    const meta = $('.scan-progress-meta span:last-child', view);
    if (meta) meta.textContent = num(scan.progress) + '%';
    const events = $('[data-events]', view);
    if (events) events.innerHTML = eventsHtml(scan.events);
  }

  function startScanPolling(view, scan) {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(async function () {
      if (location.hash !== '#/scans/' + scan.id) {
        clearInterval(state.pollTimer); state.pollTimer = null; return;
      }
      try {
        const fresh = await get('/scans/' + scan.id);
        if (ACTIVE_STATUSES.indexOf(fresh.status) === -1) {
          clearInterval(state.pollTimer); state.pollTimer = null;
          drawScanDetail(view, fresh);
          refreshActiveBadge();
          toast('Scan ' + fresh.status);
        } else {
          updateScanProgress(view, fresh);
        }
      } catch (ignore) { /* keep trying until route changes */ }
    }, 3000);
  }

  // ---------------------------------------------------------------------------
  // Active Directory import
  // ---------------------------------------------------------------------------
  async function openAdImport(preset) {
    const initial = preset || {};
    let customers;
    try { customers = await get('/customers'); }
    catch (error) { toast(errorText(error), 'error'); return; }
    if (!customers.length) {
      openModal({
        title: 'Create a customer first',
        content: '<p style="margin:0" class="muted">AD reports are stored against a customer and asset group.</p>',
        actions: [{ label: 'Close', onClick: function (ctx) { ctx.close(); } }]
      });
      return;
    }
    openModal({
      title: 'Import Active Directory report',
      size: 'wide',
      content: '<form id="ad-import-form"><div class="form-grid">' +
        '<label class="field"><span>Customer</span><select class="select" id="ad-customer">' +
          customers.map(function (customer) { return '<option value="' + customer.id + '">' + esc(customer.name) + '</option>'; }).join('') +
        '</select></label>' +
        '<label class="field"><span>Group</span><select class="select" id="ad-group"><option value="">Default group</option></select></label>' +
        '<label class="field"><span>Asset <span class="muted">(optional)</span></span><select class="select" id="ad-asset"><option value="">No specific asset</option></select></label>' +
        '<label class="field"><span>Report file</span><input class="input" id="ad-file" type="file" accept="application/json,.json"></label>' +
        '<label class="field full"><span>Report JSON</span><textarea class="textarea mono" id="ad-json" rows="12" placeholder="{ &quot;domain&quot;: { &quot;name&quot;: &quot;corp.example&quot; }, ... }"></textarea>' +
          '<span class="hint">Paste the JSON produced by the VulnScanner AD collector, PingCastle, Purple Knight or a compatible report. Collection is read-only.</span></label>' +
        '</div><div class="form-error"></div></form>' +
        '<div class="info-banner" style="margin:14px 0 0"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16.5v.5" stroke-linecap="round"/></svg>' +
        '<div><strong>Authorized use:</strong> only audit directories you own or are contracted to assess. The supplied collector never changes AD objects.</div></div>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Import report', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            clearFormError(ctx.overlay);
            try {
              const text = $('#ad-json', ctx.overlay).value.trim();
              if (!text) throw new Error('Paste a JSON report or choose a file');
              let report;
              try { report = JSON.parse(text); } catch (parseError) { throw new Error('The report is not valid JSON: ' + parseError.message); }
              if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('The report must be a JSON object');
              const payload = {
                customer_id: Number($('#ad-customer', ctx.overlay).value),
                report: report
              };
              const group = $('#ad-group', ctx.overlay).value;
              const asset = $('#ad-asset', ctx.overlay).value;
              if (group) payload.group_id = Number(group);
              if (asset) payload.asset_id = Number(asset);
              const created = await post('/ad/import', payload);
              ctx.close();
              toast('AD report imported');
              location.hash = '#/scans/' + created.id;
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ],
      onMount: function (overlay) {
        const customerSelect = $('#ad-customer', overlay);
        const groupSelect = $('#ad-group', overlay);
        const assetSelect = $('#ad-asset', overlay);
        async function loadGroups() {
          groupSelect.innerHTML = '<option value="">Default group</option>';
          assetSelect.innerHTML = '<option value="">No specific asset</option>';
          try {
            const detail = await get('/customers/' + customerSelect.value);
            groupSelect.innerHTML = '<option value="">Default group</option>' + (detail.groups || []).map(function (group) {
              return '<option value="' + group.id + '">' + esc(group.name) + '</option>';
            }).join('');
            if (initial.groupId) groupSelect.value = String(initial.groupId);
            loadAssets(detail);
          } catch (ignore) { /* shown on submit */ }
        }
        function loadAssets(detail) {
          const groupId = groupSelect.value ? Number(groupSelect.value) : null;
          const options = [];
          ((detail && detail.groups) || []).forEach(function (group) {
            if (groupId && group.id !== groupId) return;
            (group.assets || []).forEach(function (asset) { options.push({ value: asset.id, label: asset.name }); });
          });
          assetSelect.innerHTML = optionsHtml(options, initial.assetId, 'No specific asset');
        }
        let detailCache = null;
        customerSelect.addEventListener('change', loadGroups);
        groupSelect.addEventListener('change', function () {
          get('/customers/' + customerSelect.value).then(function (detail) { detailCache = detail; loadAssets(detail); }).catch(function () {});
        });
        $('#ad-file', overlay).addEventListener('change', function (event) {
          const file = event.target.files && event.target.files[0];
          if (!file) return;
          if (file.size > 20 * 1024 * 1024) { formError(overlay, 'The report is larger than 20 MiB'); return; }
          const reader = new FileReader();
          reader.onload = function () { $('#ad-json', overlay).value = String(reader.result || ''); };
          reader.onerror = function () { formError(overlay, 'Could not read the selected file'); };
          reader.readAsText(file);
        });
        if (initial.customerId) customerSelect.value = String(initial.customerId);
        loadGroups();
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Agents
  // ---------------------------------------------------------------------------
  async function renderAgents(view) {
    if (!state.meta) { try { state.meta = await get('/meta'); } catch (ignore) {} }
    const agents = await get('/agents');
    const rows = agents.length ? agents.map(function (agent) {
      const caps = (agent.capabilities || []).map(function (cap) { return '<span class="tag">' + esc(cap) + '</span>'; }).join('') || '<span class="muted small">—</span>';
      const online = agent.online ? ' online' : ' offline';
      return '<tr><td><div class="agent-name"><span class="agent-dot' + online + '"></span>' +
        '<a href="#/agents/' + encodeURIComponent(agent.id) + '">' + esc(agent.name) + '</a></div>' +
        '<div class="cell-sub">' + esc(agent.asset_name || 'No asset') + '</div></td>' +
        '<td><div class="cell-main">' + esc(agent.hostname || '—') + '</div><div class="cell-sub">' + esc(agent.platform || 'unknown') + ' · v' + esc(agent.version || '—') + '</div></td>' +
        '<td>' + (agent.online ? '<span class="status-pill status-completed"><span class="dot"></span>online</span>' :
          '<span class="status-pill status-cancelled"><span class="dot"></span>offline</span>') +
          '<div class="cell-sub">' + esc(agent.last_seen_human || 'never') + '</div></td>' +
        '<td><div class="cap-list">' + caps + '</div></td>' +
        '<td>' + num(agent.scan_count) + '</td>' +
        '<td><div class="cell-main">' + esc(relTime(agent.last_seen)) + '</div><div class="cell-sub mono">' + esc(agent.last_ip || '') + '</div></td>' +
        '<td class="actions"><div class="row-actions">' +
          '<button class="btn btn-sm" data-agent-view="' + esc(agent.id) + '">Manage</button>' +
          '<button class="btn btn-sm" data-agent-scan="' + esc(agent.id) + '">Scan</button>' +
          '<button class="btn btn-sm btn-subtle danger-text" data-agent-revoke="' + esc(agent.id) + '" data-agent-name="' + esc(agent.name) + '">Revoke</button>' +
        '</div></td></tr>';
    }).join('') : '<tr><td colspan="7">' + emptyHtml('No agents enrolled', 'Enroll an endpoint to run local checks without opening inbound firewall ports.', '<button class="btn btn-primary" data-action="enroll-agent">Enroll agent</button>') + '</td></tr>';

    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Endpoint agents</h1>' +
        '<div class="page-sub">Agents poll the server outbound, run checks locally and upload the results. No inbound rule is needed.</div></div>' +
        '<div class="page-actions"><a class="btn" href="/agent/vulnscanner_agent.py" download>Download agent</a>' +
        '<button class="btn btn-primary" data-action="enroll-agent">Enroll agent</button></div></div>' +
      '<div class="info-banner"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v5c0 4.8-3.2 8.8-8 10-4.8-1.2-8-5.2-8-10V7l8-4z"/><path d="M8.5 12l2.2 2.2L15.5 9.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
        '<div><strong>How enrollment works:</strong> create a one-time token, run the enroll command on the endpoint, then start the agent service. ' +
        'The token is shown once and expires automatically. Agent credentials are stored as SHA-256 hashes on the server.</div></div>' +
      '<section class="panel"><div class="panel-head"><h2>Enrolled endpoints</h2><span class="spacer"></span>' +
        '<span class="muted small">' + agents.length + ' agent' + (agents.length === 1 ? '' : 's') + '</span></div>' +
        '<div class="table-wrap"><table class="data-table"><thead><tr>' +
        '<th>Agent</th><th>Host</th><th>Status</th><th>Capabilities</th><th>Scans</th><th>Last seen</th><th></th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table></div></section>';

    bindCommonActions(view);
    view.addEventListener('click', function (event) {
      const enroll = event.target.closest('[data-action="enroll-agent"]');
      const scan = event.target.closest('[data-agent-scan]');
      const revoke = event.target.closest('[data-agent-revoke]');
      const manage = event.target.closest('[data-agent-view]');
      if (enroll) { event.preventDefault(); openEnrollAgent({}); return; }
      if (manage) {
        event.preventDefault();
        location.hash = '#/agents/' + encodeURIComponent(manage.getAttribute('data-agent-view'));
        return;
      }
      if (scan) {
        const agent = agents.find(function (item) { return item.id === scan.getAttribute('data-agent-scan'); });
        if (agent) openAgentScan(agent);
        return;
      }
      if (revoke) {
        const id = revoke.getAttribute('data-agent-revoke');
        const name = revoke.getAttribute('data-agent-name');
        confirmAction('Revoke agent “' + name + '”? It can no longer poll or upload results.', 'Revoke agent').then(function (ok) {
          if (!ok) return;
          del('/agents/' + id).then(function () { toast('Agent revoked'); router(); })
            .catch(function (error) { toast(errorText(error), 'error'); });
        });
      }
    });
  }

  async function renderAgentDetail(view, agentId) {
    const agent = await get('/agents/' + encodeURIComponent(agentId));
    const stats = agent.stats || {};
    const capabilities = (agent.capabilities || []).map(function (cap) {
      return '<span class="tag">' + esc(cap) + '</span>';
    }).join('') || '<span class="muted small">No capabilities reported yet</span>';
    const revoked = agent.status === 'revoked';
    const online = agent.online ? 'online' : 'offline';
    const jobs = (agent.jobs || []).length ? '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      '<th>Job</th><th>Scan</th><th>Modules</th><th>Status</th><th>Duration</th><th>Created</th><th>Error</th>' +
      '</tr></thead><tbody>' + agent.jobs.map(function (job) {
        return '<tr><td class="mono small">' + esc(job.id.slice(0, 8)) + '…</td>' +
          '<td>' + (job.scan_id ? '<a href="#/scans/' + num(job.scan_id) + '">#' + num(job.scan_id) + '</a>' : '—') +
            (job.scan_target ? '<div class="cell-sub truncate" style="max-width:220px" title="' + esc(job.scan_target) + '">' + esc(job.scan_target) + '</div>' : '') + '</td>' +
          '<td><div class="cap-list">' + (job.modules || []).map(function (module) {
            return '<span class="tag">' + esc(module) + '</span>';
          }).join('') + '</div></td>' +
          '<td>' + statusPill(job.status) + '</td>' +
          '<td>' + esc(job.duration || '—') + '</td>' +
          '<td><div class="cell-main">' + esc(relTime(job.created_at)) + '</div>' +
            '<div class="cell-sub">' + esc(job.created_human || '') + '</div></td>' +
          '<td class="danger-text small">' + esc(job.error || '') + '</td></tr>';
      }).join('') + '</tbody></table></div>' : emptyHtml('No agent jobs yet', 'Start a scan to create the first job for this endpoint.');

    const scans = (agent.scans || []).length ? '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      '<th>Scan</th><th>Target</th><th>Status</th><th>Findings</th><th>Created</th>' +
      '</tr></thead><tbody>' + agent.scans.map(function (scan) {
        return '<tr class="clickable" data-href="#/scans/' + num(scan.id) + '">' +
          '<td><div class="cell-main">#' + num(scan.id) + '</div><div class="cell-sub">' + esc(scan.scan_type) + '</div></td>' +
          '<td><div class="truncate" style="max-width:280px" title="' + esc(scan.target) + '">' + esc(scan.target) + '</div></td>' +
          '<td>' + statusPill(scan.status) + '</td>' +
          '<td>' + severityChips(scan.summary) + '</td>' +
          '<td><div class="cell-main">' + esc(relTime(scan.created_at)) + '</div>' +
            '<div class="cell-sub">' + esc(fmtShort(scan.created_at)) + '</div></td></tr>';
      }).join('') + '</tbody></table></div>' : emptyHtml('No scans from this agent yet', 'Use Scan now to queue the first agent job.');

    view.innerHTML =
      '<div class="breadcrumb"><a href="#/agents">Agents</a><span class="sep">/</span><span>' + esc(agent.name) + '</span></div>' +
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">' +
        '<span class="agent-dot ' + online + '" style="width:11px;height:11px;margin-right:8px"></span>' + esc(agent.name) + '</h1>' +
        '<div class="page-sub">' + esc(agent.hostname || 'Unknown host') + ' · ' + esc(agent.platform || 'unknown platform') +
        ' · agent v' + esc(agent.version || '—') + '</div></div>' +
        '<div class="page-actions">' +
          (revoked ? '' :
            '<button class="btn" data-action="agent-config">Configure</button>' +
            '<button class="btn" data-action="agent-rotate">Rotate token</button>' +
            '<button class="btn btn-primary" data-action="agent-scan">Scan now</button>' +
            '<button class="btn btn-danger" data-action="agent-revoke">Revoke</button>') +
        '</div></div>' +
      (revoked ? '<div class="info-banner" style="background:var(--critical-bg);border-color:#efc4c4;color:var(--critical)"><strong>Revoked.</strong> This agent can no longer poll for jobs or upload results. Enroll it again to resume scanning.</div>' :
        (agent.online ? '' : '<div class="info-banner"><strong>Agent offline.</strong> New jobs stay queued until the endpoint polls the server again. Last contact ' + esc(agent.last_seen_human || 'never') + '.</div>')) +
      '<div class="stat-grid">' +
        '<div class="stat-card ' + (agent.online ? 'stat-ok' : 'stat-warn') + '"><div class="stat-label">Last contact</div>' +
          '<div class="stat-value stat-value-text">' + esc(agent.online ? 'Online' : 'Offline') + '</div>' +
          '<div class="stat-foot">' + esc(agent.last_seen_human || 'never') + ' · ' + esc(agent.last_ip || 'no IP') + '</div></div>' +
        '<div class="stat-card"><div class="stat-label">Queued jobs</div><div class="stat-value">' + num(stats.queued_jobs) + '</div>' +
          '<div class="stat-foot">' + num(stats.active_jobs) + ' running · ' + num(stats.failed_jobs) + ' failed</div></div>' +
        '<div class="stat-card"><div class="stat-label">Agent scans</div><div class="stat-value">' + num(stats.scans) + '</div>' +
          '<div class="stat-foot">' + num(stats.jobs) + ' jobs recorded</div></div>' +
        '<div class="stat-card stat-warn"><div class="stat-label">Open findings</div><div class="stat-value">' + num(stats.open_findings) + '</div>' +
          '<div class="stat-foot">' + num(stats.findings) + ' total from this agent</div></div>' +
      '</div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>Connection and placement</h2></div><div class="panel-body">' +
          '<div class="kv"><span>Customer</span><span>' + esc(agent.customer_name || '—') + '</span></div>' +
          '<div class="kv"><span>Group</span><span>' + esc(agent.group_name || '—') + '</span></div>' +
          '<div class="kv"><span>Asset</span><span>' + esc(agent.asset_name || '—') + '</span></div>' +
          '<div class="kv"><span>Hostname</span><span class="mono">' + esc(agent.hostname || '—') + '</span></div>' +
          '<div class="kv"><span>Platform</span><span>' + esc(agent.platform || 'unknown') + '</span></div>' +
          '<div class="kv"><span>Agent version</span><span>' + esc(agent.version || '—') + '</span></div>' +
          '<div class="kv"><span>Last IP</span><span class="mono">' + esc(agent.last_ip || '—') + '</span></div>' +
          '<div class="kv"><span>Enrolled</span><span>' + esc(fmtDate(agent.created_at)) + '</span></div>' +
          '<div class="kv"><span>Agent ID</span><span class="mono" style="font-size:10.5px">' + esc(agent.id) + '</span></div>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Reported capabilities</h2></div><div class="panel-body">' +
          '<div class="cap-list" style="max-width:none">' + capabilities + '</div>' +
          '<p class="modal-note" style="margin-top:14px">Capabilities come from the most recent heartbeat. Update the agent to add new modules.</p>' +
          '<div class="kv" style="margin-top:8px"><span>Polling</span><span>Outbound every 30 seconds</span></div>' +
          '<div class="kv"><span>Token storage</span><span>SHA-256 hash on the server</span></div>' +
        '</div></section></div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>Agent commands</h2><span class="spacer"></span>' +
          '<span class="muted small">Linux / macOS</span></div><div class="panel-body">' +
          '<pre class="command-block">sudo -u vulnscanner /opt/vulnscanner-agent/vulnscanner_agent.py --config /var/lib/vulnscanner-agent/agent.json status\nsudo systemctl restart vulnscanner-agent\njournalctl -u vulnscanner-agent -n 50 --no-pager</pre>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Agent commands</h2><span class="spacer"></span>' +
          '<span class="muted small">Windows (Administrator)</span></div><div class="panel-body">' +
          '<pre class="command-block">py -3 vulnscanner_agent.py --config "C:\\ProgramData\\VulnScanner Agent\\agent.json" status\nStop-ScheduledTask -TaskName "VulnScanner Agent"\nStart-ScheduledTask -TaskName "VulnScanner Agent"</pre>' +
        '</div></section></div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>Recent jobs</h2><span class="spacer"></span>' +
          '<span class="muted small">' + num(stats.jobs) + ' total</span></div>' + jobs + '</section>' +
        '<section class="panel"><div class="panel-head"><h2>Recent scans</h2><span class="spacer"></span>' +
          '<span class="muted small">' + num(stats.scans) + ' total</span></div>' + scans + '</section></div>';

    view.addEventListener('click', function (event) {
      const action = event.target.closest('[data-action]');
      if (!action) {
        const row = event.target.closest('tr[data-href]');
        if (row && !event.target.closest('a,button,select,input')) location.hash = row.getAttribute('data-href');
        return;
      }
      const name = action.getAttribute('data-action');
      if (name === 'agent-scan') { openAgentScan(agent); return; }
      if (name === 'agent-config') { openAgentConfig(agent); return; }
      if (name === 'agent-rotate') { openAgentTokenRotate(agent); return; }
      if (name === 'agent-revoke') {
        confirmAction('Revoke agent “' + agent.name + '”? It can no longer poll or upload results.', 'Revoke agent').then(function (ok) {
          if (!ok) return;
          del('/agents/' + encodeURIComponent(agent.id)).then(function () {
            toast('Agent revoked'); location.hash = '#/agents';
          }).catch(function (error) { toast(errorText(error), 'error'); });
        });
      }
    });
  }

  async function openAgentConfig(agent) {
    let customers;
    try { customers = await get('/customers'); }
    catch (error) { toast(errorText(error), 'error'); return; }
    openModal({
      title: 'Configure ' + agent.name,
      size: 'wide',
      content: '<form id="agent-config-form"><div class="form-grid">' +
        '<label class="field full"><span>Agent name</span>' +
          '<input class="input" id="agent-config-name" maxlength="160" value="' + esc(agent.name) + '"></label>' +
        '<label class="field"><span>Customer</span><select class="select" id="agent-config-customer">' +
          customers.map(function (customer) {
            return '<option value="' + customer.id + '"' + (customer.id === agent.customer_id ? ' selected' : '') + '>' +
              esc(customer.name) + '</option>';
          }).join('') + '</select></label>' +
        '<label class="field"><span>Group</span><select class="select" id="agent-config-group"></select></label>' +
        '</div><div class="form-error"></div></form>' +
        '<div class="modal-note" style="margin-top:14px">Moving an agent moves its linked asset to the new group. ' +
        'Historical scans stay with the customer and group they were run under. The agent token does not change.</div>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Save configuration', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            clearFormError(ctx.overlay);
            try {
              const result = await patch('/agents/' + encodeURIComponent(agent.id), {
                name: $('#agent-config-name', ctx.overlay).value.trim(),
                customer_id: Number($('#agent-config-customer', ctx.overlay).value),
                group_id: Number($('#agent-config-group', ctx.overlay).value)
              });
              ctx.close();
              toast('Agent configuration saved');
              router();
              return result;
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ],
      onMount: function (overlay) {
        const customerSelect = $('#agent-config-customer', overlay);
        const groupSelect = $('#agent-config-group', overlay);
        async function loadGroups() {
          groupSelect.innerHTML = '<option value="">Loading…</option>';
          try {
            const detail = await get('/customers/' + customerSelect.value);
            groupSelect.innerHTML = '<option value="">Select a group…</option>' + (detail.groups || []).map(function (group) {
              return '<option value="' + group.id + '"' +
                (group.id === agent.group_id && Number(customerSelect.value) === agent.customer_id ? ' selected' : '') +
                '>' + esc(group.name) + '</option>';
            }).join('');
            if (!groupSelect.value) groupSelect.value = String(agent.group_id);
          } catch (error) {
            groupSelect.innerHTML = '<option value="">Could not load groups</option>';
          }
        }
        customerSelect.addEventListener('change', loadGroups);
        loadGroups();
      }
    });
  }

  function openAgentTokenRotate(agent) {
    confirmAction('Rotate the token for “' + agent.name + '”? The old token stops working immediately and the agent will be offline until you update its configuration and restart it.', 'Rotate token').then(function (ok) {
      if (!ok) return;
      post('/agents/' + encodeURIComponent(agent.id) + '/rotate-token', {}).then(function (result) {
        showAgentTokenResult(result);
      }).catch(function (error) { toast(errorText(error), 'error'); });
    });
  }

  function showAgentTokenResult(result) {
    let activeTab = 'linux';
    openModal({
      title: 'New token for ' + (result.agent_name || 'agent'),
      size: 'xwide',
      content: '<div class="info-banner" style="margin-top:0;background:#fff8e8;border-color:#f0d8a8;color:#78520a">' +
        '<div><strong>The previous token is now invalid.</strong> ' + esc(result.note) + '</div></div>' +
        '<div class="form-grid"><label class="field full"><span>Agent token</span><div class="token-reveal">' +
          '<input class="input mono" id="agent-new-token" readonly value="' + esc(result.token) + '">' +
          '<button class="btn" type="button" data-copy="' + esc(result.token) + '">Copy</button></div></label></div>' +
        '<div class="tabs" style="margin-top:18px" id="agent-token-tabs">' +
          '<button class="tab active" type="button" data-tab="linux">Linux / macOS</button>' +
          '<button class="tab" type="button" data-tab="windows">Windows</button></div>' +
        '<div id="agent-token-command">' + commandPanel(result.linux_command, 'linux') + '</div>',
      actions: [{ label: 'Done', class: 'btn-primary', onClick: function (ctx) { ctx.close(); router(); } }],
      onMount: function (overlay) {
        $('#agent-token-tabs', overlay).addEventListener('click', function (event) {
          const tab = event.target.closest('[data-tab]');
          if (!tab) return;
          activeTab = tab.getAttribute('data-tab');
          $$('.tab', overlay).forEach(function (item) { item.classList.toggle('active', item === tab); });
          $('#agent-token-command', overlay).innerHTML = activeTab === 'windows'
            ? commandPanel(result.windows_command, 'windows')
            : commandPanel(result.linux_command, 'linux');
        });
        overlay.addEventListener('click', function (event) {
          const copy = event.target.closest('[data-copy]');
          if (!copy) return;
          copyText(copy.getAttribute('data-copy')).then(function () { toast('Copied to clipboard'); })
            .catch(function () { toast('Could not access the clipboard; select the text manually', 'error'); });
        });
      }
    });
  }


  async function openEnrollAgent(preset) {
    const initial = preset || {};
    let customers;
    try { customers = await get('/customers'); }
    catch (error) { toast(errorText(error), 'error'); return; }
    if (!customers.length) {
      openModal({
        title: 'Create a customer first',
        content: '<p style="margin:0" class="muted">Agents are assigned to a customer group and appear as assets.</p>',
        actions: [{ label: 'Close', onClick: function (ctx) { ctx.close(); } }]
      });
      return;
    }
    openModal({
      title: 'Enroll endpoint agent',
      size: 'wide',
      content: '<form id="enroll-form"><div class="form-grid">' +
        '<label class="field"><span>Customer</span><select class="select" id="enroll-customer">' +
          customers.map(function (customer) { return '<option value="' + customer.id + '">' + esc(customer.name) + '</option>'; }).join('') +
        '</select></label>' +
        '<label class="field"><span>Group</span><select class="select" id="enroll-group"></select></label>' +
        '<label class="field"><span>Agent name <span class="muted">(optional)</span></span>' +
          '<input class="input" id="enroll-name" maxlength="160" placeholder="srv-web-01"></label>' +
        '<label class="field"><span>Token lifetime</span><select class="select" id="enroll-hours">' +
          '<option value="1">1 hour</option><option value="8">8 hours</option><option value="24" selected>24 hours</option>' +
          '<option value="72">3 days</option><option value="168">7 days</option></select></label>' +
        '</div><div class="form-error"></div></form>' +
        '<div class="modal-note" style="margin-top:14px">The command downloads the Python agent, enrolls it with a one-time token and starts polling. ' +
        'For production use, install it as a service with the helper scripts in the <span class="mono">agent/</span> directory.</div>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Create token', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            clearFormError(ctx.overlay);
            try {
              const payload = {
                customer_id: Number($('#enroll-customer', ctx.overlay).value),
                group_id: Number($('#enroll-group', ctx.overlay).value),
                agent_name: $('#enroll-name', ctx.overlay).value.trim(),
                hours: Number($('#enroll-hours', ctx.overlay).value)
              };
              if (!payload.group_id) throw new Error('Choose a group');
              const result = await post('/agents/enrollment-tokens', payload);
              ctx.close();
              showEnrollmentResult(result);
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ],
      onMount: function (overlay) {
        const customerSelect = $('#enroll-customer', overlay);
        const groupSelect = $('#enroll-group', overlay);
        async function loadGroups() {
          groupSelect.innerHTML = '<option value="">Select a group…</option>';
          try {
            const detail = await get('/customers/' + customerSelect.value);
            groupSelect.innerHTML = '<option value="">Select a group…</option>' + (detail.groups || []).map(function (group) {
              return '<option value="' + group.id + '">' + esc(group.name) + '</option>';
            }).join('');
            if (initial.groupId) groupSelect.value = String(initial.groupId);
          } catch (ignore) { /* shown on submit */ }
        }
        customerSelect.addEventListener('change', loadGroups);
        if (initial.customerId) customerSelect.value = String(initial.customerId);
        loadGroups();
      }
    });
  }

  function commandPanel(command, label) {
    return '<div style="position:relative"><pre class="command-block" data-command="' + esc(label) + '">' + esc(command) + '</pre>' +
      '<button type="button" class="copy-btn" data-copy="' + esc(command) + '">Copy</button></div>';
  }

  function showEnrollmentResult(result) {
    let activeTab = 'linux';
    const modal = openModal({
      title: 'Agent enrollment token',
      size: 'xwide',
      content: '<div class="info-banner" style="margin-top:0"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v5c0 4.8-3.2 8.8-8 10-4.8-1.2-8-5.2-8-10V7l8-4z"/></svg>' +
        '<div><strong>This token is shown once.</strong> It expires ' + esc(fmtDate(result.expires_at)) + '. The agent is assigned to ' +
        esc(result.customer) + ' / ' + esc(result.group) + '.</div></div>' +
        '<div class="form-grid"><label class="field full"><span>Enrollment token</span><div class="token-reveal">' +
          '<input class="input mono" id="enroll-token-value" readonly value="' + esc(result.token) + '">' +
          '<button class="btn" type="button" data-copy="' + esc(result.token) + '">Copy</button></div></label></div>' +
        '<div class="tabs" style="margin-top:18px" id="enroll-tabs">' +
          '<button class="tab active" type="button" data-tab="linux">Linux / macOS</button>' +
          '<button class="tab" type="button" data-tab="windows">Windows</button></div>' +
        '<div id="enroll-command">' + commandPanel(result.linux_command, 'linux') + '</div>' +
        '<div class="modal-note" style="margin-top:12px">Review the command before running it. For a persistent service, use the installer scripts: ' +
        '<a href="/agent/install-linux.sh" target="_blank" rel="noopener">Linux</a> · ' +
        '<a href="/agent/install-windows.ps1" target="_blank" rel="noopener">Windows</a>. ' +
        'The Windows installer can also accept the enrollment token directly.</div>',
      actions: [{ label: 'Done', class: 'btn-primary', onClick: function (ctx) { ctx.close(); } }],
      onMount: function (overlay) {
        $('#enroll-tabs', overlay).addEventListener('click', function (event) {
          const tab = event.target.closest('[data-tab]');
          if (!tab) return;
          activeTab = tab.getAttribute('data-tab');
          $$('.tab', overlay).forEach(function (item) { item.classList.toggle('active', item === tab); });
          $('#enroll-command', overlay).innerHTML = activeTab === 'windows'
            ? commandPanel(result.windows_command, 'windows')
            : commandPanel(result.linux_command, 'linux');
        });
        overlay.addEventListener('click', function (event) {
          const copy = event.target.closest('[data-copy]');
          if (!copy) return;
          copyText(copy.getAttribute('data-copy')).then(function () { toast('Copied to clipboard'); })
            .catch(function () { toast('Could not access the clipboard; select the text manually', 'error'); });
        });
      }
    });
    // Highlight the token the first time so it is easy to copy manually.
    setTimeout(function () {
      const input = $('#enroll-token-value');
      if (input) { input.focus(); input.select(); }
    }, 80);
    return modal;
  }

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }

  function openAgentScan(agent) {
    const modules = (state.meta && state.meta.agent_modules) || [
      { id: 'system', name: 'System baseline and security configuration' },
      { id: 'packages', name: 'Installed package vulnerabilities (OSV)' },
      { id: 'ports', name: 'Local listening services' },
      { id: 'secrets', name: 'Secrets in selected local paths' },
      { id: 'repo', name: 'Repository inventory in selected paths' },
      { id: 'ad', name: 'Active Directory audit (Windows)' }
    ];
    const isWindows = String(agent.platform || '').toLowerCase().indexOf('windows') !== -1;
    const checks = modules.map(function (module) {
      const disabled = module.id === 'ad' && !isWindows;
      const checked = ['system', 'packages', 'ports'].indexOf(module.id) !== -1 ? ' checked' : '';
      return '<label class="check"><input type="checkbox" value="' + esc(module.id) + '"' + checked +
        (disabled ? ' disabled' : '') + '><span><strong>' + esc(module.id) + '</strong> — ' + esc(module.name) +
        (disabled ? ' <span class="muted">(Windows only)</span>' : '') + '</span></label>';
    }).join('');
    openModal({
      title: 'Scan ' + agent.name,
      size: 'wide',
      content: '<form id="agent-scan-form"><div class="info-banner" style="margin-top:0"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16.5v.5" stroke-linecap="round"/></svg>' +
        '<div>Agent is <strong>' + (agent.online ? 'online' : 'offline') + '</strong>. ' +
        (agent.online ? 'The job starts on its next poll.' : 'The job is queued and runs when the agent reconnects.') + '</div></div>' +
        '<div class="form-section" style="margin-top:0;padding-top:0;border-top:0"><h3>Modules</h3><div class="checkbox-row" style="flex-direction:column;gap:9px">' + checks + '</div></div>' +
        '<div class="form-section"><h3>Local paths for secrets / repository modules</h3>' +
          '<label class="field full"><textarea class="textarea mono" id="agent-paths" rows="3" placeholder="/home/user/project&#10;C:\\inetpub\\wwwroot"></textarea>' +
          '<span class="hint">One absolute path per line. Required when the secrets or repository module is selected.</span></label>' +
          '<div class="form-grid" style="margin-top:10px">' +
          '<label class="field"><span>Excluded paths <span class="muted">(comma separated)</span></span><input class="input" id="agent-excludes" placeholder="/proc, /sys"></label>' +
          '<label class="field"><span>Maximum files</span><input class="input" id="agent-max-files" type="number" min="100" max="200000" value="20000"></label>' +
          '</div></div><div class="form-error"></div></form>',
      actions: [
        { label: 'Cancel', onClick: function (ctx) { ctx.close(); } },
        { label: 'Queue agent scan', class: 'btn-primary', onClick: function (ctx) {
          runWithButton(ctx.button, async function () {
            clearFormError(ctx.overlay);
            try {
              const selected = $$('#agent-scan-form input[type=checkbox]:checked', ctx.overlay).map(function (input) { return input.value; });
              if (!selected.length) throw new Error('Select at least one module');
              const paths = $('#agent-paths', ctx.overlay).value.split(/\r?\n/).map(function (line) { return line.trim(); }).filter(Boolean);
              if (selected.indexOf('secrets') !== -1 || selected.indexOf('repo') !== -1) {
                if (!paths.length) throw new Error('Add at least one local path for the secrets/repository modules');
              }
              const excludes = $('#agent-excludes', ctx.overlay).value.split(',').map(function (part) { return part.trim(); }).filter(Boolean);
              const maxFiles = Number($('#agent-max-files', ctx.overlay).value) || 20000;
              const result = await post('/agents/' + agent.id + '/scan', {
                modules: selected, paths: paths,
                options: { exclude_paths: excludes, max_files: maxFiles }
              });
              ctx.close();
              toast(result.message || 'Agent scan queued');
              refreshActiveBadge();
              location.hash = '#/scans/' + result.scan_id;
            } catch (error) { formError(ctx.overlay, errorText(error)); }
          });
        } }
      ]
    });
  }

  // ---------------------------------------------------------------------------
  // Active Directory page
  // ---------------------------------------------------------------------------
  async function renderAd(view) {
    const data = await get('/scans?scan_type=ad&limit=20');
    const table = data.items.length ? scanTableHtml(data.items) : emptyHtml('No AD audits yet',
      'Import a collector report or run the Active Directory module from a Windows agent.',
      '<button class="btn btn-primary" data-action="import-ad">Import AD report</button>');
    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Active Directory audit</h1>' +
        '<div class="page-sub">Read-only assessment of identity risk, modelled after PingCastle and Purple Knight checks.</div></div>' +
        '<div class="page-actions"><a class="btn" href="/agent/ad_audit.ps1" download>Download PowerShell collector</a>' +
        '<button class="btn btn-primary" data-action="import-ad">Import report</button></div></div>' +
      '<div class="info-banner"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v5c0 4.8-3.2 8.8-8 10-4.8-1.2-8-5.2-8-10V7l8-4z"/></svg>' +
        '<div><strong>Authorization required.</strong> Use a domain account with read-only directory access. The collector reads LDAP/AD configuration and never changes objects. ' +
        'Reports can be imported from the PowerShell collector, a Windows agent, PingCastle, Purple Knight or any compatible JSON document.</div></div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>What is assessed</h2></div><div class="panel-body">' +
          '<div class="setting-copy" style="margin-bottom:12px"><strong>Kerberos and delegation</strong><span>Unconstrained delegation, Kerberoastable and AS-REP-roastable accounts, krbtgt age.</span></div>' +
          '<div class="setting-copy" style="margin-bottom:12px"><strong>Privileged access</strong><span>Privileged group size, AdminCount hygiene, stale and non-expiring privileged accounts.</span></div>' +
          '<div class="setting-copy" style="margin-bottom:12px"><strong>Password and lockout policy</strong><span>Minimum length, complexity, lockout threshold and maximum password age.</span></div>' +
          '<div class="setting-copy"><strong>Directory hygiene</strong><span>Guest account, machine account quota, Recycle Bin, functional level and stale computers.</span></div>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Collect and import</h2></div><div class="panel-body">' +
          '<ol style="margin:0;padding-left:20px;color:var(--text-2);font-size:12.5px;line-height:1.7">' +
            '<li>On a domain-joined Windows host, run <span class="mono">ad_audit.ps1</span> with a read-only account.</li>' +
            '<li>Save the JSON output, or let a Windows VulnScanner agent run the <span class="mono">ad</span> module.</li>' +
            '<li>Use <strong>Import AD report</strong>, choose the customer/asset and paste or upload the JSON.</li>' +
            '<li>Review findings, assign false-positive or accepted-risk status, and export the HTML report.</li></ol>' +
          '<div style="margin-top:14px"><a class="btn btn-sm" href="/agent/install-windows.ps1" target="_blank" rel="noopener">Windows agent installer</a> ' +
          '<a class="btn btn-sm" href="#/help" style="margin-left:6px">Read the manual</a></div>' +
        '</div></section></div>' +
      '<section class="panel"><div class="panel-head"><h2>Recent AD audits</h2><span class="spacer"></span>' +
        '<span class="muted small">' + data.total + ' total</span></div>' + table + '</section>';
    bindCommonActions(view);
    bindScanActions(view);
  }

  // ---------------------------------------------------------------------------
  // Server monitoring and maintenance
  // ---------------------------------------------------------------------------
  function healthBadge(status) {
    const key = String(status || 'info').toLowerCase();
    const classes = { ok: 'sev-low', warning: 'sev-medium', error: 'sev-critical', info: 'sev-info' };
    return '<span class="badge ' + (classes[key] || 'sev-none') + '">' + esc(key) + '</span>';
  }

  function downloadJsonFile(filename, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  async function renderServer(view) {
    const data = await get('/server/status');
    const counts = data.counts || {};
    const queue = data.queue || {};
    const database = data.database || {};
    const disk = data.disk || {};
    const process = data.process || {};
    const settings = data.settings || {};
    const tools = data.tools || {};
    const checks = data.checks || [];
    const healthy = data.status === 'ok';
    const toolRows = ['nmap', 'nuclei', 'osv-scanner', 'gitleaks', 'semgrep', 'git'].map(function (name) {
      const tool = tools[name] || { available: false, path: '', version: '' };
      return '<div class="tool-row"><span class="tool-name">' + esc(name) + '</span>' +
        '<span class="badge ' + (tool.available ? 'sev-info' : 'sev-none') + '">' + (tool.available ? 'available' : 'not found') + '</span>' +
        '<span class="tool-path" title="' + esc(tool.path) + '">' + esc(tool.path || 'Install it or set the path in .env') + '</span>' +
        '<span class="tool-version">' + esc(tool.version || '') + '</span></div>';
    }).join('');
    const checkRows = checks.map(function (check) {
      return '<div class="health-check"><span class="health-mark ' + esc(check.status) + '"></span>' +
        '<div class="health-copy"><strong>' + esc(check.label) + '</strong><span>' + esc(check.detail) + '</span></div>' +
        healthBadge(check.status) + '</div>';
    }).join('');
    const diskPercent = Math.max(0, Math.min(100, num(disk.percent)));

    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Server</h1>' +
        '<div class="page-sub">Local runtime, storage, scan queue and maintenance for this VulnScanner instance.</div></div>' +
        '<div class="page-actions"><button class="btn" data-action="refresh-server">Refresh</button>' +
        '<a class="btn" href="#/settings">Settings</a>' +
        '<a class="btn" href="/api/docs" target="_blank" rel="noopener">API reference</a></div></div>' +
      '<div class="info-banner ' + (healthy ? '' : 'info-banner-warn') + '"><span class="agent-dot ' + (healthy ? 'online' : 'offline') + '"></span>' +
        '<div><strong>' + (healthy ? 'Server healthy' : 'Server needs attention') + '.</strong> ' +
        'VulnScanner ' + esc(data.version) + ' has been running for ' + esc(data.uptime_human) + '. ' +
        (process.auth_enabled ? 'Dashboard authentication is enabled.' : 'Dashboard authentication is disabled; keep the bind address on loopback.') +
        '</div></div>' +
      '<div class="stat-grid">' +
        '<div class="stat-card stat-ok"><div class="stat-label">Uptime</div><div class="stat-value stat-value-text">' + esc(data.uptime_human) + '</div>' +
          '<div class="stat-foot">since ' + esc(fmtShort(data.started_at)) + '</div></div>' +
        '<div class="stat-card"><div class="stat-label">Database</div><div class="stat-value stat-value-text">' + bytes(database.size) + '</div>' +
          '<div class="stat-foot">' + num(database.page_count) + ' pages · ' + esc(database.journal_mode || 'unknown') + ' journal</div></div>' +
        '<div class="stat-card ' + (diskPercent > 85 ? 'stat-warn' : '') + '"><div class="stat-label">Disk free</div><div class="stat-value stat-value-text">' + bytes(disk.free) + '</div>' +
          '<div class="stat-foot">' + diskPercent + '% used of ' + bytes(disk.total) + '</div></div>' +
        '<div class="stat-card"><div class="stat-label">Active work</div><div class="stat-value">' + num(counts.scans_active) + '</div>' +
          '<div class="stat-foot">' + num(queue.jobs_queued) + ' agent jobs queued · ' + num(queue.jobs_running) + ' running</div></div>' +
      '</div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>Health checks</h2><span class="spacer"></span>' +
          '<span class="muted small">' + checks.length + ' checks</span></div><div class="panel-body tight">' + checkRows + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Scan queue</h2></div><div class="panel-body">' +
          '<div class="kv"><span>Queued scans</span><span>' + num(queue.scans_queued) + '</span></div>' +
          '<div class="kv"><span>Running scans</span><span>' + num(queue.scans_running) + '</span></div>' +
          '<div class="kv"><span>Waiting for agents</span><span>' + num(queue.scans_waiting_agent) + '</span></div>' +
          '<div class="kv"><span>Agent jobs queued</span><span>' + num(queue.jobs_queued) + '</span></div>' +
          '<div class="kv"><span>Agent jobs running</span><span>' + num(queue.jobs_running) + '</span></div>' +
          '<div class="kv"><span>Failed agent jobs</span><span>' + num(queue.jobs_failed) + '</span></div>' +
          '<div class="kv"><span>Agents online</span><span>' + num(counts.agents_online) + ' of ' + num(counts.agents - counts.agents_revoked) + '</span></div>' +
        '</div></section></div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>Runtime</h2></div><div class="panel-body">' +
          '<div class="kv"><span>Version</span><span>' + esc(data.product) + ' ' + esc(data.version) + '</span></div>' +
          '<div class="kv"><span>Bind address</span><span class="mono">' + esc(process.host) + ':' + num(process.port) + '</span></div>' +
          '<div class="kv"><span>Dashboard auth</span><span>' + (process.auth_enabled ? 'enabled (' + esc(process.admin_user) + ')' : 'disabled') + '</span></div>' +
          '<div class="kv"><span>Process</span><span class="mono">pid ' + num(process.pid) + '</span></div>' +
          '<div class="kv"><span>Python</span><span>' + esc(process.python) + '</span></div>' +
          '<div class="kv"><span>Host platform</span><span>' + esc(process.platform) + '</span></div>' +
          '<div class="kv"><span>External API calls</span><span>' + (process.external_api_environment ? 'environment enabled' : 'environment disabled') + '</span></div>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Database and storage</h2></div><div class="panel-body">' +
          '<div class="kv"><span>Integrity</span><span class="' + (database.integrity === 'ok' ? 'ok-text' : 'danger-text') + '">' + esc(database.integrity) + '</span></div>' +
          '<div class="kv"><span>Schema version</span><span>' + num(database.schema_version) + '</span></div>' +
          '<div class="kv"><span>WAL size</span><span>' + bytes(database.wal_size) + '</span></div>' +
          '<div class="kv"><span>Free pages</span><span>' + num(database.free_pages) + '</span></div>' +
          '<div class="kv"><span>Database path</span><span class="mono">' + esc(database.path) + '</span></div>' +
          '<div class="kv"><span>Reports</span><span>' + num((data.paths || {}).reports_count) + ' files · ' + bytes((data.paths || {}).reports_size) + '</span></div>' +
          '<div class="disk-meter" title="' + diskPercent + '% used"><div class="disk-meter-fill' + (diskPercent > 85 ? ' warn' : '') + '" style="width:' + diskPercent + '%"></div></div>' +
          '<div class="muted small" style="margin-top:5px">' + bytes(disk.used) + ' used · ' + bytes(disk.free) + ' free</div>' +
        '</div></section></div>' +
      '<div class="dash-grid-2" style="margin-bottom:16px">' +
        '<section class="panel"><div class="panel-head"><h2>Runtime configuration</h2></div><div class="panel-body">' +
          switchRow('srv-external', 'Allow outbound API calls',
            'OSV.dev package lookups, CISA KEV catalogue and GitHub clones.', settings.allow_external_apis) +
          switchRow('srv-nuclei', 'Enable Nuclei integration',
            'Run Nuclei templates during web scans when the binary is installed.', settings.nuclei_enabled) +
          switchRow('srv-nmap', 'Enable Nmap integration',
            'Use Nmap for service detection during network scans when installed.', settings.nmap_enabled) +
          '<div style="display:flex;align-items:center;gap:10px;margin-top:16px"><button class="btn btn-primary" data-action="save-server-settings">Save configuration</button>' +
          '<span class="muted small">Bind address, authentication and paths are environment variables and require a restart.</span></div>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Maintenance</h2></div><div class="panel-body">' +
          '<p class="muted small" style="margin-top:0">Back up the SQLite database before upgrades. The copy is stored under the reports directory and excluded from normal report exports.</p>' +
          '<div class="kv"><span>Last backup</span><span>' + esc(data.last_backup_at ? fmtDate(data.last_backup_at) : 'never') + '</span></div>' +
          '<div class="kv"><span>Backup path</span><span class="mono">' + esc(data.last_backup_path || '—') + '</span></div>' +
          '<div class="row-actions" style="margin-top:14px">' +
            '<button class="btn" data-action="backup-db">Back up database</button>' +
            '<button class="btn" data-action="vacuum-db">Compact database</button>' +
            '<button class="btn" data-action="download-diagnostics">Download diagnostics</button></div>' +
        '</div></section></div>' +
      '<section class="panel"><div class="panel-head"><h2>Optional command-line tools</h2><span class="spacer"></span>' +
        '<span class="muted small">Failures never abort a scan; built-in checks remain available.</span></div>' +
        '<div class="panel-body">' + toolRows + '</div></section>';

    view.addEventListener('click', function (event) {
      const action = event.target.closest('[data-action]');
      if (!action) return;
      const name = action.getAttribute('data-action');
      if (name === 'refresh-server') { router(); return; }
      if (name === 'save-server-settings') {
        runWithButton(action, async function () {
          try {
            await patch('/settings', {
              allow_external_apis: $('#srv-external').checked,
              nuclei_enabled: $('#srv-nuclei').checked,
              nmap_enabled: $('#srv-nmap').checked
            });
            toast('Server configuration saved');
            router();
          } catch (error) { toast(errorText(error), 'error'); }
        });
        return;
      }
      if (name === 'backup-db') {
        runWithButton(action, async function () {
          try {
            const result = await post('/server/database/backup', {});
            toast('Database backed up (' + bytes(result.size) + ')');
            router();
          } catch (error) { toast(errorText(error), 'error'); }
        });
        return;
      }
      if (name === 'vacuum-db') {
        confirmAction('Compact the SQLite database now? Scans may pause briefly while the file is rewritten.', 'Compact database', false).then(function (ok) {
          if (!ok) return;
          runWithButton(action, async function () {
            try {
              const result = await post('/server/database/vacuum', {});
              toast('Database compacted; ' + bytes(result.saved) + ' reclaimed');
              router();
            } catch (error) { toast(errorText(error), 'error'); }
          });
        });
        return;
      }
      if (name === 'download-diagnostics') {
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        downloadJsonFile('vulnscanner-diagnostics-' + stamp + '.json', data);
        toast('Diagnostics downloaded');
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Settings
  // ---------------------------------------------------------------------------
  function switchRow(id, title, description, checked, disabled) {
    return '<div class="setting-row"><div class="setting-copy"><strong>' + esc(title) + '</strong><span>' + esc(description) + '</span></div>' +
      '<label class="switch"><input type="checkbox" id="' + esc(id) + '"' + (checked ? ' checked' : '') + (disabled ? ' disabled' : '') + '>' +
      '<span class="switch-slider"></span></label></div>';
  }

  async function renderSettings(view) {
    let settings;
    try { settings = await get('/settings'); }
    catch (error) {
      view.innerHTML = emptyHtml('Could not load settings', errorText(error));
      return;
    }
    const tools = settings.tools || {};
    const toolRows = ['nmap', 'nuclei', 'osv-scanner', 'gitleaks', 'semgrep', 'git'].map(function (name) {
      const tool = tools[name] || { available: false, path: '', version: '' };
      return '<div class="tool-row"><span class="tool-name">' + esc(name) + '</span>' +
        '<span class="badge ' + (tool.available ? 'sev-info' : 'sev-none') + '">' + (tool.available ? 'available' : 'not found') + '</span>' +
        '<span class="tool-path" title="' + esc(tool.path) + '">' + esc(tool.path || 'Install it or set the path in .env') + '</span>' +
        '<span class="tool-version">' + esc(tool.version || '') + '</span></div>';
    }).join('');

    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Settings</h1>' +
        '<div class="page-sub">Local configuration and optional integrations. Environment variables control bind address, authentication and paths.</div></div>' +
        '<div class="page-actions"><a class="btn" href="/api/docs" target="_blank" rel="noopener">API reference</a>' +
        '<a class="btn" href="/manual" target="_blank" rel="noopener">Full manual</a></div></div>' +
      '<div class="settings-grid">' +
        '<section class="panel"><div class="panel-head"><h2>Scanning integrations</h2></div><div class="panel-body">' +
          switchRow('set-external', 'Allow outbound API calls',
            'OSV.dev package lookups, CISA KEV catalogue and GitHub clones. Disable for an air-gapped environment.', settings.allow_external_apis) +
          switchRow('set-nuclei', 'Enable Nuclei integration',
            'Run Nuclei templates during web scans when the nuclei binary is installed.', settings.nuclei_enabled) +
          switchRow('set-nmap', 'Enable Nmap integration',
            'Use Nmap for service detection during network scans when the nmap binary is installed.', settings.nmap_enabled) +
          '<div style="display:flex;align-items:center;gap:10px;margin-top:16px"><button class="btn btn-primary" id="save-settings">Save settings</button>' +
          '<span class="muted small">Environment-level external API access: ' + (settings.external_apis_available ? 'enabled' : 'disabled') + '</span></div>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>CISA KEV catalogue</h2></div><div class="panel-body">' +
          '<p class="muted small" style="margin-top:0">Known Exploited Vulnerabilities data is cached in SQLite and used to flag findings that are actively exploited.</p>' +
          '<div class="kv"><span>CVEs in catalogue</span><span>' + num(settings.kev_count) + '</span></div>' +
          '<div class="kv"><span>Last sync</span><span>' + esc(settings.kev_last_sync ? fmtDate(settings.kev_last_sync) : 'never') + '</span></div>' +
          '<div style="margin-top:14px"><button class="btn" id="sync-kev">Sync catalogue now</button></div>' +
        '</div></section>' +
        '<section class="panel settings-wide"><div class="panel-head"><h2>Optional command-line tools</h2><span class="spacer"></span>' +
          '<span class="muted small">Built-in fallbacks remain available when a tool is missing.</span></div><div class="panel-body">' + toolRows + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Local data</h2></div><div class="panel-body">' +
          '<div class="kv"><span>Database</span><span class="mono">' + esc(settings.database_path) + '</span></div>' +
          '<div class="kv"><span>Database size</span><span>' + bytes(settings.database_size) + '</span></div>' +
          '<div class="kv"><span>Reports directory</span><span class="mono">' + esc(settings.reports_path) + '</span></div>' +
          '<div class="kv"><span>Top ports scanned</span><span>' + num((settings.limits || {}).top_ports) + '</span></div>' +
          '<div class="kv"><span>Agent job timeout</span><span>' + num((settings.limits || {}).agent_job_timeout_seconds) + ' seconds</span></div>' +
          '<p class="modal-note" style="margin-top:12px">Back up the data directory to preserve customers, scans, findings and agent state. ' +
          'Reports are generated on demand from the database.</p>' +
        '</div></section>' +
        '<section class="panel"><div class="panel-head"><h2>Security and access</h2></div><div class="panel-body">' +
          '<div class="kv"><span>Default bind</span><span class="mono">127.0.0.1:8765</span></div>' +
          '<div class="kv"><span>Dashboard auth</span><span>Set <span class="mono">VS_ADMIN_PASSWORD</span> to enable HTTP Basic auth</span></div>' +
          '<div class="kv"><span>Agent tokens</span><span>SHA-256 hashed at rest</span></div>' +
          '<div class="kv"><span>Enrollment tokens</span><span>One-time use, 1–168 hour expiry</span></div>' +
          '<p class="modal-note" style="margin-top:12px">Bind to <span class="mono">0.0.0.0</span> only behind a trusted network or reverse proxy with TLS. ' +
          'Scanning without authorization may be illegal. See the manual for the deployment checklist.</p>' +
        '</div></section>' +
      '</div>';

    $('#save-settings').addEventListener('click', function (event) {
      runWithButton(event.currentTarget, async function () {
        try {
          await patch('/settings', {
            allow_external_apis: $('#set-external').checked,
            nuclei_enabled: $('#set-nuclei').checked,
            nmap_enabled: $('#set-nmap').checked
          });
          toast('Settings saved');
          router();
        } catch (error) { toast(errorText(error), 'error'); }
      });
    });
    $('#sync-kev').addEventListener('click', function (event) {
      runWithButton(event.currentTarget, async function () {
        try {
          const result = await post('/settings/kev/sync', {});
          toast('KEV catalogue synced: ' + num(result.count) + ' CVEs');
          router();
        } catch (error) { toast(errorText(error), 'error'); }
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Help and Markdown rendering
  // ---------------------------------------------------------------------------
  function slugify(text) {
    return String(text).toLowerCase()
      .replace(/`([^`]*)`/g, '$1')
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'section';
  }

  function extractHeadings(markdown) {
    const lines = String(markdown).split(/\r?\n/);
    const headings = [];
    const used = {};
    let inFence = false;
    lines.forEach(function (line) {
      if (/^\s*```/.test(line)) { inFence = !inFence; return; }
      if (inFence) return;
      const match = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
      if (!match) return;
      const base = slugify(match[2]);
      let id = base;
      let counter = 1;
      while (used[id]) { counter += 1; id = base + '-' + counter; }
      used[id] = true;
      headings.push({ level: match[1].length, text: match[2], id: id });
    });
    return headings;
  }

  function inlineMarkdown(text) {
    let value = esc(text);
    value = value.replace(/`([^`]+)`/g, '<code>$1</code>');
    value = value.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    value = value.replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>');
    value = value.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+|\/[^)\s]*|#[^)\s]*)\)/g, function (match, label, href) {
      const external = /^https?:/.test(href);
      return '<a href="' + href + '"' + (external ? ' target="_blank" rel="noopener"' : '') + '>' + label + '</a>';
    });
    return value;
  }

  function isBlockStart(line) {
    const trimmed = line.trim();
    return !trimmed || /^(#{1,6})\s+/.test(trimmed) || /^```/.test(trimmed) ||
      /^[-*+]\s+/.test(trimmed) || /^\d+\.\s+/.test(trimmed) || /^>\s?/.test(trimmed) ||
      /^---+$/.test(trimmed) || trimmed.indexOf('|') !== -1 || /^\u0001CODE\d+\u0001$/.test(trimmed);
  }

  function renderMarkdown(markdown) {
    const headings = extractHeadings(markdown);
    const codeBlocks = [];
    const source = String(markdown).split(/\r?\n/);
    const lines = [];
    let inFence = false;
    let buffer = [];
    source.forEach(function (line) {
      if (/^\s*```/.test(line)) {
        if (inFence) {
          codeBlocks.push(buffer.join('\n'));
          lines.push('\u0001CODE' + (codeBlocks.length - 1) + '\u0001');
          buffer = [];
          inFence = false;
        } else {
          inFence = true;
          buffer = [];
        }
        return;
      }
      if (inFence) buffer.push(line);
      else lines.push(line);
    });
    if (inFence) {
      codeBlocks.push(buffer.join('\n'));
      lines.push('\u0001CODE' + (codeBlocks.length - 1) + '\u0001');
    }

    const html = [];
    let index = 0;
    let headingIndex = 0;

    function paragraph(start) {
      const parts = [];
      let i = start;
      while (i < lines.length && !isBlockStart(lines[i])) { parts.push(lines[i].trim()); i += 1; }
      if (!parts.length) return start + 1;
      html.push('<p>' + inlineMarkdown(parts.join(' ')) + '</p>');
      return i;
    }

    while (index < lines.length) {
      const line = lines[index];
      const trimmed = line.trim();
      if (!trimmed) { index += 1; continue; }

      const codeMatch = /^\u0001CODE(\d+)\u0001$/.exec(trimmed);
      if (codeMatch) {
        html.push('<pre><code>' + esc(codeBlocks[Number(codeMatch[1])] || '') + '</code></pre>');
        index += 1; continue;
      }
      const heading = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(trimmed);
      if (heading) {
        const level = heading[1].length;
        const known = headings[headingIndex];
        const id = known ? known.id : slugify(heading[2]);
        headingIndex += 1;
        html.push('<h' + level + ' id="' + esc(id) + '">' + inlineMarkdown(heading[2]) + '</h' + level + '>');
        index += 1; continue;
      }
      if (/^---+$/.test(trimmed)) { html.push('<hr>'); index += 1; continue; }
      if (/^>\s?/.test(trimmed)) {
        const parts = [];
        while (index < lines.length && /^>\s?/.test(lines[index].trim())) {
          parts.push(lines[index].trim().replace(/^>\s?/, ''));
          index += 1;
        }
        html.push('<blockquote>' + inlineMarkdown(parts.join(' ')) + '</blockquote>');
        continue;
      }
      if (trimmed.indexOf('|') !== -1 && index + 1 < lines.length &&
          /^\s*\|?[\s:|-]+\|[\s:|-]*$/.test(lines[index + 1]) && lines[index + 1].indexOf('-') !== -1) {
        const parseRow = function (row) {
          return row.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(function (cell) { return cell.trim(); });
        };
        const header = parseRow(lines[index]);
        index += 2;
        const rows = [];
        while (index < lines.length && lines[index].trim().indexOf('|') !== -1) {
          rows.push(parseRow(lines[index])); index += 1;
        }
        html.push('<table><thead><tr>' + header.map(function (cell) { return '<th>' + inlineMarkdown(cell) + '</th>'; }).join('') +
          '</tr></thead><tbody>' + rows.map(function (row) {
            return '<tr>' + row.map(function (cell) { return '<td>' + inlineMarkdown(cell) + '</td>'; }).join('') + '</tr>';
          }).join('') + '</tbody></table>');
        continue;
      }
      if (/^[-*+]\s+/.test(trimmed) || /^\d+\.\s+/.test(trimmed)) {
        const ordered = /^\d+\.\s+/.test(trimmed);
        const items = [];
        while (index < lines.length) {
          const match = ordered ? /^\s*\d+\.\s+(.+)$/.exec(lines[index]) : /^\s*[-*+]\s+(.+)$/.exec(lines[index]);
          if (!match) break;
          items.push('<li>' + inlineMarkdown(match[1].trim()) + '</li>');
          index += 1;
        }
        html.push((ordered ? '<ol>' : '<ul>') + items.join('') + (ordered ? '</ol>' : '</ul>'));
        continue;
      }
      index = paragraph(index);
    }
    return html.join('\n');
  }

  async function renderHelp(view) {
    let markdown = null;
    try {
      const response = await fetch('/manual', { headers: { Accept: 'text/markdown' } });
      if (response.ok) markdown = await response.text();
    } catch (ignore) { markdown = null; }
    if (!markdown) {
      view.innerHTML = '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Manual &amp; help</h1></div></div>' +
        '<section class="panel"><div class="help-fallback"><h2>Quick start</h2>' +
        '<ol><li>Create a customer and a group such as <span class="mono">webserver</span>.</li>' +
        '<li>Add an asset with its target URL, hostname or repository path.</li>' +
        '<li>Start a scan. Results are stored locally and can be exported as HTML, JSON or CSV.</li></ol>' +
        '<p>The full manual was not found at <span class="mono">/manual</span>. See the <span class="mono">docs/</span> directory in the installation.</p></div></section>';
      return;
    }
    const headings = extractHeadings(markdown);
    const toc = headings.filter(function (heading) { return heading.level === 2 || heading.level === 3; });
    view.innerHTML =
      '<div class="page-head"><div class="page-head-main"><h1 class="page-title">Manual &amp; help</h1>' +
        '<div class="page-sub">Operating instructions, integrations, security notes and the authorized-use policy.</div></div>' +
        '<div class="page-actions"><a class="btn" href="/manual" target="_blank" rel="noopener">Open Markdown source</a></div></div>' +
      '<div class="help-layout"><aside class="panel help-toc"><h3>Contents</h3>' +
        toc.map(function (heading) {
          return '<a href="#/help" data-target="' + esc(heading.id) + '" class="' + (heading.level === 3 ? 'sub' : '') + '">' +
            esc(heading.text.replace(/`/g, '')) + '</a>';
        }).join('') + '</aside>' +
      '<article class="panel markdown">' + renderMarkdown(markdown) + '</article></div>';

    $('.help-toc', view).addEventListener('click', function (event) {
      const link = event.target.closest('[data-target]');
      if (!link) return;
      event.preventDefault();
      const target = document.getElementById(link.getAttribute('data-target'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // ---------------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------------
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
