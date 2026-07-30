/* ==========================================================================
   app.js — boot, routing, navigation, filter bar
   ========================================================================== */
const ROUTES = [
  { group: 'Overview' },
  { id: 'executive', label: 'Executive view', glyph: '◈', view: r => V.executive(r) },
  { id: 'findings', label: 'Vulnerability register', glyph: '☰', view: r => V.findings(r) },
  { group: 'Grouped dashboards' },
  { id: 'department', label: 'Department', glyph: '▤', view: r => V.group(r, 'department') },
  { id: 'application', label: 'Application', glyph: '▥', view: r => V.group(r, 'application') },
  { id: 'system_owner', label: 'System owner', glyph: '▦', view: r => V.group(r, 'system_owner') },
  { id: 'environment', label: 'Environment', glyph: '▧', view: r => V.group(r, 'environment') },
  { id: 'category', label: 'Vulnerability type', glyph: '▨', view: r => V.group(r, 'category') },
  { group: 'Data' },
  { id: 'assets', label: 'Hosts & ownership', glyph: '▣', view: r => V.assets(r) },
  { id: 'imports', label: 'Scan imports', glyph: '↥', view: r => V.imports(r) },
  { id: 'admin', label: 'Settings', glyph: '⚙', view: r => V.admin(r) }
];

/* ---------- navigation ---------- */
function buildNav() {
  const nav = $('#nav');
  nav.innerHTML = ROUTES.map(r => r.group
    ? `<div class="nav-group">${r.group}</div>`
    : `<div class="nav-item ${S.route === r.id ? 'active' : ''}" data-route="${r.id}">
         <span class="glyph">${r.glyph}</span><span>${r.label}</span>
         ${r.id === 'findings' ? `<span class="count" id="openCount">—</span>` : ''}
       </div>`).join('');
  $$('[data-route]', nav).forEach(n => n.addEventListener('click', () => go(n.dataset.route)));
}

function go(route) {
  S.route = route;
  S.table.page = 1;
  if (route !== 'findings') S.selection.clear();
  location.hash = route;
  buildNav();
  render();
}

async function render() {
  const host = $('#view');
  const route = ROUTES.find(r => r.id === S.route) || ROUTES[1];
  try {
    await route.view(host);
  } catch (e) {
    if (e.message !== 'unauthenticated') {
      host.innerHTML = `<div class="empty"><b>Could not load this view</b>${esc(e.message)}</div>`;
      toast(e.message, 'bad');
    }
  }
}

/* ---------- status rail ---------- */
async function refreshStatus() {
  try {
    const [sum, k] = await Promise.all([
      API.get('/api/system/summary'),
      API.get('/api/dashboard/kpis' + qs())
    ]);
    S.summary = sum;
    const last = sum.last_scan;
    $('#statusbar').innerHTML = `
      <span><span class="dot"></span>Connected</span>
      <span>Hosts <b>${num(sum.counts.assets)}</b></span>
      <span>Findings <b>${num(sum.counts.findings)}</b></span>
      <span>Open <b>${num(k.open)}</b></span>
      <span>Critical <b style="color:var(--crit)">${num(k.open_critical)}</b></span>
      <span>Past SLA <b style="color:var(--crit)">${num(k.open_breached)}</b></span>
      <span>Last scan <b>${last ? esc(last.scan_date) : 'none loaded'}</b></span>
      ${sum.unclassified ? `<span title="Vulnerabilities the engine could not type">Unclassified <b style="color:var(--amber)">${sum.unclassified}</b></span>` : ''}
      <span class="spacer"></span>
      <span>${activeFilterCount()} filter${activeFilterCount() === 1 ? '' : 's'} active</span>`;
    const oc = $('#openCount');
    if (oc) oc.textContent = num(k.open);
  } catch (e) { /* status rail is best-effort */ }
}

/* ---------- filter bar ---------- */
const FILTER_SELECTS = [
  ['status', 'Status'], ['severity', 'Severity'], ['category', 'Type'],
  ['department', 'Department'], ['application', 'Application'], ['system_owner', 'Owner'],
  ['environment', 'Environment'], ['criticality', 'Criticality'], ['os_family', 'OS family']
];

function renderFilterBar(host) {
  if (!host) return;
  const o = S.options;
  const sel = (key, label) => {
    const opts = o[key] || [];
    const chosen = S.filters[key] || [];
    return `<div class="field"><label>${label}</label>
      <select multiple data-fk="${key}" size="4">
        ${opts.map(v => `<option value="${esc(v)}" ${chosen.includes(v) ? 'selected' : ''}>${esc(v)}</option>`).join('')}
      </select></div>`;
  };
  host.innerHTML = `<div class="filterbar">
    <div class="row">
      <div class="field grow"><label>Search host, vulnerability, CVE or ticket</label>
        <input id="fq" value="${esc(S.filters.q || '')}" placeholder="e.g. gh-db-014, log4j, CVE-2021-4104, CHG10022"></div>
      <div class="field"><label>Date field</label>
        <select id="fDateField">
          ${[['first_detected', 'First detected'], ['last_detected', 'Last detected'],
             ['closed_date', 'Closed'], ['mitigated_date', 'Mitigated'], ['due_date', 'Due']]
            .map(([v, l]) => `<option value="${v}" ${S.filters.date_field === v ? 'selected' : ''}>${l}</option>`).join('')}
        </select></div>
      <div class="field"><label>From</label><input type="date" id="fFrom" value="${esc(S.filters.date_from || '')}"></div>
      <div class="field"><label>To</label><input type="date" id="fTo" value="${esc(S.filters.date_to || '')}"></div>
      <div class="field"><label>Age min (days)</label><input type="number" id="fAgeMin" value="${esc(S.filters.age_min || '')}" min="0"></div>
      <div class="field"><label>Flags</label>
        <select id="fFlag">
          <option value="">any</option>
          <option value="sla" ${S.filters.sla_breached ? 'selected' : ''}>past SLA only</option>
          <option value="exploit" ${S.filters.exploitable ? 'selected' : ''}>known exploit only</option>
        </select></div>
    </div>
    <div class="row" style="margin-top:10px">
      ${FILTER_SELECTS.map(([k, l]) => sel(k, l)).join('')}
    </div>
    <div class="row" style="margin-top:10px">
      <button class="btn primary" id="fApply">Apply filters</button>
      <button class="btn" id="fClear">Clear all</button>
      <button class="btn" id="fSave">Save this view</button>
      <select id="fViews" style="min-width:180px"><option value="">Load a saved view…</option></select>
      <div style="flex:1"></div>
      <span class="mono-dim" id="fCount">${activeFilterCount()} active</span>
    </div>
    <div class="chips" id="fChips"></div>
  </div>`;

  drawChips();

  const apply = () => {
    S.filters.q = $('#fq', host).value.trim() || undefined;
    S.filters.date_field = $('#fDateField', host).value || undefined;
    S.filters.date_from = $('#fFrom', host).value || undefined;
    S.filters.date_to = $('#fTo', host).value || undefined;
    S.filters.age_min = $('#fAgeMin', host).value || undefined;
    const flag = $('#fFlag', host).value;
    S.filters.sla_breached = flag === 'sla' ? '1' : undefined;
    S.filters.exploitable = flag === 'exploit' ? '1' : undefined;
    $$('[data-fk]', host).forEach(s => {
      const vals = Array.from(s.selectedOptions).map(x => x.value);
      if (vals.length) S.filters[s.dataset.fk] = vals; else delete S.filters[s.dataset.fk];
    });
    Object.keys(S.filters).forEach(k => { if (!S.filters[k]) delete S.filters[k]; });
    S.table.page = 1;
    render();
    refreshStatus();
  };
  $('#fApply', host).addEventListener('click', apply);
  $('#fq', host).addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
  $('#fClear', host).addEventListener('click', () => {
    S.filters = {}; S.table.page = 1; render(); refreshStatus();
  });
  $('#fSave', host).addEventListener('click', () => {
    const body = el('div', {}, `<label>View name</label><input id="vName" style="width:100%"
      placeholder="e.g. Critical database findings past SLA">`);
    const b = el('button', { class: 'btn primary' }, 'Save view');
    const m = modal({ title: 'Save view', sub: 'Saves the current filter set for reuse.', body, footer: [b] });
    b.addEventListener('click', async () => {
      const name = $('#vName', body).value.trim();
      if (!name) { toast('Give the view a name', 'warn'); return; }
      await API.post('/api/views', { name, scope: S.route, filters: S.filters });
      toast(`Saved view "${name}"`);
      m.close(); loadViews(host);
    });
  });
  loadViews(host);
}

async function loadViews(host) {
  try {
    const views = await API.get('/api/views');
    const sel = $('#fViews', host);
    if (!sel) return;
    sel.innerHTML = '<option value="">Load a saved view…</option>' +
      views.map(v => `<option value="${v.id}">${esc(v.name)}</option>`).join('');
    sel.onchange = () => {
      const v = views.find(x => String(x.id) === sel.value);
      if (!v) return;
      S.filters = JSON.parse(v.filters || '{}');
      S.table.page = 1;
      render(); refreshStatus();
      toast(`Loaded "${v.name}"`);
    };
  } catch (e) { /* saved views are optional */ }
}

function drawChips() {
  const host = $('#fChips');
  if (!host) return;
  const chips = [];
  MULTI_KEYS.forEach(k => (S.filters[k] || []).forEach(v =>
    chips.push([k, v, () => { S.filters[k] = S.filters[k].filter(x => x !== v); if (!S.filters[k].length) delete S.filters[k]; }])));
  SCALAR_KEYS.forEach(k => { if (S.filters[k] && k !== 'date_field') chips.push([k, S.filters[k], () => delete S.filters[k]]); });
  host.innerHTML = chips.length ? '' : '<span class="mono-dim">No filters — showing everything</span>';
  chips.forEach(([k, v, remove]) => {
    const chip = el('span', { class: 'chip' }, `${k.replace(/_/g, ' ')}: <b>${esc(v)}</b> <span class="x">✕</span>`);
    $('.x', chip).addEventListener('click', () => { remove(); render(); refreshStatus(); });
    host.appendChild(chip);
  });
}

/* ---------- login ---------- */
function showLogin(msg) {
  $('#shell').classList.remove('ready');
  $('#login').style.display = 'grid';
  document.body.classList.add('locked');
  if (msg) $('#lerr').textContent = msg;
}

async function doLogin() {
  const u = $('#lu').value.trim(), p = $('#lp').value;
  $('#lerr').textContent = '';
  if (!u || !p) { $('#lerr').textContent = 'Enter a username and password'; return; }
  try {
    const res = await API.post('/api/auth/login', { username: u, password: p, client: navigator.userAgent.slice(0, 80) });
    API.token = res.token;
    S.user = res.user;
    await boot();
    if (S.user.must_change) promptPasswordChange();
  } catch (e) {
    $('#lerr').textContent = e.message === 'unauthenticated' ? 'Invalid username or password' : e.message;
  }
}

function promptPasswordChange() {
  const body = el('div');
  body.innerHTML = `<div class="form-grid">
    <div class="full"><label>Current password</label><input id="pc" type="password"></div>
    <div class="full"><label>New password (minimum 8 characters)</label><input id="pn" type="password"></div>
  </div>`;
  const b = el('button', { class: 'btn primary' }, 'Change password');
  const m = modal({
    title: 'Change your password',
    sub: 'This account is still using the password issued at setup.', body, footer: [b]
  });
  b.addEventListener('click', async () => {
    try {
      await API.post('/api/auth/password', {
        current_password: $('#pc', body).value, new_password: $('#pn', body).value
      });
      toast('Password changed');
      S.user.must_change = 0;
      m.close();
    } catch (e) { toast(e.message, 'bad'); }
  });
}

/* ---------- boot ---------- */
async function boot() {
  $('#login').style.display = 'none';
  document.body.classList.remove('locked');
  $('#shell').classList.add('ready');

  S.user = S.user || await API.get('/api/auth/me');
  $('#whoName').textContent = S.user.full_name || S.user.username;
  $('#whoRole').textContent = S.user.role;
  $('#whoAv').textContent = (S.user.full_name || S.user.username).slice(0, 1).toUpperCase();

  const meta = await API.get('/api/meta');
  $('#verline').textContent = `v${meta.version} · port ${meta.port}`;

  S.options = await API.get('/api/filters/options');
  S.route = (location.hash || '#executive').slice(1);
  if (!ROUTES.some(r => r.id === S.route)) S.route = 'executive';
  buildNav();
  await render();
  refreshStatus();
  setInterval(refreshStatus, 60000);
}

window.addEventListener('DOMContentLoaded', () => {
  $('#lgo').addEventListener('click', doLogin);
  ['lu', 'lp'].forEach(id => $('#' + id).addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  }));
  $('#logout').addEventListener('click', async () => {
    try { await API.post('/api/auth/logout', {}); } catch (e) { /* already gone */ }
    API.token = null; S.user = null;
    showLogin('Signed out');
  });
  window.addEventListener('hashchange', () => {
    const r = location.hash.slice(1);
    if (r && r !== S.route && ROUTES.some(x => x.id === r)) go(r);
  });

  // an existing session cookie means we can skip the login screen
  API.get('/api/auth/me')
    .then(u => { S.user = u; boot(); })
    .catch(() => showLogin());
});
