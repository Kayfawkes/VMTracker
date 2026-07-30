/* ==========================================================================
   api.js — server access, shared state, small DOM helpers
   ========================================================================== */
const API = {
  token: null,

  async call(path, opts = {}) {
    bar(true);
    try {
      const headers = Object.assign({}, opts.headers || {});
      if (API.token) headers['X-VMT-Token'] = API.token;
      if (opts.json !== undefined) {
        headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(opts.json);
      }
      const res = await fetch(path, { ...opts, headers });
      if (res.status === 401) { API.token = null; showLogin('Session expired — sign in again'); throw new Error('unauthenticated'); }
      const ctype = res.headers.get('content-type') || '';
      if (!res.ok) {
        let msg = res.statusText;
        if (ctype.includes('json')) { const b = await res.json(); msg = b.detail || msg; }
        throw new Error(msg);
      }
      if (ctype.includes('json')) return res.json();
      return res;
    } finally { bar(false); }
  },

  get:   (p)      => API.call(p),
  post:  (p, j)   => API.call(p, { method: 'POST', json: j }),
  patch: (p, j)   => API.call(p, { method: 'PATCH', json: j }),
  put:   (p, j)   => API.call(p, { method: 'PUT', json: j }),
  del:   (p)      => API.call(p, { method: 'DELETE' }),

  async upload(path, formData) {
    bar(true);
    try {
      const headers = API.token ? { 'X-VMT-Token': API.token } : {};
      const res = await fetch(path, { method: 'POST', body: formData, headers });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || res.statusText);
      return body;
    } finally { bar(false); }
  },

  async download(path) {
    bar(true);
    try {
      const headers = API.token ? { 'X-VMT-Token': API.token } : {};
      const res = await fetch(path, { headers });
      if (!res.ok) {
        let msg = res.statusText;
        try { msg = (await res.json()).detail || msg; } catch (e) { /* not json */ }
        throw new Error(msg);
      }
      const blob = await res.blob();
      const name = res.headers.get('X-VMT-Filename') || 'export';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name; document.body.appendChild(a); a.click();
      a.remove(); setTimeout(() => URL.revokeObjectURL(url), 4000);
      return name;
    } finally { bar(false); }
  }
};

/* ---------- shared state ---------- */
const S = {
  user: null,
  route: 'executive',
  filters: {},
  options: {},
  sla: [],
  summary: null,
  table: { sort: 'severity', direction: 'desc', page: 1, page_size: 100 },
  selection: new Set()
};

const MULTI_KEYS = ['status', 'severity', 'category', 'subcategory', 'department',
  'application', 'system_owner', 'environment', 'criticality', 'os_family', 'location',
  'business_unit', 'remediation_owner'];
const SCALAR_KEYS = ['q', 'date_field', 'date_from', 'date_to', 'age_min', 'age_max',
  'exploitable', 'sla_breached', 'confidence_below'];

function qs(extra = {}) {
  const p = new URLSearchParams();
  MULTI_KEYS.forEach(k => (S.filters[k] || []).forEach(v => p.append(k, v)));
  SCALAR_KEYS.forEach(k => { if (S.filters[k]) p.append(k, S.filters[k]); });
  Object.entries(extra).forEach(([k, v]) => { if (v !== undefined && v !== null) p.append(k, v); });
  const s = p.toString();
  return s ? '?' + s : '';
}

function activeFilterCount() {
  return MULTI_KEYS.reduce((n, k) => n + ((S.filters[k] || []).length ? 1 : 0), 0)
       + SCALAR_KEYS.reduce((n, k) => n + (S.filters[k] ? 1 : 0), 0);
}

/* ---------- DOM helpers ---------- */
const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, html) {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  });
  if (html !== undefined) node.innerHTML = html;
  return node;
}

function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function num(v, dash = '—') {
  if (v === null || v === undefined || v === '') return dash;
  return typeof v === 'number' ? v.toLocaleString() : v;
}

const SEV_CLASS = { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low', Info: 'info' };
const SEV_COLOUR = {
  Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)',
  Low: 'var(--low)', Info: 'var(--info)'
};

function sevPill(s) { return `<span class="pill ${SEV_CLASS[s] || 'info'}">${esc(s)}</span>`; }
function statusPill(s) {
  return `<span class="pill st-${esc(s)}">${esc(String(s).replace('_', ' '))}</span>`;
}

function bar(on) {
  const p = $('#progress');
  if (!p) return;
  if (on) { p.classList.add('on'); p.style.width = '68%'; }
  else { p.style.width = '100%'; setTimeout(() => { p.classList.remove('on'); p.style.width = '0'; }, 220); }
}

function toast(msg, kind = '') {
  const t = el('div', { class: 'toast ' + kind }, esc(msg));
  $('#toasts').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 320); }, 4200);
}

/* ---------- modal ---------- */
function modal({ title, sub, body, footer, wide }) {
  const host = $('#modalHost');
  const scrim = el('div', { class: 'scrim' });
  const box = el('div', { class: 'modal' + (wide ? ' wide' : '') });
  box.innerHTML = `<h2>${esc(title)}</h2>${sub ? `<div class="sub">${sub}</div>` : ''}`;
  const content = el('div');
  if (typeof body === 'string') content.innerHTML = body; else content.appendChild(body);
  box.appendChild(content);
  const foot = el('div', { class: 'foot' });
  (footer || []).forEach(b => foot.appendChild(b));
  const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  foot.appendChild(el('button', { class: 'btn', onclick: close }, 'Close'));
  box.appendChild(foot);
  scrim.appendChild(box);
  scrim.addEventListener('click', e => { if (e.target === scrim) close(); });
  document.addEventListener('keydown', onKey);
  host.appendChild(scrim);
  return { close, content: box };
}

function confirmAction(message, onYes, label = 'Confirm') {
  const m = modal({
    title: label, sub: message, body: '',
    footer: [el('button', { class: 'btn primary', onclick: () => { m.close(); onYes(); } }, label)]
  });
}
