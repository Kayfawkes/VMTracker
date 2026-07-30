/* ==========================================================================
   views.js — page renderers
   ========================================================================== */
const V = {};

/* ---------- shared pieces ---------- */
function kpiTile(label, value, { detail, tone, spark } = {}) {
  return `<div class="card span-2 kpi ${tone || ''}">
    <div class="v">${num(value)}</div>
    <div class="l">${esc(label)}</div>
    ${detail ? `<div class="d">${detail}</div>` : ''}
    ${spark || ''}
  </div>`;
}

function exportButtons(scope) {
  return `<button class="btn sm" data-export="xlsx" data-scope="${scope}">Excel</button>
          <button class="btn sm" data-export="pdf"  data-scope="${scope}">PDF</button>
          <button class="btn sm" data-export="pptx" data-scope="${scope}">PowerPoint</button>
          <button class="btn sm" data-export="csv"  data-scope="${scope}">CSV</button>`;
}

function wireExports(root) {
  $$('[data-export]', root).forEach(b => b.addEventListener('click', async () => {
    const fmt = b.dataset.export, scope = b.dataset.scope || 'executive';
    b.disabled = true;
    try {
      const name = await API.download(`/api/export/${fmt}${qs({ scope })}`);
      toast(`Exported ${name}`);
    } catch (e) { toast(`Export failed: ${e.message}`, 'bad'); }
    finally { b.disabled = false; }
  }));
}

/* ==========================================================================
   Executive view
   ========================================================================== */
V.executive = async function (root) {
  const d = await API.get('/api/dashboard/executive' + qs());
  const k = d.kpis;
  const riskSeries = d.trend.map(t => t.total_risk);
  const openSeries = d.trend.map(t => t.open);
  const first = riskSeries[0] || 0, last = riskSeries[riskSeries.length - 1] || 0;
  const delta = first ? Math.round(((last - first) / first) * 100) : 0;
  const dir = delta < 0 ? '▼' : delta > 0 ? '▲' : '■';
  const dirTone = delta < 0 ? 'good' : delta > 0 ? 'alarm' : '';

  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1>Executive view</h1>
        <div class="sub">Period ${k.period.from} to ${k.period.to} · ${num(k.assets)} hosts in register</div>
      </div>
      <div class="actions">${exportButtons('executive')}</div>
    </div>
    <div id="filterbar"></div>
    <div class="grid">
      <div class="card span-8">
        <h3>Risk score trend <span class="note">${dir} ${Math.abs(delta)}% over period</span></h3>
        ${C.trend(d.trend)}
      </div>
      <div class="grid span-4" style="grid-template-columns:repeat(2,1fr);align-content:start">
        ${kpiTile('Total risk score', last, { tone: dirTone, detail: `${dir} ${Math.abs(delta)}% vs period start`, spark: C.spark(riskSeries) })}
        ${kpiTile('Open findings', k.open, { detail: `${num(k.affected_assets)} hosts affected`, spark: C.spark(openSeries, 'var(--high)') })}
        ${kpiTile('SLA breach rate', k.sla_breach_rate + '%', { tone: k.sla_breach_rate > 25 ? 'alarm' : 'good', detail: `${num(k.open_breached)} open past due` })}
        ${kpiTile('Mean time to remediate', k.mttr_days + 'd', { detail: `critical ${k.mttr_critical || '—'}d · high ${k.mttr_high || '—'}d` })}
        ${kpiTile('Critical open', k.open_critical, { tone: k.open_critical ? 'alarm' : 'good', detail: `${num(k.open_exploitable)} with known exploit` })}
        ${kpiTile('High open', k.open_high, { tone: k.open_high ? 'warn' : 'good', detail: `${num(k.reopened)} reopened` })}
      </div>

      <div class="card span-4">
        <h3>Severity of open findings</h3>
        ${C.donut(d.severity, { total: k.open })}
      </div>
      <div class="card span-4">
        <h3>SLA performance <span class="note">vs configured targets</span></h3>
        ${C.slaGauges(d.sla)}
      </div>
      <div class="card span-4">
        <h3>Ageing of open findings</h3>
        ${C.ageColumns(d.aging)}
      </div>

      <div class="card span-4">
        <h3>By vulnerability type</h3>
        ${C.stackedRows(d.by_category)}
      </div>
      <div class="card span-4">
        <h3>By department</h3>
        ${C.stackedRows(d.by_department)}
      </div>
      <div class="card span-4">
        <h3>By system owner</h3>
        ${C.stackedRows(d.by_owner)}
      </div>

      <div class="card span-6">
        <h3>Flow this period</h3>
        <div class="kv">
          <dt>New findings</dt><dd>${num(k.new_in_period)}</dd>
          <dt>Remediated</dt><dd>${num(k.remediated_in_period)}</dd>
          <dt>Net change</dt><dd style="color:${k.new_in_period > k.remediated_in_period ? 'var(--crit)' : 'var(--ok)'}">
            ${k.new_in_period - k.remediated_in_period > 0 ? '+' : ''}${num(k.new_in_period - k.remediated_in_period)}</dd>
          <dt>Mitigated (awaiting rescan)</dt><dd>${num(k.mitigated)}</dd>
          <dt>Closed (verified gone)</dt><dd>${num(k.closed)}</dd>
          <dt>Risk accepted</dt><dd>${num(k.risk_accepted)}</dd>
          <dt>False positive</dt><dd>${num(k.false_positive)}</dd>
          <dt>Average age open</dt><dd>${num(k.avg_open_age)} days</dd>
        </div>
      </div>
      <div class="card span-6">
        <h3>Most widespread open vulnerabilities</h3>
        <div class="table-wrap" style="max-height:280px"><table>
          <thead><tr><th>Vulnerability</th><th>Sev</th><th class="num">Hosts</th><th class="num">Avg age</th></tr></thead>
          <tbody>${d.top_vulnerabilities.map(v => `<tr>
            <td style="max-width:330px">${esc(v.title)}${v.exploit_available ? ' <span class="tag">exploit</span>' : ''}</td>
            <td>${sevPill(v.severity)}</td>
            <td class="num">${v.assets}</td>
            <td class="num ${v.avg_age > 60 ? 'breached' : ''}">${v.avg_age}d</td></tr>`).join('')}</tbody>
        </table></div>
      </div>
    </div>`;
  renderFilterBar($('#filterbar', root));
  wireExports(root);
};

/* ==========================================================================
   Group dashboards
   ========================================================================== */
const DIM_LABEL = {
  department: 'Department', application: 'Application / System', system_owner: 'System owner',
  environment: 'Environment', category: 'Vulnerability type'
};

V.group = async function (root, dim) {
  const d = await API.get(`/api/dashboard/group/${dim}` + qs());
  const k = d.kpis;
  const label = DIM_LABEL[dim] || dim;
  const worst = d.rows[0];

  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1>${esc(label)} dashboard</h1>
        <div class="sub">${d.rows.length} groups · ${num(k.open)} open findings${worst ? ` · highest exposure: ${esc(worst.grp)}` : ''}</div>
      </div>
      <div class="actions">${exportButtons('group:' + dim)}</div>
    </div>
    <div id="filterbar"></div>
    <div class="grid">
      ${kpiTile('Open findings', k.open, { detail: `${num(k.affected_assets)} hosts` })}
      ${kpiTile('Critical', k.open_critical, { tone: k.open_critical ? 'alarm' : 'good' })}
      ${kpiTile('High', k.open_high, { tone: k.open_high ? 'warn' : 'good' })}
      ${kpiTile('Past SLA', k.open_breached, { tone: k.open_breached ? 'alarm' : 'good', detail: k.sla_breach_rate + '% breach rate' })}
      ${kpiTile('MTTR', k.mttr_days + 'd', { detail: `${num(k.remediated_in_period)} remediated` })}
      ${kpiTile('Exploitable', k.open_exploitable, { tone: k.open_exploitable ? 'alarm' : 'good' })}

      <div class="card span-6">
        <h3>Open findings by ${esc(label.toLowerCase())}</h3>
        ${C.stackedRows(d.rows, { limit: 14 })}
      </div>
      <div class="card span-6">
        <h3>${esc(label)} × vulnerability type</h3>
        ${C.matrix(d.matrix)}
      </div>

      <div class="card span-12">
        <h3>Scorecard <span class="note">click a row to filter the register to that group</span></h3>
        <div class="table-wrap"><table id="scorecard">
          <thead><tr>
            <th>${esc(label)}</th>
            <th class="num">Open</th><th class="num">Crit</th><th class="num">High</th>
            <th class="num">Med</th><th class="num">Low</th>
            <th class="num">Past SLA</th><th class="num">Breach %</th>
            <th class="num">Avg age</th><th class="num">Oldest</th>
            <th class="num">MTTR</th><th class="num">Mitigated</th><th class="num">Closed</th>
            <th class="num">Closure %</th><th class="num">Hosts</th><th class="num">Risk</th>
          </tr></thead>
          <tbody>${d.rows.map(r => `<tr data-grp="${esc(r.grp)}" style="cursor:pointer">
            <td>${esc(r.grp)}</td>
            <td class="num"><b>${r.open}</b></td>
            <td class="num" style="color:${r.critical ? 'var(--crit)' : 'var(--muted)'}">${r.critical}</td>
            <td class="num" style="color:${r.high ? 'var(--high)' : 'var(--muted)'}">${r.high}</td>
            <td class="num">${r.medium}</td><td class="num">${r.low}</td>
            <td class="num ${r.breached ? 'breached' : ''}">${r.breached}</td>
            <td class="num ${r.sla_breach_rate > 25 ? 'breached' : ''}">${r.sla_breach_rate}%</td>
            <td class="num">${r.avg_age}d</td><td class="num">${r.max_age}d</td>
            <td class="num">${r.mttr || '—'}</td>
            <td class="num">${r.mitigated}</td><td class="num">${r.closed}</td>
            <td class="num" style="color:${r.closure_rate > 60 ? 'var(--ok)' : 'var(--ink-dim)'}">${r.closure_rate}%</td>
            <td class="num">${r.assets}</td><td class="num">${num(r.risk)}</td>
          </tr>`).join('')}</tbody>
        </table></div>
      </div>

      <div class="card span-6">
        <h3>Ageing by ${esc(label.toLowerCase())}</h3>
        <div class="table-wrap" style="max-height:320px"><table>
          <thead><tr><th>${esc(label)}</th><th class="num">0-30</th><th class="num">31-60</th>
            <th class="num">61-90</th><th class="num">91-180</th><th class="num">180+</th></tr></thead>
          <tbody>${d.aging.slice(0, 14).map(a => `<tr><td>${esc(a.group)}</td>
            <td class="num">${a['0-30']}</td><td class="num">${a['31-60']}</td>
            <td class="num">${a['61-90']}</td><td class="num" style="color:var(--high)">${a['91-180']}</td>
            <td class="num" style="color:var(--crit)">${a['180+']}</td></tr>`).join('')}</tbody>
        </table></div>
      </div>
      <div class="card span-6">
        <h3>Trend for this filter</h3>
        ${C.trend(d.trend, { h: 190 })}
      </div>
    </div>`;

  renderFilterBar($('#filterbar', root));
  wireExports(root);
  $$('#scorecard tbody tr', root).forEach(tr => tr.addEventListener('click', () => {
    const val = tr.dataset.grp;
    if (val === '(unassigned)') { toast('That group has no owner assigned yet', 'warn'); return; }
    S.filters[dim] = [val];
    go('findings');
  }));
};

/* ==========================================================================
   Findings register
   ========================================================================== */
const COLS = [
  { k: 'hostname', l: 'Host', sort: 'hostname' },
  { k: 'title', l: 'Vulnerability', sort: 'title', wide: true },
  { k: 'category', l: 'Type', sort: 'category' },
  { k: 'severity', l: 'Sev', sort: 'severity' },
  { k: 'status', l: 'Status', sort: 'status', edit: 'select' },
  { k: 'department', l: 'Department', sort: 'department' },
  { k: 'application', l: 'Application', sort: 'application' },
  { k: 'system_owner', l: 'Owner', sort: 'system_owner' },
  { k: 'age_days', l: 'Age', sort: 'age', num: true },
  { k: 'due_date', l: 'Due', sort: 'due_date' },
  { k: 'remediation_owner', l: 'Assigned', edit: 'text' },
  { k: 'ticket_ref', l: 'Ticket', edit: 'text' }
];

V.findings = async function (root) {
  const t = S.table;
  const data = await API.get('/api/findings' + qs({
    sort: t.sort, direction: t.direction, page: t.page, page_size: t.page_size
  }));

  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1>Vulnerability register</h1>
        <div class="sub">${num(data.total)} findings match · page ${data.page} of ${data.pages}
          · click a dashed cell to edit, a row to open the record</div>
      </div>
      <div class="actions">
        <button class="btn sm" id="bulkBtn">Bulk update</button>
        ${exportButtons('executive')}
      </div>
    </div>
    <div id="filterbar"></div>
    <div class="card span-12">
      <div class="table-wrap"><table id="ftable">
        <thead><tr>
          <th style="width:26px"><input type="checkbox" id="selAll"></th>
          ${COLS.map(c => `<th class="${c.num ? 'num' : ''}" ${c.sort ? `data-sort="${c.sort}"` : ''}>
            ${c.l}${t.sort === c.sort ? ` <span class="dir">${t.direction === 'asc' ? '▲' : '▼'}</span>` : ''}</th>`).join('')}
        </tr></thead>
        <tbody>${data.rows.map(rowHtml).join('')}</tbody>
      </table></div>
      <div class="pager">
        <span>${num(data.total)} rows · ${S.selection.size} selected</span>
        <span class="spacer"></span>
        <label style="display:flex;gap:6px;align-items:center;margin:0">Rows
          <select id="psize" style="padding:3px 6px">
            ${[50, 100, 250, 500].map(n => `<option ${n === t.page_size ? 'selected' : ''}>${n}</option>`).join('')}
          </select></label>
        <button class="btn sm" id="prev" ${data.page <= 1 ? 'disabled' : ''}>Previous</button>
        <button class="btn sm" id="next" ${data.page >= data.pages ? 'disabled' : ''}>Next</button>
      </div>
    </div>`;

  renderFilterBar($('#filterbar', root));
  wireExports(root);
  wireTable(root, data);
};

function rowHtml(r) {
  const cell = (c) => {
    let v = r[c.k];
    if (c.k === 'severity') return `<td>${sevPill(v)}</td>`;
    if (c.k === 'status') return `<td class="editable" data-edit="status" data-id="${r.id}">${statusPill(v)}</td>`;
    if (c.k === 'age_days') return `<td class="num ${r.sla_breached ? 'breached' : ''}">${v}d</td>`;
    if (c.k === 'due_date') return `<td class="${r.sla_breached ? 'breached' : ''}">${esc(v || '—')}</td>`;
    if (c.k === 'title') return `<td style="max-width:400px" title="${esc(v)}">${esc(v)}${r.exploit_available ? ' <span class="tag">exploit</span>' : ''}${r.reopened_count ? ` <span class="tag" style="color:var(--crit)">reopened×${r.reopened_count}</span>` : ''}</td>`;
    if (c.edit) return `<td class="editable" data-edit="${c.k}" data-id="${r.id}">${esc(v || '—')}</td>`;
    return `<td>${esc(v || '—')}</td>`;
  };
  return `<tr data-id="${r.id}" class="${S.selection.has(r.id) ? 'sel' : ''}">
    <td><input type="checkbox" class="rowsel" data-id="${r.id}" ${S.selection.has(r.id) ? 'checked' : ''}></td>
    ${COLS.map(cell).join('')}</tr>`;
}

function wireTable(root, data) {
  $$('#ftable thead th[data-sort]', root).forEach(th => th.addEventListener('click', () => {
    const s = th.dataset.sort;
    if (S.table.sort === s) S.table.direction = S.table.direction === 'asc' ? 'desc' : 'asc';
    else { S.table.sort = s; S.table.direction = 'desc'; }
    render();
  }));

  $('#prev', root)?.addEventListener('click', () => { S.table.page--; render(); });
  $('#next', root)?.addEventListener('click', () => { S.table.page++; render(); });
  $('#psize', root)?.addEventListener('change', e => {
    S.table.page_size = parseInt(e.target.value, 10); S.table.page = 1; render();
  });

  $('#selAll', root)?.addEventListener('change', e => {
    data.rows.forEach(r => e.target.checked ? S.selection.add(r.id) : S.selection.delete(r.id));
    render();
  });
  $$('.rowsel', root).forEach(cb => cb.addEventListener('click', e => {
    e.stopPropagation();
    const id = parseInt(cb.dataset.id, 10);
    cb.checked ? S.selection.add(id) : S.selection.delete(id);
    cb.closest('tr').classList.toggle('sel', cb.checked);
    $('.pager span', root).textContent = `${num(data.total)} rows · ${S.selection.size} selected`;
  }));

  $$('#ftable tbody td.editable', root).forEach(td =>
    td.addEventListener('click', e => { e.stopPropagation(); inlineEdit(td); }));

  $$('#ftable tbody tr', root).forEach(tr => tr.addEventListener('click', () =>
    openFinding(parseInt(tr.dataset.id, 10))));

  $('#bulkBtn', root)?.addEventListener('click', () => bulkDialog(data.total));
}

const STATUS_OPTS = ['open', 'mitigated', 'closed', 'risk_accepted', 'false_positive'];

function inlineEdit(td) {
  if ($('input,select', td)) return;
  const field = td.dataset.edit, id = parseInt(td.dataset.id, 10);
  const current = td.textContent.trim().replace('—', '').replace(/\s/g, field === 'status' ? '_' : ' ');
  const input = field === 'status'
    ? el('select', { class: 'inline' }, STATUS_OPTS.map(o =>
        `<option ${o === current ? 'selected' : ''} value="${o}">${o.replace('_', ' ')}</option>`).join(''))
    : el('input', { class: 'inline', value: current === '—' ? '' : current });
  const old = td.innerHTML;
  td.innerHTML = '';
  td.appendChild(input);
  input.focus();
  if (input.select) input.select();

  const commit = async () => {
    const value = input.value.trim();
    if (value === current) { td.innerHTML = old; return; }
    try {
      await API.patch(`/api/findings/${id}`, { [field]: value });
      toast(`Updated ${field.replace('_', ' ')} on finding ${id}`);
      td.innerHTML = field === 'status' ? statusPill(value) : esc(value || '—');
      if (field === 'status') refreshStatus();
    } catch (e) { toast(`Could not save: ${e.message}`, 'bad'); td.innerHTML = old; }
  };
  input.addEventListener('blur', commit);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
    if (e.key === 'Escape') { td.innerHTML = old; }
  });
  if (field === 'status') input.addEventListener('change', () => input.blur());
}

/* ---------- finding detail ---------- */
async function openFinding(id) {
  const f = await API.get(`/api/findings/${id}`);
  const body = el('div');
  body.innerHTML = `
    <div class="grid" style="grid-template-columns:repeat(2,1fr)">
      <div>
        <h3 style="color:var(--muted);font-size:10.5px;margin:0 0 8px">Finding</h3>
        <dl class="kv">
          <dt>Vulnerability</dt><dd>${esc(f.title)}</dd>
          <dt>Plugin / QID</dt><dd>${esc(f.plugin_id || '—')}</dd>
          <dt>Type</dt><dd>${esc(f.category)} / ${esc(f.subcategory || '—')}
            <span class="tag">(${esc(f.classified_by)}, confidence ${f.classify_confidence})</span></dd>
          <dt>CVE</dt><dd>${esc(f.cve || '—')}</dd>
          <dt>Severity</dt><dd>${sevPill(f.severity)} CVSS ${f.cvss_score ?? '—'} · risk ${f.risk_score}</dd>
          <dt>Exploit known</dt><dd>${f.exploit_available ? '<span style="color:var(--crit)">yes</span>' : 'no'}</dd>
          <dt>Port / service</dt><dd>${esc(f.port)}/${esc(f.protocol || '—')} ${esc(f.service || '')}</dd>
          <dt>Status</dt><dd>${statusPill(f.status)}${f.reopened_count ? ` reopened ${f.reopened_count}×` : ''}</dd>
          <dt>First detected</dt><dd>${esc(f.first_detected)}</dd>
          <dt>Last detected</dt><dd>${esc(f.last_detected)}</dd>
          <dt>Age</dt><dd class="${f.sla_breached ? 'breached' : ''}">${f.age_days} days${f.sla_breached ? ' — past SLA' : ''}</dd>
          <dt>Due date</dt><dd>${esc(f.due_date || '—')} (${f.sla_days}d SLA)</dd>
          <dt>Mitigated / closed</dt><dd>${esc(f.mitigated_date || '—')} / ${esc(f.closed_date || '—')}</dd>
        </dl>
      </div>
      <div>
        <h3 style="color:var(--muted);font-size:10.5px;margin:0 0 8px">Host and ownership</h3>
        <dl class="kv">
          <dt>Hostname</dt><dd>${esc(f.hostname)}</dd>
          <dt>IP address</dt><dd>${esc(f.ip_address || '—')}</dd>
          <dt>Operating system</dt><dd>${esc(f.os_name || '—')} <span class="tag">${esc(f.os_family || '')}</span></dd>
          <dt>Department</dt><dd>${esc(f.department || '—')}</dd>
          <dt>Application</dt><dd>${esc(f.application || '—')}</dd>
          <dt>System owner</dt><dd>${esc(f.system_owner || '—')} ${esc(f.owner_email || '')}</dd>
          <dt>Environment</dt><dd>${esc(f.environment || '—')} · ${esc(f.criticality || '—')} criticality</dd>
          <dt>Location</dt><dd>${esc(f.location || '—')}</dd>
        </dl>
        <div class="hr"></div>
        <div class="form-grid">
          <div><label>Status</label><select id="dStatus">${STATUS_OPTS.map(o =>
            `<option value="${o}" ${o === f.status ? 'selected' : ''}>${o.replace('_', ' ')}</option>`).join('')}</select></div>
          <div><label>Assigned to</label><input id="dOwner" value="${esc(f.remediation_owner || '')}"></div>
          <div><label>Ticket / change ref</label><input id="dTicket" value="${esc(f.ticket_ref || '')}"></div>
          <div><label>Due date override</label><input id="dDue" type="date" value="${esc((f.due_date || '').slice(0, 10))}"></div>
          <div class="full"><label>Notes</label><textarea id="dNotes" rows="2">${esc(f.notes || '')}</textarea></div>
        </div>
      </div>
    </div>
    ${f.solution ? `<div class="hr"></div><h3 style="color:var(--muted);font-size:10.5px;margin:0 0 6px">Vendor remediation</h3>
      <div style="font-family:var(--sans);font-size:12px;color:var(--ink-dim);line-height:1.6">${esc(f.solution)}</div>` : ''}
    <div class="hr"></div>
    <h3 style="color:var(--muted);font-size:10.5px;margin:0 0 6px">History</h3>
    <div class="timeline">${(f.events || []).map(e => `<div class="ev">
      <b>${esc(e.event_type)}</b> ${e.from_status ? `${esc(e.from_status)} → ${esc(e.to_status)}` : esc(e.to_status || '')}
      ${e.note ? `<div class="mono-dim">${esc(e.note)}</div>` : ''}
      <div class="when">${esc(e.created_at)} · ${esc(e.actor || 'system')}</div></div>`).join('') || '<div class="ev mono-dim">No events recorded</div>'}</div>`;

  const save = el('button', { class: 'btn primary' }, 'Save changes');
  const m = modal({
    title: `Finding ${f.id}`, sub: esc(f.hostname) + ' — ' + esc(f.title), body, wide: true,
    footer: [save]
  });
  save.addEventListener('click', async () => {
    try {
      await API.patch(`/api/findings/${f.id}`, {
        status: $('#dStatus', body).value,
        remediation_owner: $('#dOwner', body).value,
        ticket_ref: $('#dTicket', body).value,
        due_date: $('#dDue', body).value || null,
        notes: $('#dNotes', body).value
      });
      toast(`Saved finding ${f.id}`);
      m.close();
      render();
    } catch (e) { toast(`Could not save: ${e.message}`, 'bad'); }
  });
}

/* ---------- bulk update ---------- */
function bulkDialog(matchTotal) {
  const count = S.selection.size;
  const body = el('div');
  body.innerHTML = `
    <div class="form-grid">
      <div class="full"><label>Apply to</label>
        <select id="bScope">
          <option value="sel" ${count ? '' : 'disabled'}>${count} selected row${count === 1 ? '' : 's'}</option>
          <option value="all" ${count ? '' : 'selected'}>All ${num(matchTotal)} rows matching the current filter</option>
        </select></div>
      <div><label>Set status</label><select id="bStatus"><option value="">— leave unchanged —</option>
        ${STATUS_OPTS.map(o => `<option value="${o}">${o.replace('_', ' ')}</option>`).join('')}</select></div>
      <div><label>Assign to</label><input id="bOwner" placeholder="leave blank to keep"></div>
      <div><label>Ticket / change ref</label><input id="bTicket" placeholder="leave blank to keep"></div>
      <div><label>Notes</label><input id="bNotes" placeholder="leave blank to keep"></div>
    </div>`;
  const apply = el('button', { class: 'btn primary' }, 'Apply update');
  const m = modal({
    title: 'Bulk update',
    sub: 'Every change is written to the audit log against your username.',
    body, footer: [apply]
  });
  apply.addEventListener('click', async () => {
    const fields = {};
    const st = $('#bStatus', body).value; if (st) fields.status = st;
    const ow = $('#bOwner', body).value.trim(); if (ow) fields.remediation_owner = ow;
    const tk = $('#bTicket', body).value.trim(); if (tk) fields.ticket_ref = tk;
    const nt = $('#bNotes', body).value.trim(); if (nt) fields.notes = nt;
    if (!Object.keys(fields).length) { toast('Nothing to change — set at least one field', 'warn'); return; }
    const payload = { fields };
    if ($('#bScope', body).value === 'sel') payload.ids = Array.from(S.selection);
    else payload.filters = S.filters;
    apply.disabled = true;
    try {
      const res = await API.post('/api/findings/bulk', payload);
      toast(`Updated ${res.updated} findings`);
      S.selection.clear();
      m.close();
      render();
    } catch (e) { toast(`Bulk update failed: ${e.message}`, 'bad'); apply.disabled = false; }
  });
}

/* ==========================================================================
   Assets / ownership
   ========================================================================== */
const ASSET_EDIT = ['hostname', 'ip_address', 'department', 'application', 'system_owner',
  'owner_email', 'environment', 'criticality', 'location', 'business_unit'];

V.assets = async function (root) {
  const rows = await API.get('/api/assets' + qs());
  const unowned = rows.filter(r => !r.department || !r.application || !r.system_owner).length;

  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1>Hosts and ownership</h1>
        <div class="sub">${rows.length} hosts · ${unowned} missing ownership data ·
          edits are pinned so scan imports never overwrite them</div>
      </div>
      <div class="actions"><button class="btn sm" id="assignBtn">Bulk assign ownership</button></div>
    </div>
    <div id="filterbar"></div>
    <div class="card span-12">
      <div class="table-wrap"><table id="atable">
        <thead><tr>
          <th>Hostname</th><th>IP</th><th>Operating system</th><th>Department</th>
          <th>Application</th><th>System owner</th><th>Environment</th><th>Criticality</th>
          <th>Location</th><th class="num">Open</th><th class="num">Crit+High</th>
          <th class="num">Risk</th><th>Pinned</th>
        </tr></thead>
        <tbody>${rows.map(a => {
          const pinned = JSON.parse(a.manual_fields || '[]');
          const ed = (k) => `<td class="editable" data-aedit="${k}" data-id="${a.id}">${esc(a[k] || '—')}</td>`;
          return `<tr>
            ${ed('hostname')}${ed('ip_address')}
            <td title="${esc(a.os_name)}">${esc(a.os_family || '—')}</td>
            ${ed('department')}${ed('application')}${ed('system_owner')}
            ${ed('environment')}${ed('criticality')}${ed('location')}
            <td class="num"><b>${a.open_findings || 0}</b></td>
            <td class="num" style="color:${a.open_high ? 'var(--crit)' : 'var(--muted)'}">${a.open_high || 0}</td>
            <td class="num">${a.risk_score || 0}</td>
            <td class="tag">${pinned.length ? pinned.join(', ') : '—'}</td>
          </tr>`;
        }).join('')}</tbody>
      </table></div>
    </div>`;

  renderFilterBar($('#filterbar', root));
  $$('#atable td.editable', root).forEach(td => td.addEventListener('click', () => {
    if ($('input', td)) return;
    const field = td.dataset.aedit, id = parseInt(td.dataset.id, 10);
    const cur = td.textContent.trim() === '—' ? '' : td.textContent.trim();
    const input = el('input', { class: 'inline', value: cur });
    const old = td.innerHTML;
    td.innerHTML = ''; td.appendChild(input); input.focus(); input.select();
    const commit = async () => {
      const v = input.value.trim();
      if (v === cur) { td.innerHTML = old; return; }
      try {
        await API.patch(`/api/assets/${id}`, { [field]: v });
        toast(`Updated ${field.replace('_', ' ')} — pinned against future imports`);
        render();
      } catch (e) { toast(`Could not save: ${e.message}`, 'bad'); td.innerHTML = old; }
    };
    input.addEventListener('blur', commit);
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') input.blur();
      if (e.key === 'Escape') td.innerHTML = old;
    });
  }));

  $('#assignBtn', root).addEventListener('click', () => {
    const body = el('div');
    body.innerHTML = `<div class="form-grid">
      ${ASSET_EDIT.slice(2).map(k => `<div><label>${k.replace('_', ' ')}</label>
        <input data-bk="${k}" placeholder="leave blank to keep"></div>`).join('')}
      <div class="full mono-dim">Applies to every host matching the current filter
        (${rows.length} host${rows.length === 1 ? '' : 's'}).</div>
    </div>`;
    const go2 = el('button', { class: 'btn primary' }, 'Assign ownership');
    const m = modal({ title: 'Bulk assign ownership', sub: 'Useful after onboarding a new department or renaming an application.', body, footer: [go2] });
    go2.addEventListener('click', async () => {
      const fields = {};
      $$('[data-bk]', body).forEach(i => { if (i.value.trim()) fields[i.dataset.bk] = i.value.trim(); });
      if (!Object.keys(fields).length) { toast('Fill at least one field', 'warn'); return; }
      go2.disabled = true;
      try {
        const res = await API.post('/api/assets/bulk', { filters: S.filters, fields });
        toast(`Updated ${res.updated} hosts`);
        m.close(); render();
      } catch (e) { toast(`Failed: ${e.message}`, 'bad'); go2.disabled = false; }
    });
  });
};

/* ==========================================================================
   Imports
   ========================================================================== */
V.imports = async function (root) {
  const scans = await API.get('/api/scans');
  root.innerHTML = `
    <div class="page-head">
      <div><h1>Scan imports</h1>
      <div class="sub">Weekly scans, mitigation evidence and the watch folder</div></div>
    </div>
    <div class="grid">
      <div class="card span-5">
        <h3>Load a file</h3>
        <div class="drop" id="drop">
          Drop a scan export here, or click to choose<br>
          <span class="mono-dim">CSV · TSV · XLSX · JSON · .nessus</span>
        </div>
        <input type="file" id="file" style="display:none">
        <div class="form-grid" style="margin-top:12px">
          <div><label>File type</label><select id="iKind">
            <option value="scan">Vulnerability scan</option>
            <option value="mitigation">Mitigation / remediation evidence</option>
          </select></div>
          <div><label>Scan date</label><input id="iDate" type="date"></div>
          <div class="full"><label>Label (optional)</label>
            <input id="iName" placeholder="e.g. Weekly scan — week 31, Prod servers"></div>
          <div class="full mono-dim">
            <label style="display:flex;gap:7px;align-items:center;text-transform:none;letter-spacing:0">
              <input type="checkbox" id="iClose" checked style="width:auto">
              Close findings absent from this scan (only for hosts in the file)
            </label>
          </div>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px">
          <button class="btn" id="iPreview" disabled>Preview mapping</button>
          <button class="btn primary" id="iGo" disabled>Import</button>
        </div>
        <div id="iOut" style="margin-top:12px"></div>
      </div>

      <div class="card span-7">
        <h3>Import history</h3>
        <div class="table-wrap" style="max-height:520px"><table>
          <thead><tr><th>#</th><th>Label</th><th>Kind</th><th>Scanner</th><th>Scan date</th>
            <th class="num">Rows</th><th class="num">New</th><th class="num">Updated</th>
            <th class="num">Reopened</th><th class="num">Closed</th><th>Status</th><th>By</th></tr></thead>
          <tbody>${scans.length ? scans.map(s => `<tr>
            <td>${s.id}</td><td title="${esc(s.filename)}">${esc(s.name || s.filename)}</td>
            <td>${esc(s.kind)}</td><td>${esc(s.scanner || '—')}</td><td>${esc(s.scan_date || '—')}</td>
            <td class="num">${num(s.rows_total)}</td><td class="num">${num(s.findings_new)}</td>
            <td class="num">${num(s.findings_updated)}</td><td class="num">${num(s.findings_reopened)}</td>
            <td class="num">${num(s.findings_closed)}</td>
            <td>${s.status === 'complete' ? '<span class="pill st-closed">complete</span>'
              : `<span class="pill st-reopened" title="${esc(s.message || '')}">${esc(s.status)}</span>`}</td>
            <td class="tag">${esc(s.imported_by || '—')}</td></tr>`).join('')
            : `<tr><td colspan="12"><div class="empty"><b>No scans loaded yet</b>
                 Load your first weekly export to start tracking.</div></td></tr>`}</tbody>
        </table></div>
      </div>
    </div>`;

  const fileInput = $('#file', root), drop = $('#drop', root);
  let chosen = null;
  const setFile = (f) => {
    chosen = f;
    drop.innerHTML = `<b style="color:var(--accent)">${esc(f.name)}</b><br>
      <span class="mono-dim">${(f.size / 1024).toFixed(0)} KB — ready</span>`;
    $('#iPreview', root).disabled = false;
    $('#iGo', root).disabled = false;
  };
  drop.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', e => e.target.files[0] && setFile(e.target.files[0]));
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.add('hot');
  }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.remove('hot');
  }));
  drop.addEventListener('drop', e => e.dataTransfer.files[0] && setFile(e.dataTransfer.files[0]));

  const send = async (dry) => {
    const fd = new FormData();
    fd.append('file', chosen);
    fd.append('kind', $('#iKind', root).value);
    fd.append('auto_close', $('#iClose', root).checked ? 'true' : 'false');
    fd.append('dry_run', dry ? 'true' : 'false');
    if ($('#iDate', root).value) fd.append('scan_date', $('#iDate', root).value);
    if ($('#iName', root).value) fd.append('name', $('#iName', root).value);
    const out = $('#iOut', root);
    try {
      const res = await API.upload('/api/scans/import', fd);
      if (dry) {
        const mapped = Object.entries(res.detected_columns);
        out.innerHTML = `<div class="mono-dim" style="margin-bottom:8px">
            Scan date read as <b style="color:var(--ink)">${esc(res.scan_date)}</b> ·
            ${res.rows_total} rows · ${mapped.length} columns recognised</div>
          <div class="table-wrap" style="max-height:200px"><table>
            <thead><tr><th>Your column</th><th>Mapped to</th></tr></thead>
            <tbody>${mapped.map(([h, f]) => `<tr><td>${esc(h)}</td><td style="color:var(--accent)">${esc(f)}</td></tr>`).join('')}</tbody>
          </table></div>
          ${res.unmapped_columns.length ? `<div class="mono-dim" style="margin-top:8px">Ignored: ${res.unmapped_columns.map(esc).join(', ')}</div>` : ''}
          <div class="mono-dim" style="margin-top:8px">Sample classification:</div>
          <div class="table-wrap" style="max-height:180px"><table>
            <thead><tr><th>Host</th><th>Vulnerability</th><th>Sev</th><th>Type</th></tr></thead>
            <tbody>${res.preview.slice(0, 12).map(p => `<tr><td>${esc(p.hostname)}</td>
              <td style="max-width:280px">${esc(p.title)}</td><td>${sevPill(p.severity)}</td>
              <td>${esc(p.category)} / ${esc(p.subcategory)}</td></tr>`).join('')}</tbody>
          </table></div>`;
      } else {
        out.innerHTML = `<div class="mono-dim">Imported: <b style="color:var(--ok)">${res.rows_imported}</b> rows ·
          ${res.findings_new} new · ${res.findings_updated} updated ·
          ${res.findings_reopened} reopened · ${res.findings_closed} closed ·
          ${res.assets_touched} hosts</div>`;
        toast(`Import complete — ${res.findings_new} new, ${res.findings_closed} closed`);
        refreshStatus();
        setTimeout(render, 900);
      }
    } catch (e) {
      out.innerHTML = `<div style="color:var(--crit);font-size:11.5px">${esc(e.message)}</div>`;
      toast('Import failed', 'bad');
    }
  };
  $('#iPreview', root).addEventListener('click', () => send(true));
  $('#iGo', root).addEventListener('click', () => send(false));
};

/* ==========================================================================
   Admin
   ========================================================================== */
V.admin = async function (root) {
  const tab = S.adminTab || 'sla';
  root.innerHTML = `
    <div class="page-head"><div><h1>Settings</h1>
      <div class="sub">Remediation targets, the classification engine, users and background jobs</div></div></div>
    <div class="tabs">
      ${[['sla', 'SLA targets'], ['rules', 'Classification rules'], ['users', 'Users'],
         ['jobs', 'Background jobs'], ['audit', 'Audit log']]
        .map(([k, l]) => `<div class="tab ${tab === k ? 'active' : ''}" data-atab="${k}">${l}</div>`).join('')}
    </div>
    <div id="atab"></div>`;
  $$('[data-atab]', root).forEach(t => t.addEventListener('click', () => {
    S.adminTab = t.dataset.atab; render();
  }));
  const host = $('#atab', root);
  if (tab === 'sla') await adminSla(host);
  if (tab === 'rules') await adminRules(host);
  if (tab === 'users') await adminUsers(host);
  if (tab === 'jobs') await adminJobs(host);
  if (tab === 'audit') await adminAudit(host);
};

async function adminSla(host) {
  const policy = await API.get('/api/sla');
  const perf = await API.get('/api/dashboard/sla' + qs());
  const byS = Object.fromEntries(perf.map(p => [p.severity, p]));
  host.innerHTML = `<div class="grid">
    <div class="card span-5">
      <h3>Remediation targets</h3>
      <div class="mono-dim" style="margin-bottom:12px">Days allowed from first detection to
        closure, per severity. Changing a target recomputes every due date and breach flag.</div>
      ${policy.map(p => `<div style="display:flex;gap:10px;align-items:center;margin-bottom:9px">
        <span class="pill ${SEV_CLASS[p.severity]}" style="min-width:74px;text-align:center">${p.severity}</span>
        <input type="number" min="1" max="3650" value="${p.days}" data-sla="${p.severity}" style="width:88px">
        <span class="mono-dim">days</span>
        <span class="mono-dim" style="margin-left:auto">${byS[p.severity] ? `${byS[p.severity].within_sla_pct}% within target` : ''}</span>
      </div>`).join('')}
      <button class="btn primary" id="slaSave" style="margin-top:8px">Save targets</button>
    </div>
    <div class="card span-7">
      <h3>Current performance against targets</h3>
      ${C.slaGauges(perf)}
    </div>
  </div>`;
  $('#slaSave', host).addEventListener('click', async () => {
    const payload = {};
    $$('[data-sla]', host).forEach(i => payload[i.dataset.sla] = parseInt(i.value, 10));
    try {
      await API.put('/api/sla', payload);
      toast('SLA targets saved — due dates and breach flags recomputed');
      render();
    } catch (e) { toast(`Could not save: ${e.message}`, 'bad'); }
  });
}

async function adminRules(host) {
  const rules = await API.get('/api/rules');
  const cats = ['OS', 'Database', 'Application', 'Web/Middleware', 'Network', 'Virtualization',
    'Security', 'Cloud/Container', 'Crypto/PKI', 'Configuration', 'Other'];
  host.innerHTML = `<div class="grid">
    <div class="card span-4">
      <h3>Add a rule</h3>
      <div class="mono-dim" style="margin-bottom:10px">Use this for in-house systems the
        scanner names in a way the built-in rules don't recognise. Lower priority wins.</div>
      <div style="display:flex;flex-direction:column;gap:9px">
        <div><label>Rule name</label><input id="rName" placeholder="e.g. Acme Ledger (in-house)"></div>
        <div><label>Match pattern (regular expression)</label><input id="rPat" placeholder="\\backme\\s+ledger\\b"></div>
        <div><label>Classify as</label><select id="rCat">${cats.map(c => `<option>${c}</option>`).join('')}</select></div>
        <div><label>Sub-type</label><input id="rSub" placeholder="e.g. Core Banking Platform"></div>
        <div><label>Priority</label><input id="rPrio" type="number" value="1" min="1" max="999"></div>
        <div><label>Test against a title</label><input id="rTest" placeholder="paste a vulnerability name"></div>
        <div style="display:flex;gap:8px">
          <button class="btn" id="rTestGo">Test</button>
          <button class="btn primary" id="rAdd">Add rule</button>
        </div>
        <div id="rOut" class="mono-dim"></div>
      </div>
      <div class="hr"></div>
      <button class="btn" id="rReclass">Re-run classification over all history</button>
    </div>
    <div class="card span-8">
      <h3>Active rules <span class="note">${rules.length} loaded, in evaluation order</span></h3>
      <div class="table-wrap" style="max-height:560px"><table>
        <thead><tr><th class="num">Prio</th><th>Name</th><th>Type</th><th>Sub-type</th>
          <th class="num">Hits</th><th>Source</th><th></th></tr></thead>
        <tbody>${rules.map(r => `<tr style="${r.enabled ? '' : 'opacity:.45'}">
          <td class="num">${r.priority}</td><td>${esc(r.name)}</td>
          <td style="color:var(--accent)">${esc(r.category)}</td><td>${esc(r.subcategory || '—')}</td>
          <td class="num">${num(r.hits, '0')}</td>
          <td class="tag">${r.builtin ? 'built-in' : 'custom'}</td>
          <td><button class="btn sm" data-toggle="${r.id}" data-on="${r.enabled}">
            ${r.enabled ? 'Disable' : 'Enable'}</button></td></tr>`).join('')}</tbody>
      </table></div>
    </div>
  </div>`;

  const testRule = async () => {
    const title = $('#rTest', host).value.trim();
    if (!title) { toast('Paste a vulnerability name to test', 'warn'); return; }
    const res = await API.post('/api/rules/test', { title });
    $('#rOut', host).innerHTML = `Classified as <b style="color:var(--accent)">${esc(res.category)}
      / ${esc(res.subcategory)}</b> by ${esc(res.classified_by)}${res.rule ? ` (${esc(res.rule)})` : ''},
      confidence ${res.confidence}`;
  };
  $('#rTestGo', host).addEventListener('click', testRule);
  $('#rAdd', host).addEventListener('click', async () => {
    try {
      await API.post('/api/rules', {
        name: $('#rName', host).value || 'custom rule',
        pattern: $('#rPat', host).value,
        category: $('#rCat', host).value,
        subcategory: $('#rSub', host).value,
        priority: parseInt($('#rPrio', host).value, 10) || 1
      });
      toast('Rule added — it applies to the next import, or re-run classification now');
      render();
    } catch (e) { toast(e.message, 'bad'); }
  });
  $('#rReclass', host).addEventListener('click', () => confirmAction(
    'Re-classify every stored vulnerability using the current rule set?',
    async () => {
      const res = await API.post('/api/rules/reclassify', {});
      toast(`Re-classified ${res.reclassified} vulnerabilities`);
      render();
    }, 'Re-classify'));
  $$('[data-toggle]', host).forEach(b => b.addEventListener('click', async () => {
    await API.patch(`/api/rules/${b.dataset.toggle}`, { enabled: b.dataset.on === '1' ? 0 : 1 });
    render();
  }));
}

async function adminUsers(host) {
  if (S.user.role !== 'admin') {
    host.innerHTML = C.empty('Only administrators can manage user accounts.');
    return;
  }
  const users = await API.get('/api/users');
  host.innerHTML = `<div class="grid">
    <div class="card span-4">
      <h3>Add a user</h3>
      <div style="display:flex;flex-direction:column;gap:9px">
        <div><label>Username</label><input id="uName"></div>
        <div><label>Full name</label><input id="uFull"></div>
        <div><label>Email</label><input id="uMail"></div>
        <div><label>Role</label><select id="uRole">
          <option value="viewer">viewer — read and export</option>
          <option value="analyst">analyst — import and edit</option>
          <option value="admin">admin — full control</option>
        </select></div>
        <div><label>Temporary password</label><input id="uPass" type="text" placeholder="minimum 8 characters"></div>
        <button class="btn primary" id="uAdd">Create user</button>
      </div>
    </div>
    <div class="card span-8">
      <h3>Accounts</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Active</th>
          <th>Last sign-in</th><th></th></tr></thead>
        <tbody>${users.map(u => `<tr>
          <td>${esc(u.username)}${u.must_change ? ' <span class="tag">must change password</span>' : ''}</td>
          <td>${esc(u.full_name || '—')}</td>
          <td><select data-role="${u.id}" style="padding:2px 5px">
            ${['viewer', 'analyst', 'admin'].map(r => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}
          </select></td>
          <td>${u.is_active ? '<span class="pill st-closed">yes</span>' : '<span class="pill st-false_positive">no</span>'}</td>
          <td class="tag">${esc(u.last_login || 'never')}</td>
          <td><button class="btn sm" data-toggleu="${u.id}" data-on="${u.is_active}">
            ${u.is_active ? 'Deactivate' : 'Reactivate'}</button></td></tr>`).join('')}</tbody>
      </table></div>
    </div>
  </div>`;
  $('#uAdd', host).addEventListener('click', async () => {
    try {
      await API.post('/api/users', {
        username: $('#uName', host).value, password: $('#uPass', host).value,
        full_name: $('#uFull', host).value, email: $('#uMail', host).value,
        role: $('#uRole', host).value
      });
      toast('User created — they must change the password at first sign-in');
      render();
    } catch (e) { toast(e.message, 'bad'); }
  });
  $$('[data-role]', host).forEach(s => s.addEventListener('change', async () => {
    await API.patch(`/api/users/${s.dataset.role}`, { role: s.value });
    toast('Role updated');
  }));
  $$('[data-toggleu]', host).forEach(b => b.addEventListener('click', async () => {
    try {
      await API.patch(`/api/users/${b.dataset.toggleu}`, { is_active: b.dataset.on === '1' ? 0 : 1 });
      render();
    } catch (e) { toast(e.message, 'bad'); }
  }));
}

async function adminJobs(host) {
  if (S.user.role !== 'admin') { host.innerHTML = C.empty('Administrators only.'); return; }
  const st = await API.get('/api/system/jobs');
  host.innerHTML = `<div class="grid">
    <div class="card span-5">
      <h3>Scheduled jobs</h3>
      <div class="mono-dim" style="margin-bottom:10px">Scheduler ${st.running ? 'running' : 'stopped'}</div>
      <table><thead><tr><th>Job</th><th>Next run</th><th></th></tr></thead>
      <tbody>${st.jobs.map(j => `<tr><td>${esc(j.id)}</td>
        <td class="tag">${esc((j.next_run || '—').replace('T', ' ').slice(0, 16))}</td>
        <td><button class="btn sm" data-run="${j.id}">Run now</button></td></tr>`).join('')}</tbody></table>
      <div class="hr"></div>
      <h3>Watch folder</h3>
      <div class="mono-dim">Drop scan exports here and they are imported within 5 minutes.
        Files whose name contains "mitig" or "remedi" are treated as mitigation evidence.</div>
      <div style="margin-top:8px;color:var(--accent);font-size:11px;word-break:break-all">${esc(st.watch_folder)}</div>
    </div>
    <div class="card span-7">
      <h3>Recent job runs</h3>
      <div class="table-wrap" style="max-height:420px"><table>
        <thead><tr><th>Job</th><th>Started</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>${st.recent.length ? st.recent.map(r => `<tr><td>${esc(r.job)}</td>
          <td class="tag">${esc((r.started_at || '').replace('T', ' '))}</td>
          <td>${r.status === 'ok' ? '<span class="pill st-closed">ok</span>' : '<span class="pill st-reopened">failed</span>'}</td>
          <td class="wrap" style="max-width:420px">${esc((r.detail || '—').slice(0, 220))}</td></tr>`).join('')
          : '<tr><td colspan="4"><div class="empty">No job runs recorded yet</div></td></tr>'}</tbody>
      </table></div>
    </div>
  </div>`;
  $$('[data-run]', host).forEach(b => b.addEventListener('click', async () => {
    b.disabled = true;
    const res = await API.post(`/api/system/jobs/${b.dataset.run}/run`, {});
    toast(`${b.dataset.run}: ${res.status} ${res.detail ? '— ' + res.detail.slice(0, 90) : ''}`,
      res.status === 'ok' ? '' : 'bad');
    render();
  }));
}

async function adminAudit(host) {
  const log = await API.get('/api/audit?limit=300');
  host.innerHTML = `<div class="card span-12">
    <h3>Audit log <span class="note">every edit, export and setting change</span></h3>
    <div class="table-wrap"><table>
      <thead><tr><th>When</th><th>User</th><th>Entity</th><th class="num">ID</th>
        <th>Field</th><th>From</th><th>To</th><th>Source</th></tr></thead>
      <tbody>${log.map(a => `<tr>
        <td class="tag">${esc((a.created_at || '').replace('T', ' '))}</td>
        <td style="color:var(--accent)">${esc(a.actor)}</td><td>${esc(a.entity)}</td>
        <td class="num">${a.entity_id || '—'}</td><td>${esc(a.field)}</td>
        <td class="tag">${esc((a.old_value || '—').slice(0, 40))}</td>
        <td>${esc((a.new_value || '—').slice(0, 60))}</td>
        <td class="tag">${esc(a.source || '—')}</td></tr>`).join('')}</tbody>
    </table></div></div>`;
}
