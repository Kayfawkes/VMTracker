/* ==========================================================================
   charts.js — hand-rolled SVG. No chart library: the console must run offline
   from the bundled files alone.
   ========================================================================== */
const C = {
  /* ---------- trend: risk area + open line + new/remediated flow ---------- */
  trend(points, { h = 210, showFlow = true } = {}) {
    if (!points || !points.length) return C.empty('No trend data in this period');
    const w = 1000, padL = 46, padR = 46, padT = 14, padB = 26;
    const iw = w - padL - padR, ih = h - padT - padB;
    const maxRisk = Math.max(1, ...points.map(p => p.total_risk));
    const maxOpen = Math.max(1, ...points.map(p => p.open));
    const x = i => padL + (points.length === 1 ? iw / 2 : (i * iw) / (points.length - 1));
    const yR = v => padT + ih - (v / maxRisk) * ih;
    const yO = v => padT + ih - (v / maxOpen) * ih;

    const riskLine = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${yR(p.total_risk).toFixed(1)}`).join(' ');
    const riskArea = `${riskLine} L${x(points.length - 1).toFixed(1)},${padT + ih} L${x(0).toFixed(1)},${padT + ih} Z`;
    const openLine = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${yO(p.open).toFixed(1)}`).join(' ');

    const grid = [0, 0.25, 0.5, 0.75, 1].map(f => {
      const y = padT + ih - f * ih;
      return `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="var(--line-soft)" stroke-width="1"/>
              <text x="${padL - 7}" y="${y + 3}" fill="var(--muted)" font-size="9" text-anchor="end">${Math.round(maxRisk * f)}</text>
              <text x="${w - padR + 7}" y="${y + 3}" fill="var(--muted)" font-size="9">${Math.round(maxOpen * f)}</text>`;
    }).join('');

    const flow = showFlow ? points.map((p, i) => {
      const bw = Math.max(2, iw / points.length / 3.4);
      const scale = Math.max(1, ...points.map(q => Math.max(q.new, q.remediated)));
      const hn = (p.new / scale) * (ih * 0.28), hr = (p.remediated / scale) * (ih * 0.28);
      return `<rect x="${x(i) - bw - 1}" y="${padT + ih - hn}" width="${bw}" height="${hn}" fill="var(--high)" opacity=".5"/>
              <rect x="${x(i) + 1}" y="${padT + ih - hr}" width="${bw}" height="${hr}" fill="var(--ok)" opacity=".5"/>`;
    }).join('') : '';

    const dots = points.map((p, i) =>
      `<circle cx="${x(i)}" cy="${yO(p.open)}" r="2.6" fill="var(--accent)"/>
       <title>${p.date} — open ${p.open}, critical ${p.critical}, risk ${p.total_risk}, new ${p.new}, remediated ${p.remediated}</title>`
    ).join('');

    const labels = points.map((p, i) => (i % Math.ceil(points.length / 8) === 0 || i === points.length - 1)
      ? `<text x="${x(i)}" y="${h - 7}" fill="var(--muted)" font-size="9" text-anchor="middle">${p.date.slice(5)}</text>` : ''
    ).join('');

    return `<svg viewBox="0 0 ${w} ${h}" style="width:100%;height:auto;max-height:${h}px">
      <defs><linearGradient id="riskgrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--accent)" stop-opacity=".26"/>
        <stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/>
      </linearGradient></defs>
      ${grid}${flow}
      <path d="${riskArea}" fill="url(#riskgrad)"/>
      <path d="${riskLine}" fill="none" stroke="var(--accent)" stroke-width="1.6"/>
      <path d="${openLine}" fill="none" stroke="var(--high)" stroke-width="1.6" stroke-dasharray="4 3"/>
      ${dots}${labels}
    </svg>
    <div class="legend" style="margin-top:8px">
      <span><i style="background:var(--accent)"></i>Total risk score (left axis)</span>
      <span><i style="background:var(--high)"></i>Open findings (right axis)</span>
      ${showFlow ? '<span><i style="background:var(--high);opacity:.5"></i>New in period</span><span><i style="background:var(--ok);opacity:.5"></i>Remediated in period</span>' : ''}
    </div>`;
  },

  /* ---------- sparkline for KPI tiles ---------- */
  spark(values, colour = 'var(--accent)', h = 26) {
    if (!values || values.length < 2) return '';
    const w = 120, max = Math.max(...values, 1), min = Math.min(...values, 0);
    const span = (max - min) || 1;
    const pts = values.map((v, i) =>
      `${i ? 'L' : 'M'}${(i * w / (values.length - 1)).toFixed(1)},${(h - ((v - min) / span) * (h - 4) - 2).toFixed(1)}`).join(' ');
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" style="width:100%;height:auto;max-height:${h}px">
      <path d="${pts}" fill="none" stroke="${colour}" stroke-width="1.4"/></svg>`;
  },

  /* ---------- severity donut ---------- */
  donut(rows, { size = 168, total = null } = {}) {
    const sum = rows.reduce((n, r) => n + r.n, 0);
    if (!sum) return C.empty('Nothing open in this filter');
    const r = size / 2 - 16, cx = size / 2, cy = size / 2, circ = 2 * Math.PI * r;
    let off = 0;
    const arcs = rows.filter(x => x.n).map(x => {
      const len = (x.n / sum) * circ;
      const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
        stroke="${SEV_COLOUR[x.severity]}" stroke-width="15"
        stroke-dasharray="${len.toFixed(2)} ${(circ - len).toFixed(2)}"
        stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})">
        <title>${x.severity}: ${x.n}</title></circle>`;
      off += len;
      return seg;
    }).join('');
    return `<div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
      <svg viewBox="0 0 ${size} ${size}" style="width:${size}px;height:${size}px;flex:none">
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--panel-3)" stroke-width="15"/>
        ${arcs}
        <text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="var(--ink)" font-size="26" font-weight="700">${total ?? sum}</text>
        <text x="${cx}" y="${cy + 15}" text-anchor="middle" fill="var(--muted)" font-size="9" letter-spacing="1.5">OPEN</text>
      </svg>
      <div style="flex:1;min-width:150px">
        ${rows.map(x => `<div style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:11.5px">
          <i style="width:8px;height:8px;border-radius:2px;background:${SEV_COLOUR[x.severity]};display:inline-block"></i>
          <span style="color:var(--ink-dim);min-width:62px">${x.severity}</span>
          <b style="color:var(--ink)">${x.n}</b>
          <span class="mono-dim" style="margin-left:auto">${x.breached ? `<span class="breached">${x.breached} late</span>` : '—'}</span>
        </div>`).join('')}
      </div></div>`;
  },

  /* ---------- horizontal stacked bars by severity ---------- */
  stackedRows(rows, { keyField = 'grp', max = null, limit = 12 } = {}) {
    const data = rows.slice(0, limit);
    if (!data.length) return C.empty('No groups match this filter');
    const top = max || Math.max(1, ...data.map(r => r.open));
    return `<div style="display:flex;flex-direction:column;gap:7px">${data.map(r => {
      const parts = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'],
                     ['low', 'Low'], ['info', 'Info']];
      const width = (r.open / top) * 100;
      return `<div>
        <div style="display:flex;font-size:11px;margin-bottom:3px">
          <span style="color:var(--ink-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r[keyField])}</span>
          <span style="margin-left:auto;color:var(--ink)"><b>${r.open}</b>${r.breached ? ` <span class="breached">(${r.breached} late)</span>` : ''}</span>
        </div>
        <div class="microbar" style="width:${Math.max(width, 1.5)}%;min-width:14px">
          ${parts.map(([k, label]) => r[k] ? `<i style="flex:${r[k]};background:${SEV_COLOUR[label]}"><title>${label}: ${r[k]}</title></i>` : '').join('')}
        </div></div>`;
    }).join('')}</div>`;
  },

  /* ---------- age buckets as vertical stacked columns ---------- */
  ageColumns(buckets, h = 190) {
    const total = buckets.reduce((n, b) => n + b.n, 0);
    if (!total) return C.empty('Nothing open to age');
    const max = Math.max(1, ...buckets.map(b => b.n));
    return `<div style="display:flex;gap:10px;align-items:flex-end;height:${h}px">
      ${buckets.map(b => {
        const colH = (b.n / max) * (h - 40);
        const segs = ['Critical', 'High', 'Medium', 'Low', 'Info']
          .filter(s => b[s]).map(s => `<i style="display:block;flex:${b[s]};background:${SEV_COLOUR[s]}"><title>${s}: ${b[s]}</title></i>`).join('');
        return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:6px">
          <div style="font-size:12px;color:var(--ink);font-weight:700">${b.n}</div>
          <div style="width:100%;height:${Math.max(colH, 3)}px;display:flex;flex-direction:column-reverse;border-radius:2px;overflow:hidden;background:var(--panel-3)">${segs}</div>
          <div style="font-size:9.5px;color:var(--muted);letter-spacing:.08em">${b.bucket}</div>
        </div>`;
      }).join('')}
    </div>
    <div class="legend" style="margin-top:9px">${['Critical', 'High', 'Medium', 'Low']
      .map(s => `<span><i style="background:${SEV_COLOUR[s]}"></i>${s}</span>`).join('')}
      <span style="margin-left:auto">Days since first detected</span></div>`;
  },

  /* ---------- SLA gauge strip: the signature instrument ---------- */
  slaGauges(rows) {
    const live = rows.filter(r => r.open || r.remediated);
    if (!live.length) return C.empty('No SLA activity in this period');
    return `<div style="display:flex;flex-direction:column;gap:12px">${live.map(r => {
      const pct = Math.max(0, Math.min(100, r.within_sla_pct));
      const colour = pct >= 90 ? 'var(--ok)' : pct >= 70 ? 'var(--med)' : 'var(--crit)';
      const ticks = [0, 25, 50, 75, 100].map(t =>
        `<line x1="${t}%" y1="0" x2="${t}%" y2="6" stroke="var(--line)" stroke-width="1"/>`).join('');
      return `<div>
        <div style="display:flex;font-size:11px;margin-bottom:4px;align-items:baseline">
          <span class="pill ${SEV_CLASS[r.severity]}">${r.severity}</span>
          <span class="mono-dim" style="margin-left:8px">target ${r.target_days}d</span>
          <span style="margin-left:auto;color:${colour};font-weight:700">${pct}%</span>
          <span class="mono-dim" style="margin-left:8px">within SLA</span>
        </div>
        <div style="position:relative;height:9px;background:var(--panel-3);border:1px solid var(--line);border-radius:2px;overflow:hidden">
          <div style="position:absolute;inset:0 auto 0 0;width:${pct}%;background:${colour};opacity:.85"></div>
          <svg style="position:absolute;inset:0;width:100%;height:100%" preserveAspectRatio="none">${ticks}</svg>
        </div>
        <div class="mono-dim" style="margin-top:3px;font-size:10px">
          ${r.open} open · ${r.open_breached} past due · ${r.remediated} remediated (${r.remediated_late} late) · MTTR ${r.mttr || '—'}d
        </div></div>`;
    }).join('')}</div>`;
  },

  /* ---------- group x type heat matrix ---------- */
  matrix(m, { limit = 12 } = {}) {
    if (!m || !m.rows || !m.rows.length) return C.empty('No data to cross-tabulate');
    const rows = m.rows.slice(0, limit);
    const max = Math.max(1, ...rows.flatMap(r => m.categories.map(c => r[c] || 0)));
    const cell = v => {
      if (!v) return `<td class="num mono-dim">·</td>`;
      const a = 0.12 + 0.72 * (v / max);
      return `<td class="num" style="background:rgba(47,212,200,${a.toFixed(2)});color:${a > .5 ? '#04140f' : 'var(--ink)'}">${v}</td>`;
    };
    return `<div class="table-wrap" style="max-height:none"><table>
      <thead><tr><th>${esc(m.dimension).replace('_', ' ')}</th>
        ${m.categories.map(c => `<th class="num">${esc(c)}</th>`).join('')}
        <th class="num">Total</th></tr></thead>
      <tbody>${rows.map(r => `<tr><td>${esc(r.group)}</td>
        ${m.categories.map(c => cell(r[c] || 0)).join('')}
        <td class="num"><b>${r.total}</b></td></tr>`).join('')}</tbody>
    </table></div>`;
  },

  empty(msg) { return `<div class="empty">${esc(msg)}</div>`; }
};
