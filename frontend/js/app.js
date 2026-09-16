/* ============================================================
   HAWK AI — Dashboard logic
   Sections: 1 state · 2 helpers · 3 api · 4 stats · 5 overview
             6 list · 7 detail · 8 chat · 9 shortcuts · 10 init
   ============================================================ */

/* ---------- 1. State ---------- */
const API = '';                  // same-origin. Change to 'http://localhost:8000' if serving separately.
const S = {
  incidents: [],                 // everything from /api/alerts
  filtered: [],                  // after search + severity filter
  stats: null,                   // from /api/stats
  selectedId: null,
  sev: 'all',
  query: '',
  tab: 'overview',               // detail panel tab
  status: {},                    // incidentKey -> 'new' | 'investigating' | 'resolved'
  reports: {},                   // incidentKey -> report object (cached)
  busy: false,
};

const SEV_COLOR = { critical: '--rd', high: '--am', medium: '--vi', low: '--gy' };

/* ---------- 2. Helpers ---------- */
const $ = id => document.getElementById(id);
const cssVar = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/** Escape user/server text before putting it into innerHTML. */
function esc(str) {
  return String(str === null || str === undefined ? '' : str).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Incidents are re-numbered on every fetch, so identify them by content instead of id. */
const keyOf = inc => `${inc.src_ip}|${inc.user || ''}|${inc.first_seen}`;

const fmtTime = iso => String(iso).replace('T', ' ').split('.')[0];
function fmtClock(iso) {
  const part = String(iso).split('T')[1];
  return part ? part.split('.')[0].slice(0, 5) : '';
}

function toast(title, sub, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<div class="tt">${esc(title)}</div>${sub ? `<div class="ts">${esc(sub)}</div>` : ''}`;
  $('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 260); }, 3200);
}

/** Count up to a number so stat changes are noticeable. */
function animateNum(el, to) {
  const from = parseInt(el.textContent, 10) || 0;
  if (from === to) return;
  const steps = 18, diff = to - from;
  let i = 0;
  clearInterval(el._t);
  el._t = setInterval(() => {
    i++;
    el.textContent = Math.round(from + diff * (1 - Math.pow(1 - i / steps, 3)));
    if (i >= steps) { clearInterval(el._t); el.textContent = to; }
  }, 22);
}

/* ---------- 3. API ---------- */
async function api(path, opts) {
  const res = await fetch(`${API}${path}`, opts);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.status === 204 ? null : res.json();
}

async function refreshStatus() {
  try {
    const d = await api('/api/status');
    $('llmDot').className = 'dot ' + (d.llm_enabled ? 'on' : 'warn');
    $('llmText').textContent = d.llm_enabled ? 'Claude connected' : 'Offline mode';
    $('logText').textContent = `${d.log_count} logs`;
  } catch {
    $('llmDot').className = 'dot err';
    $('llmText').textContent = 'backend unreachable';
  }
}

async function refreshAll() {
  try {
    const [incidents, stats] = await Promise.all([api('/api/alerts'), api('/api/stats')]);
    S.incidents = incidents;
    S.stats = stats;
    applyFilters();
    paintStats();
    if (S.selectedId === null) renderOverview();
  } catch (e) {
    console.error(e);
    toast('Could not load data', 'Is the backend running on port 8000?', 'err');
  }
}

/* ---------- 4. Stats strip ---------- */
function paintStats() {
  const st = S.stats;
  if (!st) return;
  const sev = Object.fromEntries(st.severity_breakdown.map(x => [x.severity, x.count]));
  animateNum($('sIncidents'), st.total_incidents);
  animateNum($('sCritical'), sev.critical || 0);
  animateNum($('sHigh'), sev.high || 0);
  animateNum($('sEvents'), st.total_events);
  animateNum($('sAssets'), st.unique_assets);
  animateNum($('sIps'), st.unique_ips);
}

/* ---------- 5. Overview (shown when no incident is selected) ---------- */
function donutSVG(breakdown, total) {
  const R = 52, C = 2 * Math.PI * R;
  let offset = 0;
  const arcs = breakdown.filter(b => b.count > 0).map(b => {
    const frac = total ? b.count / total : 0;
    const seg = `<circle cx="64" cy="64" r="${R}" fill="none"
        stroke="${cssVar(SEV_COLOR[b.severity])}" stroke-width="17"
        stroke-dasharray="${(frac * C).toFixed(2)} ${C}"
        stroke-dashoffset="${(-offset * C).toFixed(2)}" stroke-linecap="butt"/>`;
    offset += frac;
    return seg;
  }).join('');

  return `<svg width="128" height="128" viewBox="0 0 128 128" style="transform:rotate(-90deg);flex:none">
      <circle cx="64" cy="64" r="${R}" fill="none" stroke="${cssVar('--bg-3')}" stroke-width="17"/>
      ${arcs}
    </svg>`;
}

function renderOverview() {
  const st = S.stats;
  const main = $('main');

  if (!st || !st.total_incidents) {
    main.innerHTML = `
      <div class="empty">
        <img src="assets/logo.png" alt="">
        <div class="t">No incidents yet</div>
        <div class="s">Click <b>Run attack demo</b> to generate synthetic security logs containing five
        real-world attack patterns, then watch HAWK AI correlate them automatically.</div>
      </div>`;
    return;
  }

  const maxAsset = Math.max(...st.top_assets.map(a => a.count), 1);
  const maxHour = Math.max(...st.hourly_activity.map(h => h.count), 1);

  main.innerHTML = `
    <div class="ov">
      <div class="d-title" style="margin-bottom:4px">Threat overview</div>
      <div class="d-sub">${st.total_incidents} incidents · ${st.total_events} correlated events ·
        ${st.mitre_coverage.length} ATT&amp;CK techniques observed</div>

      <div class="ov-grid">

        <div class="card">
          <div class="card-h">Severity distribution</div>
          <div class="donut-row">
            ${donutSVG(st.severity_breakdown, st.total_incidents)}
            <div class="legend">
              ${st.severity_breakdown.map(b => `
                <div class="li">
                  <span class="sw" style="background:${cssVar(SEV_COLOR[b.severity])}"></span>
                  <span style="text-transform:capitalize">${b.severity}</span>
                  <span class="n">${b.count}</span>
                </div>`).join('')}
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-h">Most targeted assets</div>
          ${st.top_assets.map(a => `
            <div class="bar-row">
              <span class="bar-lb" title="${esc(a.asset)}">${esc(a.asset)}</span>
              <span class="bar-tk"><span class="bar-fl" data-w="${(a.count / maxAsset) * 100}"></span></span>
              <span class="bar-n">${a.count}</span>
            </div>`).join('') || '<div style="color:var(--txt-3);font-size:12px">No data</div>'}
        </div>

        <div class="card" style="grid-column:1/-1">
          <div class="card-h">MITRE ATT&amp;CK coverage</div>
          <div class="mitre-grid">
            ${st.mitre_coverage.map(m => `
              <div class="mt" title="${esc(m.technique_name)} — seen in ${m.count} incident(s)">
                <div class="id">${esc(m.technique_id)}</div>
                <div class="nm">${esc(m.technique_name)}</div>
              </div>`).join('')}
          </div>
        </div>

        <div class="card">
          <div class="card-h">Activity by hour (UTC)</div>
          <div class="spark">
            ${st.hourly_activity.map(h => `
              <span class="b" data-h="${(h.count / maxHour) * 100}" title="${h.hour} — ${h.count} events"></span>`).join('')}
          </div>
          <div class="spark-x">
            ${st.hourly_activity.map(h => `<span>${esc(h.hour.split(':')[0])}</span>`).join('')}
          </div>
        </div>

        <div class="card">
          <div class="card-h">Noisiest source IPs</div>
          ${st.top_ips.map(i => `
            <div class="bar-row">
              <span class="bar-lb" title="${esc(i.src_ip)}">${esc(i.src_ip)}</span>
              <span class="bar-tk"><span class="bar-fl" data-w="${(i.count / ((st.top_ips[0] && st.top_ips[0].count) || 1)) * 100}"></span></span>
              <span class="bar-n">${i.count}</span>
            </div>`).join('') || '<div style="color:var(--txt-3);font-size:12px">No data</div>'}
        </div>

      </div>
    </div>`;

  // Animate bars/sparkline in after paint so the CSS transition actually runs.
  requestAnimationFrame(() => {
    main.querySelectorAll('.bar-fl').forEach(b => { b.style.width = b.dataset.w + '%'; });
    main.querySelectorAll('.spark .b').forEach(b => { b.style.height = Math.max(4, +b.dataset.h) + '%'; });
  });
}

/* ---------- 6. Incident list ---------- */
function applyFilters() {
  const q = S.query.toLowerCase().trim();
  S.filtered = S.incidents.filter(inc => {
    if (S.sev !== 'all' && inc.severity !== S.sev) return false;
    if (!q) return true;
    const hay = [
      inc.src_ip, inc.user || '', inc.assets_involved.join(' '), inc.severity,
      inc.mitre_tags.map(t => `${t.technique_id} ${t.technique_name} ${t.tactic}`).join(' '),
      inc.events.map(e => e.event_type).join(' '),
      inc.reason                       // lets plain words like "ransomware" or "brute force" match
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });
  renderList();
}

function renderList() {
  const el = $('list');
  $('listCount').textContent = S.incidents.length ? `${S.filtered.length}/${S.incidents.length}` : '';

  if (!S.incidents.length) {
    el.innerHTML = `<div style="padding:22px 16px;color:var(--txt-3);font-size:12.5px;line-height:1.6">
      No incidents yet.<br>Run the attack demo to get started.</div>`;
    return;
  }
  if (!S.filtered.length) {
    el.innerHTML = `<div style="padding:22px 16px;color:var(--txt-3);font-size:12.5px">
      Nothing matches this filter.</div>`;
    return;
  }

  el.innerHTML = S.filtered.map((inc, i) => {
    const status = S.status[keyOf(inc)] || 'new';
    return `
    <div class="inc ${inc.id === S.selectedId ? 'on' : ''}" data-id="${inc.id}" style="animation-delay:${i * 26}ms">
      <div class="inc-top">
        <span class="sev sev-${inc.severity}">${inc.severity} ${inc.severity_score}</span>
        <span class="st st-${status}">${status}</span>
      </div>
      <div class="inc-ip">${esc(inc.src_ip)}</div>
      <div class="inc-meta">
        <span>👤 ${esc(inc.user || '—')}</span>
        <span>◈ ${inc.event_count} events</span>
        <span>🖥 ${inc.assets_involved.length}</span>
      </div>
      <div class="inc-tags">
        ${inc.mitre_tags.slice(0, 3).map(t => `<span class="mini-tag">${esc(t.technique_id)}</span>`).join('')}
        ${inc.mitre_tags.length > 3 ? `<span class="mini-tag">+${inc.mitre_tags.length - 3}</span>` : ''}
      </div>
    </div>`;
  }).join('');

  el.querySelectorAll('.inc').forEach(node =>
    node.addEventListener('click', () => selectIncident(+node.dataset.id)));
}

/* ---------- 7. Incident detail ---------- */
function ringSVG(score, sevColor) {
  const R = 26, C = 2 * Math.PI * R, frac = Math.min(score, 100) / 100;
  return `<div class="ring">
      <svg width="64" height="64" viewBox="0 0 64 64">
        <circle cx="32" cy="32" r="${R}" fill="none" stroke="${cssVar('--bg-3')}" stroke-width="7"/>
        <circle cx="32" cy="32" r="${R}" fill="none" stroke="${cssVar(sevColor)}" stroke-width="7"
          stroke-linecap="round" stroke-dasharray="${(frac * C).toFixed(1)} ${C}"/>
      </svg>
      <div class="val" style="color:${cssVar(sevColor)}">${score}</div>
    </div>`;
}

function selectIncident(id) {
  S.selectedId = id;
  S.tab = 'overview';
  renderList();
  renderDetail();
  const inc = S.incidents.find(i => i.id === id);
  $('chatScope').textContent = inc ? `incident #${id}` : 'all incidents';
}

function renderDetail() {
  const inc = S.incidents.find(i => i.id === S.selectedId);
  if (!inc) { renderOverview(); return; }

  const k = keyOf(inc), status = S.status[k] || 'new', col = SEV_COLOR[inc.severity];

  $('main').innerHTML = `
    <div class="detail">
      <div class="d-head">
        <div>
          <div class="d-title">
            Incident #${inc.id}
            <span class="sev sev-${inc.severity}">${inc.severity}</span>
            <span class="st st-${status}">${status}</span>
          </div>
          <div class="d-sub">${fmtTime(inc.first_seen)} → ${fmtTime(inc.last_seen)}</div>
        </div>
        <div class="d-actions">
          <button id="btnInvestigate" class="ghost">🔍 Investigating</button>
          <button id="btnResolve" class="ghost">✓ Resolve</button>
          <button id="btnExport" class="ghost">⭳ Export</button>
          <button id="btnBack" class="ghost">✕ Close</button>
        </div>
      </div>

      <div class="ring-wrap">
        ${ringSVG(inc.severity_score, col)}
        <div class="ring-info">
          <div class="l">Severity score</div>
          <div class="v">${inc.severity_score} / 100 — ${inc.severity}</div>
          <div class="l" style="margin-top:7px">Correlated from</div>
          <div class="v">${inc.event_count} raw events</div>
        </div>
      </div>

      <div class="kv">
        <div class="kv-b"><div class="kv-l">Source IP</div><div class="kv-v">${esc(inc.src_ip)}</div></div>
        <div class="kv-b"><div class="kv-l">User account</div><div class="kv-v">${esc(inc.user || '—')}</div></div>
        <div class="kv-b"><div class="kv-l">Assets involved</div><div class="kv-v">${esc(inc.assets_involved.join(', '))}</div></div>
        <div class="kv-b"><div class="kv-l">Techniques</div><div class="kv-v">${inc.mitre_tags.length}</div></div>
      </div>

      <div class="reason"><span class="ico">💡</span><span>${esc(inc.reason)}</span></div>

      <div class="tabs">
        <button class="tab ${S.tab === 'overview' ? 'on' : ''}" data-tab="overview">Overview</button>
        <button class="tab ${S.tab === 'timeline' ? 'on' : ''}" data-tab="timeline">Timeline</button>
        <button class="tab ${S.tab === 'report' ? 'on' : ''}" data-tab="report">AI Report</button>
      </div>
      <div class="tab-body" id="tabBody"></div>
    </div>`;

  renderTab(inc);

  $('main').querySelectorAll('.tab').forEach(t =>
    t.addEventListener('click', () => {
      S.tab = t.dataset.tab;
      $('main').querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === t));
      renderTab(inc);
    }));

  $('btnBack').onclick = () => { S.selectedId = null; $('chatScope').textContent = 'all incidents'; renderList(); renderOverview(); };
  $('btnInvestigate').onclick = () => setStatus(inc, 'investigating');
  $('btnResolve').onclick = () => setStatus(inc, 'resolved');
  $('btnExport').onclick = () => exportIncident(inc);
}

function renderTab(inc) {
  const body = $('tabBody');

  if (S.tab === 'overview') {
    body.innerHTML = `
      <div class="sec-l">MITRE ATT&amp;CK techniques</div>
      <div>${inc.mitre_tags.map(t => `
        <span class="tag"><span class="id">${esc(t.technique_id)}</span>
          <span>${esc(t.technique_name)}</span>
          <span class="tc">· ${esc(t.tactic)}</span></span>`).join('')
        || '<span style="color:var(--txt-3);font-size:12.5px">No techniques matched.</span>'}</div>

      <div class="sec-l">Event type breakdown</div>
      ${(() => {
        const c = {};
        inc.events.forEach(e => c[e.event_type] = (c[e.event_type] || 0) + 1);
        const max = Math.max(...Object.values(c), 1);
        return Object.entries(c).sort((a, b) => b[1] - a[1]).map(([t, n]) => `
          <div class="bar-row">
            <span class="bar-lb" title="${esc(t)}">${esc(t)}</span>
            <span class="bar-tk"><span class="bar-fl" style="width:${(n / max) * 100}%"></span></span>
            <span class="bar-n">${n}</span>
          </div>`).join('');
      })()}`;
    return;
  }

  if (S.tab === 'timeline') {
    body.innerHTML = `
      <div class="sec-l">Correlated events (${inc.event_count})</div>
      <div class="tl">
        ${inc.events.map(e => `
          <div class="tl-item ${['file_encryption', 'privilege_escalation', 'successful_login_unusual'].includes(e.event_type) ? 'hot' : ''}">
            <span class="tl-t">${fmtClock(e.timestamp)}</span>
            <span class="tl-e">${esc(e.event_type)}</span>
            <span class="tl-a">${esc(e.asset)}${e.user ? ' · ' + esc(e.user) : ''}${e.geo_country ? ' · ' + esc(e.geo_country) : ''}</span>
            ${e.raw_message ? `<span class="tl-m">${esc(e.raw_message)}</span>` : ''}
          </div>`).join('')}
      </div>`;
    return;
  }

  // report tab
  const cached = S.reports[keyOf(inc)];
  if (cached) { paintReport(cached); return; }
  body.innerHTML = `
    <div class="sec-l">AI incident report</div>
    <p style="color:var(--txt-2);font-size:12.5px;margin:0 0 12px">
      Generate a written report with a summary, severity justification and prioritised response actions.</p>
    <button id="btnGen" class="primary">✨ Generate report</button>`;
  $('btnGen').onclick = () => generateReport(inc);
}

function paintReport(r) {
  $('tabBody').innerHTML = `
    <div class="sec-l">AI incident report</div>
    <span class="rtag ${r.generated_by}">${r.generated_by === 'llm' ? '✦ AI generated' : '◈ template fallback'}</span>
    <div class="report">${esc(r.summary)}</div>
    <div class="sec-l">Recommended actions</div>
    ${r.recommended_actions.map((a, i) => `<div class="act"><span class="n">${i + 1}</span><span>${esc(a)}</span></div>`).join('')}`;
}

async function generateReport(inc) {
  $('tabBody').innerHTML = `<div class="sec-l">AI incident report</div>
    <div style="color:var(--txt-3);font-family:var(--mono);font-size:12px;padding:14px 0">
      <span class="typing"><i></i><i></i><i></i></span> analysing incident…</div>`;
  try {
    const r = await api(`/api/alerts/${inc.id}/report`);
    S.reports[keyOf(inc)] = r;
    if (S.selectedId === inc.id && S.tab === 'report') paintReport(r);
    toast('Report ready', r.generated_by === 'llm' ? 'Written by Claude' : 'Template fallback used', 'ok');
  } catch {
    $('tabBody').innerHTML = `<div style="color:var(--rd);font-size:12.5px">Failed to generate report.</div>`;
    toast('Report failed', 'Check the backend logs', 'err');
  }
}

function setStatus(inc, status) {
  S.status[keyOf(inc)] = status;
  try { localStorage.setItem('hawk-status', JSON.stringify(S.status)); } catch {}
  renderList(); renderDetail();
  toast(`Marked ${status}`, `Incident #${inc.id} · ${inc.src_ip}`, status === 'resolved' ? 'ok' : 'warn');
}

function exportIncident(inc) {
  const r = S.reports[keyOf(inc)];
  const txt = [
    `HAWK AI — INCIDENT EXPORT`,
    `==============================`,
    `Incident ID   : #${inc.id}`,
    `Severity      : ${inc.severity} (${inc.severity_score}/100)`,
    `Source IP     : ${inc.src_ip}`,
    `User          : ${inc.user || 'N/A'}`,
    `Assets        : ${inc.assets_involved.join(', ')}`,
    `Time range    : ${fmtTime(inc.first_seen)} -> ${fmtTime(inc.last_seen)}`,
    `MITRE tags    : ${inc.mitre_tags.map(t => `${t.technique_id} (${t.technique_name})`).join(', ') || 'none'}`,
    ``,
    `WHY FLAGGED`,
    `-----------`,
    inc.reason,
    ``,
    `CORRELATED EVENTS (${inc.event_count})`,
    `-----------`,
    ...inc.events.map(e => `[${fmtTime(e.timestamp)}] ${e.event_type} on ${e.asset}${e.user ? ' (' + e.user + ')' : ''}`),
    ``,
    ...(r ? [`AI REPORT`, `-----------`, r.summary, ``, `RECOMMENDED ACTIONS`, `-----------`,
      ...r.recommended_actions.map((a, i) => `${i + 1}. ${a}`)] : [`(No AI report generated yet.)`]),
    ``,
    `Exported ${new Date().toISOString()}`
  ].join('\n');

  const url = URL.createObjectURL(new Blob([txt], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url; a.download = `hawk-ai-incident-${inc.id}.txt`; a.click();
  URL.revokeObjectURL(url);
  toast('Incident exported', `hawk-ai-incident-${inc.id}.txt`, 'ok');
}

/* ---------- 8. Chat ---------- */
function addMsg(who, html, cls) {
  const wrap = document.createElement('div');
  wrap.className = `msg ${cls}`;
  wrap.innerHTML = `<div class="who">${who}</div><div class="bub">${html}</div>`;
  $('chatMsgs').appendChild(wrap);
  $('chatMsgs').scrollTop = $('chatMsgs').scrollHeight;
  return wrap;
}

async function sendChat(text) {
  const msg = (text === undefined ? $('chatInput').value : text).trim();
  if (!msg) return;
  $('chatInput').value = '';
  addMsg('You', esc(msg), 'me');
  const pending = addMsg('Copilot', `<span class="typing"><i></i><i></i><i></i></span>`, 'bot');

  try {
    const d = await api('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, incident_id: S.selectedId })
    });
    pending.querySelector('.bub').innerHTML = esc(d.reply).replace(/\n/g, '<br>');
  } catch {
    pending.querySelector('.bub').textContent = 'Could not reach the backend.';
  }
  $('chatMsgs').scrollTop = $('chatMsgs').scrollHeight;
}

/* ---------- 9. Actions + shortcuts ---------- */
async function runGenerate(full) {
  if (S.busy) return;
  S.busy = true;
  $('scan').classList.add('on');
  $('list').innerHTML = '<div class="skel"></div><div class="skel"></div><div class="skel"></div>';
  try {
    const d = await api(`/api/logs/generate?full=${full}`, { method: 'POST' });
    await refreshStatus();
    await refreshAll();
    toast(full ? 'Attack demo generated' : 'Sample logs added',
          `${d.inserted} events ingested and correlated`, 'ok');
  } catch {
    toast('Generation failed', 'Is the backend running?', 'err');
  } finally {
    S.busy = false;
    $('scan').classList.remove('on');
  }
}

async function runReset() {
  try {
    await api('/api/logs', { method: 'DELETE' });
    S.selectedId = null; S.reports = {};
    $('chatScope').textContent = 'all incidents';
    await refreshStatus(); await refreshAll();
    renderOverview();
    toast('All logs cleared', 'Dashboard reset to empty state', 'warn');
  } catch { toast('Reset failed', '', 'err'); }
}

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  $('btnTheme').textContent = t === 'dark' ? '🌙' : '☀️';
  try { localStorage.setItem('hawk-theme', t); } catch {}
  // Charts read CSS variables at paint time, so repaint them after a theme flip.
  if (S.selectedId === null) renderOverview(); else renderDetail();
}

function moveSelection(step) {
  if (!S.filtered.length) return;
  const idx = S.filtered.findIndex(i => i.id === S.selectedId);
  const next = idx === -1 ? 0 : Math.min(Math.max(idx + step, 0), S.filtered.length - 1);
  selectIncident(S.filtered[next].id);
}

function bindEvents() {
  $('btnDemo').onclick = () => runGenerate(true);
  $('btnSample').onclick = () => runGenerate(false);
  $('btnReset').onclick = runReset;
  $('btnTheme').onclick = () =>
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  $('btnKeys').onclick = () => $('keysModal').style.display = 'flex';
  $('btnKeysClose').onclick = () => $('keysModal').style.display = 'none';
  $('keysModal').onclick = e => { if (e.target.id === 'keysModal') $('keysModal').style.display = 'none'; };

  $('search').addEventListener('input', e => { S.query = e.target.value; applyFilters(); });

  $('sevChips').addEventListener('click', e => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    S.sev = chip.dataset.sev;
    $('sevChips').querySelectorAll('.chip').forEach(c => c.classList.toggle('on', c === chip));
    applyFilters();
  });

  $('btnSend').onclick = () => sendChat();
  $('chatInput').addEventListener('keydown', e => { if (e.key === 'Enter') sendChat(); });
  $('sugg').addEventListener('click', e => {
    const b = e.target.closest('button');
    if (b) sendChat(b.dataset.q);
  });

  document.addEventListener('keydown', e => {
    const typing = ['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName);
    if (e.key === 'Escape') {
      $('keysModal').style.display = 'none';
      if (typing) document.activeElement.blur();
      return;
    }
    if (typing) return;
    const k = e.key.toLowerCase();
    if (k === 'g') { e.preventDefault(); runGenerate(true); }
    if (k === 'r') { e.preventDefault(); runReset(); }
    if (k === 't') { e.preventDefault(); $('btnTheme').click(); }
    if (k === 'j') { e.preventDefault(); moveSelection(1); }
    if (k === 'k') { e.preventDefault(); moveSelection(-1); }
    if (e.key === '/') { e.preventDefault(); $('search').focus(); }
  });
}

/* ---------- 10. Init ---------- */
function init() {
  try { S.status = JSON.parse(localStorage.getItem('hawk-status') || '{}'); } catch { S.status = {}; }
  let theme = 'dark';
  try {
    theme = localStorage.getItem('hawk-theme') ||
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  } catch {}
  document.documentElement.setAttribute('data-theme', theme);
  $('btnTheme').textContent = theme === 'dark' ? '🌙' : '☀️';

  bindEvents();
  addMsg('Copilot',
    'Hi — I can answer questions about the current incidents. Try a suggestion below, or ask about a specific IP, user or asset.',
    'bot');

  refreshStatus();
  refreshAll();
  setInterval(refreshStatus, 10000);
}

init();
