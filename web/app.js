'use strict';
const $ = id => document.getElementById(id);
const views = new Map();
const clearedAt = new Map();
let renderPending = false;
function scheduleRender() { if (!renderPending) { renderPending = true; requestAnimationFrame(() => { renderPending = false; render(); }); } }
let paused = false, selected = null, status = {}, socket, connectionNotice = "", config = null, controlBusy = false, lastTraffic = null;
const count = n => Number(n || 0).toLocaleString();
function bytes(n) { n = Number(n || 0); if (!n) return '0 B'; const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4); return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${['B','KiB','MiB','GiB','TiB'][i]}`; }
function updateNotice() { const message = connectionNotice || (status.last_error ? `Capture error: ${status.last_error}` : ''); $('notice').textContent = message; $('notice').hidden = !message; }
function notice(message) { connectionNotice = message; updateNotice(); }
function category(value) { value = String(value || 'unknown').toLowerCase(); if (value.includes('reality') || value.includes('vless')) return ['reality', 'Suspected VLESS / REALITY']; if (value.includes('suspicious') || value.includes('tunnel')) return ['suspicious', 'Suspicious tunnel']; if (value.includes('normal') || value.includes('ordinary')) return ['ordinary', 'Ordinary TLS']; if (value.includes('other')) return ['other', 'Other encrypted traffic']; return ['unknown', 'Unknown']; }
function endpoint(value) { return String(value ?? '—'); }
function port(value) { const s = endpoint(value); const i = s.lastIndexOf(':'); return i < 0 ? '—' : s.slice(i + 1); }
function time(ms) { return ms ? new Date(Number(ms)).toLocaleTimeString() : '—'; }
function textCell(row, value) { const cell = row.insertCell(); cell.textContent = value; return cell; }
function setStatus(s) {
  if (!s) return;
  status = s; updateNotice();
  $('capture-status').textContent = `Capture ${s.capture_running ? 'running' : 'stopped'}`;
  $('capture-dot').className = `dot ${s.capture_running ? 'good' : 'warn'}`;
  const ai = String(s.ai_status || (s.ai_enabled ? 'offline' : 'disabled'));
  $('ai-status').textContent = `AI ${ai}`;
  $('ai-dot').className = `dot ${ai.toLowerCase() === 'online' ? 'good' : ai.toLowerCase() === 'disabled' ? '' : 'warn'}`;
  $('interface-status').textContent = `Interface ${s.interface || '—'}`;
  $('mode').textContent = String(s.mode || 'LIVE').toUpperCase();
  const isDemo = String(s.mode || '').startsWith('demo');
  $('toggle-ai').disabled = isDemo;
  $('toggle-ai').textContent = isDemo ? 'Unavailable in demo' : (s.ai_enabled ? 'Disable cloud AI' : 'Enable cloud AI');
  $('ai-description').textContent = ai;
  updateControls();
}
function updateControls() {
  const live = String(status.mode || 'live').startsWith('live');
  $('capture-start').disabled = controlBusy || !live || !!status.capture_running;
  $('capture-stop').disabled = controlBusy || !live || !status.capture_running;
  $('capture-restart').disabled = controlBusy || !live;
  $('select-interface').disabled = controlBusy || !live || !$('interface').value;
  $('detect-interface').disabled = controlBusy || !live;
  $('interface').disabled = controlBusy || !live;
}
function setStats(s) {
  if (!s) return;
  $('packets-captured').textContent = count(s.packets_captured);
  $('active-flows').textContent = count(s.active_flows);
  $('flow-protocols').textContent = `TCP ${count(s.tcp_flows)} · UDP ${count(s.udp_flows)}`;
  $('total-bytes').textContent = bytes(s.total_bytes);
  $('suspicious-flows').textContent = count(s.suspicious_flows);
  $('packets-per-second').textContent = Number(s.packets_per_second || 0).toFixed(1);
  const now = Date.now(), total = Number(s.total_bytes || 0);
  if (lastTraffic && now > lastTraffic.time && total >= lastTraffic.total) $('bandwidth').textContent = `${bytes((total - lastTraffic.total) * 1000 / (now - lastTraffic.time))}/s`;
  lastTraffic = {time: now, total};
  $('drops').textContent = `Capture: ${count(s.dropped_capture_events)} · Analysis: ${count(s.dropped_analysis_events)}`;
}
function aiScore(ai) { if (!ai) return '—'; const q = ai.answers?.traffic_type || ai.traffic_type; const score = q?.probabilities?.[q?.choice] ?? q?.confidence ?? q?.probability ?? q?.score ?? ai.probability ?? ai.score; return typeof score === 'number' ? score.toFixed(2) : '—'; }
function updateFlow(view) { if (!view || !view.flow || view.flow.id == null) return; const id = String(view.flow.id); if (clearedAt.has(id)) { if ((view.flow.last_seen_ms || 0) <= clearedAt.get(id)) return; clearedAt.delete(id); } views.set(id, view); while (views.size > 1000) views.delete(views.keys().next().value); }
function render() { const body = $('flows'); body.replaceChildren(); const term = $('search').value.trim().toLowerCase(), filter = $('filter').value; let shown = 0; const list = [...views.values()].sort((a,b) => (b.flow.last_seen_ms || 0) - (a.flow.last_seen_ms || 0)); for (const view of list) { const f = view.flow, local = view.local || {}, [key,label] = category(local.classification); if (filter !== 'all' && filter !== key) continue; if (term && !`${endpoint(f.src)} ${endpoint(f.dst)}`.toLowerCase().includes(term)) continue; const row = body.insertRow(); row.tabIndex = 0; row.setAttribute('aria-label', `Inspect ${endpoint(f.src)} to ${endpoint(f.dst)}`); if (String(f.id) === selected) row.classList.add('selected'); textCell(row, time(f.first_seen_ms)); textCell(row, endpoint(f.src)); textCell(row, endpoint(f.dst)); textCell(row, String(f.protocol || '—').toUpperCase()); textCell(row, port(f.dst)); const badge = document.createElement('span'); badge.className = `badge ${key}`; badge.textContent = label; row.insertCell().append(badge); textCell(row, view.ai ? aiScore(view.ai) : (view.ai_status || '—')); const choose = () => { selected = String(f.id); render(); }; row.addEventListener('click', choose); row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); } }); shown++; } $('empty').hidden = shown > 0; $('empty').textContent = views.size ? 'No flows match the current filters.' : 'Waiting for observed flows.'; $('flow-count').textContent = `· ${count(shown)} shown`; renderDetails(); }
function renderDetails() { const root = $('details'); root.replaceChildren(); const view = views.get(selected); if (!view) { root.className = 'details-empty'; root.textContent = 'Select a connection to inspect its metadata and analysis.'; return; } root.className = 'details-content'; const f = view.flow, local = view.local || {}, tls = f.tls || {}; const group = (title, rows) => { const div = document.createElement('div'); div.className = 'detail-group'; const heading = document.createElement('h3'); heading.textContent = title; div.append(heading); for (const [key,value] of rows) { const row = document.createElement('div'); row.className = 'detail-row'; const k = document.createElement('span'), v = document.createElement('span'); k.textContent = key; v.textContent = value == null || value === '' ? '—' : Array.isArray(value) ? value.join(', ') || '—' : String(value); row.append(k,v); div.append(row); } root.append(div); }; group('Observed connection', [['Source',f.src],['Destination',f.dst],['Protocol',f.protocol],['Duration',`${Math.max(0, (f.last_seen_ms || 0) - (f.first_seen_ms || 0))} ms`],['Packets first / reverse' ,`${count(f.packets_sent)} / ${count(f.packets_received)}`],['Bytes first / reverse' ,`${bytes(f.bytes_sent)} / ${bytes(f.bytes_received)}`],['TCP SYN / SYN-ACK / ACK',`${f.tcp_syn ? 'yes' : 'no'} / ${f.tcp_syn_ack ? 'yes' : 'no'} / ${f.tcp_ack ? 'yes' : 'no'}`]]); group('Observed TLS metadata', [['Highest offered version',tls.version],['SNI',tls.sni],['ALPN',tls.alpn],['Cipher suites',tls.cipher_suites],['JA3',tls.ja3]]); group('Local inference', [['Classification',category(local.classification)[1]],['Heuristic score',typeof local.suspicion_score === 'number' ? local.suspicion_score.toFixed(2) : null],['Observations',local.observations],['Explanation',local.explanation],['AI requested',local.ai_requested ? 'Yes' : 'No']]); group('Cloud inference', [['Processing status',view.ai_status],['Traffic class',view.ai?.answers?.traffic_type?.choice],['Class scores',view.ai?.answers?.traffic_type?.probabilities ? JSON.stringify(view.ai.answers.traffic_type.probabilities) : null],['Evidence score',view.ai?.answers?.evidence_strength?.score],['Evidence scores',view.ai?.answers?.evidence_strength?.probabilities ? JSON.stringify(view.ai.answers.evidence_strength.probabilities) : null],['Last analysis',view.last_analysis_ms ? new Date(view.last_analysis_ms).toLocaleString() : null]]); }
async function request(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    const body = await res.text();
    let message = body;
    try { message = JSON.parse(body).error || body; } catch (_) { /* Plain text errors remain readable. */ }
    throw new Error(message || `${res.status} ${res.statusText}`);
  }
  return res.json();
}
const jsonRequest = (method, value) => ({method, headers:{'Content-Type':'application/json'}, body:JSON.stringify(value)});
async function refresh() { try { const [s,t] = await Promise.all([request('/api/status'),request('/api/stats')]); setStatus(s); if (!paused) setStats(t); } catch (_) { notice('Cannot reach Axion. Retrying connection.'); } }
async function loadFlows() { try { const data = await request('/api/flows?limit=1000'); for (const view of (Array.isArray(data) ? data : data.flows || [])) updateFlow(view); render(); } catch (_) { notice('Unable to load traffic history.'); } }
async function interfaces() {
  try {
    const data = await request('/api/interfaces');
    const values = data.details?.length ? data.details : (Array.isArray(data) ? data : data.interfaces || []);
    const previous = $('interface').value || status.interface;
    $('interface').replaceChildren();
    if (!values.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No interfaces available'; $('interface').append(o); }
    else { const o = document.createElement('option'); o.value = 'auto'; o.textContent = 'Automatic selection'; $('interface').append(o); }
    for (const item of values) {
      const name = typeof item === 'string' ? item : item.name;
      if (!name) continue;
      const o = document.createElement('option'); o.value = name;
      const details = typeof item === 'string' ? [] : [item.description && item.description !== name ? item.description : '', ...(item.addresses || []), item.loopback ? 'loopback' : '', item.wireless ? 'Wi-Fi' : '', item.up === false ? 'down' : (item.running === false ? 'not running' : '')].filter(Boolean);
      o.textContent = [name, ...details].join(' · '); $('interface').append(o);
    }
    if (previous && [...$('interface').options].some(o => o.value === previous)) $('interface').value = previous;
    updateControls();
  } catch (e) { $('interface').replaceChildren(); const o = document.createElement('option'); o.value = ''; o.textContent = 'Interfaces unavailable'; $('interface').append(o); $('interface-help').textContent = `Could not enumerate interfaces: ${e.message}`; updateControls(); }
}
function connect() {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${scheme}//${location.host}/ws`);
  socket.addEventListener('open', () => { $('socket-status').textContent = 'Live updates connected'; $('socket-dot').className = 'dot good'; notice(''); });
  socket.addEventListener('message', e => { try { const event = JSON.parse(e.data); if (event.type === 'status') setStatus(event.data); else if (!paused && (event.type === 'flow' || event.type === 'flow_update')) { updateFlow(event.data); scheduleRender(); } else if (!paused && event.type === 'stats') setStats(event.data); } catch (_) { /* Ignore malformed server events. */ } });
  socket.addEventListener('close', () => { $('socket-status').textContent = 'Live updates disconnected'; $('socket-dot').className = 'dot warn'; notice('Live updates disconnected. Reconnecting…'); setTimeout(connect, 2000); });
}
async function captureAction(path, payload = {}) {
  controlBusy = true; updateControls();
  try { const result = await request(path, jsonRequest('POST', payload)); setStatus(result); notice(''); if (path === '/api/interfaces/auto') $('auto-interface').checked = true; else if (path === '/api/control/interface') $('auto-interface').checked = payload.interface === 'auto'; await interfaces(); if (result.interface && [...$('interface').options].some(o => o.value === result.interface)) $('interface').value = result.interface; }
  catch (e) { notice(`Capture control failed: ${e.message}`); await refresh(); }
  finally { controlBusy = false; updateControls(); }
}
function showConfig(c) {
  config = c;
  $('web-host').value = c.web_host;
  $('web-port').value = c.web_port;
  $('max-flows').value = c.max_flows;
  $('flow-timeout').value = c.flow_timeout_seconds;
  $('log-filter').value = c.log_filter;
  $('auto-interface').checked = c.auto_interface;
  $('open-browser').checked = c.open_browser;
  $('start-capture').checked = c.start_capture;
  $('strict-port').checked = c.strict_port;
}
async function loadConfig() { try { showConfig(await request('/api/config')); $('settings-state').textContent = 'Saved preferences'; } catch (e) { $('settings-state').textContent = `Settings unavailable: ${e.message}`; $('save-settings').disabled = true; $('reset-settings').disabled = true; } }
$('pause').addEventListener('click', () => { paused = !paused; $('pause').textContent = paused ? 'Resume updates' : 'Pause updates'; $('pause').setAttribute('aria-pressed', String(paused)); if (!paused) { refresh(); loadFlows(); } });
$('clear').addEventListener('click', () => { for (const [id, view] of views) clearedAt.set(id, view.flow.last_seen_ms || 0); views.clear(); selected = null; render(); });
$('search').addEventListener('input', render); $('filter').addEventListener('change', render);
$('toggle-ai').addEventListener('click', async () => { try { const s = await request('/api/control/ai', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!status.ai_enabled})}); setStatus(s); if (config) config.ai_enabled = s.ai_enabled; notice(''); } catch (e) { notice(`Could not change AI setting: ${e.message}`); } });
$('select-interface').addEventListener('click', () => captureAction('/api/control/interface', {interface:$('interface').value}));
$('detect-interface').addEventListener('click', () => captureAction('/api/interfaces/auto'));
const captureSelection = () => $('interface').value && $('interface').value !== status.interface ? {interface:$('interface').value} : {};
$('capture-start').addEventListener('click', () => captureAction('/api/capture/start', captureSelection()));
$('capture-stop').addEventListener('click', () => captureAction('/api/capture/stop'));
$('capture-restart').addEventListener('click', () => captureAction('/api/capture/restart', captureSelection()));
$('interface').addEventListener('change', updateControls);
$('settings-form').addEventListener('submit', async e => {
  e.preventDefault(); if (!config) return;
  $('save-settings').disabled = true;
  try {
  const current = await request('/api/config');
  const next = {...current, web_host:$('web-host').value.trim(), web_port:Number($('web-port').value), max_flows:Number($('max-flows').value), flow_timeout_seconds:Number($('flow-timeout').value), log_filter:$('log-filter').value.trim(), auto_interface:$('auto-interface').checked, open_browser:$('open-browser').checked, start_capture:$('start-capture').checked, strict_port:$('strict-port').checked};
  const result = await request('/api/config', jsonRequest('PUT', next)); showConfig(result.settings || result); $('settings-state').textContent = 'Saved. Startup, dashboard, flow, and logging preferences apply on the next launch.'; }
  catch (err) { $('settings-state').textContent = `Could not save settings: ${err.message}`; }
  finally { $('save-settings').disabled = false; }
});
$('reset-settings').addEventListener('click', async () => {
  $('reset-settings').disabled = true;
  try { const result = await request('/api/config/reset', {method:'POST'}); showConfig(result.settings || result); $('settings-state').textContent = 'Defaults saved. Startup, dashboard, flow, and logging preferences apply on the next launch.'; }
  catch (err) { $('settings-state').textContent = `Could not reset settings: ${err.message}`; }
  finally { $('reset-settings').disabled = false; }
});
$('dashboard-address').textContent = `Dashboard ${location.host}`;
render(); refresh().then(interfaces); loadConfig(); loadFlows(); connect(); setInterval(refresh, 2000);
