(() => {
  "use strict";

  const TOKEN_KEY = "axion.token";
  let token = sessionStorage.getItem(TOKEN_KEY) || "";
  let statusData = null;
  let eventTimer = null;
  let flowTimer = null;
  let statusTimer = null;

  const $ = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function showTokenPanel(show) {
    $("token-panel").classList.toggle("hidden", !show);
  }

  function banner(message) {
    const el = $("banner");
    if (!message) {
      el.classList.add("hidden");
      return;
    }
    el.textContent = message;
    el.classList.remove("hidden");
    clearTimeout(el._timer);
    el._timer = setTimeout(() => el.classList.add("hidden"), 7000);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ Accept: "application/json" }, options.headers || {});
    if (token) headers["X-Axion-Token"] = token;
    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, Object.assign({}, options, { headers }));
    if (response.status === 401) {
      showTokenPanel(true);
      throw new Error("management token required");
    }
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body.error) message = body.error;
      } catch (_) {}
      throw new Error(message);
    }
    return response.json();
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function formatRate(bps) {
    if (!Number.isFinite(bps) || bps <= 0) return "0 bps";
    const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let value = bps;
    let unit = 0;
    while (value >= 1000 && unit < units.length - 1) {
      value /= 1000;
      unit++;
    }
    return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function formatNumber(value) {
    if (!Number.isFinite(value)) return "0";
    if (value >= 1e9) return `${(value / 1e9).toFixed(2)}G`;
    if (value >= 1e6) return `${(value / 1e6).toFixed(2)}M`;
    if (value >= 1e3) return `${(value / 1e3).toFixed(1)}k`;
    return Math.round(value).toString();
  }

  function formatDuration(seconds) {
    const s = Math.max(0, Math.floor(seconds || 0));
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const mins = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  }

  function timeOf(ms) {
    try {
      return new Date(ms).toLocaleTimeString();
    } catch (_) {
      return String(ms);
    }
  }

  function pill(text, className = "") {
    return `<span class="pill ${className}">${escapeHtml(text)}</span>`;
  }

  function updateStatus(data) {
    statusData = data;
    $("status-dot").className = "dot online";
    $("version").textContent = `v${data.version}`;
    const badge = $("mode-badge");
    badge.textContent = data.mode;
    badge.className = `badge ${data.mode === "enforce" ? "enforce" : "monitor"}`;
    $("mode-monitor").classList.toggle("active", data.mode === "monitor");
    $("mode-enforce").classList.toggle("active", data.mode === "enforce");
    $("mode-enforce").disabled = !data.can_enforce;
    $("dry-run-btn").textContent = `Dry run: ${data.dry_run ? "on" : "off"}`;
    $("dry-run-btn").classList.toggle("active", data.dry_run);
    $("backend").textContent = `backend: ${data.backend} · ${data.capture_source}`;

    const m = data.metrics;
    $("stat-bps").textContent = formatRate(m.bps);
    $("stat-bps-sub").textContent = `${formatBytes(m.bytes_total)} total`;
    $("stat-pps").textContent = formatNumber(m.pps);
    $("stat-pps-sub").textContent = `${m.packets_total.toLocaleString()} packets`;
    $("stat-flows").textContent = m.active_flows.toLocaleString();
    $("stat-flows-sub").textContent = `${data.event_buffer} events buffered`;
    $("stat-blocked").textContent = m.blocked_flows.toLocaleString();
    $("stat-blocked-sub").textContent = `${m.dropped_packets.toLocaleString()} dropped packets`;
    $("stat-detections").textContent = m.detections_total.toLocaleString();
    $("stat-detections-sub").textContent = `${data.rules.compiled} rules compiled`;
    $("stat-cpu").textContent = `${m.cpu_percent.toFixed(1)}%`;
    $("stat-mem").textContent = formatBytes(m.memory_bytes);
    $("stat-uptime").textContent = formatDuration(data.uptime_seconds);
    $("stat-workers").textContent = `${data.capture_workers} workers`;
    $("rule-summary").textContent = `${data.rules.compiled} compiled · allow ${data.rules.allowlist} · deny ${data.rules.blocklist}`;

    let note = "";
    if (!data.can_enforce) {
      note = "Passive capture: classification and rule decisions are evaluated, but packets can never be blocked. Start with --inline (NFQUEUE) to enable enforcement.";
    } else if (data.mode === "enforce" && data.dry_run) {
      note = "Dry-run is active: would-be drops are logged and every packet is accepted.";
    } else if (data.mode === "enforce") {
      note = "Inline NFQUEUE enforcement is active. DROP/REJECT rules are enforced; blocked flows are dropped on subsequent packets.";
    } else {
      note = "Monitor mode on an inline backend: every packet is accepted while classification continues.";
    }
    $("enforcement-note").textContent = note;

    updateProtocols(m.protocols || {});
    drawChart(m.history || []);
  }

  function updateProtocols(protocols) {
    const list = $("protocol-list");
    const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]).slice(0, 12);
    if (!entries.length) {
      list.innerHTML = '<p class="muted">No classified flows yet.</p>';
      return;
    }
    const max = Math.max(...entries.map((entry) => entry[1]), 1);
    list.innerHTML = entries
      .map(([name, count]) => {
        const width = Math.max(2, Math.round((count / max) * 100));
        return `<div class="bar-row"><span class="mono">${escapeHtml(name)}</span><div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div><span class="bar-value">${formatNumber(count)}</span></div>`;
      })
      .join("");
  }

  function drawChart(history) {
    const canvas = $("rate-chart");
    if (!canvas || !canvas.isConnected) return;
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 600;
    const height = 220;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const pad = { left: 46, right: 16, top: 14, bottom: 24 };
    const plotW = Math.max(1, width - pad.left - pad.right);
    const plotH = Math.max(1, height - pad.top - pad.bottom);
    const values = history.slice(-120);
    const maxBps = Math.max(1, ...values.map((point) => point.bps));
    const maxPps = Math.max(1, ...values.map((point) => point.pps));

    ctx.strokeStyle = "rgba(29,53,70,0.9)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (plotH * i) / 4;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + plotW, y);
      ctx.stroke();
    }
    ctx.fillStyle = "#7f9aab";
    ctx.font = "10px ui-monospace, monospace";
    for (let i = 0; i <= 4; i++) {
      const value = maxBps * (1 - i / 4);
      const y = pad.top + (plotH * i) / 4 + 3;
      ctx.fillText(formatRate(value), 4, y);
    }
    if (values.length < 2) {
      ctx.fillStyle = "#7f9aab";
      ctx.font = "12px ui-sans-serif, sans-serif";
      ctx.fillText("Collecting samples…", pad.left + 10, pad.top + 20);
      return;
    }

    const xFor = (index) => pad.left + (plotW * index) / Math.max(1, values.length - 1);
    const yBps = (value) => pad.top + plotH - (value / maxBps) * plotH;
    const yPps = (value) => pad.top + plotH - (value / maxPps) * plotH;

    const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + plotH);
    gradient.addColorStop(0, "rgba(57,208,216,0.35)");
    gradient.addColorStop(1, "rgba(57,208,216,0.02)");
    ctx.beginPath();
    ctx.moveTo(xFor(0), pad.top + plotH);
    values.forEach((point, index) => ctx.lineTo(xFor(index), yBps(point.bps)));
    ctx.lineTo(xFor(values.length - 1), pad.top + plotH);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.beginPath();
    values.forEach((point, index) => {
      const x = xFor(index);
      const y = yBps(point.bps);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#39d0d8";
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.beginPath();
    values.forEach((point, index) => {
      const x = xFor(index);
      const y = yPps(point.pps);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "rgba(126,242,154,0.9)";
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = "#39d0d8";
    ctx.fillText("throughput", pad.left, height - 5);
    ctx.fillStyle = "#7ef29a";
    ctx.fillText("packets/s", pad.left + 90, height - 5);
  }

  async function refreshStatus() {
    try {
      const data = await api("/api/status");
      updateStatus(data);
      showTokenPanel(false);
    } catch (err) {
      $("status-dot").className = "dot offline";
      banner(err.message);
    }
  }

  async function refreshEvents() {
    try {
      const events = await api("/api/events?limit=100");
      const body = $("events-body");
      if (!events.length) {
        body.innerHTML = '<tr><td colspan="6" class="empty">No detection events yet.</td></tr>';
        return;
      }
      body.innerHTML = events
        .map((event) => {
          const protocols = (event.protocols || []).map((p) => pill(p, "proxy")).join("");
          const evidence = (event.evidence || []).slice(0, 3).map(escapeHtml).join("<br>");
          const actionClass = event.blocked ? "proxy" : event.action === "monitor" || event.action === "log" ? "warn" : "ok";
          return `<tr>
            <td class="mono">${escapeHtml(timeOf(event.ts_ms))}</td>
            <td class="mono">${escapeHtml(event.src)}:${event.src_port} → ${escapeHtml(event.dst)}:${event.dst_port}<br><span class="muted">${escapeHtml(event.sni || "")}</span></td>
            <td class="evidence">${protocols}<br>${evidence}</td>
            <td class="mono">${Math.round(event.confidence * 100)}%</td>
            <td>${escapeHtml(event.matched_rule || "—")}</td>
            <td>${pill(event.action, actionClass)}${event.blocked ? pill("blocked", "proxy") : ""}</td>
          </tr>`;
        })
        .join("");
    } catch (err) {
      banner(err.message);
    }
  }

  async function refreshFlows() {
    try {
      const flows = await api("/api/flows?limit=100");
      const body = $("flows-body");
      if (!flows.length) {
        body.innerHTML = '<tr><td colspan="6" class="empty">No active flows yet.</td></tr>';
        return;
      }
      body.innerHTML = flows
        .map((flow) => {
          const protocols = (flow.detected_protocols || []).slice(0, 4).map((p) => pill(p)).join("");
          const names = [flow.sni, (flow.dns_names || [])[0]].filter(Boolean).map(escapeHtml).join("<br>");
          const decision = flow.blocked ? pill(flow.action, "proxy") : pill(flow.action, flow.blocked ? "proxy" : "ok");
          return `<tr>
            <td class="mono">${escapeHtml(flow.client)}<br>→ ${escapeHtml(flow.server)}<br><span class="muted">${escapeHtml(flow.protocol)} · ${flow.packets} pkts</span></td>
            <td>${protocols || '<span class="muted">unknown</span>'}</td>
            <td class="mono">${names || "—"}</td>
            <td class="mono">${formatBytes(flow.total_bytes)}</td>
            <td class="mono">${Math.round((flow.proxy_score || 0) * 100)}%</td>
            <td>${decision}<br><span class="muted">${escapeHtml(flow.matched_rule || "")}</span></td>
          </tr>`;
        })
        .join("");
    } catch (err) {
      banner(err.message);
    }
  }

  async function refreshRules() {
    try {
      const data = await api("/api/rules");
      const list = $("rules-list");
      if (!data.rules.length) {
        list.innerHTML = '<p class="muted">No explicit rules. Built-in confidence policy is active.</p>';
        return;
      }
      list.innerHTML = data.rules
        .map((rule) => {
          const matcher = Object.entries(rule.match || {})
            .filter(([, value]) => (Array.isArray(value) ? value.length : value !== null && value !== undefined && value !== 0 && value !== ""))
            .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(",") : value}`)
            .join(" · ");
          const cls = rule.action === "drop" || rule.action === "reject" ? "proxy" : rule.action === "allow" ? "ok" : "warn";
          return `<div class="rule-item">
            <div class="rule-top"><span class="rule-name">${escapeHtml(rule.name)}</span>${pill(rule.action, cls)}</div>
            <div class="rule-match">priority ${rule.priority} · ${rule.enabled ? "enabled" : "disabled"}${matcher ? " · " + escapeHtml(matcher) : ""}</div>
          </div>`;
        })
        .join("");
    } catch (err) {
      banner(err.message);
    }
  }

  async function setMode(mode) {
    try {
      await api("/api/mode", { method: "POST", body: JSON.stringify({ mode }) });
      await refreshStatus();
    } catch (err) {
      banner(err.message);
    }
  }

  async function toggleDryRun() {
    if (!statusData) return;
    try {
      await api("/api/dry-run", {
        method: "POST",
        body: JSON.stringify({ enabled: !statusData.dry_run }),
      });
      await refreshStatus();
    } catch (err) {
      banner(err.message);
    }
  }

  async function reloadRules() {
    try {
      const result = await api("/api/rules/reload", { method: "POST", body: "{}" });
      banner(`Rules reloaded: ${result.rules} compiled`);
      await refreshRules();
      await refreshStatus();
    } catch (err) {
      banner(`Rule reload failed: ${err.message}`);
    }
  }

  function saveToken() {
    token = $("token-input").value.trim();
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
      showTokenPanel(false);
      banner("");
      start();
    } else {
      banner("Enter a management token.");
    }
  }

  function schedule() {
    refreshStatus();
    if (statusTimer) clearInterval(statusTimer);
    if (eventTimer) clearInterval(eventTimer);
    if (flowTimer) clearInterval(flowTimer);
    statusTimer = setInterval(refreshStatus, 1500);
    eventTimer = setInterval(refreshEvents, 2500);
    flowTimer = setInterval(refreshFlows, 3000);
    refreshEvents();
    refreshFlows();
  }

  function start() {
    schedule();
    refreshRules();
  }

  $("mode-monitor").addEventListener("click", () => setMode("monitor"));
  $("mode-enforce").addEventListener("click", () => setMode("enforce"));
  $("dry-run-btn").addEventListener("click", toggleDryRun);
  $("reload-rules").addEventListener("click", reloadRules);
  $("token-save").addEventListener("click", saveToken);
  $("token-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter") saveToken();
  });
  window.addEventListener("resize", () => {
    if (statusData) drawChart(statusData.metrics.history || []);
  });

  if (token) showTokenPanel(false);
  start();
})();
