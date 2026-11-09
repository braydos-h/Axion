(() => {
  "use strict";

  const TOKEN_KEY = "axion.token";
  let token = sessionStorage.getItem(TOKEN_KEY) || "";
  let statusData = null;
  let eventTimer = null;
  let flowTimer = null;
  let statusTimer = null;
  let currentView = "operations";
  let demoOnly = false;
  let demoViewLoaded = false;
  let demoScenarios = [];
  let demoSelectedScenarioId = null;
  let demoSessionId = null;
  let demoDetail = null;
  let demoRefreshTimer = null;
  let demoListTimer = null;

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
    el._timer = setTimeout(() => el.classList.add("hidden"), 8000);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ Accept: "application/json" }, options.headers || {});
    if (token) headers["X-Axion-Token"] = token;
    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, Object.assign({}, options, { headers, cache: "no-store" }));
    if (response.status === 401) {
      showTokenPanel(true);
      const unauthorized = new Error("management token required");
      unauthorized.status = 401;
      throw unauthorized;
    }
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body.error) message = body.error;
      } catch (_) {}
      const error = new Error(message);
      error.status = response.status;
      throw error;
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

  function percent(value) {
    return `${Math.round(Math.max(0, Math.min(1, value || 0)) * 100)}%`;
  }

  function actionClass(action) {
    if (action === "drop" || action === "reject") return "proxy";
    if (action === "allow") return "ok";
    if (action === "log" || action === "monitor") return "warn";
    return "";
  }

  function decisionPill(action, blocked) {
    if (blocked) return pill("blocked", "proxy");
    if (action === "drop" || action === "reject") {
      return `${pill(action, "proxy")}${pill("simulated", "warn")}`;
    }
    return pill(action, actionClass(action));
  }

  function updateStatus(data) {
    statusData = data;
    demoOnly = Boolean(data.demo_only);
    document.body.classList.toggle("demo-only", demoOnly);
    $("status-dot").className = "dot online";
    $("version").textContent = `v${data.version}`;
    const badge = $("mode-badge");
    if (data.demo_only) {
      badge.textContent = "demo";
      badge.className = "badge demo";
    } else {
      badge.textContent = data.mode;
      badge.className = `badge ${data.mode === "enforce" ? "enforce" : "monitor"}`;
    }
    $("mode-monitor").classList.toggle("active", data.mode === "monitor");
    $("mode-enforce").classList.toggle("active", data.mode === "enforce");
    $("mode-enforce").disabled = !data.can_enforce || data.demo_only;
    $("dry-run-btn").textContent = `Dry run: ${data.dry_run ? "on" : "off"}`;
    $("dry-run-btn").classList.toggle("active", data.dry_run);
    $("dry-run-btn").disabled = data.demo_only;
    $("reload-rules").disabled = data.demo_only;
    $("backend").textContent = `backend: ${data.backend} · ${data.capture_source}`;
    $("nav-demos").classList.toggle("hidden", !data.demo_enabled);
    $("open-demos").classList.toggle("hidden", !data.demo_enabled);
    $("nav-operations").classList.toggle("hidden", data.demo_only);
    $("demo-public-note").textContent = data.demo_only
      ? "Public demo mode: production management controls are disabled."
      : "Demo sessions are isolated from production capture and enforcement.";

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
    if (data.demo_only) {
      note = "Demo-only server: no production capture or enforcement is running. Use the Live Demos tab to replay isolated traffic.";
    } else if (!data.can_enforce) {
      note = "Passive capture: classification and rule decisions are evaluated, but packets can never be blocked. Start with --inline (NFQUEUE) to enable enforcement.";
    } else if (data.mode === "enforce" && data.dry_run) {
      note = "Dry-run is active: would-be drops are logged and every packet is accepted.";
    } else if (data.mode === "enforce") {
      note = "Inline NFQUEUE enforcement is active. DROP/REJECT rules are enforced; blocked flows are dropped on subsequent packets.";
    } else {
      note = "Monitor mode on an inline backend: every packet is accepted while classification continues.";
    }
    $("enforcement-note").textContent = note;

    updateProtocols(m.protocols || {}, "protocol-list", "No classified flows yet.");
    drawTrafficChart($("rate-chart"), m.history || [], 220, true);
    if (data.demo_enabled && demoOnly && currentView !== "demos") switchView("demos", false);
  }

  function updateProtocols(protocols, elementId, emptyText) {
    const list = $(elementId);
    const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]).slice(0, 12);
    if (!entries.length) {
      list.innerHTML = `<p class="muted">${escapeHtml(emptyText)}</p>`;
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

  function drawTrafficChart(canvas, history, height = 220, insideLegend = true) {
    if (!canvas || !canvas.isConnected) return;
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 600;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const pad = { left: 52, right: 16, top: 14, bottom: insideLegend ? 28 : 18 };
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
      ctx.fillText(formatRate(value), 2, y);
    }
    if (values.length < 2) {
      ctx.fillStyle = "#7f9aab";
      ctx.font = "12px ui-sans-serif, sans-serif";
      ctx.fillText("Waiting for playback samples…", pad.left + 10, pad.top + 20);
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

    if (insideLegend) {
      ctx.fillStyle = "#39d0d8";
      ctx.fillText("throughput", pad.left, height - 5);
      ctx.fillStyle = "#7ef29a";
      ctx.fillText("packets/s", pad.left + 90, height - 5);
    }
  }

  async function refreshStatus() {
    try {
      const data = await api("/api/status");
      updateStatus(data);
      showTokenPanel(false);
    } catch (err) {
      $("status-dot").className = "dot offline";
      if (err.status !== 401) banner(err.message);
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
          return `<tr>
            <td class="mono">${escapeHtml(timeOf(event.ts_ms))}</td>
            <td class="mono">${escapeHtml(event.src)}:${event.src_port} → ${escapeHtml(event.dst)}:${event.dst_port}<br><span class="muted">${escapeHtml(event.sni || "")}</span></td>
            <td class="evidence">${protocols}<br>${evidence}</td>
            <td class="mono">${Math.round(event.confidence * 100)}%</td>
            <td>${escapeHtml(event.matched_rule || "—")}</td>
            <td>${decisionPill(event.action, event.blocked)}</td>
          </tr>`;
        })
        .join("");
    } catch (err) {
      if (err.status !== 401) banner(err.message);
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
          return `<tr>
            <td class="mono">${escapeHtml(flow.client)}<br>→ ${escapeHtml(flow.server)}<br><span class="muted">${escapeHtml(flow.protocol)} · ${flow.packets} pkts</span></td>
            <td>${protocols || '<span class="muted">unknown</span>'}</td>
            <td class="mono">${names || "—"}</td>
            <td class="mono">${formatBytes(flow.total_bytes)}</td>
            <td class="mono">${Math.round((flow.proxy_score || 0) * 100)}%</td>
            <td>${decisionPill(flow.action, flow.blocked)}<br><span class="muted">${escapeHtml(flow.matched_rule || "")}</span></td>
          </tr>`;
        })
        .join("");
    } catch (err) {
      if (err.status !== 401) banner(err.message);
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
      if (err.status !== 401) banner(err.message);
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

  function switchView(view, updateHash = true) {
    if (view === "operations" && demoOnly) return;
    currentView = view;
    $("view-operations").classList.toggle("hidden", view !== "operations");
    $("view-demos").classList.toggle("hidden", view !== "demos");
    $("nav-operations").classList.toggle("active", view === "operations");
    $("nav-demos").classList.toggle("active", view === "demos");
    $("nav-operations").setAttribute("aria-selected", view === "operations" ? "true" : "false");
    $("nav-demos").setAttribute("aria-selected", view === "demos" ? "true" : "false");
    if (updateHash) {
      try {
        history.replaceState(null, "", view === "demos" ? "#demos" : "#operations");
      } catch (_) {}
    }
    if (view === "demos") {
      if (!demoViewLoaded) initDemos();
      else {
        refreshDemoSessions();
        if (demoSessionId) refreshDemoDetail();
      }
      startDemoPolling();
    } else {
      stopDemoPolling();
    }
  }

  function startDemoPolling() {
    if (!demoRefreshTimer) {
      demoRefreshTimer = setInterval(() => {
        if (currentView === "demos" && demoSessionId) refreshDemoDetail();
      }, 650);
    }
    if (!demoListTimer) {
      demoListTimer = setInterval(() => {
        if (currentView === "demos") refreshDemoSessions();
      }, 2800);
    }
  }

  function stopDemoPolling() {
    if (demoRefreshTimer) clearInterval(demoRefreshTimer);
    if (demoListTimer) clearInterval(demoListTimer);
    demoRefreshTimer = null;
    demoListTimer = null;
  }

  async function initDemos() {
    try {
      const data = await api("/api/demo/scenarios");
      demoScenarios = data.scenarios || [];
      demoViewLoaded = true;
      $("demo-scenario-count").textContent = `${demoScenarios.length} scenarios · max ${data.max_sessions} sessions`;
      renderScenarioCards();
      if (!demoSelectedScenarioId && demoScenarios.length) {
        selectScenario(demoScenarios[0].id, false);
      }
      await refreshDemoSessions();
      if (demoSessionId) await refreshDemoDetail();
    } catch (err) {
      demoViewLoaded = false;
      $("demo-scenario-grid").innerHTML = `<p class="muted">Demo scenarios unavailable: ${escapeHtml(err.message)}</p>`;
      if (err.status !== 401) banner(err.message);
    }
  }

  function renderScenarioCards() {
    const grid = $("demo-scenario-grid");
    if (!demoScenarios.length) {
      grid.innerHTML = '<p class="muted">No demo scenarios are available on this server.</p>';
      return;
    }
    grid.innerHTML = demoScenarios
      .map((scenario) => {
        const active = scenario.id === demoSelectedScenarioId ? " active" : "";
        const mode = scenario.enforcement_demo ? "policy demo" : "classification demo";
        return `<button type="button" class="scenario-card${active}" data-scenario-id="${escapeHtml(scenario.id)}" aria-pressed="${active ? "true" : "false"}">
          <span class="scenario-number">${String(scenario.number).padStart(2, "0")}</span>
          <span class="scenario-body">
            <span class="scenario-title">${escapeHtml(scenario.title)}</span>
            <span class="scenario-tagline">${escapeHtml(scenario.tagline)}</span>
            <span class="scenario-meta">${scenario.fixtures.length} fixture${scenario.fixtures.length === 1 ? "" : "s"} · ${mode}</span>
          </span>
          <span class="scenario-arrow" aria-hidden="true">→</span>
        </button>`;
      })
      .join("");
  }

  function selectScenario(id, focusRunner = false) {
    const scenario = demoScenarios.find((item) => item.id === id);
    if (!scenario) return;
    demoSelectedScenarioId = id;
    renderScenarioCards();
    renderScenarioInfo(scenario);
    setDemoControls(demoDetail);
    if (focusRunner) {
      $("demo-runner-title").scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  function renderScenarioInfo(scenario) {
    $("demo-info-title").textContent = scenario.title;
    $("demo-info-number").textContent = `Demo ${scenario.number}`;
    $("demo-info-tagline").textContent = scenario.tagline;
    $("demo-info-description").textContent = scenario.description;
    $("demo-info-focus").innerHTML = (scenario.focus || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    $("demo-info-expected").innerHTML = (scenario.expected || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    $("demo-info-caveats").innerHTML = (scenario.caveats || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    $("demo-info-fixtures").textContent = (scenario.fixtures || []).join(" · ");
    if (!demoDetail) {
      $("demo-runner-title").textContent = scenario.title;
      $("demo-runner-sub").textContent = scenario.tagline;
    }
  }

  function setDemoControls(detail) {
    const state = detail ? detail.state : null;
    $("demo-pause").disabled = state !== "playing";
    $("demo-resume").disabled = state !== "paused";
    $("demo-reset").disabled = !detail;
    $("demo-stop").disabled = !detail;
    $("demo-start").disabled = !demoSelectedScenarioId || !demoViewLoaded;
    const badge = $("demo-state-badge");
    badge.textContent = state || "idle";
    badge.className = `badge demo-state ${state || "idle"}`;
  }

  function resetDemoPanels(message) {
    demoDetail = null;
    setDemoControls(null);
    $("demo-stat-frames").textContent = "0";
    $("demo-stat-packets").textContent = "0";
    $("demo-stat-bytes").textContent = "0 bytes";
    $("demo-stat-flows").textContent = "0";
    $("demo-stat-detections").textContent = "0";
    $("demo-stat-drops").textContent = "0";
    $("demo-stat-progress").textContent = "0%";
    $("demo-progress-bar").style.width = "0%";
    $("demo-progress-text").textContent = "No session";
    $("demo-session-note").textContent = message || "Playback runs in passive monitor mode. Drop verdicts are simulated and never affect real packets.";
    $("demo-flows-body").innerHTML = '<tr><td colspan="6" class="empty">Start a demo to inspect flows.</td></tr>';
    $("demo-events-body").innerHTML = '<tr><td colspan="6" class="empty">Start a demo to inspect detection events.</td></tr>';
    updateProtocols({}, "demo-protocol-list", "No classifications yet.");
    drawTrafficChart($("demo-rate-chart"), [], 240, false);
  }

  async function startDemoScenario() {
    if (!demoSelectedScenarioId) {
      banner("Select a demo scenario first.");
      return;
    }
    const speed = Number($("demo-speed").value) || 1;
    $("demo-start").disabled = true;
    try {
      const detail = await api("/api/demo/sessions", {
        method: "POST",
        body: JSON.stringify({ scenario_id: demoSelectedScenarioId, speed }),
      });
      demoSessionId = detail.id;
      demoDetail = detail;
      renderDemoDetail(detail);
      renderScenarioInfo(detail.scenario);
      await refreshDemoSessions();
      startDemoPolling();
      banner(`Started ${detail.scenario_title} at ${speed}×.`);
    } catch (err) {
      banner(`Could not start demo: ${err.message}`);
      setDemoControls(demoDetail);
    }
  }

  async function demoControl(action) {
    if (!demoSessionId) return;
    try {
      if (action === "stop") {
        await api(`/api/demo/sessions/${encodeURIComponent(demoSessionId)}`, { method: "DELETE" });
        const stopped = demoSessionId;
        demoSessionId = null;
        resetDemoPanels(`Session ${stopped} stopped and released.`);
        await refreshDemoSessions();
        banner("Demo session stopped.");
        return;
      }
      const detail = await api(`/api/demo/sessions/${encodeURIComponent(demoSessionId)}/${action}`, {
        method: "POST",
        body: action === "speed" ? JSON.stringify({ speed: Number($("demo-speed").value) || 1 }) : "{}",
      });
      demoDetail = detail;
      renderDemoDetail(detail);
      await refreshDemoSessions();
    } catch (err) {
      banner(`${action} failed: ${err.message}`);
    }
  }

  async function applyDemoSpeed() {
    if (!demoSessionId) return;
    await demoControl("speed");
  }

  async function refreshDemoSessions() {
    try {
      const data = await api("/api/demo/sessions");
      renderSessionList(data.sessions || []);
    } catch (err) {
      if (err.status !== 401) banner(err.message);
    }
  }

  function renderSessionList(sessions) {
    const list = $("demo-session-list");
    if (!sessions.length) {
      list.innerHTML = '<span class="muted">No playback sessions yet.</span>';
      return;
    }
    list.innerHTML = sessions
      .map((session) => {
        const active = session.id === demoSessionId ? " active" : "";
        return `<button type="button" class="session-chip${active}" data-session-id="${escapeHtml(session.id)}" title="${escapeHtml(session.id)}">
          <span class="session-title">${escapeHtml(session.scenario_title)}</span>
          <span class="session-state ${escapeHtml(session.state)}">${escapeHtml(session.state)}</span>
          <span class="session-progress">${percent(session.progress)}</span>
        </button>`;
      })
      .join("");
  }

  async function refreshDemoDetail() {
    if (!demoSessionId) return;
    try {
      const detail = await api(`/api/demo/sessions/${encodeURIComponent(demoSessionId)}?limit=200`);
      demoDetail = detail;
      renderDemoDetail(detail);
    } catch (err) {
      if (err.status === 404) {
        const missing = demoSessionId;
        demoSessionId = null;
        resetDemoPanels(`Session ${missing} is no longer available.`);
        await refreshDemoSessions();
      } else if (err.status !== 401) {
        banner(err.message);
      }
    }
  }

  function renderDemoDetail(detail) {
    const summary = detail;
    const pct = percent(summary.progress);
    if (detail.scenario) {
      demoSelectedScenarioId = detail.scenario.id;
      renderScenarioCards();
      renderScenarioInfo(detail.scenario);
    }
    $("demo-runner-title").textContent = summary.scenario_title;
    $("demo-runner-sub").textContent = detail.scenario ? detail.scenario.tagline : "Deterministic fixture replay";
    $("demo-stat-frames").textContent = `${summary.processed_frames} / ${summary.total_frames}`;
    $("demo-stat-packets").textContent = Number(summary.packets || 0).toLocaleString();
    $("demo-stat-bytes").textContent = `${formatBytes(summary.bytes || 0)} processed`;
    $("demo-stat-flows").textContent = Number(summary.active_flows || 0).toLocaleString();
    $("demo-stat-detections").textContent = Number(summary.detections || 0).toLocaleString();
    $("demo-stat-drops").textContent = Number(summary.simulated_drops || 0).toLocaleString();
    $("demo-stat-progress").textContent = pct;
    $("demo-progress-bar").style.width = pct;
    $("demo-progress-text").textContent = `${summary.processed_frames} / ${summary.total_frames} frames · ${pct} · ${summary.speed}× · ${summary.state}`;
    if (summary.speed) $("demo-speed").value = String(summary.speed);
    const note = detail.enforcement
      ? `${detail.enforcement.note} Engine mode: ${detail.enforcement.mode}; can_enforce=${detail.enforcement.can_enforce}; real enforcement=${detail.enforcement.enforcement_active}.`
      : "Passive monitor mode.";
    $("demo-session-note").textContent = note;
    setDemoControls(detail);
    updateProtocols((detail.metrics && detail.metrics.protocols) || {}, "demo-protocol-list", "No classifications yet.");
    drawTrafficChart($("demo-rate-chart"), (detail.metrics && detail.metrics.history) || [], 240, false);
    renderDemoFlows(detail.flows || []);
    renderDemoEvents(detail.events || []);
  }

  function metadataLines(flow) {
    const parts = [];
    if (flow.sni) parts.push(`<div><span class="meta-key">SNI</span> <span class="mono">${escapeHtml(flow.sni)}</span></div>`);
    if (flow.alpn && flow.alpn.length) parts.push(`<div><span class="meta-key">ALPN</span> <span class="mono">${escapeHtml(flow.alpn.join(", "))}</span></div>`);
    if (flow.tls_version) {
      const extras = [];
      if (flow.tls_cipher_count) extras.push(`${flow.tls_cipher_count} ciphers`);
      if (flow.tls_extension_count) extras.push(`${flow.tls_extension_count} extensions`);
      if (flow.tls_grease_count) extras.push(`${flow.tls_grease_count} GREASE`);
      if (flow.tls_ech_present) extras.push("ECH");
      parts.push(`<div><span class="meta-key">TLS</span> <span class="mono">${escapeHtml(flow.tls_version)}${extras.length ? " · " + escapeHtml(extras.join(" · ")) : ""}</span></div>`);
    }
    if (flow.tls_ja3) parts.push(`<div><span class="meta-key">JA3</span> <span class="mono">${escapeHtml(flow.tls_ja3)}</span></div>`);
    if (flow.http_method) {
      const target = flow.http_target ? ` ${flow.http_target}` : "";
      parts.push(`<div><span class="meta-key">HTTP</span> <span class="mono">${escapeHtml(flow.http_method + target)}</span></div>`);
    }
    if (flow.http_host) parts.push(`<div><span class="meta-key">Host</span> <span class="mono">${escapeHtml(flow.http_host)}</span></div>`);
    if (flow.dns_names && flow.dns_names.length) {
      const qtype = flow.dns_qtype ? ` ${flow.dns_qtype}` : "";
      parts.push(`<div><span class="meta-key">DNS</span> <span class="mono">${escapeHtml(flow.dns_names.join(", ") + qtype)}</span></div>`);
    }
    const evidence = (flow.evidence || []).slice(0, 3);
    if (evidence.length) {
      parts.push(`<div class="flow-evidence">${evidence.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>`);
    }
    return parts.length ? `<div class="meta-list">${parts.join("")}</div>` : '<span class="muted">No extra metadata</span>';
  }

  function renderDemoFlows(flows) {
    const body = $("demo-flows-body");
    if (!flows.length) {
      body.innerHTML = '<tr><td colspan="6" class="empty">No flows yet. The session may still be starting.</td></tr>';
      return;
    }
    body.innerHTML = flows
      .map((flow) => {
        const protocols = (flow.detected_protocols || []).map((p) => pill(p)).join("") || '<span class="muted">unknown</span>';
        const categories = Object.entries(flow.categories || {})
          .filter(([, score]) => score > 0)
          .map(([name, score]) => pill(`${name} ${percent(score)}`, name === "proxy" ? "proxy" : name === "obfuscation" ? "warn" : ""));
        return `<tr>
          <td class="mono flow-endpoints">${escapeHtml(flow.client)}<br><span class="flow-arrow">→</span> ${escapeHtml(flow.server)}<br><span class="muted">${escapeHtml(flow.protocol)} · flow ${flow.id} · ${flow.duration_ms} ms</span></td>
          <td>${protocols}${categories.length ? `<div class="pill-row">${categories.join("")}</div>` : ""}</td>
          <td>${metadataLines(flow)}</td>
          <td class="mono">${Number(flow.packets).toLocaleString()} pkts<br>${formatBytes(flow.total_bytes)}<br><span class="muted">${Number(flow.client_bytes).toLocaleString()} ↑ / ${Number(flow.server_bytes).toLocaleString()} ↓</span></td>
          <td class="mono">${percent(flow.confidence)}<br><span class="muted">proxy ${percent(flow.proxy_score)}</span></td>
          <td>${decisionPill(flow.action, flow.blocked)}<br><span class="muted">${escapeHtml(flow.matched_rule || "policy default")}</span></td>
        </tr>`;
      })
      .join("");
  }

  function renderDemoEvents(events) {
    const body = $("demo-events-body");
    if (!events.length) {
      body.innerHTML = '<tr><td colspan="6" class="empty">No detection events for this scenario yet. Benign traffic can produce none by design.</td></tr>';
      return;
    }
    body.innerHTML = events
      .map((event) => {
        const protocols = (event.protocols || []).map((p) => pill(p)).join("");
        const categories = (event.categories || []).map((c) => pill(c, "warn")).join("");
        const evidence = (event.evidence || []).map((item) => `<div class="evidence-line">${escapeHtml(item)}</div>`).join("");
        return `<tr>
          <td class="mono">${escapeHtml(timeOf(event.ts_ms))}<br><span class="muted">flow ${event.flow_id}</span></td>
          <td class="mono">${escapeHtml(event.src)}:${event.src_port}<br>→ ${escapeHtml(event.dst)}:${event.dst_port}<br><span class="muted">${escapeHtml(event.transport)}${event.sni ? " · " + escapeHtml(event.sni) : ""}</span></td>
          <td>${protocols}<div class="pill-row">${categories}</div></td>
          <td class="evidence">${evidence}</td>
          <td class="mono">${percent(event.confidence)}<br><span class="muted">proxy ${percent(event.proxy_score)}</span></td>
          <td>${decisionPill(event.action, event.blocked)}<br><span class="muted">${escapeHtml(event.matched_rule || "policy default")}</span></td>
        </tr>`;
      })
      .join("");
  }

  function saveToken() {
    token = $("token-input").value.trim();
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
      showTokenPanel(false);
      banner("");
      demoViewLoaded = false;
      start();
      if (currentView === "demos") initDemos();
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
  $("nav-operations").addEventListener("click", () => switchView("operations"));
  $("nav-demos").addEventListener("click", () => switchView("demos"));
  $("open-demos").addEventListener("click", () => switchView("demos"));
  $("demo-start").addEventListener("click", startDemoScenario);
  $("demo-pause").addEventListener("click", () => demoControl("pause"));
  $("demo-resume").addEventListener("click", () => demoControl("resume"));
  $("demo-reset").addEventListener("click", () => demoControl("reset"));
  $("demo-stop").addEventListener("click", () => demoControl("stop"));
  $("demo-speed").addEventListener("change", applyDemoSpeed);
  $("demo-scenario-grid").addEventListener("click", (event) => {
    const card = event.target.closest("[data-scenario-id]");
    if (!card) return;
    selectScenario(card.dataset.scenarioId, false);
  });
  $("demo-session-list").addEventListener("click", (event) => {
    const chip = event.target.closest("[data-session-id]");
    if (!chip) return;
    demoSessionId = chip.dataset.sessionId;
    demoDetail = null;
    resetDemoPanels("Loading selected session…");
    refreshDemoDetail();
    refreshDemoSessions();
  });
  window.addEventListener("resize", () => {
    if (statusData) drawTrafficChart($("rate-chart"), statusData.metrics.history || [], 220, true);
    if (demoDetail) drawTrafficChart($("demo-rate-chart"), (demoDetail.metrics && demoDetail.metrics.history) || [], 240, false);
  });

  if (token) showTokenPanel(false);
  start();
  if (window.location.hash === "#demos") switchView("demos", false);
  resetDemoPanels();
})();
