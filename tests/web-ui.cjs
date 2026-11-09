#!/usr/bin/env node
/* Static checks for the embedded dashboard. Dependency-free and CI-friendly. */
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "src/api/dashboard.html"), "utf8");
const js = fs.readFileSync(path.join(root, "src/api/dashboard.js"), "utf8");
const css = fs.readFileSync(path.join(root, "src/api/dashboard.css"), "utf8");
const api = fs.readFileSync(path.join(root, "src/api/mod.rs"), "utf8");
const errors = [];

const requiredIds = [
  "status-dot",
  "mode-badge",
  "mode-monitor",
  "mode-enforce",
  "dry-run-btn",
  "reload-rules",
  "stat-bps",
  "stat-pps",
  "stat-flows",
  "stat-blocked",
  "stat-detections",
  "stat-cpu",
  "stat-mem",
  "stat-uptime",
  "rate-chart",
  "protocol-list",
  "events-body",
  "flows-body",
  "rules-list",
  "token-panel",
  "token-input",
  "token-save",
  "nav-operations",
  "nav-demos",
  "view-operations",
  "view-demos",
  "demo-scenario-grid",
  "demo-session-list",
  "demo-speed",
  "demo-start",
  "demo-pause",
  "demo-resume",
  "demo-reset",
  "demo-stop",
  "demo-state-badge",
  "demo-progress-bar",
  "demo-progress-text",
  "demo-stat-frames",
  "demo-stat-packets",
  "demo-stat-bytes",
  "demo-stat-flows",
  "demo-stat-detections",
  "demo-stat-drops",
  "demo-stat-progress",
  "demo-rate-chart",
  "demo-protocol-list",
  "demo-flows-body",
  "demo-events-body",
  "demo-info-title",
  "demo-info-description",
  "demo-info-focus",
  "demo-info-expected",
  "demo-info-caveats",
  "demo-info-fixtures",
  "demo-session-note",
  "demo-public-note",
];
for (const id of requiredIds) {
  if (!html.includes(`id="${id}"`)) errors.push(`missing dashboard element #${id}`);
}
const seenIds = new Set();
for (const match of html.matchAll(/id="([^"]+)"/g)) {
  if (seenIds.has(match[1])) errors.push(`duplicate dashboard element #${match[1]}`);
  seenIds.add(match[1]);
}

for (const endpoint of ["/api/status", "/api/events", "/api/flows", "/api/rules", "/api/rules/reload", "/api/mode", "/api/dry-run"]) {
  if (!api.includes(`"${endpoint}"`)) errors.push(`API route missing ${endpoint}`);
  if (!js.includes(endpoint)) errors.push(`dashboard JavaScript does not call ${endpoint}`);
}

const demoRoutes = [
  "/api/demo/scenarios",
  "/api/demo/status",
  "/api/demo/sessions",
  "/api/demo/sessions/{id}",
  "/api/demo/sessions/{id}/status",
  "/api/demo/sessions/{id}/flows",
  "/api/demo/sessions/{id}/events",
  "/api/demo/sessions/{id}/pause",
  "/api/demo/sessions/{id}/resume",
  "/api/demo/sessions/{id}/reset",
  "/api/demo/sessions/{id}/speed",
  "/api/demo/sessions/{id}/stop",
];
for (const endpoint of demoRoutes) {
  if (!api.includes(`"${endpoint}"`)) errors.push(`demo API route missing ${endpoint}`);
}
for (const fragment of [
  "/api/demo/scenarios",
  "/api/demo/sessions",
  "/api/demo/sessions/",
  "scenario_id",
  "demoControl(\"pause\")",
  "demoControl(\"resume\")",
  "demoControl(\"reset\")",
  "demoControl(\"stop\")",
  "applyDemoSpeed",
]) {
  if (!js.includes(fragment)) errors.push(`dashboard JavaScript is missing demo integration ${fragment}`);
}
for (const marker of ["DEMO DATA", "No decryption claims", "no firewall changes", "simulated"]) {
  if (!html.includes(marker)) errors.push(`dashboard is missing demo safety text: ${marker}`);
}
if (!api.includes("demo_only_mutation")) errors.push("API is missing the demo-only management guard");
if (!api.includes("demo_only") || !api.includes("production management operations are disabled")) {
  errors.push("API does not expose a demo-only safety mode");
}
if (!js.includes("demo_only")) errors.push("dashboard does not react to demo-only mode");
if (!js.includes("demoDetail") || !js.includes("renderDemoFlows") || !js.includes("renderDemoEvents")) {
  errors.push("dashboard does not render live demo metrics, flows and events");
}
if (!js.includes("X-Axion-Token")) errors.push("dashboard does not send the management token header");
if (!api.includes("Content-Security-Policy") && !api.includes("CONTENT_SECURITY_POLICY")) {
  errors.push("API is missing a CSP header");
}
if (!api.includes("X_FRAME_OPTIONS")) errors.push("API is missing X-Frame-Options");
if (!api.includes("DefaultBodyLimit")) errors.push("API is missing its request body limit");
if (/https?:\/\//.test(html.replace(/https?:\/\/github\.com\/[^\s"']+/g, ""))) {
  errors.push("dashboard must not load external resources");
}
if (html.includes("<script>")) errors.push("dashboard must not use inline scripts (CSP)");
if (!css.includes("--accent")) errors.push("dashboard CSS did not load as expected");
if (!css.includes(".scenario-card") || !css.includes(".demo-ribbon")) {
  errors.push("dashboard CSS is missing the Live Demos layout");
}
try {
  new Function(js);
} catch (error) {
  errors.push(`dashboard JavaScript does not parse: ${error.message}`);
}
if (!html.includes("Axion") && !html.includes("AXION")) errors.push("dashboard title missing");

if (errors.length) {
  console.error("dashboard checks failed:");
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}
console.log(`dashboard checks passed (${requiredIds.length} elements, ${js.length + css.length + html.length} bytes of embedded assets)`);
