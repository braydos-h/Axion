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
];
for (const id of requiredIds) {
  if (!html.includes(`id="${id}"`)) errors.push(`missing dashboard element #${id}`);
}
for (const endpoint of ["/api/status", "/api/events", "/api/flows", "/api/rules", "/api/rules/reload", "/api/mode", "/api/dry-run"]) {
  if (!api.includes(`"${endpoint}"`)) errors.push(`API route missing ${endpoint}`);
  if (!js.includes(endpoint)) errors.push(`dashboard JavaScript does not call ${endpoint}`);
}
if (!js.includes("X-Axion-Token")) errors.push("dashboard does not send the management token header");
if (!api.includes("Content-Security-Policy") && !api.includes("CONTENT_SECURITY_POLICY")) {
  errors.push("API is missing a CSP header");
}
if (!api.includes("X_FRAME_OPTIONS")) errors.push("API is missing X-Frame-Options");
if (/https?:\/\//.test(html.replace(/https?:\/\/github\.com\/[^\s"']+/g, ""))) {
  errors.push("dashboard must not load external resources");
}
if (html.includes("<script>")) errors.push("dashboard must not use inline scripts (CSP)");
if (!css.includes("--accent")) errors.push("dashboard CSS did not load as expected");
if (!html.includes("Axion") && !html.includes("AXION")) errors.push("dashboard title missing");

if (errors.length) {
  console.error("dashboard checks failed:");
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}
console.log(`dashboard checks passed (${requiredIds.length} elements, ${js.length + css.length + html.length} bytes of embedded assets)`);
