// Lightweight browser-contract smoke test; run with node tests/web-ui.cjs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(id = '') { this.id = id; this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false; this.checked = false; this.children = []; this.listeners = {}; this.classList = { add() {} }; }
  addEventListener(event, callback) { this.listeners[event] = callback; }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  setAttribute() {}
  insertRow() { const row = new Element(); this.append(row); return row; }
  insertCell() { const cell = new Element(); this.append(cell); return cell; }
  get options() { return this.children; }
  dispatch(event) { return this.listeners[event]?.({ preventDefault() {}, key: '' }); }
}
const elements = new Map();
const element = id => { if (!elements.has(id)) elements.set(id, new Element(id)); return elements.get(id); };
element('filter').value = 'all';
const settings = {preferred_interface:null, auto_interface:true, web_host:'127.0.0.1', web_port:8080, strict_port:false, open_browser:false, start_capture:true, ai_enabled:false, max_flows:10000, flow_timeout_seconds:120, log_filter:'axion=info'};
let status = {capture_running:false, ai_status:'disabled', interface:'test0', mode:'live', ai_enabled:false, last_error:null};
const calls = [];
async function fetch(path, options = {}) {
  calls.push({path, ...options});
  let data;
  if (path === '/api/status') data = status;
  else if (path === '/api/stats') data = {packets_captured:3, total_bytes:120, active_flows:3, tcp_flows:2, udp_flows:1};
  else if (path === '/api/flows?limit=1000') data = {flows:[]};
  else if (path === '/api/interfaces') data = {interfaces:['test0'], details:[{name:'test0',addresses:['192.0.2.1']}]};
  else if (path === '/api/config' && !options.method) data = settings;
  else if (path === '/api/config' && options.method === 'PUT') data = {settings:JSON.parse(options.body),restart_required:true};
  else if (path === '/api/capture/start') { status = {...status, capture_running:true}; data = status; }
  else if (path === '/api/capture/stop') { status = {...status, capture_running:false}; data = status; }
  else if (path === '/api/capture/restart') { status = {...status, capture_running:true}; data = status; }
  else if (path === '/api/control/interface') { status = {...status, interface:JSON.parse(options.body).interface}; data = status; }
  else if (path === '/api/interfaces/auto') { status = {...status, interface:'test0'}; data = status; }
  else if (path === '/api/config/reset') data = {settings,restart_required:true};
  else throw Error(`Unexpected request: ${path}`);
  return {ok:true, json:async () => data};
}
class Socket { constructor() { this.listeners = {}; Socket.instance = this; } addEventListener(name, cb) { this.listeners[name] = cb; } }
const context = {document:{getElementById:element,createElement:() => new Element()}, location:{protocol:'http:',host:'127.0.0.1:8080'}, fetch, WebSocket:Socket, requestAnimationFrame:fn => fn(), setTimeout(){}, setInterval(){}, console, Date, Map, Number, String, JSON};
vm.runInNewContext(fs.readFileSync('web/app.js','utf8'), context);
const flush = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  await flush(); await flush();
  assert.equal(element('packets-captured').textContent, '3');
  assert.equal(element('flow-protocols').textContent, 'TCP 2 · UDP 1');
  assert.match(element('interface').children[1].textContent, /192\.0\.2\.1/);
  assert.equal(element('dashboard-address').textContent, 'Dashboard 127.0.0.1:8080');
  element('interface').value = 'auto';
  element('capture-start').dispatch('click');
  await flush(); await flush();
  const start = calls.find(call => call.path === '/api/capture/start');
  assert.equal(start.method, 'POST');
  assert.equal(JSON.parse(start.body).interface, 'auto');
  assert.equal(element('capture-status').textContent, 'Capture running');
  element('capture-stop').dispatch('click');
  await flush(); await flush();
  assert.equal(element('capture-status').textContent, 'Capture stopped');
  element('interface').value = 'test0';
  element('select-interface').dispatch('click');
  await flush(); await flush();
  assert.equal(JSON.parse(calls.find(call => call.path === '/api/control/interface').body).interface, 'test0');
  element('detect-interface').dispatch('click');
  await flush(); await flush();
  assert.ok(calls.some(call => call.path === '/api/interfaces/auto'));
  element('capture-restart').dispatch('click');
  await flush(); await flush();
  assert.ok(calls.some(call => call.path === '/api/capture/restart'));
  element('web-port').value = '8085';
  element('settings-form').dispatch('submit');
  await flush(); await flush();
  const save = calls.find(call => call.path === '/api/config' && call.method === 'PUT');
  assert.equal(JSON.parse(save.body).web_port, 8085);
  assert.match(element('settings-state').textContent, /next launch/);
  element('reset-settings').dispatch('click');
  await flush(); await flush();
  assert.ok(calls.some(call => call.path === '/api/config/reset'));
  assert.equal(element('web-port').value, 8080);
  Socket.instance.listeners.open();
  assert.equal(element('socket-status').textContent, 'Live updates connected');
  Socket.instance.listeners.message({data:JSON.stringify({type:'status',data:{...status,capture_running:true}})});
  assert.equal(element('capture-status').textContent, 'Capture running');
  console.log('Web UI contract smoke test passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
