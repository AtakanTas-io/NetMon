const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const elements = {topTalkersFullLeaderboard: {innerHTML: ''}, trafficFilterResult: {textContent: ''}};
for (const name of ['trafficSessionSearch', 'trafficUserFilter', 'trafficDirectionFilter',
  'trafficStateFilter', 'trafficScopeFilter', 'trafficAttentionFilter']) elements[name] = {value: ''};
const events = {};
const menus = [];
let now = 10000;
const context = vm.createContext({
  $: id => elements[id],
  esc: value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c])),
  Date: {now: () => now},
  document: {
    addEventListener: (name, handler) => {events[name] = handler;},
    querySelectorAll: () => menus.filter(menu => menu.classList.contains('is-open')),
    querySelector: () => menus.find(menu => menu.classList.contains('is-open'))?.button,
  },
});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/js/traffic.js'), 'utf8')
  .replace(/^import .*;\s*$/mg, ''), context);
function render() {context.renderTrafficSessions(); return elements.topTalkersFullLeaderboard.innerHTML;}
function classes() {
  const values = new Set();
  return {contains: value => values.has(value), remove: value => values.delete(value), toggle(value, force) {
    const enabled = force ?? !values.has(value);
    if (enabled) values.add(value); else values.delete(value);
    return enabled;
  }};
}
const base = {process_name: 'Browser.exe', pid: 10, process_username: 'alice', local_ip: '10.0.0.1',
  local_port: 5000, remote_ip: '8.8.8.8', remote_port: 443, state: 'ESTABLISHED', direction: 'outbound',
  scope: 'internet', attention_level: 'normal', destination_source: 'inventory'};
const sessions = [base, {...base, local_port: 5001}, {...base, pid: 20}, {...base, local_ip: '10.0.0.2'}];
context.updateTrafficSessionsSnapshot(sessions);
let html = render();
assert.equal((html.match(/class="traffic-session-group/g) || []).length, 3);
assert.equal((html.match(/class="traffic-session-row/g) || []).length, 4);
assert.ok(html.includes('2 bağlantı'));
assert.ok(!html.includes('highlight-flash'));
assert.ok(!html.includes('traffic-session-group is-open'));
assert.equal(elements.trafficFilterResult.textContent, '4 / 4 bağlantı gösteriliyor');
for (const heading of ['Yerel uç', 'Uzak uç', 'Servis / port', 'Yön', 'TCP durumu', 'Kapsam']) assert.ok(html.includes(heading));
for (const handler of ['quickPing(this.dataset.ip)', 'quickTraceroute(this.dataset.ip)',
  "openDeviceDrawer('', this.dataset.ip)", 'copyToClipboard(this.dataset.address, this)']) assert.ok(html.includes(handler));

const group = {classList: classes(), dataset: {groupKey: context.trafficSessionGroupKey(base)}};
const arrow = {};
const button = {closest: () => group, setAttribute: (key, value) => {button[key] = value;}, querySelector: () => arrow};
context.toggleTrafficSessionGroup(button);
assert.equal(button['aria-expanded'], 'true');
assert.equal(arrow.textContent, '▾');
elements.trafficSessionSearch.value = 'missing';
assert.ok(render().includes('eşleşen bağlantı yok'));
elements.trafficSessionSearch.value = 'browser';
assert.ok(render().includes('traffic-session-group is-open'));
elements.trafficDirectionFilter.value = 'inbound';
assert.ok(render().includes('eşleşen bağlantı yok'));
elements.trafficDirectionFilter.value = 'all';
assert.ok(render().includes('traffic-session-group is-open'));
context.toggleTrafficSessionGroup(button);
assert.equal(button['aria-expanded'], 'false');

context.updateTrafficSessionsSnapshot([...sessions, {...base, local_port: 6000}]);
assert.equal((render().match(/highlight-flash/g) || []).length, 2); // Yeni satır ve kapalı grup başlığı.
now += 1600;
assert.ok(!render().includes('highlight-flash'));
context.updateTrafficSessionsSnapshot(sessions.map(s => ({...s, state: 'CLOSE_WAIT'})));
assert.ok(!render().includes('highlight-flash'));

for (let i = 0; i < 2; i++) {
  const menu = {classList: classes()};
  menu.button = {closest: () => menu, setAttribute: (key, value) => {menu.button[key] = value;}, focus() {}};
  menu.querySelector = () => menu.button;
  menus.push(menu);
}
context.toggleTrafficSessionMenu(menus[0].button);
context.toggleTrafficSessionMenu(menus[1].button);
assert.equal(menus[0].button['aria-expanded'], 'false');
assert.equal(menus[1].button['aria-expanded'], 'true');
events.click({target: {closest: () => null}});
assert.equal(menus[1].button['aria-expanded'], 'false');
context.toggleTrafficSessionMenu(menus[0].button);
events.keydown({key: 'Escape'});
assert.equal(menus[0].button['aria-expanded'], 'false');

elements.trafficSessionSearch.value = '';
context.updateTrafficSessionsSnapshot([{...base, process_name: '<img onerror="attack()">', remote_ip: "x');attack();//"}]);
html = render();
assert.ok(!html.includes('<img'));
assert.ok(html.includes('&lt;img'));
assert.ok(!html.includes("quickPing('x"));
context.updateTrafficSessionsSnapshot([]);
assert.ok(render().includes('açık TCP bağlantısı bulunamadı'));
assert.equal(elements.trafficFilterResult.textContent, '0 / 0 bağlantı gösteriliyor');
console.log('Oturum gruplama, filtre, menü, XSS ve canlı vurgu kontrolleri geçti.');
