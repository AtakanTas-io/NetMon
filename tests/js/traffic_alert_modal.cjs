const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const fields = {};
for (const id of ['alertRuleType', 'alertRuleThresholdLabel', 'alertRuleThreshold', 'alertRuleMultiplierField',
  'alertRuleWindowHint', 'alertRuleTarget', 'alertRuleName', 'alertRuleLevel', 'alertRuleEmail', 'alertRuleWebhook',
  'alertRuleCooldown']) fields[id] = {value: '', checked: false};
let html = '';
let submitted;
const context = vm.createContext({
  $: id => fields[id], openModal: value => {html = value;},
  post: async (url, body) => {submitted = {url, body};}, closeModalForce() {}, toast() {},
});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/js/diagnostics.js'), 'utf8')
  .replace(/^import .*;\s*$/mg, ''), context);
vm.runInContext('refreshSecurity = () => {};', context);
context.openAlertRuleModal();
const select = html.match(/<select id="alertRuleType"[^>]*>(.*?)<\/select>/s)[1];
assert.deepEqual([...select.matchAll(/value="([^"]+)"/g)].map(item => item[1]),
  ['offline_duration', 'new_device', 'rogue_dhcp', 'ip_conflict', 'config_diff', 'bandwidth_spike', 'connection_burst']);
fields.alertRuleThreshold.value = '120';
fields.alertRuleTarget.value = '4x';
fields.alertRuleName.value = 'Trafik';
fields.alertRuleCooldown.value = '900';
fields.alertRuleLevel.value = 'warning';
(async () => {
  for (const type of ['bandwidth_spike', 'connection_burst', 'offline_duration']) {
    fields.alertRuleType.value = type;
    context.updateAlertRuleFields();
    assert.equal(fields.alertRuleThresholdLabel.textContent, type === 'offline_duration' ? 'Eşik (saniye)' : 'Pencere (saniye)');
    assert.equal(fields.alertRuleMultiplierField.hidden, type !== 'bandwidth_spike');
    await context.createAlertRule();
    assert.equal(submitted.url, '/api/alert-rules');
    assert.equal(submitted.body.target, type === 'bandwidth_spike' ? '4x' : '');
    assert.equal(submitted.body.threshold_seconds, 120);
    assert.equal(submitted.body.rule_type, type);
  }
  console.log('Alarm seçenekleri, pencere etiketi ve çarpan kaydı kontrolleri geçti.');
})().catch(error => {console.error(error); process.exitCode = 1;});
