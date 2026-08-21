import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# 1. Add Dropdown to UI
old_search_input = '<input type="text" id="devFilter" placeholder="IP, Donanım, OS veya Ad ara..." style="width:200px" oninput="renderDeviceTable()" />'
new_filters = '''<input type="text" id="devFilter" placeholder="IP, Donanım, OS veya Ad ara..." style="width:200px" oninput="renderDeviceTable()" />
            <select id="devSubnetFilter" onchange="S.deviceSubnetFilter=this.value;renderDeviceTable()" style="width:135px; background:var(--panel-2); color:var(--txt); border:1px solid var(--line); border-radius:6px;">
              <option value="all">🌐 Tüm Ağlar</option>
            </select>'''
c = c.replace(old_search_input, new_filters)

# 2. Update renderDeviceTable to populate dropdown and filter
render_func_start = 'const q = ($("devFilter")?.value || "").toLowerCase().trim();'
inject_filter_logic = '''const q = ($("devFilter")?.value || "").toLowerCase().trim();
  
  // Alt Ağ (Subnet) Filtresini Dinamik Doldur
  const subnetSelect = $("devSubnetFilter");
  if (subnetSelect) {
    const currentVal = S.deviceSubnetFilter || "all";
    const nets = [...new Set(S.devices.filter(d=>d.ip).map(d => {
      const parts = d.ip.split('.');
      return parts.length === 4 ? parts.slice(0,3).join('.') + '.*' : 'Bilinmeyen';
    }))].filter(x => x !== 'Bilinmeyen').sort();
    
    let html = `<option value="all">🌐 Tüm Ağlar</option>`;
    nets.forEach(n => {
       html += `<option value="${n}" ${currentVal===n?'selected':''}>${n}</option>`;
    });
    subnetSelect.innerHTML = html;
  }
'''
c = c.replace(render_func_start, inject_filter_logic)

filter_condition_start = 'if (S.deviceStatusFilter && S.deviceStatusFilter !== "all") {'
inject_condition = '''
    if (S.deviceSubnetFilter && S.deviceSubnetFilter !== "all") {
       const prefix = S.deviceSubnetFilter.replace('.*', '');
       if (!d.ip || !d.ip.startsWith(prefix + '.')) return false;
    }
    if (S.deviceStatusFilter && S.deviceStatusFilter !== "all") {
'''
c = c.replace(filter_condition_start, inject_condition)


with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("Subnet filter injected.")
