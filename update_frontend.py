import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# Modify the Hint in Settings to show the new =Name syntax
old_hint = '<div class="hint">BT yöneticinizden alacağınız ağ IP bloklarını virgülle buraya yapıştırın (Örn: 10.33.214.0/24, 192.168.5.0/24). NetMon sizin kişisel IP adresinizden bağımsız olarak buradaki tüm ağları tarayacaktır.</div>'
new_hint = '<div class="hint">İsterseniz ağlara =AğAdı şeklinde isim verebilirsiniz. (Örn: 10.33.214.0/24=Ofis Ağı, 192.168.5.0/24=Guest). Filtrelerde bu isimler görünecektir.</div>'
c = c.replace(old_hint, new_hint)


# Update renderDeviceTable to parse the names and use them in the dropdown
old_filter_logic = '''  // Alt Ağ (Subnet) Filtresini Dinamik Doldur
  const subnetSelect = $("devSubnetFilter");
  if (subnetSelect) {
    const currentVal = S.deviceSubnetFilter || "all";
    const nets = [...new Set(S.devices.filter(d=>d.ip).map(d => {
      const parts = d.ip.split('.');
      return parts.length === 4 ? parts.slice(0,3).join('.') + '.*' : 'Bilinmeyen';
    }))].filter(x => x !== 'Bilinmeyen').sort();
    
    let html = `<option value="all">🌐 Tüm Şirket Ağları</option>`;
    nets.forEach(n => {
       html += `<option value="${n}" ${currentVal===n?'selected':''}>Ağ Bloğu: ${n.replace(".*", ".x")}</option>`;
    });
    subnetSelect.innerHTML = html;
  }'''

new_filter_logic = '''  // Alt Ağ (Subnet) Filtresini Dinamik Doldur
  const subnetSelect = $("devSubnetFilter");
  if (subnetSelect) {
    const currentVal = S.deviceSubnetFilter || "all";
    
    // Parse custom names from settings
    const subnetNames = {};
    if (S.settings && S.settings.subnet) {
       S.settings.subnet.split(',').forEach(s => {
          const parts = s.split('=');
          if (parts.length > 1) {
             const ipPart = parts[0].trim();
             const namePart = parts[1].trim();
             const prefix = ipPart.substring(0, ipPart.lastIndexOf('.'));
             subnetNames[prefix] = namePart;
          }
       });
    }

    const nets = [...new Set(S.devices.filter(d=>d.ip).map(d => {
      const parts = d.ip.split('.');
      return parts.length === 4 ? parts.slice(0,3).join('.') : 'Bilinmeyen';
    }))].filter(x => x !== 'Bilinmeyen').sort();
    
    let html = `<option value="all">🌐 Tüm Şirket Ağları (Tümü)</option>`;
    nets.forEach(prefix => {
       const val = prefix + ".*";
       const customName = subnetNames[prefix];
       const displayName = customName ? `${customName} (${prefix}.x)` : `Ağ Bloğu: ${prefix}.x`;
       html += `<option value="${val}" ${currentVal===val?'selected':''}>${esc(displayName)}</option>`;
    });
    subnetSelect.innerHTML = html;
  }'''
c = c.replace(old_filter_logic, new_filter_logic)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("Frontend updated for Named Subnets.")
