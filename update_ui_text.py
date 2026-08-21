import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# 1. Update Settings UI labels
c = c.replace('<div class="field-label" style="margin-top:10px">Alt Ağlar (opsiyonel)</div>',
              '<div class="field-label" style="margin-top:10px">Taranacak Hedef Ağlar (Şirket VLAN/Subnet Listesi)</div>')
c = c.replace('<div class="hint">Aynı anda en fazla 16 özel IPv4 subnet\'i virgülle ayırabilirsiniz.</div>',
              '<div class="hint">BT yöneticinizden alacağınız ağ IP bloklarını virgülle buraya yapıştırın (Örn: 10.33.214.0/24, 192.168.5.0/24). NetMon sizin kişisel IP adresinizden bağımsız olarak buradaki tüm ağları tarayacaktır.</div>')

# 2. Update the Subnet Filter Dropdown in Inventory
c = c.replace('<select id="devSubnetFilter" onchange="S.deviceSubnetFilter=this.value;renderDeviceTable()" style="width:135px;',
              '<select id="devSubnetFilter" onchange="S.deviceSubnetFilter=this.value;renderDeviceTable()" style="width:170px;')

old_dropdown_html = 'let html = `<option value="all">🌐 Tüm Ağlar</option>`;\n    nets.forEach(n => {\n       html += `<option value="${n}" ${currentVal===n?\'selected\':\'\'}>${n}</option>`;\n    });'
new_dropdown_html = 'let html = `<option value="all">🌐 Tüm Şirket Ağları</option>`;\n    nets.forEach(n => {\n       html += `<option value="${n}" ${currentVal===n?\'selected\':\'\'}>Ağ Bloğu: ${n.replace(".*", ".x")}</option>`;\n    });'
c = c.replace(old_dropdown_html, new_dropdown_html)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("UI made more understandable.")
