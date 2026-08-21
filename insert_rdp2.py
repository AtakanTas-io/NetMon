import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# ADD THE downloadRdp JS FUNCTION GLOBALLY
if 'function downloadRdp' not in c:
    rdp_func = '''
window.downloadRdp = function(ip, name) {
    if(!ip) return toast("IP adresi bulunamadi", "error");
    const content = "auto connect:i:1\\nfull address:s:" + ip + "\\nprompt for credentials:i:1\\n";
    const blob = new Blob([content], {type: "application/x-rdp"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (name || ip) + ".rdp";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
};
'''
    c = c.replace('function renderDeviceTable() {', rdp_func + '\nfunction renderDeviceTable() {')


# INJECT RDP BUTTON INTO THE TABLE ACTIONS
# Search for the Detay button inside the All Devices view (line 3162 approximately)
old_action_1 = '''<button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>'''
new_action_1 = '''<button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button>'''

c = c.replace(old_action_1, new_action_1)

# INJECT RDP BUTTON INTO DEVICE DETAILS DRAWER
old_action_2 = '''${n.ip ? `<button class="mini-btn blue" onclick="quickPing('${esc(n.ip)}')">Ping Gönder</button>` : ""}'''
new_action_2 = '''${n.ip ? `<button class="mini-btn blue" onclick="quickPing('${esc(n.ip)}')">Ping Gönder</button>` : ""}
      ${n.ip ? `<button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(n.ip)}', '${esc(n.hostname || n.ip)}')">💻 RDP Bağlantısı</button>` : ""}'''

# Sometimes it's written as 'Ping Gnder' due to encoding. We can use a regex.
c = re.sub(r'(\$\{n\.ip \? `<button class="mini-btn blue" onclick="quickPing\(\'\$\{esc\(n\.ip\)\}\'\)">Ping[^<]+</button>` : ""\})',
           r'\1\n      ${n.ip ? `<button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp(\'${esc(n.ip)}\', \'${esc(n.hostname || n.ip)}\')">💻 RDP Bağlantısı</button>` : ""}',
           c)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("RDP button added.")
