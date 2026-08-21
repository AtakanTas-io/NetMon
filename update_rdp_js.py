import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

old_func = """window.downloadRdp = function(ip, name) {
    if(!ip) return toast("IP adresi bulunamadi", "error");
    const content = "auto connect:i:1\\nfull address:s:" + ip + "\\nprompt for credentials:i:1\\n";
    const blob = new Blob([content], {type: "application/x-rdp"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (name || ip) + ".rdp";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
};"""

new_func = """window.downloadRdp = function(ip, name) {
    if(!ip) return toast("IP adresi bulunamadi", "error");
    window.location.href = `/api/rdp?ip=${encodeURIComponent(ip)}&name=${encodeURIComponent(name || ip)}`;
};"""

c = c.replace(old_func, new_func)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("JS RDP updated.")
