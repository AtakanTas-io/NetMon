import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# 1. Network Tab Headers
old_net_head = 'tableHead = `<tr><th>Durum</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Gateway</th><th>Subnet</th><th>Kaynak</th><th>İşlemler</th></tr>`;'
new_net_head = 'tableHead = `<tr><th>Durum</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Üretici</th><th>Kaynak</th><th>İşlemler</th></tr>`;'
c = c.replace(old_net_head, new_net_head)

# 2. Network Tab Rows
old_net_row = '</td><td>${esc(iface.gateway || d.gateway || "-")}</td><td>${esc(iface.subnet || d.subnet || "-")}</td><td>${esc(d.inventory_source || "Discovery")}'
new_net_row = '</td><td>${esc(d.vendor || "-")}</td><td>${esc(d.inventory_source || "Discovery")}'
c = c.replace(old_net_row, new_net_row)

old_colspan_8 = '<td colspan="8" class="hint">Ağ envanteri bulunamadı.</td>'
new_colspan_7 = '<td colspan="7" class="hint">Ağ envanteri bulunamadı.</td>'
c = c.replace(old_colspan_8, new_colspan_7)

# 3. Remove Mini Quiz button
c = re.sub(r'<button class="mini-btn"[^>]+openAcademyQuiz[^>]+>.*?Mini Quiz</button>', '', c)

# 4. Add Global Error Handler to the top
err_handler = """
window.addEventListener('error', function(e) {
  console.warn("NetMon Auto-Recover (Error):", e.message);
  e.preventDefault();
});
window.addEventListener('unhandledrejection', function(e) {
  console.warn("NetMon Auto-Recover (Promise):", e.reason);
  e.preventDefault();
});
"""
if "NetMon Auto-Recover" not in c:
    c = err_handler + "\n" + c

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("JS fixes applied.")
