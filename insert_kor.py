import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

old_kor = '''    if (co) co.innerHTML = (correlation?.devices || []).slice(0,30).map(d => { const p=d.review_priority||{}; const c=d.correlation||{}; return <div style="padding:10px;border-bottom:1px solid var(--line-soft)"><div style="display:flex;justify-content:space-between;gap:8px"><b></b><span class="badge ">Öncelik  — Korelasyon %</span></div><div class="hint"></div><div class="hint"></div></div>; }).join("") || '<div class="hint">Korelasyon verisi için önce keşif çalıştırın.</div>';'''

new_kor = '''    if (co) co.innerHTML = (correlation?.devices || []).slice(0,30).map(d => {
      const p=d.review_priority||{};
      const c=d.correlation||{};
      const devType = d.type || "unknown";
      const iconKey = DEVICE_TYPE_ICON[devType] || "cpu";
      const devId = d.mac || d.ip;
      return <div style="padding:12px;border:1px solid var(--line-soft);border-radius:8px;background:var(--panel-2);margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:10px;">
            <div style="color:var(--blue)"></div>
            <div style="display:flex;flex-direction:column;">
              <b style="font-size:15px;"></b>
              <span class="hint" style="font-size:12px"> </span>
            </div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
             <span class="badge ">Öncelik  • Korelasyon %</span>
             <button class="btn btn-sm" onclick="showDeviceDetails('')">Detayları Gör</button>
          </div>
        </div>
        <div style="background:var(--bg);padding:8px;border-radius:6px;font-size:13px;color:var(--text-soft);margin-bottom:6px;">
          <b style="color:var(--text)">💡 Korelasyon Kanıtları:</b> 
        </div>
        <div style="background:var(--bg);padding:8px;border-radius:6px;font-size:13px;color:var(--text-soft);">
          <b style="color:var(--text)">⚠️ İnceleme Nedeni:</b> 
        </div>
      </div>;
    }).join("") || '<div class="hint">Korelasyon verisi için önce keşif çalıştırın.</div>';'''

c = c.replace(old_kor, new_kor)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("Correlation UI restored.")
