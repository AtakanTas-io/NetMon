import re
with open('frontend/app.js', 'r', encoding='utf-8') as f:
    content = f.read()
pattern = re.compile(r'async function refreshSecurity\(\) \{.*?\}(?=\n\n/\* ---------- Raporlar)', re.DOTALL)
new_code = '''async function refreshSecurity() {
  try {
    const data = await get("/api/security");
    const body = securityBody;
    if (!body) return;
    if (data.error) {
      body.innerHTML = <div class="hint c-red"></div>;
      return;
    }
    const statusBadge = (desc) => {
      const d = (desc || "").toLowerCase();
      if (d.includes("aktif") || d.includes("açık") || d.includes("açik") || d.includes("izin") || d.includes("başarılı")) return <span class="badge ok">PASS</span>;
      if (d.includes("uyarı") || d.includes("sınırlı") || d.includes("warning")) return <span class="badge warn">WARNING</span>;
      return <span class="badge fail">ERROR</span>;
    };
    const rulesHtml = (data.rules || []).length > 0 ? (data.rules || []).map((r) => 
      <div style="display:flex; justify-content:space-between; padding:12px; border:1px solid var(--line-soft); border-radius:8px; background:var(--panel-2); margin-bottom:8px; align-items:center;">
        <div style="display:flex; align-items:center; gap:10px;">
          <div style="color:var(--blue);"></div>
          <span style="color:var(--txt); font-weight:600; font-size:13px;"></span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
          
          <button class="mini-btn" onclick="alert('Kural detayları simüle ediliyor...')">İncele</button>
        </div>
      </div>
    ).join("") : '<div class="hint">Kayıtlı güvenlik kuralı ihlali bulunamadı.</div>';
    
    body.innerHTML = 
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:12px; margin-bottom:20px;">
        <div style="padding:16px; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; display:flex; flex-direction:column; gap:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px; color:var(--cyan); font-weight:bold;"> Güvenlik Duvarı</div>
            
          </div>
          <div style="font-size:12px; color:var(--txt-2); line-height:1.5; margin-top:4px;"></div>
          <div style="margin-top:auto; padding-top:12px;"><button class="btn btn-sm" style="width:100%" onclick="alert('Firewall konfigürasyonu taranıyor...')">Yapılandırmayı Tara</button></div>
        </div>
        <div style="padding:16px; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; display:flex; flex-direction:column; gap:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px; color:var(--cyan); font-weight:bold;"> Web Filtresi</div>
            
          </div>
          <div style="font-size:12px; color:var(--txt-2); line-height:1.5; margin-top:4px;"></div>
          <div style="margin-top:auto; padding-top:12px;"><button class="btn btn-sm" style="width:100%" onclick="alert('Web filtre logları analiz ediliyor...')">Trafik Loglarını İncele</button></div>
        </div>
      </div>
      <h3 style="margin:0 0 12px; font-size:14px; color:var(--txt); border-bottom:1px solid var(--line-soft); padding-bottom:8px;">Politika İhlalleri & Güvenlik Logları</h3>
      
    ;
  } catch (e) {
    console.warn("Güvenlik verisi alınamadı:", e);
  }
}'''
content = pattern.sub(new_code, content)
with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(content)
print('OK')
