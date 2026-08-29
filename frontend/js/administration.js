import "./purple-team.js";

function renderReportsPage() {
  const el = $("page-reports");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap;height:auto;padding:12px;gap:12px">
          <div><h2 style="margin:0">Operasyon & SLA Raporu</h2><small class="hint">Gerçek envanter, trafik, alarm ve snapshot kayıtlarından üretilir.</small></div>
          <div class="right"><button class="mini-btn" onclick="downloadOperationsReport('pdf')">PDF indir</button><button class="mini-btn" onclick="downloadOperationsReport('xlsx')">Excel indir</button><button class="mini-btn blue" onclick="refreshReports()">Raporu Güncelle</button></div>
        </div>
        <div class="panel-body" id="reportsBody"><div class="hint">Rapor hazırlanıyor…</div></div>
      </div>
    `;
  }
}

async function refreshReports() {
  const body = $("reportsBody");
  if (!body) return;
  try {
    const range = S.reportHistoryRange || "24h";
    const [data, history, schedules] = await Promise.all([
      get("/api/reports/operations"),
      get(`/api/history?range=${range}`),
      get("/api/report-schedules"),
    ]);
    const s = data.summary || {};
    const t = data.traffic || {};
    const val = v => v == null ? "Ölçüm yok" : v;
    body.innerHTML = `
      <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:16px">
        <div class="info-card"><span>Varlık</span><b>${val(s.assets)}</b><small>${val(s.verified_assets)} doğrulanmış</small></div>
        <div class="info-card"><span>Envanter Tamlığı</span><b>${s.inventory_completeness_pct == null ? "Veri yok" : "%"+s.inventory_completeness_pct}</b></div>
        <div class="info-card"><span>Tahmini SLA · 24s</span><b>${s.estimated_sla_pct == null ? "Snapshot yok" : "%"+s.estimated_sla_pct}</b></div>
        <div class="info-card"><span>Ortalama Sağlık</span><b>${s.average_health == null ? "Ölçüm yok" : s.average_health+"/100"}</b></div>
        <div class="info-card"><span>Lokasyon Kapsamı</span><b>${s.location_coverage_pct == null ? "Veri yok" : "%"+s.location_coverage_pct}</b></div>
        <div class="info-card"><span>NCM Yedeği · 24s</span><b>${val(s.configuration_backups_24h)}</b></div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px">
        <div class="panel" style="box-shadow:none"><div class="panel-head"><h2>Trafik & Kapasite</h2></div><div class="panel-body">
          <div class="info-card"><span>Ortalama In / Out</span><b>${t.average_in_mbps} / ${t.average_out_mbps} Mbps</b></div>
          <div class="info-card" style="margin-top:8px"><span>Tepe In / Out</span><b>${t.peak_in_mbps} / ${t.peak_out_mbps} Mbps</b></div>
        </div></div>
        <div class="panel" style="box-shadow:none"><div class="panel-head"><h2>Tekrarlanan Alarmlar</h2></div><div class="panel-body">
          ${(data.recurring_alerts||[]).map(a=>`<div style="padding:8px 0;border-bottom:1px solid var(--line-soft)"><span class="badge ${a.level==='critical'?'fail':a.level==='warning'?'warn':'blue'}">${esc(a.level)}</span> <b>${a.count}×</b> ${esc(a.message)}</div>`).join("") || '<div class="hint">Son 24 saatte alarm kaydı yok.</div>'}
        </div></div>
      </div>
      <div class="panel" style="box-shadow:none;margin-top:12px"><div class="panel-head" style="height:auto;flex-wrap:wrap;gap:8px"><div><h2>Operasyon Geçmişi</h2><small class="hint">Gerçek snapshot kayıtları; veri yoksa çizgi üretilmez.</small></div><div class="right">${["24h","7d","30d"].map(r=>`<button class="mini-btn ${range===r?'blue':''}" onclick="setReportHistoryRange('${r}')">${r}</button>`).join("")}</div></div><div class="panel-body">${renderHistoryChart(history.points||[])}</div></div>
      <div class="panel" style="box-shadow:none;margin-top:12px"><div class="panel-head"><div><h2>Zamanlanmış Raporlar</h2><small class="hint">PDF/XLSX üretimi; alıcı girilirse SMTP ile gönderilir.</small></div>${hasPermission("system.settings.manage")?'<button class="mini-btn blue" onclick="openReportScheduleModal()">Program Ekle</button>':''}</div><div class="panel-body">${(schedules.schedules||[]).map(item=>`<div style="display:flex;justify-content:space-between;padding:9px;border-bottom:1px solid var(--line-soft)"><span><b>${esc(item.name)}</b><small class="hint"> · ${esc(item.format.toUpperCase())} · ${Math.round(item.interval_seconds/3600)} saat</small></span><span class="badge ${item.enabled?'ok':'gray'}">${item.enabled?'Etkin':'Kapalı'}</span></div>`).join("") || '<div class="hint">Henüz rapor programı yok.</div>'}</div></div>
      <div class="hint" style="margin-top:12px">${esc(data.data_note)}</div>
    `;
  } catch (e) {
    body.innerHTML = `<div class="hint c-red">Rapor alınamadı: ${esc(e.message)}</div>`;
  }
}

function renderHistoryChart(points) {
  if (!points.length) return '<div class="hint">Bu aralıkta snapshot yok. Arka plan toplayıcısı ilk ölçümü kaydettiğinde grafik oluşur.</div>';
  const values = points.map(p=>Number(p.online)||0);
  const max = Math.max(1, ...values);
  const polyline = values.map((value,index)=>`${points.length===1?50:(index/(points.length-1))*100},${92-(value/max)*78}`).join(" ");
  const last = points[points.length-1];
  return `<div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:10px"><span><b>${last.devices}</b> cihaz</span><span><b>${last.online}</b> çevrimiçi</span><span><b>${last.open_ports}</b> benzersiz açık port</span><span><b>${last.traffic_bps==null?'Ölçüm yok':fmtBandwidthRate(last.traffic_bps)}</b> trafik</span></div><svg viewBox="0 0 100 100" preserveAspectRatio="none" style="width:100%;height:180px;background:var(--panel-2);border-radius:8px" role="img" aria-label="Çevrimiçi cihaz geçmişi"><polyline fill="none" stroke="var(--cyan)" stroke-width="2" vector-effect="non-scaling-stroke" points="${polyline}"/></svg><div class="hint">${points.length} snapshot · ${new Date(points[0].ts*1000).toLocaleString("tr-TR")} — ${new Date(last.ts*1000).toLocaleString("tr-TR")}</div>`;
}

function setReportHistoryRange(range) { S.reportHistoryRange = range; refreshReports(); }

async function downloadOperationsReport(format) {
  try {
    const response = await fetch(`/api/reports/export?format=${format}`, {headers:{Authorization:`Bearer ${getToken()}`}});
    if (!response.ok) throw new Error("Rapor üretilemedi.");
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob); link.download = `netmon-report.${format}`; link.click();
    setTimeout(()=>URL.revokeObjectURL(link.href), 1000);
  } catch (e) { toast(e.message || "Rapor indirilemedi.", "error"); }
}

function openReportScheduleModal() {
  openModal(`<h3>Rapor Programı</h3><div class="field-label">Ad</div><input id="reportScheduleName" value="Haftalık operasyon raporu"><div class="field-label" style="margin-top:10px">Format</div><select id="reportScheduleFormat"><option value="xlsx">Excel</option><option value="pdf">PDF</option></select><div class="field-label" style="margin-top:10px">Aralık</div><select id="reportScheduleInterval"><option value="86400">Günlük</option><option value="604800">Haftalık</option><option value="2592000">30 günlük</option></select><div class="field-label" style="margin-top:10px">E-posta alıcısı (isteğe bağlı)</div><input id="reportScheduleRecipient" type="email" placeholder="noc@example.com"><div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="createReportSchedule()">Kaydet</button></div>`);
}

async function createReportSchedule() {
  try {
    await post("/api/report-schedules", {name:$("reportScheduleName").value.trim(),format:$("reportScheduleFormat").value,interval_seconds:Number($("reportScheduleInterval").value),recipient:$("reportScheduleRecipient").value.trim()});
    closeModalForce(); toast("Rapor programı kaydedildi.", "success"); refreshReports();
  } catch (e) { toast(e.message || "Rapor programı kaydedilemedi.", "error"); }
}

function renderAccessPage() {
  const el = $("page-access");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `<div class="panel"><div class="panel-head"><div><h2 style="margin:0">Yetki ve Hazırlık Merkezi</h2><small class="hint">Rol izni ile uzak sistem erişimi birbirinden ayrıdır.</small></div></div><div class="panel-body" id="accessCenterBody"><div class="hint">Yetkiler denetleniyor…</div></div></div>`;
  }
}

async function refreshAccessCenter() {
  const body = $("accessCenterBody"); if (!body) return;
  try {
    const [data, readiness] = await Promise.all([get("/api/access/capabilities"), get("/api/system/readiness")]);
    const stateLabel = {ready:"HAZIR",degraded:"SINIRLI",needs_configuration:"AYAR GEREKLİ",unavailable:"KULLANILAMIYOR",error:"HATA"};
    const stateBadge = {ready:"ok",degraded:"warn",needs_configuration:"warn",unavailable:"gray",error:"fail"};
    body.innerHTML = `
      <div style="padding:14px;border:1px solid ${data.is_admin?'rgba(168,85,247,.45)':'var(--line)'};background:${data.is_admin?'rgba(88,28,135,.16)':'var(--panel-2)'};border-radius:10px;margin-bottom:14px">
        <b>${data.is_admin?'🛡️ YÖNETİCİ MODU AKTİF':'🔐 STANDART ROL'}</b> · ${esc(data.current_user)} / ${esc(data.current_role)}
        <div class="hint" style="margin-top:5px">${esc(data.important)}</div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:end;gap:12px;margin:4px 0 10px"><div><h3 style="margin:0">Sistem Hazırlığı</h3><div class="hint">Bağımlılık, ayar ve çalışma durumu gerçek zamanlı denetlenir.</div></div><button class="mini-btn" onclick="refreshAccessCenter()">Yeniden Denetle</button></div>
      <div class="readiness-grid">
        ${(readiness.items||[]).map(item=>`<div class="readiness-card ${esc(item.state)}"><div><b>${esc(item.title)}</b><span class="badge ${stateBadge[item.state]||'gray'}">${stateLabel[item.state]||esc(item.state)}</span></div><p>${esc(item.detail)}</p>${item.action?`<small>${esc(item.action)}</small>`:''}</div>`).join('')}
      </div>
      <h3 style="margin:18px 0 10px">Rol ve Operasyon Yetkileri</h3>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px">
        ${(data.capabilities||[]).map(c=>`<div style="padding:16px;background:var(--panel-2);border:1px solid ${c.state==='ready'?'rgba(16,185,129,.35)':c.state==='needs_role'?'rgba(239,68,68,.35)':'rgba(245,158,11,.35)'};border-radius:12px">
          <div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(c.title)}</b><span class="badge ${c.state==='ready'?'ok':c.state==='needs_role'?'fail':'warn'}">${c.state==='ready'?'HAZIR':c.state==='needs_role'?'ROL İZNİ YOK':'ORTAM HAZIR DEĞİL'}</span></div>
          <div class="hint" style="margin:8px 0"><b>Yöneticimden isteyeceğim:</b> ${esc(c.request_text)}</div>
          <div style="font-size:11px;color:var(--txt-2)"><b>Uygun roller:</b> ${esc((c.roles||[]).join(', '))}<br><b>NetMon izni:</b> <code>${esc(c.permission)}</code></div>
          <ol style="padding-left:18px;margin:10px 0 0;font-size:11px;line-height:1.55">${(c.manager_checklist||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ol>
        </div>`).join('')}
      </div>`;
  } catch (e) { body.innerHTML = `<div class="hint c-red">Yetki bilgisi alınamadı: ${esc(e.message)}</div>`; }
}

function renderLocationsPage() {
  const el = $("page-locations");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `<div class="panel"><div class="panel-head"><div><h2 style="margin:0">Lokasyon Haritası</h2><small class="hint">Şube > Bina > Kat > Oda/Kabinet standardı</small></div><button class="mini-btn" onclick="refreshLocations()">Güncelle</button></div><div class="panel-body" id="locationsBody"><div class="hint">Lokasyonlar yükleniyor…</div></div></div>`;
  }
}

async function refreshLocations() {
  const body = $("locationsBody"); if (!body) return;
  try {
    const [data, siteData] = await Promise.all([get("/api/locations/summary"), get("/api/sites")]);
    body.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div><b>Ağ kapsamı siteleri</b><div class="hint">Subnetler otomatik olarak envanter varlıklarını siteye bağlar.</div></div>${hasPermission("locations.manage")?'<button class="mini-btn blue" onclick="openSiteModal()">Site Ekle</button>':''}</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:16px">${(siteData.sites||[]).map(s=>`<div class="info-card"><span>${esc(s.name)}</span><b>${s.asset_count} varlık</b><small>${esc((s.cidrs||[]).join(', ')||'Subnet yok')}</small></div>`).join('') || '<div class="hint">Henüz subnet tabanlı site tanımlanmadı.</div>'}</div>
      <div class="hint" style="margin-bottom:12px">Adlandırma örneği: <code>${esc(data.naming_example)}</code></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:16px">${(data.sites||[]).map(s=>`<div class="info-card"><span>${esc(s.location)}</span><b>${s.total} cihaz</b><small>${s.online} çevrimiçi · ${s.offline} çevrimdışı</small></div>`).join('') || '<div class="hint">Henüz lokasyon atanmış envanter yok.</div>'}</div>
      <div class="table-wrap"><table><thead><tr><th>Cihaz</th><th>IP</th><th>Tip</th><th>Durum</th><th>Lokasyon</th>${data.can_manage?'<th>İşlem</th>':''}</tr></thead><tbody>
      ${(data.assets||[]).map(a=>`<tr><td>${esc(a.hostname||'İsimsiz')}</td><td><code>${esc(a.ip||'-')}</code></td><td>${esc(a.device_type||'unknown')}</td><td>${esc(a.status||'unknown')}</td><td>${data.can_manage?`<input id="loc-${a.asset_id}" value="${esc(a.location==='Atanmamış'?'':a.location)}" placeholder="Şube > Bina > Kat > Kabinet" style="min-width:260px">`:esc(a.location)}</td>${data.can_manage?`<td><button class="mini-btn blue" onclick="saveLocation(${a.asset_id})">Kaydet</button></td>`:''}</tr>`).join('')}
      </tbody></table></div>`;
  } catch(e) { body.innerHTML=`<div class="hint c-red">Lokasyon verisi alınamadı: ${esc(e.message)}</div>`; }
}

function openSiteModal() {
  openModal(`<h3>Yeni Site</h3><div class="field-label">Ad</div><input id="newSiteName" placeholder="İstanbul Merkez"><div class="field-label" style="margin-top:10px">Açıklama</div><input id="newSiteDescription" placeholder="Merkez ofis"><div class="field-label" style="margin-top:10px">Özel IPv4 subnetleri</div><input id="newSiteCidrs" placeholder="10.20.0.0/16, 192.168.10.0/24"><div class="hint">En geniş /16 desteklenir. Birden çok ağı virgülle ayırın.</div><div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="createSite()">Kaydet</button></div>`);
}

async function createSite() {
  try {
    const cidrs = $("newSiteCidrs").value.split(",").map(x=>x.trim()).filter(Boolean);
    await post("/api/sites", {name:$("newSiteName").value.trim(),description:$("newSiteDescription").value.trim(),cidrs});
    closeModalForce(); toast("Site kaydedildi ve varlıklar eşleştirildi.", "success"); refreshLocations();
  } catch (e) { toast(e.message || "Site kaydedilemedi.", "error"); }
}

async function saveLocation(assetId) {
  const location = $("loc-"+assetId)?.value.trim();
  if (!location) { toast("Lokasyon alanını doldurun.", "warn"); return; }
  try { await post("/api/locations/assign", {asset_id:assetId, location}); toast("Lokasyon kaydedildi.", "success"); refreshLocations(); }
  catch(e) { toast(e.message || "Lokasyon kaydedilemedi.", "error"); }
}

/* ---------- Ayarlar sayfası ---------- */
function renderSettingsPage() {
  const el = $("page-settings");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Ayarlar</h2></div>
        <div class="panel-body" id="settingsBody"><div class="hint">Yükleniyor…</div></div>
      </div>
    `;
  }
  loadSettings();
}

async function loadSettings() {
  const body = $("settingsBody");
  if (!body) return;
  try {
    const data = await get("/api/settings");
    const s = data.settings || {};
    const isAdmin = hasPermission("system.settings.manage");
    body.innerHTML = `
      <div class="field-label">Ping Hedefi</div>
      <input id="setPingTarget" type="text" value="${esc(s.ping_target)}" ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">DNS Test Alanı</div>
      <input id="setDnsDomain" type="text" value="${esc(s.dns_domain)}" ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">Tanılama Ping Sayısı</div>
      <input id="setPingCount" type="number" min="1" max="20" value="${esc(s.ping_count)}" ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">Taranacak Hedef Ağlar (Şirket VLAN/Subnet Listesi)</div>
      <input id="setSubnet" type="text" value="${esc(s.subnet || "")}" placeholder="Örn. 10.10.1.0/24, 10.10.2.0/24" ${isAdmin ? "" : "disabled"} />
      <div class="hint">İsterseniz ağlara =AğAdı şeklinde isim verebilirsiniz. (Örn: 10.33.214.0/24=Ofis Ağı, 192.168.5.0/24=Guest). Filtrelerde bu isimler görünecektir.</div>
      <div class="field-label" style="margin-top:10px">Ağ Tarama Sıklığı (saniye)</div>
      <input id="setScanInterval" type="number" min="60" max="86400" value="${esc(s.scan_interval)}" ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">Tanılama Aralığı (saniye)</div>
      <input id="setDiagInterval" type="number" min="5" max="3600" value="${esc(s.diagnostics_interval)}" ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">Veri Saklama Süresi (saat)</div>
      <input id="setRetention" type="number" min="1" max="8760" value="${esc(s.retention_hours)}" ${isAdmin ? "" : "disabled"} />
      <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
        <h4 style="margin:0 0 8px;color:var(--purple);font-size:13px">📜 Otomatik NCM Yedekleme</h4>
        <label style="display:flex;align-items:center;gap:8px"><input id="setNcmAuto" type="checkbox" ${s.ncm_auto_backup_enabled ? "checked" : ""} ${isAdmin ? "" : "disabled"}><span>Ağ cihazlarının konfigürasyonunu otomatik sürümle</span></label>
        <div class="field-label" style="margin-top:10px">Yedekleme Aralığı (saniye)</div>
        <input id="setNcmInterval" type="number" min="900" max="604800" value="${esc(s.ncm_backup_interval || 86400)}" ${isAdmin ? "" : "disabled"} />
        <div class="hint">Önerilen: 86400 (24 saat). SSH salt-okuma hesabı kullanılır ve değişiklikte alarm oluşturulur.</div>
      </div>

      <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
        <h4 style="margin:0 0 4px;color:var(--red);font-size:13px">🚨 Rogue DHCP Koruması</h4>
        <div class="field-label">Onaylı DHCP Sunucuları (IP Adresleri)</div>
        <input id="setAuthDhcp" type="text" value="${esc(s.authorized_dhcp_servers || "")}" placeholder="Örn. 192.168.1.1, 10.0.0.1" ${isAdmin ? "" : "disabled"} />
        <div class="hint">Bu listeye eklenmeyen bir IP'den DHCP teklifi (Offer) gelirse anında kritik güvenlik alarmı üretilir.</div>
      </div>

      <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
        <h4 style="margin:0 0 4px;color:var(--purple);font-size:13px">🏢 Active Directory / LDAP Entegrasyonu</h4>
        <div class="field-label">AD Sunucu IP/Hostname</div>
        <input id="setAdServer" type="text" value="${esc(s.ad_server || "")}" placeholder="Örn. 192.168.1.10 veya dc.sirket.local" ${isAdmin ? "" : "disabled"} />
        <div class="field-label" style="margin-top:10px">AD Domain (Kısa veya tam)</div>
        <input id="setAdDomain" type="text" value="${esc(s.ad_domain || "")}" placeholder="Örn. sirket.local veya sirket" ${isAdmin ? "" : "disabled"} />
        <div class="hint">Doldurulduğunda, sisteme giriş yapan kullanıcılar önce Active Directory üzerinde doğrulanır. Başarılı olursa otomatik 'user' rolü ile hesap oluşturulur. Lokal hesaplar çalışmaya devam eder.</div>
      </div>

      <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
        <h4 style="margin:0 0 4px;color:var(--cyan);font-size:13px">📨 Alarm ve Rapor Bildirimleri</h4>
        <div class="hint" style="margin-bottom:10px">SMTP, alarm e-postaları ve zamanlanmış rapor ekleri için kullanılır. Webhook yalnız yönetici tarafından tanımlanan adrese gönderilir.</div>
        <div style="display:grid;grid-template-columns:2fr 1fr;gap:8px"><div><div class="field-label">SMTP sunucusu</div><input id="setSmtpHost" value="${esc(s.smtp_host||'')}" placeholder="smtp.example.com" ${isAdmin ? "" : "disabled"}></div><div><div class="field-label">Port</div><input id="setSmtpPort" type="number" min="1" max="65535" value="${esc(s.smtp_port||587)}" ${isAdmin ? "" : "disabled"}></div></div>
        <div class="field-label" style="margin-top:10px">SMTP kullanıcı adı</div><input id="setSmtpUser" value="${esc(s.smtp_username||'')}" ${isAdmin ? "" : "disabled"}>
        <div class="field-label" style="margin-top:10px">SMTP parolası</div><input id="setSmtpPass" type="password" placeholder="${s.smtp_password_configured?'Kayıtlı — değiştirmek için yeni parola yazın':'Parola'}" ${isAdmin ? "" : "disabled"}>
        ${s.smtp_password_configured&&isAdmin?'<label class="hint"><input id="clearSmtpPass" type="checkbox"> Kayıtlı SMTP parolasını sil</label>':''}
        <div class="field-label" style="margin-top:10px">Gönderen / alarm alıcısı</div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><input id="setSmtpFrom" type="email" value="${esc(s.smtp_from||'')}" placeholder="netmon@example.com" ${isAdmin ? "" : "disabled"}><input id="setNotificationEmail" type="email" value="${esc(s.notification_email||'')}" placeholder="noc@example.com" ${isAdmin ? "" : "disabled"}></div>
        <label style="display:flex;align-items:center;gap:8px;margin-top:10px"><input id="setSmtpTls" type="checkbox" ${s.smtp_tls!==false?'checked':''} ${isAdmin ? "" : "disabled"}><span>STARTTLS kullan</span></label>
        <div class="field-label" style="margin-top:10px">Webhook URL</div><input id="setWebhookUrl" type="url" value="" placeholder="${s.webhook_url_configured?'Kayıtlı — değiştirmek için yeni URL yazın':'https://hooks.example.com/netmon'}" ${isAdmin ? "" : "disabled"}>
        ${s.webhook_url_configured&&isAdmin?'<label class="hint"><input id="clearWebhookUrl" type="checkbox"> Kayıtlı webhook adresini sil</label>':''}
      </div>

      <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
        <h4 style="margin:0 0 4px;color:var(--blue);font-size:13px">🔑 Yetkili Envanter Kimlik Bilgileri</h4>
        <div class="hint" style="margin-bottom:10px">Windows için WMI/WinRM, Linux için SSH ve ağ cihazları için SNMP salt-okuma bilgileri kullanılır.</div>
        <div class="field-label">Windows Envanter Servis Hesabı (en az yetki)</div>
      <input id="setWmiUser" name="netmon-wmi-user" type="text" value="${esc(s.wmi_username || "")}" placeholder="Örn. DOMAIN\\svc_netmon_ro" autocomplete="off" spellcheck="false" data-lpignore="true" data-1p-ignore ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">Windows Servis Hesabı Şifresi</div>
      <input id="setWmiPass" name="netmon-wmi-secret" type="password" value="" placeholder="${s.wmi_password_configured ? "Kayıtlı — değiştirmek için yeni parola yazın" : "Şifre"}" autocomplete="new-password" data-lpignore="true" data-1p-ignore ${isAdmin ? "" : "disabled"} />
      <div class="hint">Parola API'den geri okunmaz; Windows DPAPI ile şifrelenir.</div>
      ${s.wmi_password_configured && isAdmin ? '<label class="hint"><input id="clearWmiPass" type="checkbox" /> Kayıtlı WMI/WinRM parolasını sil</label>' : ''}
      <label style="display:flex;align-items:center;gap:8px;margin-top:10px">
        <input id="setWinrmVerifyTls" type="checkbox" ${s.winrm_verify_tls !== false ? "checked" : ""} ${isAdmin ? "" : "disabled"} />
        <span>WinRM HTTPS sertifikasını doğrula (önerilir)</span>
      </label>
      <div class="field-label" style="margin-top:12px">Linux SSH Kullanıcı Adı</div>
      <input id="setSshUser" name="netmon-ssh-user" type="text" value="${esc(s.ssh_username || "")}" placeholder="Örn. netmon-readonly" autocomplete="off" spellcheck="false" data-lpignore="true" data-1p-ignore ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">Linux SSH Şifresi</div>
      <input id="setSshPass" name="netmon-ssh-secret" type="password" value="" placeholder="${s.ssh_password_configured ? "Kayıtlı — değiştirmek için yeni parola yazın" : "Şifre"}" autocomplete="new-password" data-lpignore="true" data-1p-ignore ${isAdmin ? "" : "disabled"} />
      ${s.ssh_password_configured && isAdmin ? '<label class="hint"><input id="clearSshPass" type="checkbox" /> Kayıtlı SSH parolasını sil</label>' : ''}
      <div class="field-label" style="margin-top:10px">SNMP Community</div>
      <input id="setSnmpCommunity" name="netmon-snmp-secret" type="password" value="" placeholder="${s.snmp_community_configured ? "Kayıtlı — değiştirmek için yeni değer yazın" : "Örn. salt-okuma community"}" autocomplete="new-password" data-lpignore="true" data-1p-ignore ${isAdmin ? "" : "disabled"} />
      ${s.snmp_community_configured && isAdmin ? '<label class="hint"><input id="clearSnmpCommunity" type="checkbox" /> Kayıtlı SNMP community değerini sil</label>' : ''}
      <label style="display:flex;align-items:center;gap:8px;margin-top:14px">
        <input id="setPublicIpLookup" type="checkbox" ${s.public_ip_lookup ? "checked" : ""} ${isAdmin ? "" : "disabled"} />
        <span>Harici servisten genel IP sorgusuna izin ver</span>
      </label>
      </div>

      ${isAdmin ? `<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px"><button class="mini-btn" onclick="resetSettings()">Varsayılana Sıfırla</button><button class="mini-btn blue" onclick="saveSettings()">${ico("save", 14)} Kaydet</button></div>` : `<div class="hint" style="margin-top:14px">Ayarları değiştirmek için yönetici yetkisi gerekir.</div>`}
    `;
  } catch (e) {
    body.innerHTML = `<div class="hint c-red">Ayarlar alınamadı: ${esc(e.message)}</div>`;
  }
}

async function saveSettings() {
  try {
    const payload = {
      ping_target: $("setPingTarget")?.value.trim() || undefined,
      dns_domain: $("setDnsDomain")?.value.trim() || undefined,
      ping_count: Number($("setPingCount")?.value) || undefined,
      subnet: $("setSubnet")?.value.trim() ?? undefined,
      scan_interval: Number($("setScanInterval")?.value) || undefined,
      diagnostics_interval: Number($("setDiagInterval")?.value) || undefined,
      retention_hours: Number($("setRetention")?.value) || undefined,
      ncm_auto_backup_enabled: Boolean($("setNcmAuto")?.checked),
      ncm_backup_interval: Number($("setNcmInterval")?.value) || undefined,
      authorized_dhcp_servers: $("setAuthDhcp")?.value.trim() ?? undefined,
      ad_server: $("setAdServer")?.value.trim() ?? undefined,
      ad_domain: $("setAdDomain")?.value.trim() ?? undefined,
      smtp_host: $("setSmtpHost")?.value.trim() ?? undefined,
      smtp_port: Number($("setSmtpPort")?.value) || undefined,
      smtp_username: $("setSmtpUser")?.value.trim() ?? undefined,
      smtp_from: $("setSmtpFrom")?.value.trim() ?? undefined,
      smtp_tls: Boolean($("setSmtpTls")?.checked),
      notification_email: $("setNotificationEmail")?.value.trim() ?? undefined,
      wmi_username: $("setWmiUser")?.value.trim() ?? undefined,
      ssh_username: $("setSshUser")?.value.trim() ?? undefined,
      public_ip_lookup: Boolean($("setPublicIpLookup")?.checked),
      winrm_verify_tls: Boolean($("setWinrmVerifyTls")?.checked),
    };
    const wmiPassword = $("setWmiPass")?.value || "";
    const sshPassword = $("setSshPass")?.value || "";
    const snmpCommunity = $("setSnmpCommunity")?.value || "";
    const smtpPassword = $("setSmtpPass")?.value || "";
    const webhookUrl = $("setWebhookUrl")?.value.trim() || "";
    if ($("clearWmiPass")?.checked) payload.wmi_password = "";
    else if (wmiPassword) payload.wmi_password = wmiPassword;
    if ($("clearSshPass")?.checked) payload.ssh_password = "";
    else if (sshPassword) payload.ssh_password = sshPassword;
    if ($("clearSnmpCommunity")?.checked) payload.snmp_community = "";
    else if (snmpCommunity) payload.snmp_community = snmpCommunity;
    if ($("clearSmtpPass")?.checked) payload.smtp_password = "";
    else if (smtpPassword) payload.smtp_password = smtpPassword;
    if ($("clearWebhookUrl")?.checked) payload.webhook_url = "";
    else if (webhookUrl) payload.webhook_url = webhookUrl;
    await post("/api/settings", payload);
    toast("Ayarlar kaydedildi.", "success");
    await loadSettings();
  } catch (e) {
    toast(e.message || "Ayarlar kaydedilemedi.", "error");
  }
}

async function resetSettings() {
  try {
    await post("/api/settings/reset", {});
    toast("Ayarlar sıfırlandı.", "success");
    loadSettings();
  } catch (e) {
    toast(e.message || "Ayarlar sıfırlanamadı.", "error");
  }
}

/* ---------- Yönetim ---------- */
function renderManagementPage() {
  const el = $("page-management");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="admin-command-header">
        <div>
          <span class="ops-eyebrow">IDENTITY & ACCESS CONTROL</span>
          <h2>Yönetim Merkezi</h2>
          <p>Kullanıcı rolleri, hesap güvenliği ve yönetim hareketleri.</p>
        </div>
        <button class="admin-primary-action" onclick="openCreateUserModal()">${ico("plus", 15)} Kullanıcı Ekle</button>
      </div>
      <div class="admin-stat-grid" id="adminStats"></div>
      <div class="admin-role-matrix" id="adminRoleMatrix"></div>
      <div class="admin-layout">
        <section class="panel admin-users-panel">
          <div class="panel-head"><div><h2>Hesaplar & Roller</h2><span class="data-scope">En az yetki ilkesiyle yönetin</span></div></div>
          <div class="panel-body"><div class="admin-user-grid" id="usersBody"><div class="hint">Yükleniyor…</div></div></div>
        </section>
        <aside class="panel admin-audit-panel">
          <div class="panel-head"><div><h2>Son Yönetim Hareketleri</h2><span class="data-scope">Denetim izi</span></div><span class="badge ok">Kayıt aktif</span></div>
          <div class="panel-body" id="adminAuditList"><div class="hint">Yükleniyor…</div></div>
          <div class="admin-security-note">${ico("shield", 15)}<div><b>Güvenlik korumaları</b><span>Son admin koruması, oturum iptali ve zorunlu parola değişimi etkin.</span></div></div>
        </aside>
      </div>
      <div class="panel admin-inventory-guide">
        <div class="panel-head"><div><h2>Yetkili Envanter Hazırlık Rehberi</h2><span class="data-scope">BT yöneticinizle paylaşın</span></div><button class="mini-btn" onclick="go('settings')">Kimlik Ayarlarını Aç</button></div>
        <div class="panel-body admin-prereq-grid">
          <div><b>Windows WMI / WinRM</b><span>DOMAIN\\kullanıcı veya HEDEF\\kullanıcı · TCP 135 ya da 5985/5986 · Remote Enable / Administrators</span></div>
          <div><b>Linux SSH</b><span>Salt-okuma yetkili hesap · TCP 22 · doğrulanmış host anahtarı</span></div>
          <div><b>Ağ Cihazı SNMP</b><span>Salt-okuma community · UDP 161 · NetMon sunucu IP'sine izin veren ACL</span></div>
        </div>
      </div>
      <div class="panel" style="margin-top:14px">
        <div class="panel-head"><div><h2>API Anahtarlarım</h2><span class="data-scope">Rolünüzü aşmayan kapsam ve anahtar başına hız sınırı</span></div><button class="mini-btn blue" onclick="openApiKeyModal()">Anahtar Oluştur</button></div>
        <div class="panel-body" id="apiKeysBody"><div class="hint">API anahtarları yükleniyor…</div></div>
      </div>
    `;
  }
  Promise.all([loadUsers(), loadAdminAudit(), loadApiKeys()]);
}

async function loadApiKeys() {
  const body = $("apiKeysBody"); if (!body) return;
  try {
    const data = await get("/api/api-keys");
    body.innerHTML = (data.keys||[]).map(key=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid var(--line-soft)"><div><b>${esc(key.name)}</b> <code>${esc(key.prefix)}…</code><div class="hint">${esc((key.permissions||[]).join(', '))} · ${key.rate_limit_per_minute}/dk · ${key.last_used_at?`son kullanım ${new Date(key.last_used_at*1000).toLocaleString('tr-TR')}`:'henüz kullanılmadı'}</div></div><div><span class="badge ${key.revoked?'gray':'ok'}">${key.revoked?'İptal':'Etkin'}</span>${key.revoked?'':` <button class="mini-btn" onclick="revokeApiKey(${key.id})">İptal Et</button>`}</div></div>`).join("") || '<div class="hint">Henüz API anahtarı oluşturmadınız.</div>';
  } catch (e) { body.innerHTML = `<div class="hint c-red">API anahtarları alınamadı: ${esc(e.message)}</div>`; }
}

function openApiKeyModal() {
  openModal(`<h3>API Anahtarı Oluştur</h3><div class="field-label">Ad</div><input id="apiKeyName" placeholder="Rapor otomasyonu"><div class="field-label" style="margin-top:10px">İzinler</div><input id="apiKeyPermissions" placeholder="reports.view, locations.view"><div class="hint">Boş bırakırsanız rolünüzün tüm izinleri verilir. Anahtar rolünüzü aşamaz.</div><div class="field-label" style="margin-top:10px">Dakikalık istek sınırı</div><input id="apiKeyRate" type="number" min="5" max="600" value="60"><div class="field-label" style="margin-top:10px">Geçerlilik (gün)</div><input id="apiKeyExpiry" type="number" min="1" max="3650" value="365"><div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="createApiKey()">Oluştur</button></div>`);
}

async function createApiKey() {
  try {
    const permissions = $("apiKeyPermissions").value.split(",").map(x=>x.trim()).filter(Boolean);
    const data = await post("/api/api-keys", {name:$("apiKeyName").value.trim(),permissions,rate_limit_per_minute:Number($("apiKeyRate").value),expires_in_days:Number($("apiKeyExpiry").value)});
    openModal(`<h3>API anahtarı hazır</h3><div class="device-learning warning"><b>Bu değer yalnız bir kez gösterilir.</b><code style="display:block;word-break:break-all;margin-top:10px">${esc(data.key)}</code></div><div style="display:flex;justify-content:flex-end;margin-top:16px"><button class="mini-btn blue" onclick="closeModalForce();loadApiKeys()">Anladım</button></div>`);
  } catch (e) { toast(e.message || "API anahtarı oluşturulamadı.", "error"); }
}

async function revokeApiKey(id) {
  try { await del(`/api/api-keys/${id}`); toast("API anahtarı iptal edildi.", "success"); loadApiKeys(); }
  catch (e) { toast(e.message || "API anahtarı iptal edilemedi.", "error"); }
}

async function loadUsers() {
  const body = $("usersBody");
  if (!body) return;
  try {
    const [data, roleData] = await Promise.all([get("/api/admin/users"), get("/api/admin/roles")]);
    const users = data.users || [];
    const roles = roleData.roles || [];
    S.rbacRoles = roles;
    const matrix = $("adminRoleMatrix");
    if (matrix) matrix.innerHTML = roles.map(role => `
      <div class="admin-role-summary ${esc(role.id)}">
        <b>${esc(role.label)}</b>
        <span>${role.permissions.includes("*") ? "Tüm sistem izinleri" : `${role.permissions.length} operasyon izni`}</span>
        <small>${role.permissions.includes("*") ? "Tam yönetim" : role.permissions.map(p => esc(p)).join(" · ") || "Salt okunur"}</small>
      </div>`).join("");
    const stats = $("adminStats");
    if (stats) {
      const active = users.filter(u => u.active).length;
      const admins = users.filter(u => u.role === "admin" && u.active).length;
      const pending = users.filter(u => u.must_change_password).length;
      stats.innerHTML = `
        <div class="admin-stat-card blue"><span>Toplam hesap</span><b>${users.length}</b><small>Tanımlı kullanıcı</small></div>
        <div class="admin-stat-card green"><span>Aktif hesap</span><b>${active}</b><small>${users.length - active} devre dışı</small></div>
        <div class="admin-stat-card purple"><span>Aktif yönetici</span><b>${admins}</b><small>Yüksek yetkili rol</small></div>
        <div class="admin-stat-card orange"><span>Parola işlemi</span><b>${pending}</b><small>Değişiklik bekliyor</small></div>`;
    }
    body.innerHTML = users
      .map(
        (u) => `
      <article class="admin-user-card ${u.active ? "" : "disabled"}">
        <div class="admin-user-main">
          <div class="admin-avatar">${esc(String(u.username || "?").slice(0, 2).toUpperCase())}</div>
          <div class="admin-user-identity"><b>${esc(u.username)}</b><span>${esc(u.role_label || ROLE_LABELS[u.role] || u.role)}</span></div>
          <span class="admin-role-badge ${u.role}">${esc(u.role === "admin" ? "ADMIN" : u.role.replaceAll("_", " ").toUpperCase())}</span>
        </div>
        <div class="admin-user-state"><span><i class="${u.active ? "online" : ""}"></i>${u.active ? "Aktif" : "Devre dışı"}</span>${u.must_change_password ? '<span class="c-orange">Parola değişmeli</span>' : '<span class="c-green">Parola güncel</span>'}</div>
        <div class="admin-user-actions">
          <select aria-label="${esc(u.username)} rolü" onchange="changeUserRole(${u.id}, this.value)">${roles.map(role => `<option value="${esc(role.id)}" ${role.id === u.role ? "selected" : ""}>${esc(role.label)}</option>`).join("")}</select>
          <button onclick="openResetUserPasswordModal(${u.id}, '${esc(u.username)}')">Parola sıfırla</button>
          <button onclick="toggleUserActive(${u.id}, ${u.active ? "false" : "true"})">${u.active ? "Devre dışı" : "Etkinleştir"}</button>
          <button class="danger" title="Kullanıcıyı sil" onclick="deleteUser(${u.id})">${ico("trash", 13)}</button>
        </div>
      </article>
    `,
      )
      .join("");
  } catch (e) {
    body.innerHTML = `<div class="hint">Kullanıcılar alınamadı: ${esc(e.message)}</div>`;
  }
}

async function loadAdminAudit() {
  const body = $("adminAuditList");
  if (!body) return;
  try {
    const data = await get("/api/admin/audit-log?limit=12");
    const entries = data.entries || [];
    body.innerHTML = entries.length ? entries.map(entry => `
      <div class="admin-audit-row">
        <i class="${entry.success ? "ok" : "fail"}"></i>
        <div><b>${esc(entry.action || "işlem")}</b><span>${esc(entry.username || "sistem")} · ${entry.ts ? new Date(entry.ts * 1000).toLocaleString("tr-TR") : "-"}</span>${entry.detail ? `<small>${esc(entry.detail)}</small>` : ""}</div>
      </div>`).join("") : '<div class="hint">Henüz yönetim hareketi yok.</div>';
  } catch (e) {
    body.innerHTML = `<div class="hint c-red">Denetim izi alınamadı: ${esc(e.message)}</div>`;
  }
}

function refreshManagementData() {
  return Promise.all([loadUsers(), loadAdminAudit(), loadApiKeys()]);
}

function openCreateUserModal() {
  const roles = S.rbacRoles.length ? S.rbacRoles : [
    { id: "viewer", label: "Salt Okunur" },
    { id: "noc_operator", label: "NOC Operatörü" },
    { id: "inventory_specialist", label: "Envanter Uzmanı" },
    { id: "security_analyst", label: "Güvenlik Analisti" },
    { id: "admin", label: "Sistem Yöneticisi" },
  ];
  openModal(`
    <h3>Yeni Kullanıcı</h3>
    <div class="field-label" style="margin-top:10px">Kullanıcı Adı</div>
    <input id="newUserName" type="text" autocomplete="off" />
    <div class="field-label" style="margin-top:10px">Şifre</div>
    <input id="newUserPass" type="password" minlength="12" autocomplete="new-password" />
    <div class="hint" style="margin-top:5px">En az 12 karakter. Kullanıcı ilk girişte bu parolayı değiştirmek zorundadır.</div>
    <div class="field-label" style="margin-top:10px">Rol</div>
    <select id="newUserRole">${roles.map(role => `<option value="${esc(role.id)}" ${role.id === "viewer" ? "selected" : ""}>${esc(role.label)}</option>`).join("")}</select>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="createUser()">Oluştur</button></div>
  `);
}

async function createUser() {
  const username = $("newUserName")?.value.trim();
  const password = $("newUserPass")?.value;
  const role = $("newUserRole")?.value || "viewer";
  if (!username || !password) {
    toast("Kullanıcı adı ve şifre gerekli.", "warn");
    return;
  }
  if (password.length < 12) {
    toast("Geçici parola en az 12 karakter olmalıdır.", "warn");
    return;
  }
  try {
    await post("/api/admin/users", { username, password, role });
    closeModalForce();
    toast("Kullanıcı oluşturuldu.", "success");
    refreshManagementData();
  } catch (e) {
    toast(e.message || "Kullanıcı oluşturulamadı.", "error");
  }
}

async function toggleUserActive(id, active) {
  try {
    await post(`/api/admin/users/${id}`, { active });
    refreshManagementData();
  } catch (e) {
    toast(e.message || "İşlem başarısız.", "error");
  }
}

async function changeUserRole(id, role) {
  try {
    await post(`/api/admin/users/${id}`, { role });
    toast("Kullanıcı rolü güncellendi.", "success");
    refreshManagementData();
  } catch (e) {
    toast(e.message || "Rol güncellenemedi.", "error");
    loadUsers();
  }
}

function openResetUserPasswordModal(id, username) {
  openModal(`
    <h3>Kullanıcı Parolasını Sıfırla</h3>
    <div class="sub">${esc(username)} yeni parolayla giriş yaptıktan sonra parolasını yeniden değiştirmek zorundadır.</div>
    <div class="field-label" style="margin-top:12px">Geçici Parola</div>
    <input id="resetUserPass" type="password" minlength="12" autocomplete="new-password" />
    <div class="hint" style="margin-top:5px">En az 12 karakter olmalıdır.</div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="resetUserPassword(${id})">Parolayı Sıfırla</button></div>
  `);
}

async function resetUserPassword(id) {
  const password = $("resetUserPass")?.value || "";
  if (password.length < 12) {
    toast("Geçici parola en az 12 karakter olmalıdır.", "warn");
    return;
  }
  try {
    await post(`/api/admin/users/${id}`, { new_password: password });
    closeModalForce();
    toast("Parola sıfırlandı; kullanıcının açık oturumları kapatıldı.", "success");
    refreshManagementData();
  } catch (e) {
    toast(e.message || "Parola sıfırlanamadı.", "error");
  }
}

async function deleteUser(id) {
  if (!window.confirm("Bu kullanıcıyı ve tüm açık oturumlarını silmek istediğinize emin misiniz?")) return;
  try {
    await del(`/api/admin/users/${id}`);
    toast("Kullanıcı silindi.", "success");
    refreshManagementData();
  } catch (e) {
    toast(e.message || "Kullanıcı silinemedi.", "error");
  }
}

async function stopSim() {
  try {
    await post("/api/simulate/stop", {});
    const banner = $("simBanner");
    if (banner) banner.style.display = "none";
  } catch (e) {
    toast(e.message || "Simülasyon durdurulamadı.", "error");
  }
}

/* ---------- Trafik Grafiği ---------- */

Object.assign(globalThis, {
  renderReportsPage,
  refreshReports,
  setReportHistoryRange,
  downloadOperationsReport,
  openReportScheduleModal,
  createReportSchedule,
  renderAccessPage,
  refreshAccessCenter,
  renderLocationsPage,
  refreshLocations,
  saveLocation,
  openSiteModal,
  createSite,
  renderSettingsPage,
  loadSettings,
  saveSettings,
  resetSettings,
  renderManagementPage,
  loadUsers,
  loadAdminAudit,
  refreshManagementData,
  loadApiKeys,
  openApiKeyModal,
  createApiKey,
  revokeApiKey,
  openCreateUserModal,
  createUser,
  toggleUserActive,
  changeUserRole,
  openResetUserPasswordModal,
  resetUserPassword,
  deleteUser,
  stopSim,
});
