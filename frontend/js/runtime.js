import "./ncm.js";

function renderDevicesPage() {
  const el = $("page-devices");
  const tab = S.deviceTab || "all";
  const statusFilter = S.deviceStatusFilter || "all";
  if (!el.dataset.built) {
    el.dataset.built = "1";

    let tableHead = `<tr><th>Durum</th><th>IP</th><th>Hostname</th><th>Tip</th><th>MAC</th><th>Gecikme</th><th>Son Görülme</th><th>İşlemler</th></tr>`;
    if (tab === "network") {
      tableHead = `<tr><th>Durum</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Üretici</th><th>Kaynak</th><th>İşlemler</th></tr>`;
    } else if (tab === "security") {
      tableHead = `<tr><th>Durum</th><th>Cihaz</th><th>OS</th><th>Firewall</th><th>Antivirüs</th><th>Envanter</th><th>Tamamlanma</th><th>İşlemler</th></tr>`;
    } else if (tab === "history") {
      tableHead = `<tr><th>Durum</th><th>Cihaz</th><th>IP</th><th>MAC</th><th>Son değişiklik</th><th>Kaynak</th><th>Envanter</th><th>İşlemler</th></tr>`;
    } else if (tab === "hardware") {
      tableHead = `<tr><th>Envanter Durumu</th><th>IP Adresi</th><th>Cihaz Adı</th><th>İşlemci (CPU)</th><th>RAM</th><th>GPU</th><th>Anakart / Model</th><th>Disk Durumu</th><th>İşlemler</th></tr>`;
    } else if (tab === "software") {
      tableHead = `<tr><th>Envanter Durumu</th><th>IP Adresi</th><th>Cihaz Adı</th><th>İşletim Sistemi</th><th>Aktif Kullanıcı</th><th>Antivirüs</th><th>Firewall</th><th>Programlar</th><th>İşlemler</th></tr>`;
    }

    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:10px">
            <h2 style="margin:0">Ağ Envanteri & Cihazlar</h2>
            <div style="display:flex;gap:4px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:3px">
              <button class="mini-btn ${tab === 'all' ? 'blue' : ''}" onclick="setDeviceTab('all')">Kimlik</button>
              <button class="mini-btn ${tab === 'network' ? 'blue' : ''}" onclick="setDeviceTab('network')">Ağ</button>
              <button class="mini-btn ${tab === 'hardware' ? 'blue' : ''}" onclick="setDeviceTab('hardware')">Donanım</button>
              <button class="mini-btn ${tab === 'software' ? 'blue' : ''}" onclick="setDeviceTab('software')">Yazılım</button>
              <button class="mini-btn ${tab === 'security' ? 'blue' : ''}" onclick="setDeviceTab('security')">Güvenlik</button>
              <button class="mini-btn ${tab === 'history' ? 'blue' : ''}" onclick="setDeviceTab('history')">Geçmiş</button>
            </div>
            <div style="display:flex;gap:4px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:3px;margin-left:6px">
              <button class="mini-btn ${S.deviceViewMode !== 'grid' ? 'blue' : ''}" onclick="setDeviceViewMode('table')">📋 Tablo</button>
              <button class="mini-btn ${S.deviceViewMode === 'grid' ? 'blue' : ''}" onclick="setDeviceViewMode('grid')">🗂️ Kartlar</button>
            </div>
          </div>
          <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">
            <button class="mini-btn" style="background:#10b981;border-color:#059669;color:white;margin-right:8px;" onclick="exportDevicesExcel()">📊 Excel'e Aktar</button>
            <input type="text" id="devFilter" placeholder="IP, Donanım, OS veya Ad ara…" style="width:200px" oninput="renderDeviceTable()" />
            <select id="devStatusFilter" onchange="S.deviceStatusFilter=this.value;renderDeviceTable()" style="width:125px">
              <option value="all" ${statusFilter==='all'?'selected':''}>Tüm durumlar</option>
              <option value="online" ${statusFilter==='online'?'selected':''}>Çevrimiçi</option>
              <option value="discovered" ${statusFilter==='discovered'?'selected':''}>Görüldü</option>
              <option value="offline" ${statusFilter==='offline'?'selected':''}>Çevrimdışı</option>
              <option value="stale" ${statusFilter==='stale'?'selected':''}>Eski kayıt</option>
            </select>
            <select id="devTypeFilter" onchange="S.deviceTypeFilter=this.value;renderDeviceTable()" style="width:135px">
              <option value="all">Tüm cihazlar</option>
              <option value="computer">Bilgisayar</option>
              <option value="laptop">Laptop</option>
              <option value="phone">Telefon</option>
              <option value="tablet">Tablet</option>
              <option value="server">Sunucu</option>
              <option value="printer">Yazıcı</option>
              <option value="router">Router</option>
              <option value="firewall">Firewall</option>
              <option value="switch">Switch</option>
              <option value="access_point">Access Point</option>
              <option value="smart_tv">Smart TV</option>
              <option value="camera">Kamera</option>
              <option value="nas">NAS / Depolama</option>
              <option value="iot">IoT</option>
              <option value="unknown">Bilinmeyen</option>
            </select>
            <span class="scan-note" id="devNote"></span>
            ${hasPermission("inventory.scan") ? `<button class="mini-btn blue" id="devScanBtn" onclick="scanNetwork()">Ağı Tara</button>` : ""}
            ${hasPermission("inventory.scan") ? `<button class="mini-btn" onclick="openWmiScanModal()">🔑 Yetkili Envanter</button>` : ""}
            ${hasPermission("diagnostics.run") ? `<button class="mini-btn" id="deepScanBtn" onclick="runDeepScan()">Port Tarama</button>` : ""}
          </div>
        </div>
        <div id="networkInfoStrip" class="device-learning" style="margin:10px 12px 0"></div>
        <div id="inventoryScanHistory" style="padding:8px 12px 0"></div>
        <div class="panel-body" style="padding:0;max-height:calc(100vh - 300px);overflow:auto">
          <table>
            <thead>${tableHead}</thead>
            <tbody id="devBody"></tbody>
          </table>
        </div>
        <div id="deepScanResults" style="padding:12px"></div>
      </div>
    `;
  }
  renderDeviceTable();
}

async function runDeepScan() {
  const btn = $("deepScanBtn");
  const box = $("deepScanResults");
  if (!box) return;
  if (btn) { btn.disabled = true; btn.textContent = "Taranıyor…"; }
  box.innerHTML = `<div class="hint" style="padding:10px">Ağdaki cihazlar için port taraması yapılıyor, bu birkaç dakika sürebilir…</div>`;
  try {
    const data = await post("/api/tools/deep-scan", {});
    if (!data || data.error) {
      box.innerHTML = `<div class="hint" style="padding:10px;color:var(--red)">Derin tarama başarısız: ${esc(data?.error || "bilinmeyen hata")}</div>`;
      return;
    }
    const rows = (data.results || [])
      .map((r) => {
        const ports = r.open_ports?.length
          ? r.open_ports.map((p) => `<span class="badge gray" style="margin:2px">${p.port}/${esc(p.service)}</span>`).join("")
          : `<span class="hint">açık port yok</span>`;
        return `<div style="padding:8px 0;border-bottom:1px solid var(--line-soft)">
          <b>${esc(r.hostname || r.ip)}</b> <span class="hint">${esc(r.ip)}${r.mac ? " · " + esc(r.mac) : ""}</span><br/>
          ${ports}
        </div>`;
      })
      .join("");
    box.innerHTML = `<h3 style="margin:6px 0">Derin Tarama Sonuçları (${data.scanned_hosts} cihaz)</h3>${rows || '<div class="hint">Taranacak online cihaz bulunamadı. Önce "Yeniden Tara" ile cihazları keşfedin.</div>'}`;
    toast(`Derin tarama tamamlandı: ${data.scanned_hosts} cihaz.`, "success");
  } catch (e) {
    box.innerHTML = `<div class="hint" style="padding:10px;color:var(--red)">Derin tarama başarısız: ${esc(e.message || e)}</div>`;
    toast(e.message || "Derin tarama başarısız.", "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Derin Tarama (Portlar)"; }
  }
}

async function scanNetwork() {
  if (!hasPermission("inventory.scan") || S.scanning) return;
  S.scanning = true;
  renderDeviceTable();
  try {
    const data = await post("/api/devices/scan", { mode: "agentless" });
    S.deviceScanError = data?.error || null;
    if (data && data.devices) {
      S.devices = data.devices;
      S.devicesTs = data.ts || Date.now() / 1000;
      await refreshTopology();
      toast(`${S.devices.length} cihaz tarandı.`, "success");
    }
  } catch (e) {
    S.deviceScanError = e.message || "Ağ taraması başarısız.";
    toast(e.message || "Ağ taraması başarısız.", "error");
  } finally {
    S.scanning = false;
    renderDeviceTable();
    renderStats();
    renderInventoryCommandCenter();
    updateDeviceFilterSummary();
    drawTopology();
  }
}

function updateDeviceFilterSummary() {
  const note = $("devNote");
  if (!note) return;
  const all = S.devices || [];
  const online = all.filter(d => deviceStatus(d) === "online").length;
  const discovered = all.filter(d => deviceStatus(d) === "discovered").length;
  const offline = all.filter(d => deviceStatus(d) === "offline" || deviceStatus(d) === "stale").length;
  const groups = {};
  all.forEach(d => { const t = d.type || "unknown"; groups[t] = (groups[t] || 0) + 1; });
  const top = Object.entries(groups).sort((a,b) => b[1]-a[1]).slice(0,4)
    .map(([t,n]) => `${TYPE_LABEL[t] || t}: ${n}`).join(" · ");
  note.textContent = `${online} çevrimiçi · ${discovered} görüldü · ${offline} çevrimdışı${top ? " · " + top : ""}`;
}

async function refreshNetworkInfo() {
  try {
    const data = await get("/api/network-info");
    const el = $("networkInfoStrip");
    if (!el || data?.error) return;
    const dns = Array.isArray(data.dns_servers) && data.dns_servers.length ? data.dns_servers.join(", ") : "-";
    el.innerHTML = `
      <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
        <div><b>Yerel ağ</b><span class="sub" style="margin-left:6px">${esc(data.cidr || "belirlenemedi")}</span></div>
        <div><b>IP</b><span class="sub" style="margin-left:6px">${esc(data.local_ip || "-")}</span></div>
        <div><b>Gateway</b><span class="sub" style="margin-left:6px">${esc(data.gateway || "-")}</span></div>
        <div><b>DNS</b><span class="sub" style="margin-left:6px">${esc(dns)}</span></div>
        <div><b>Arayüz</b><span class="sub" style="margin-left:6px">${esc(data.interface || "-")}</span></div>
      </div>
      <div style="margin-top:5px;color:var(--muted);font-size:10px">İpucu: "Yanıt doğrulanamadı" cihazın kapalı olduğunu kanıtlamaz; ICMP filtrelenmiş olabilir.</div>
    `;
  } catch (e) {
    const el = $("networkInfoStrip");
    if (el) renderLoadError(el, "Yerel ağ bilgisi alınamadı", e, "refreshNetworkInfo()");
  }
}

async function refreshDevices() {
  try {
    const summary = await get("/api/inventory/summary").catch(() => null);
    if (summary) {
      S.inventorySummary = summary;
      const total = $("nmsTotalCnt");
      const online = $("nmsOnlineCnt");
      if (total) total.textContent = summary.total ?? 0;
      if (online) online.textContent = summary.online ?? 0;
    }
    const data = await get("/api/devices");
    S.devices = data.devices || data;
    S.devicesTs = Number(data.ts || 0);
    S.deviceScanError = data.error || null;
    renderDeviceTable();
    renderStats();
    renderInventoryCommandCenter();
    const scanBox = $("inventoryScanHistory");
    if (scanBox) {
      const scans = await get("/api/inventory/scans?limit=5").catch(() => null);
      if (scans?.scans?.length) {
        scanBox.innerHTML = `<div class="device-learning"><b>Son envanter taramaları</b><div style="display:grid;gap:4px;margin-top:6px">${scans.scans.map(x => `<div style="display:flex;justify-content:space-between;gap:8px;font-size:10.5px"><span>${esc(x.mode)} · ${esc(x.requested_by || "-")}</span><span>${Number(x.total||0)} cihaz · ${x.finished_at ? "Tamamlandı" : "Devam ediyor"}</span></div>`).join("")}</div></div>`;
      }
    }
  } catch (e) {
    S.deviceScanError = e.message || "Cihaz verisi alınamadı.";
    renderInventoryCommandCenter();
    const body = $("deviceTableBody");
    if (body) body.innerHTML = `<tr><td colspan="9"><div class="load-state error"><b>Cihaz listesi alınamadı</b><span>${esc(S.deviceScanError)}</span><button class="mini-btn" onclick="refreshDevices()">Tekrar Dene</button></div></td></tr>`;
  }
}

async function refreshTopology() {
  try {
    const data = await get("/api/topology");
    S.topology = data.topology || data;
    drawTopology();
  } catch (e) {
    const drawer = $("topoDetailDrawer");
    if (drawer) renderLoadError(drawer, "Topoloji alınamadı", e, "refreshTopology()");
    toast(e.message || "Topoloji alınamadı.", "error");
  }
}

function renderSystemStatus(sys) {
  S.system = { ...(S.system || {}), ...(sys || {}) };
  sys = S.system;
  const quickRow = $("quickRow");
  if (quickRow && sys) {
    const percent = (value) => value == null ? "-" : `${value}%`;
    const netSpeed = S.trafficSampleTs == null ? "-" : `${Number(((S.traffic.up || 0) + (S.traffic.down || 0)) / 1e6).toFixed(2)} Mbps`;
    quickRow.innerHTML = `
      <div class="quick"><span style="color:var(--blue); font-weight:bold;">${percent(sys.cpu)}</span><span>CPU</span></div>
      <div class="quick"><span style="color:var(--purple); font-weight:bold;">${percent(sys.ram)}</span><span>RAM</span></div>
      <div class="quick"><span style="color:var(--orange); font-weight:bold;">${percent(sys.disk)}</span><span>DİSK</span></div>
      <div class="quick"><span style="color:var(--green); font-weight:bold;">${netSpeed}</span><span>AĞ</span></div>
    `;
  }
  const healthGrid = $("healthMetricGrid");
  if (healthGrid && sys) {
    const pct = value => value == null ? "Ölçülmedi" : `%${Number(value).toFixed(1)}`;
    const uptime = value => {
      if (value == null) return "Ölçülmedi";
      const total = Math.max(0, Number(value));
      const days = Math.floor(total / 86400);
      const hours = Math.floor((total % 86400) / 3600);
      const mins = Math.floor((total % 3600) / 60);
      return `${days}g ${hours}sa ${mins}dk`;
    };
    const metric = (label, value, note, color = "var(--txt)") => `<div class="health-metric"><span>${label}</span><b style="color:${color}">${esc(value)}</b><small>${note}</small></div>`;
    healthGrid.innerHTML = [
      metric("CPU kullanımı", pct(sys.cpu), "Gerçek zamanlı", Number(sys.cpu) >= 85 ? "var(--red)" : "var(--blue)"),
      metric("RAM kullanımı", pct(sys.ram), "Gerçek zamanlı", Number(sys.ram) >= 90 ? "var(--red)" : "var(--purple)"),
      metric("Uptime", uptime(sys.uptime_seconds), "Kesintisiz çalışma", "var(--green)"),
      metric("Sıcaklık", sys.temperature_c == null ? "Sensör yok" : `${Number(sys.temperature_c).toFixed(1)} °C`, "Donanım sensörü", Number(sys.temperature_c) >= 75 ? "var(--red)" : "var(--orange)"),
      metric("Güç kaynağı", sys.power_status || "Telemetri yok", "OS güç sensörü", sys.power_status ? "var(--green)" : "var(--muted)"),
    ].join("");
  }
  const trafficStrip = $("trafficMetricStrip");
  if (trafficStrip) {
    const overview = S.overview || {};
    const latency = overview.latency?.average;
    const loss = overview.packet_loss;
    const item = (label, value, color) => `<div style="border-left-color:${color}"><span>${label}</span><b>${value}</b></div>`;
    trafficStrip.innerHTML = [
      item("Alınan (Download)", `${Number((S.traffic.down || 0) / 1e6).toFixed(2)} Mbps`, "#3b9bff"),
      item("Gönderilen (Upload)", `${Number((S.traffic.up || 0) / 1e6).toFixed(2)} Mbps`, "#10b981"),
      item("Gecikme", latency == null ? "Ölçülmedi" : `${latency} ms`, "#8b5cf6"),
      item("Paket kaybı", loss == null ? "Ölçülmedi" : `%${loss}`, Number(loss) > 2 ? "#ef4444" : "#f59e0b"),
    ].join("");
  }
  renderDashboardDataStatus();
}

function formatSampleAge(ts) {
  if (!ts) return "Örnek bekleniyor";
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - Number(ts)));
  if (seconds < 5) return "Şimdi";
  if (seconds < 60) return `${seconds} sn önce`;
  return `${Math.floor(seconds / 60)} dk önce`;
}

function renderDashboardDataStatus() {
  const sample = $("trafficSampleStatus");
  if (sample) {
    const stale = !S.trafficSampleTs || (Date.now() / 1000 - Number(S.trafficSampleTs)) > 20;
    sample.className = `dashboard-freshness ${stale ? "stale" : "fresh"}`;
    sample.innerHTML = `<i></i><span>${S.trafficSimulated ? "Simülasyon verisi" : "Gerçek arayüz ölçümü"} · ${formatSampleAge(S.trafficSampleTs)}</span>`;
  }
  const live = $("dashboardLiveState");
  if (live) {
    const socketOpen = networkSocket && networkSocket.readyState === WebSocket.OPEN;
    live.innerHTML = `<i class="dot ${socketOpen ? "pulse" : "red pulse"}"></i><div><b>${socketOpen ? "Canlı veri akışı" : "Yedek yenileme etkin"}</b><span>${socketOpen ? "WebSocket bağlı" : "Bağlantı bekleniyor"} · son trafik ${formatSampleAge(S.trafficSampleTs)}</span></div>`;
  }
}

async function refreshOverview() {
  try {
    const data = await get("/api/overview");
    S.overview = data.overview || data;
    S.system = { ...(S.system || {}), ...(S.overview.system || {}) };
    const c = S.overview.connections || {};
    S.connections = {
      tcp: Number(c.tcp || 0), listen: Number(c.listen || 0), udp: Number(c.udp || 0),
      total: Number(c.total || 0), supported: c.supported !== false,
    };
    renderStats();
    renderInventoryCommandCenter();
    renderNetworkHealth();
    renderSystemStatus(S.system);
  } catch (e) {
    renderLoadError("statRow", "Kontrol merkezi özeti alınamadı", e, "refreshOverview()");
  }
}

async function refreshConnections() {
  try {
    const data = await get("/api/overview");
    const c = data.connections || {};
    S.connections = {
      tcp: Number(c.tcp || 0),
      listen: Number(c.listen || 0),
      udp: Number(c.udp || 0),
      total: Number(c.total || 0),
      supported: c.supported !== false,
    };
    renderStats();
  } catch (e) { console.warn("Bağlantı özeti alınamadı:", e); }
}

// /api/traffic'ten çekip sparkUp/sparkDown'ı dolduruyor ve grafiği çiziyor.
async function refreshTraffic() {
  try {
    const rows = await get("/api/traffic?minutes=5");
    const list = Array.isArray(rows) ? rows : rows.traffic || [];
    if (list.length) {
      S.sparkUp = list.map((r) => {
        const mbps = ((Number(r.wifi_sent) || 0) + (Number(r.eth_sent) || 0)) / 1_000_000;
        return Number(mbps.toFixed(2));
      });
      S.sparkDown = list.map((r) => {
        const mbps = ((Number(r.wifi_recv) || 0) + (Number(r.eth_recv) || 0)) / 1_000_000;
        return Number(mbps.toFixed(2));
      });
      S.sparkTs = list.map((r) => Number(r.ts || 0));
      const last = list[list.length - 1];
      S.traffic.up = (Number(last.wifi_sent) || 0) + (Number(last.eth_sent) || 0);
      S.traffic.down = (Number(last.wifi_recv) || 0) + (Number(last.eth_recv) || 0);
      S.trafficSampleTs = Number(last.ts || 0) || null;
      S.trafficSimulated = false;
    }
    if (typeof renderStats === "function") renderStats();
    if (typeof drawTrafficChart === "function") drawTrafficChart();
    renderSystemStatus(S.system || {});
  } catch (e) {
    const status = $("trafficSampleStatus");
    if (status) {
      status.className = "dashboard-freshness stale";
      status.innerHTML = `<i></i><span>Trafik API hatası: ${esc(e.message || e)}</span>`;
    }
  }
}

function updateLastScan() {
  const el = $("lastUpdate");
  if (el) el.textContent = nowTime();
}

let _refreshInFlight = null;

async function refreshAll(force = false) {
  if (!S.auto && !force) return;
  if (_refreshInFlight) return _refreshInFlight;
  const page = S.page || "dashboard";
  const tasksByPage = {
    dashboard: [refreshOverview, refreshTraffic, refreshDevices, refreshNetworkInfo, refreshLogs, refreshDashboardWidgets],
    devices: [refreshDevices],
    topology: [refreshDevices, refreshTopology],
    ipam: [refreshIpam],
    toptalkers: [refreshTopTalkers],
    ncm: [refreshNcm],
    security: [refreshSecurity],
    reports: [refreshReports],
    locations: [refreshLocations],
    access: [refreshAccessCenter],
    analyst: [refreshAnalyst],
    logs: [refreshLogs],
    settings: [loadSettings],
    management: [refreshManagementData],
  };
  const taskFns = tasksByPage[page] || [];
  _refreshInFlight = Promise.allSettled(taskFns.map(fn => Promise.resolve().then(() => fn())))
    .finally(() => { _refreshInFlight = null; });
  await _refreshInFlight;
  updateLastScan();
}

async function manualRefreshDashboard() {
  const btn = $("refreshBtn");
  if (btn) {
    btn.style.transition = "transform 0.6s ease";
    btn.style.transform = "rotate(360deg)";
    setTimeout(() => {
      btn.style.transition = "none";
      btn.style.transform = "rotate(0deg)";
    }, 600);
  }
  await refreshAll(true);
  updateLastScan();
  toast("Ağ verileri yenileme isteği tamamlandı.", "info");
}
window.manualRefreshDashboard = manualRefreshDashboard;

/* ---------- Aşama 5: Ağ Sağlığı paneli ---------- */
function renderNetworkHealth() {
  const panel = $("healthPanel");
  if (!panel) return;
  const o = S.overview || {};
  const health = o.health || {};
  const score = health.score;
  const scoreCls = score == null ? "c-muted" : score >= 85 ? "c-green" : score >= 65 ? "c-orange" : "c-red";
  const gw = o.gateway || {};
  const inet = o.internet || {};
  const dev = o.devices || {};

  const row = (label, ok, valueTxt) => `
    <div class="quick">
      <span class="${ok === null ? "c-muted" : ok ? "c-green" : "c-red"}" style="font-weight:bold;">${esc(valueTxt)}</span>
      <span>${esc(label)}</span>
    </div>`;

  panel.innerHTML = `
    <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:14px;">
      <div style="font-size:38px;font-weight:700;" class="${scoreCls}">${score ?? "-"}<span style="font-size:16px;color:var(--muted);"> / 100</span></div>
      <div class="${scoreCls}" style="font-weight:600;">${esc(health.label || "-")}</div>
    </div>
    <div class="quick-row">
      ${row("Gateway", gw.reachable, gw.latency != null ? gw.latency + " ms" : gw.reachable ? "OK" : "Yanıt yok")}
      ${row("İnternet", inet.connected, inet.connected ? "Bağlı" : "Yok")}
      ${row("Gecikme (Ort.)", null, (o.latency && o.latency.average != null) ? o.latency.average + " ms" : "-")}
      ${row("Paket Kaybı", o.packet_loss == null ? null : o.packet_loss <= 2, o.packet_loss == null ? "-" : "%" + o.packet_loss)}
      ${row("Bilinmeyen Cihaz", (dev.unknown || 0) === 0, dev.unknown || 0)}
    </div>
  `;
}

/* ---------- Aşama 6: Sorun Giderme Sihirbazı ---------- */
async function runTroubleshootWizard() {
  const btn = $("troubleshootBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Kontrol ediliyor…";
  }
  try {
    const r = await get("/api/diagnostics");
    const step = (label, ok) => `
      <div style="display:flex; justify-content:space-between; padding:10px 12px; background:var(--panel-2); border:1px solid var(--line-soft); border-radius:8px; align-items:center; font-size:11.5px;">
        <span style="color:var(--txt); font-weight:600;">${esc(label)}</span>
        <span class="badge ${ok ? "ok" : "fail"}">${ok ? "PASS" : "ERROR"}</span>
      </div>`;
    const issueOk = r.adapter && r.gateway && r.dns && r.internet;
    openModal(`
      <h3 style="margin-bottom:4px;">Sorun Giderme Sihirbazı</h3>
      <div class="sub" style="margin-bottom:16px;">Ağ Bağdaştırıcısı → Gateway → DNS → İnternet sırasıyla test edildi.</div>
      <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:16px;">
        ${step("Ağ Bağdaştırıcısı İletişimi", r.adapter)}
        ${step("Gateway Erişimi", r.gateway)}
        ${step("DNS Sunucusu Çözümlemesi", r.dns)}
        ${step("İnternet Bağlantısı", r.internet)}
      </div>
      <div class="quick" style="grid-template-columns:none;display:block;">
        <div class="${issueOk ? "c-green" : "c-red"}" style="font-weight:700;margin-bottom:6px;">${esc(r.issue || "-")}</div>
        <div>${esc(r.recommendation || "")}</div>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:18px;">
        <button class="mini-btn" onclick="closeModalForce()">Kapat</button>
      </div>
    `);
  } catch (e) {
    toast("Teşhis çalıştırılamadı.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Sorun Gider";
    }
  }
}

/* ============================================================
   GİRİŞ İŞLEMLERİ (LOGIN SUBMIT)
   ============================================================ */
async function handleLoginSubmit(e) {
  if (e) e.preventDefault();

  const usernameInput = $("loginUser");
  const passwordInput = $("loginPass");
  const rememberInput = $("rememberMe") || $("loginRemember");
  const errBox = $("loginErr");
  const btn = $("loginBtn");
  if (btn && btn.disabled) return false;

  if (!usernameInput || !passwordInput) return false;

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const remember = rememberInput ? rememberInput.checked : true;

  if (!username || !password) {
    if (errBox) errBox.textContent = "Kullanıcı adı ve şifre gerekli.";
    return false;
  }

  if (btn) {
    btn.disabled = true;
    btn.textContent = "Giriş yapılıyor…";
  }
  if (errBox) errBox.textContent = "";

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, remember }),
    });

    let data = {};
    try {
      data = await res.json();
    } catch (err) {}

    if (!res.ok) {
      if (errBox) {
        if (data.error) errBox.textContent = data.error;
        else errBox.textContent = `Hata: HTTP ${res.status} (Sunucu yanıt vermedi veya yol bulunamadı)`;
      }
      return false;
    }

    setToken(data.token, remember);
    S.user = data.user;
    passwordInput.value = "";
    boot();
  } catch (err) {
    console.error("Login error:", err);
    if (errBox) errBox.textContent = "Sunucuya ulaşılamadı.";
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Giriş Yap";
    }
  }

  return false;
}

/* ---------- Başlangıç / Boot ---------- */
function boot() {
  hideLogin();
  applyRolePermissions();
  buildNav();
  go("dashboard");
  if (S.user?.must_change_password) {
    setTimeout(() => openPasswordChangeModal(true), 100);
    return;
  }
  try {
    connectNetworkSocket();
    if (!autoRefreshTimer) startAutoRefresh();
  } catch (e) {}
  refreshAll();
}

/* ---------- WebSocket & Gerçek Zamanlı Akış ---------- */
let networkSocket = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
let autoRefreshTimer = null;
let _lastSocketDetailRefresh = 0;

function getWebSocketUrl() {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return protocol + "//" + location.host + "/ws/live";
}

function connectNetworkSocket() {
  if (
    networkSocket &&
    (networkSocket.readyState === WebSocket.OPEN ||
      networkSocket.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  try {
    const token = typeof getToken === "function" ? getToken() : "";
    networkSocket = new WebSocket(getWebSocketUrl(), ["netmon", token]);
    networkSocket.onopen = () => {
      reconnectAttempts = 0;
      setConnectionStatus(true);
      networkSocket.send(
        JSON.stringify({
          type: "subscribe",
          channels: ["devices", "traffic", "connections", "topology"],
        }),
      );
    };
    networkSocket.onmessage = async (event) => {
      try {
        const message = JSON.parse(event.data);
        handleNetworkMessage(message);
      } catch (err) {}
    };
    networkSocket.onerror = () => {
      setConnectionStatus(false);
    };
    networkSocket.onclose = () => {
      setConnectionStatus(false);
      scheduleSocketReconnect();
    };
  } catch (err) {
    setConnectionStatus(false);
    scheduleSocketReconnect();
  }
}

function scheduleSocketReconnect() {
  if (reconnectTimer) return;
  reconnectAttempts++;
  const delay = Math.min(
    30000,
    1000 * Math.pow(2, Math.min(reconnectAttempts, 5)),
  );
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectNetworkSocket();
  }, delay);
}

function setConnectionStatus(connected) {
  const brandState = $("brandState");
  const brandDot = $("brandDot");
  const liveText = $("liveText");
  const liveDot = $("liveDot");
  if (brandState)
    brandState.textContent = connected ? "Bağlı" : "Bağlantı bekleniyor...";
  if (liveText) liveText.textContent = connected ? "Canlı" : "Bağlantı koptu";
  if (brandDot) brandDot.className = connected ? "dot" : "dot red pulse";
  if (liveDot) liveDot.className = connected ? "dot" : "dot red pulse";
  renderDashboardDataStatus();
}

async function handleNetworkMessage(message) {
  if (!message) return;
  const type = message.type || message.event || message.channel;

  if (type === "scan_wave") {
    toast(`🌊 ${message.label || "Scan Wave"} (%${message.progress || 0})`, "info");
    const bar = $("scanWaveBar");
    const text = $("scanWaveText");
    if (bar) bar.style.width = (message.progress || 0) + "%";
    if (text) text.textContent = `${message.label} (%${message.progress})`;
    return;
  }

  if (
    type === "devices" ||
    type === "device_update" ||
    type === "devices_update"
  ) {
    const devices = message.devices || message.data;
    if (Array.isArray(devices)) {
      S.devices = devices;
      S.devicesTs = Number(message.ts || Date.now() / 1000);
      S.deviceScanError = null;
      renderDeviceTable();
      renderStats();
      renderInventoryCommandCenter();
      if (typeof drawTopology === "function") drawTopology();
    }
    return;
  }

  if (type === "topology" || type === "topology_update") {
    S.topology = message.topology || message.data || message;
    if (typeof drawTopology === "function") drawTopology();
    return;
  }

  if (type === "traffic" || type === "traffic_update") {
    const traffic = message.traffic || message.data || message || {};
    const sentBps = Number(traffic.sent ?? traffic.upload ?? traffic.up ?? 0);
    const recvBps = Number(traffic.recv ?? traffic.download ?? traffic.down ?? 0);
    S.traffic.up = sentBps;
    S.traffic.down = recvBps;
    S.trafficSampleTs = Number(traffic.ts || message.ts || Date.now() / 1000);
    S.trafficSimulated = Boolean(traffic.simulated);

    const MAX_POINTS = 60;
    const mbpsUp = Number((sentBps / 1_000_000).toFixed(2));
    const mbpsDown = Number((recvBps / 1_000_000).toFixed(2));
    S.sparkUp.push(mbpsUp);
    S.sparkDown.push(mbpsDown);
    S.sparkTs.push(S.trafficSampleTs);
    if (S.sparkUp.length > MAX_POINTS) S.sparkUp.shift();
    if (S.sparkDown.length > MAX_POINTS) S.sparkDown.shift();
    if (S.sparkTs.length > MAX_POINTS) S.sparkTs.shift();
    if (typeof renderStats === "function") renderStats();
    if (typeof drawTrafficChart === "function") drawTrafficChart();
    renderSystemStatus(S.system || {});
    const detailNow = Date.now();
    if (detailNow - _lastSocketDetailRefresh > 20000) {
      _lastSocketDetailRefresh = detailNow;
      if (S.page === "toptalkers" && typeof refreshTopTalkers === "function") refreshTopTalkers();
      if (S.page === "dashboard" && typeof refreshDashboardWidgets === "function") refreshDashboardWidgets();
    }
    return;
  }

  if (type === "alert") {
    const banner = document.getElementById("securityBannerContainer");
    if (banner) {
        banner.innerHTML = `<div style="background-color: var(--fail); color: #fff; padding: 12px; margin-bottom: 15px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 12px rgba(239,68,68,0.2);">
            <div>
                <strong style="display:block; margin-bottom: 4px;">⚠️ Güvenlik Uyarısı</strong>
                <span style="font-size: 13px;">${message.message || "Bilinmeyen Güvenlik Uyarısı"}</span>
            </div>
            <button onclick="this.parentElement.style.display='none'" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 4px 10px; border-radius: 4px; cursor: pointer;">Kapat</button>
        </div>`;
    }
    toast("⚠️ " + (message.message || "Güvenlik uyarısı"), message.level === "critical" ? "fail" : "warn");
    return;
  }

  if (type === "system_alert") {
    toast(message.message || "Sistem Uyarısı", message.level === "critical" ? "fail" : "warn");
    return;
  }

  if (type === "system" || type === "system_update") {
    if (typeof renderSystemStatus === "function") renderSystemStatus(message);
    return;
  }

  if (type === "log" || type === "logs" || type === "log_update") {
    const log = message.log || message.data;
    if (log) {
      S.logs = Array.isArray(S.logs) ? S.logs : [];
      S.logs.unshift(log);
      if (S.logs.length > 200) S.logs = S.logs.slice(0, 200);
      if (typeof renderLogs === "function") renderLogs();
    }
    return;
  }
}

function startAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(async () => {
    if (document.hidden) return;
    refreshAll();
  }, 10000);
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

/* ---------- DOMContentLoaded Dinleyicisi ---------- */
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = $("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", handleLoginSubmit);
  }

  let token = getToken();
  if (token) {
    get("/api/auth/me")
      .then((me) => {
        S.user = me;
        boot();
      })
      .catch(() => {
        showLogin();
      });
  } else {
    showLogin();
  }
});

// Fonksiyon Global Seviyede Çağırılabilir Hale Getirilir.
window.handleLoginSubmit = handleLoginSubmit;

function playDhcpStep(step) {
  const anim = $("dhcpPacketAnim");
  const msg = $("dhcpSimMsg");
  const sub = $("dhcpSimSubtitle");
  if(!anim || !msg) return;
  msg.style.display = "block";
  anim.style.opacity = "1";
  anim.style.transition = "none";
  if(step === 1 || step === 3) {
     anim.style.left = "5%";
     setTimeout(() => { anim.style.transition = "left 1.5s ease-in-out"; anim.style.left = "90%"; }, 50);
  } else {
     anim.style.left = "90%";
     setTimeout(() => { anim.style.transition = "left 1.5s ease-in-out"; anim.style.left = "5%"; }, 50);
  }
  if(step === 1) { sub.innerText="Step 1 of 4: DHCP DISCOVER"; msg.innerHTML="<span style='color:var(--orange)'>Client broadcasts:</span> Is there a DHCP server? I need an IP."; }
  if(step === 2) { sub.innerText="Step 2 of 4: DHCP OFFER"; msg.innerHTML="<span style='color:var(--green)'>Server replies:</span> I can offer you <span style='color:var(--orange)'>192.168.1.100</span>."; }
  if(step === 3) { sub.innerText="Step 3 of 4: DHCP REQUEST"; msg.innerHTML="<span style='color:var(--orange)'>Client requests:</span> I accept 192.168.1.100."; }
  if(step === 4) { sub.innerText="Step 4 of 4: DHCP ACK"; msg.innerHTML="<span style='color:var(--green)'>Server acknowledges:</span> It is yours for 24 hours."; }
}

Object.assign(globalThis, {
  renderDevicesPage,
  runDeepScan,
  scanNetwork,
  updateDeviceFilterSummary,
  refreshNetworkInfo,
  refreshDevices,
  refreshTopology,
  renderSystemStatus,
  formatSampleAge,
  renderDashboardDataStatus,
  refreshOverview,
  refreshConnections,
  refreshTraffic,
  updateLastScan,
  _refreshInFlight,
  refreshAll,
  manualRefreshDashboard,
  renderNetworkHealth,
  runTroubleshootWizard,
  handleLoginSubmit,
  boot,
  networkSocket,
  reconnectTimer,
  reconnectAttempts,
  autoRefreshTimer,
  _lastSocketDetailRefresh,
  getWebSocketUrl,
  connectNetworkSocket,
  scheduleSocketReconnect,
  setConnectionStatus,
  handleNetworkMessage,
  startAutoRefresh,
  stopAutoRefresh,
  playDhcpStep,
});
