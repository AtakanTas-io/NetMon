import "./navigation.js";

function logRowHtml(l) {
  const rawLevel = String(l.level || "info").toLowerCase();
  const level = ["critical", "error", "fail"].includes(rawLevel)
    ? "critical"
    : ["warning", "warn"].includes(rawLevel)
      ? "warning"
      : "info";
  const cls =
    level === "critical"
      ? "red"
      : level === "warning"
        ? "orange"
        : rawLevel === "ok"
          ? "green"
          : "";
  const source = l.source || l.tag || (String(l.message || "").startsWith("%") ? "SYSLOG" : "NETMON");
  return `
    <div class="log-row">
      <span class="log-time">${esc(l.time || "")}</span>
      <span class="log-source">${esc(source)}</span>
      <span class="log-level ${cls}">${esc(level)}</span>
      <span class="log-msg">${esc(l.message || "")}</span>
    </div>
  `;
}

function renderLogs() {
  const visibleLogs = (S.logs || []).filter(l => {
    const raw = String(l.level || "info").toLowerCase();
    const normalized = ["critical", "error", "fail"].includes(raw) ? "critical" : ["warning", "warn"].includes(raw) ? "warning" : "info";
    const levelMatch = S.logLevel === "all" || normalized === S.logLevel;
    const q = String(S.logQuery || "").trim().toLowerCase();
    const queryMatch = !q || `${l.time || ""} ${l.source || l.tag || ""} ${l.message || ""}`.toLowerCase().includes(q);
    return levelMatch && queryMatch;
  });
  const list = $("logList");
  if (list) {
    list.innerHTML =
      visibleLogs.slice(0, 60).map(logRowHtml).join("") ||
      `<div class="hint" style="padding:14px;text-align:center">Henüz log yok.</div>`;
  }
  const pageList = $("logsPageList");
  if (pageList) {
    pageList.innerHTML =
      visibleLogs.map(logRowHtml).join("") ||
      `<div class="hint" style="padding:14px;text-align:center">Filtreyle eşleşen kayıt yok.</div>`;
  }
}

function setLogLevel(level) {
  S.logLevel = level;
  document.querySelectorAll("[data-log-level]").forEach(btn => btn.classList.toggle("blue", btn.dataset.logLevel === level));
  renderLogs();
}

function setLogQuery(value) {
  S.logQuery = value || "";
  renderLogs();
}

async function refreshLogs() {
  try {
    const data = await get("/api/logs?limit=100");
    S.logs = data.logs || data || [];
    renderLogs();
  } catch (e) {
    console.warn("Loglar alınamadı:", e);
  }
}

async function clearLogs() {
  if (!hasPermission("logs.manage")) {
    toast("Logları temizlemek için log yönetimi izni gerekli.", "warn");
    return;
  }
  try {
    await post("/api/logs/clear", {});
    S.logs = [];
    renderLogs();
    toast("Loglar temizlendi.", "success");
  } catch (e) {
    toast(e.message || "Loglar temizlenemedi.", "error");
  }
}

function renderLogsPage() {
  const el = $("page-logs");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div><h2 style="margin:0">Canlı Log & Alarm Yönetimi</h2><span class="data-scope">Syslog uyumlu olay akışı · geçmiş kayıtları</span></div>
          <div class="right log-toolbar">
            <input type="search" placeholder="Mesaj, cihaz veya kaynak ara…" oninput="setLogQuery(this.value)" />
            <button class="mini-btn blue" data-log-level="all" onclick="setLogLevel('all')">Tümü</button>
            <button class="mini-btn" data-log-level="critical" onclick="setLogLevel('critical')">Critical</button>
            <button class="mini-btn" data-log-level="warning" onclick="setLogLevel('warning')">Warning</button>
            <button class="mini-btn" data-log-level="info" onclick="setLogLevel('info')">Info</button>
            <button class="mini-btn" data-permission="logs.manage" onclick="clearLogs()">Temizle</button>
          </div>
        </div>
        <div class="panel-body" id="logsPageList" style="max-height:calc(100vh - 230px);overflow:auto"></div>
      </div>
    `;
    applyRolePermissions();
  }
  renderLogs();
}

/* ---------- Ping sayfası ---------- */
function renderPingPage() {
  const el = $("page-ping");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Ping Testi</h2></div>
        <div class="panel-body">
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
            <input type="text" id="pgPingTarget" placeholder="IP veya alan adı (örn. 8.8.8.8)" style="flex:1;min-width:220px" value="8.8.8.8" />
            <button class="mini-btn blue" id="pgPingBtn" onclick="runPagePing()">Ping At</button>
          </div>
          <div id="pgPingSummary" class="hint"></div>
          <div id="pgPingList" style="margin-top:10px"></div>
        </div>
      </div>

      <div class="panel" style="margin-top:14px">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Hızlı Ağ Komutları & Onarım (Essential Network Commands)</h2></div>
        <div class="panel-body">
          <div style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Sık kullanılan Windows ağ teşhis ve bakım komutlarını doğrudan arayüzden çalıştırın:
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
            <button class="mini-btn" onclick="runNetworkCmd('flushdns')">🧹 ipconfig /flushdns</button>
            <button class="mini-btn" onclick="runNetworkCmd('ipconfig_all')">📋 ipconfig /all</button>
            <button class="mini-btn" onclick="runNetworkCmd('renew')">🔄 ipconfig /renew</button>
            <button class="mini-btn" onclick="runNetworkCmd('release')">❌ ipconfig /release</button>
            <button class="mini-btn" onclick="runNetworkCmd('arp_a')">🔍 arp -a</button>
            <button class="mini-btn" onclick="runNetworkCmd('netstat_an')">🌐 netstat -an</button>
            <button class="mini-btn" onclick="runNetworkCmd('getmac')">💻 getmac</button>
            <button class="mini-btn" onclick="runNetworkCmd('hostname')">🆔 hostname</button>
            <button class="mini-btn" onclick="runNetworkCmd('net_share')">📁 net share</button>
          </div>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px">
            <input type="text" id="cmdNslookupTarget" placeholder="DNS Sorgusu için Etki Alanı (örn: google.com)" style="flex:1" value="google.com" />
            <button class="mini-btn blue" onclick="runNetworkCmd('nslookup', $('cmdNslookupTarget').value)">🔎 nslookup</button>
          </div>
          <div id="cmdOutputBox" style="display:none;background:#060a12;border:1px solid var(--line);border-radius:8px;padding:12px;font-family:Consolas, monospace;font-size:12px;color:#3ddc84;white-space:pre-wrap;max-height:360px;overflow-y:auto"></div>
        </div>
      </div>
    `;
  }
}

async function runNetworkCmd(action, target) {
  const box = $("cmdOutputBox");
  if (!box) return;
  box.style.display = "block";
  box.innerHTML = `<span style="color:var(--txt-2)">⌛ Komut çalıştırılıyor: ${esc(action)}...</span>`;

  try {
    const res = await post("/api/tools/network-cmd", { action, target: target || "" });
    if (res.error) {
      box.innerHTML = `<span style="color:var(--red)">❌ Hata: ${esc(res.error)}</span>`;
      return;
    }
    box.innerHTML = `<div style="color:var(--blue);margin-bottom:6px;font-weight:bold">$ ${esc(res.command)}</div><div style="color:#e7eefb">${esc(res.output)}</div>`;
  } catch (err) {
    box.innerHTML = `<span style="color:var(--red)">❌ Bağlantı hatası: ${esc(err.message)}</span>`;
  }
}

async function _doPing(ids, count) {
  const target = ($(ids.target)?.value || "").trim();
  if (!target) {
    toast("Hedef adres gerekli.", "warn");
    return;
  }
  const btn = $(ids.btn);
  const btnLabel = btn ? btn.textContent : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = ico("refresh", 14, "spin") + " Atılıyor…";
  }
  try {
    const data = await post("/api/tools/ping", { target, count: count || 4 });
    const summaryEl = $(ids.summary);
    const listEl = $(ids.list);
    if (data.error) {
      if (summaryEl) summaryEl.innerHTML = `<span class="c-red">${esc(data.error)}</span>`;
      if (listEl) listEl.innerHTML = "";
      return;
    }
    if (summaryEl) {
      summaryEl.innerHTML = `Ortalama: <b>${data.average} ms</b> · Min/Max: ${data.min}/${data.max} ms · Kayıp: %${data.loss}`;
    }
    if (listEl) {
      listEl.innerHTML = (data.times || [])
        .map((t, i) => `<div class="log-row"><span>#${i + 1}</span><span>${t} ms</span></div>`)
        .join("");
    }
  } catch (e) {
    toast(e.message || "Ping başarısız.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = btnLabel || "Ping At";
    }
  }
}

async function runPagePing() {
  await _doPing({ target: "pgPingTarget", btn: "pgPingBtn", summary: "pgPingSummary", list: "pgPingList" }, 4);
}

/* Dashboard'daki hızlı ping widget'ı için: index.html içinde
   onclick="runPing()" çağrılıyordu fakat bu fonksiyon hiç tanımlı
   değildi (BUG) — buton hiçbir şey yapmıyordu / konsola hata düşüyordu.
   Ayrı sayfadaki (_doPing) mantığı burada dashboard id'leriyle yeniden
   kullanılıyor, "Sayı" seçiciyle girilen ping adedi de artık işleniyor. */
async function runPing() {
  const count = parseInt($("pingCount")?.value || "4", 10) || 4;
  await _doPing({ target: "pingTarget", btn: "pingBtn", summary: "pingSummary", list: "pingList" }, count);
}

/* ---------- Traceroute sayfası ---------- */
function renderTraceroutePage() {
  const el = $("page-traceroute");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Traceroute</h2></div>
        <div class="panel-body">
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
            <input type="text" id="trTarget" placeholder="Alan adı veya IP" style="flex:1;min-width:220px" value="google.com" />
            <button class="mini-btn blue" id="trBtn" onclick="runTraceroute()">Başlat</button>
          </div>
          <div id="trList"></div>
        </div>
      </div>
    `;
  }
}

async function runTraceroute() {
  const target = ($("trTarget")?.value || "").trim();
  if (!target) {
    toast("Hedef adres gerekli.", "warn");
    return;
  }
  const btn = $("trBtn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = ico("refresh", 14, "spin") + " Çalışıyor…";
  }
  try {
    const data = await post("/api/tools/traceroute", { target, max_hops: 20 });
    if (data.error) {
      $("trList").innerHTML = `<span class="c-red">${esc(data.error)}</span>`;
      return;
    }
    const hops = data.hops || data.steps || [];
    $("trList").innerHTML = hops.length
      ? hops
          .map(
            (h, i) =>
              `<div class="log-row"><span>${h.hop ?? i + 1}</span><span>${esc(h.ip || h.host || "-")}</span><span>${h.ms !== undefined ? h.ms + " ms" : "-"}</span></div>`,
          )
          .join("")
      : `<div class="hint">Sonuç bulunamadı.</div>`;
  } catch (e) {
    toast(e.message || "Traceroute başarısız.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Başlat";
    }
  }
}

/* ---------- Port tarama sayfası ---------- */
function showInfoModal(type) {
  const infos = {
    nmap: {
      title: "Nmap Nedir?",
      desc: "Nmap (Network Mapper), ağ keşfi ve güvenlik denetimi için kullanılan açık kaynaklı bir araçtır.",
    },
    port: {
      title: "Port Nedir?",
      desc: "Ağ üzerindeki veri iletişiminde belirli bir servise tahsis edilmiş mantıksal bağlantı noktasıdır.",
    },
    common: {
      title: "Yaygın Portlar",
      desc: "<b>22:</b> SSH, <b>80:</b> HTTP, <b>443:</b> HTTPS, <b>445:</b> SMB",
    },
    tcpudp: {
      title: "TCP / UDP Farkı",
      desc: "<b>TCP:</b> Güvenli/bağlantılı, <b>UDP:</b> Hızlı/bağlantısız.",
    },
    scans: {
      title: "Tarama Türleri",
      desc: "Yaygın, web ve tam tarama seçenekleri mevcuttur.",
    },
  };
  const info = infos[type];
  if (!info) return;
  openModal(`
    <h3 style="color:var(--txt);">${info.title}</h3>
    <div style="font-size:12.5px; color:var(--txt-2); line-height:1.6; margin-top:10px;">${info.desc}</div>
    <div style="display:flex; justify-content:flex-end; margin-top:18px;"><button class="mini-btn blue" onclick="closeModalForce()">Tamam</button></div>
  `);
}

function renderPortscanPage() {
  const el = $("page-portscan");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Port Tarama</h2></div>
        <div class="panel-body">
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;">
            <button class="mini-btn" onclick="showInfoModal('nmap')">Nmap Nedir?</button>
            <button class="mini-btn" onclick="showInfoModal('port')">Port Nedir?</button>
            <button class="mini-btn" onclick="showInfoModal('common')">Yaygın Portlar</button>
            <button class="mini-btn" onclick="showInfoModal('tcpudp')">TCP / UDP</button>
            <button class="mini-btn" onclick="showInfoModal('scans')">Tarama Türleri</button>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
            <input type="text" id="psTarget" placeholder="IP adresi" style="flex:1;min-width:220px" value="127.0.0.1" />
            <select id="psPreset">
              <option value="common">Yaygın Portlar</option>
              <option value="web">Web Portları</option>
              <option value="full">Tam Tarama (1-1024)</option>
            </select>
            <button class="mini-btn blue" id="psBtn" onclick="runPortScan()">Tara</button>
          </div>
          <div id="psSummary" class="hint"></div>
          <div id="psList" style="margin-top:10px"></div>
        </div>
      </div>
    `;
  }
}

async function runPortScan() {
  if (!hasPermission("diagnostics.run")) {
    toast("Port taraması için tanılama izni gerekli.", "warn");
    return;
  }
  const target = ($("psTarget")?.value || "").trim();
  const preset = $("psPreset")?.value || "common";
  if (!target) {
    toast("Hedef IP gerekli.", "warn");
    return;
  }
  const btn = $("psBtn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = ico("refresh", 14, "spin") + " Taranıyor…";
  }
  try {
    const data = await post("/api/tools/portscan", { target, preset });
    $("psSummary").innerHTML =
      `<div style="font-size:12px; font-weight:600; color:var(--txt); margin-bottom:12px;">Tarama Özeti: ${esc(data.ip)} — ${data.open.length} açık / ${data.scanned} taranan port</div>`;
    $("psList").innerHTML = data.open.length
      ? data.open
          .map(
            (p) =>
              `<div style="display:flex; justify-content:space-between; padding:10px 12px; background:var(--panel-2); border:1px solid var(--line-soft); border-radius:8px; margin-bottom:6px; font-size:11.5px; align-items:center;">
                 <span style="font-weight:600; color:var(--cyan);">Port ${p.port}</span>
                 <div>
                   <span class="badge ${['http','https','ssh','ftp'].includes(p.service?.toLowerCase()) ? 'warn' : 'info'}" style="margin-right:8px;">${esc(p.service?.toUpperCase() || "BİLİNMİYOR")}</span>
                   <span style="color:var(--muted); font-variant-numeric:tabular-nums;">${p.ms} ms</span>
                 </div>
               </div>`,
          )
          .join("")
      : `<div class="hint">Açık port bulunamadı.</div>`;
  } catch (e) {
    toast(e.message || "Port taraması başarısız.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Tara";
    }
  }
}

/* ---------- Hız testi ---------- */
function gaugeHtml(label, value, unit, max, color) {
  const pct = Math.min(100, Math.round(((value || 0) / max) * 100));
  return `
    <div class="gauge">
      <div class="gauge-ring" style="--pct:${pct};--color:${color}">
        <b>${value ?? "-"}</b>
        <small>${unit}</small>
      </div>
      <div class="gauge-label">${esc(label)}</div>
    </div>
  `;
}

function renderGauges(data) {
  const row = $("gaugeRow");
  if (!row) return;
  row.innerHTML = [
    gaugeHtml("Download", data?.download ?? "-", "Mbps", 200, "#3b9bff"),
    gaugeHtml("Upload", data?.upload ?? "-", "Mbps", 100, "#3ddc84"),
    gaugeHtml("Ping", data?.ping ?? "-", "ms", 100, "#f5a623"),
  ].join("");
}

async function runSpeedTest() {
  const btn = $("speedBtn");
  const note = $("speedNote");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = ico("refresh", 14, "spin") + " Test ediliyor…";
  }
  if (note) note.textContent = "Test çalışıyor, bu biraz sürebilir…";
  try {
    const data = await post("/api/tools/speedtest", {});
    if (data.error) {
      toast(data.error, "error");
      if (note) note.textContent = data.error;
      return;
    }
    renderGauges(data);
    if (note) note.textContent = `Sunucu: ${data.server || "-"}`;
    toast("Hız testi tamamlandı.", "success");
  } catch (e) {
    toast(e.message || "Hız testi başarısız.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Testi Başlat";
    }
  }
}

function renderSpeedtestPage() {
  const el = $("page-speedtest");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <h2>Hız Testi</h2>
          <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;"><button class="mini-btn blue" onclick="runSpeedTest()">Testi Başlat</button></div>
        </div>
        <div class="panel-body"><div class="gauge-row" id="gaugeRow"></div></div>
      </div>
    `;
  }
}

/* ---------- Network Analyst Merkezi ---------- */
function renderAnalystPage() {
  const el = $("page-analyst");
  if (!el || el.dataset.built) return;
  el.dataset.built = "1";
  el.innerHTML = `
    <div class="panel">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>🧠 Network Analyst Merkezi</h2><div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;"><button class="mini-btn blue" onclick="refreshAnalyst()">Yenile</button></div></div>
      <div class="panel-body">
        <div id="analystSummary" class="grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px"></div>
        <div style="display:grid;grid-template-columns:minmax(0,1.3fr) minmax(280px,.7fr);gap:12px;margin-top:12px">
          <div class="panel" style="margin:0"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>Değerlendirme Gerektiren Cihazlar</h3></div><div class="panel-body" id="analystDevices"></div></div>
          <div class="panel" style="margin:0"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>Analist Önerileri</h3></div><div class="panel-body" id="analystRecommendations"></div></div>
        </div>
        <div class="panel" style="margin-top:12px"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>Son Değişiklikler / Anomaliler</h3></div><div class="panel-body" id="analystAnomalies"></div></div>
        <div class="panel" style="margin-top:12px"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>🧠 Korelasyon ve İnceleme Önceliği</h3></div><div class="panel-body" id="analystCorrelation"></div></div>
        <div class="panel" style="margin-top:12px"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>🛡️ Security Baseline</h3></div><div class="panel-body" id="analystBaseline"></div></div>
        <div class="panel" style="margin-top:12px"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>🗺️ Topoloji Kanıtları</h3></div><div class="panel-body" id="analystTopologyEvidence"></div></div>
        <div class="panel" style="margin-top:12px"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>📈 Analiz Geçmişi</h3></div><div class="panel-body" id="analystTrends"></div></div>
        <div class="panel" style="margin-top:12px"><div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h3>Bilgi Merkezi</h3></div><div class="panel-body" id="analystKnowledge"></div></div>
      </div>
    </div>`;
}

async function refreshAnalyst() {
  try {
    renderAnalystPage();
    const [summary, devices, anomalies, knowledge, correlation, baseline, topo, trends] = await Promise.all([
      get("/api/analyst/summary"), get("/api/analyst/devices"), get("/api/analyst/anomalies"), get("/api/knowledge/network"),
      get("/api/analyst/correlation"), get("/api/analyst/baseline"), get("/api/analyst/topology-evidence"), get("/api/analyst/trends")
    ]);
    const s = summary || {};
    const inv = s.inventory || {}, sec = s.security || {}, perf = s.performance || {};
    const summaryEl = $("analystSummary");
    if (summaryEl) summaryEl.innerHTML = [
      ["Network Health", `${s.health?.score ?? "-"}/100`], ["Toplam", inv.total ?? 0], ["Çevrimiçi", inv.online ?? 0], ["Çevrimdışı", inv.offline ?? 0],
      ["Envanter Tamlığı", `%${inv.completeness ?? 0}`], ["Güvenlik İncelemesi", sec.review_items ?? 0], ["Ort. Gecikme", perf.average_latency_ms == null ? "-" : `${perf.average_latency_ms} ms`]
    ].map(x => `<div class="info-card"><span>${esc(x[0])}</span><b>${esc(x[1])}</b></div>`).join("");
    const ds = (devices?.devices || []).filter(d => d.exposure?.findings?.length || d.completeness < 70 || d.confidence < 70 || ["offline","stale"].includes(d.status));
    const de = $("analystDevices");
    if (de) de.innerHTML = ds.length ? ds.slice(0,50).map(d => `<div style="padding:10px;border-bottom:1px solid var(--line-soft)"><div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(d.hostname || d.ip || "Bilinmeyen cihaz")}</b><span class="badge ${d.exposure?.risk === 'medium' ? 'warn' : d.status === 'online' ? 'ok' : 'gray'}">${esc(d.device_type)} · %${d.confidence}</span></div><div class="hint">${esc(d.recommendations?.[0] || `Envanter tamlığı %${d.completeness}`)}</div></div>`).join("") : '<div class="hint">Şu anda aksiyon gerektiren belirgin bir cihaz yok.</div>';
    const re = $("analystRecommendations");
    if (re) re.innerHTML = (s.top_recommendations || []).map(x => `<div style="padding:9px;border-bottom:1px solid var(--line-soft)">• ${esc(x)}</div>`).join("") || '<div class="hint">Öneri bulunmuyor.</div>';
    const ae = $("analystAnomalies");
    if (ae) ae.innerHTML = (anomalies?.anomalies || []).slice(0,25).map(a => `<div style="padding:8px;border-bottom:1px solid var(--line-soft)"><b>${esc(a.event)}</b> · ${esc(a.field || "")}: ${esc(a.old || "-")} → ${esc(a.new || "-")} <span class="hint">${esc(a.source || "")}</span></div>`).join("") || '<div class="hint">Henüz değişiklik kaydı yok.</div>';
    const co = $("analystCorrelation");
    if (co) co.innerHTML = (correlation?.devices || []).slice(0,30).map(d => { const p=d.review_priority||{}; const c=d.correlation||{}; return `<div style="padding:10px;border-bottom:1px solid var(--line-soft)"><div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(d.hostname||d.ip||"Bilinmeyen")}</b><span class="badge ${p.level==='high'?'fail':p.level==='medium'?'warn':'ok'}">Öncelik ${esc(p.score)} · Korelasyon ${esc(c.score)}%</span></div><div class="hint">${esc((c.signals||[]).slice(0,4).join(' · ')||'Yeterli kanıt yok')}</div><div class="hint">${esc((p.reasons||[]).join(' · ')||'Belirgin ek inceleme nedeni yok')}</div></div>`; }).join("") || '<div class="hint">Korelasyon verisi için önce keşif çalıştırın.</div>';
    const be = $("analystBaseline");
    if (be) be.innerHTML = (baseline?.devices || []).slice(0,30).map(d => `<div style="display:flex;justify-content:space-between;padding:8px;border-bottom:1px solid var(--line-soft)"><span>${esc(d.hostname||d.ip||'Bilinmeyen')}</span><b>${esc(d.score)}%</b></div>`).join("") || '<div class="hint">Baseline verisi yok.</div>';
    const te = $("analystTopologyEvidence");
    if (te) te.innerHTML = (topo?.edges || []).slice(0,50).map(e => `<div style="padding:7px;border-bottom:1px solid var(--line-soft)"><b>${esc(e.source)}</b> → <b>${esc(e.target)}</b> <span class="hint">${esc(e.protocol||'')} ${e.port?'· '+esc(e.port):''}</span></div>`).join("") || '<div class="hint">LLDP/CDP/komşuluk kanıtı bulunamadı. Kanıt yoksa bağlantı uydurulmaz.</div>';
    const tr = $("analystTrends");
    if (tr) { const pts=trends?.points||[]; tr.innerHTML=pts.length ? `<div class="hint">Son ${pts.length} analiz snapshotı. Health ve envanter tamlığı zaman içinde izlenir.</div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-top:8px">${pts.slice(-12).map(x=>`<div class="info-card"><span>${new Date(x.created_at*1000).toLocaleTimeString()}</span><b>${esc(x.total)} cihaz</b><small>Health ${esc(x.health)} · Env. ${esc(x.completeness)}%</small></div>`).join('')}</div>` : '<div class="hint">Henüz analiz snapshotı yok. Yönetici bir snapshot oluşturduğunda trend burada tutulur.</div>'; }
    const ke = $("analystKnowledge");
    if (ke) ke.innerHTML = (knowledge?.topics || []).map(t => `<details style="padding:8px;border-bottom:1px solid var(--line-soft)"><summary style="cursor:pointer;font-weight:700">${esc(t.title)}</summary><div class="hint" style="margin-top:6px;line-height:1.6">${esc(t.text)}</div></details>`).join("");
  } catch (e) { toast(e.message || "Analist verileri alınamadı.", "error"); }
}

/* ---------- Güvenlik sayfası ---------- */
function renderSecurityPage() {
  const el = $("page-security");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Güvenlik</h2></div>
        <div class="panel-body" id="securityBody"><div class="hint">Yükleniyor…</div></div>
      </div>
    `;
  }
}

async function refreshSecurity() {
  try {
    const data = await get("/api/security");
    S.securityData = data;
    const body = $("securityBody");
    if (!body) return;
    if (data.error) {
      body.innerHTML = `<div class="hint c-red">${esc(data.error)}</div>`;
      return;
    }
    const statusBadge = (desc) => {
      const d = (desc || "").toLowerCase();
      if (d.includes("aktif") || d.includes("açık") || d.includes("açik") || d.includes("izin") || d.includes("başarılı")) return `<span class="badge ok">PASS</span>`;
      if (d.includes("uyarı") || d.includes("sınırlı") || d.includes("warning")) return `<span class="badge warn">WARNING</span>`;
      if (!d || d.includes("bilinmiyor") || d.includes("doğrulanamadı") || d.includes("ölçül")) return `<span class="badge gray">DOĞRULANAMADI</span>`;
      return `<span class="badge fail">SORUN</span>`;
    };

    const rulesHtml = (data.rules || []).length > 0 ? (data.rules || []).map((r, index) =>
      `<div style="display:flex; justify-content:space-between; padding:12px; border:1px solid var(--line-soft); border-radius:8px; background:var(--panel-2); margin-bottom:8px; align-items:center;">
        <div style="display:flex; align-items:center; gap:10px;">
          <div style="color:var(--blue);">${ico("shield", 20)}</div>
          <span style="color:var(--txt); font-weight:600; font-size:13px;">${esc(r.name || r.title || "")}</span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
          ${statusBadge(r.status)}
          <button class="mini-btn" onclick="showSecurityRule(${index})">Kanıtı İncele</button>
        </div>
      </div>`
    ).join("") : '<div class="hint">Kayıtlı güvenlik kuralı ihlali bulunamadı.</div>';

    body.innerHTML = `
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:12px; margin-bottom:20px;">
        <div style="padding:16px; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; display:flex; flex-direction:column; gap:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px; color:var(--cyan); font-weight:bold;">${ico("shield", 20)} Güvenlik Duvarı</div>
            ${statusBadge(data.firewall_desc)}
          </div>
          <div style="font-size:12px; color:var(--txt-2); line-height:1.5; margin-top:4px;">${esc(data.firewall_desc || "")}</div>
          <div style="margin-top:auto; padding-top:12px;"><button class="btn btn-sm" style="width:100%" onclick="inspectSecurityCapability('firewall')">Ölçüm Ayrıntısını Gör</button></div>
        </div>
        <div style="padding:16px; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; display:flex; flex-direction:column; gap:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px; color:var(--cyan); font-weight:bold;">${ico("globe", 20)} Web Filtresi</div>
            ${statusBadge(data.webfilter_desc)}
          </div>
          <div style="font-size:12px; color:var(--txt-2); line-height:1.5; margin-top:4px;">${esc(data.webfilter_desc || "")}</div>
          <div style="margin-top:auto; padding-top:12px;"><button class="btn btn-sm" style="width:100%" onclick="inspectSecurityCapability('web_filter')">Entegrasyon Durumunu Gör</button></div>
        </div>
      </div>
      <h3 style="margin:0 0 12px; font-size:14px; color:var(--txt); border-bottom:1px solid var(--line-soft); padding-bottom:8px;">Politika İhlalleri & Güvenlik Logları</h3>
      ${rulesHtml}
      <div id="securityPostureBody" style="margin-top:18px"></div>
    `;
    const postureEl = $("securityPostureBody");
    if (!hasPermission("security.manage")) {
      postureEl.innerHTML = `<div style="padding:14px;border:1px solid rgba(245,158,11,.35);border-radius:10px"><b>Risk bulguları için rol izni gerekiyor.</b><div class="hint">Gerekli izin: <code>security.manage</code></div><button class="mini-btn" style="margin-top:8px" onclick="go('access')">Yöneticiden Ne İstemeliyim?</button></div>`;
    } else {
      const posture = await get("/api/security/posture");
      postureEl.innerHTML = `<h3>Kanıta Dayalı Risk Bulguları</h3><div class="hint" style="margin-bottom:10px">${esc(posture.scope_note)}</div>
        ${(posture.findings||[]).map(f=>`<div style="padding:12px;border:1px solid ${f.severity==='high'?'rgba(239,68,68,.35)':'rgba(245,158,11,.35)'};border-radius:9px;margin-bottom:8px"><div style="display:flex;justify-content:space-between"><b>${esc(f.asset)}</b><span class="badge ${f.severity==='high'?'fail':'warn'}">${esc(f.severity)}</span></div><div>${esc(f.title)}</div><div class="hint">Kanıt: ${esc(f.evidence)}</div><div class="hint"><b>Öneri:</b> ${esc(f.recommendation)}</div></div>`).join('') || '<div class="hint">Mevcut keşif kanıtlarında risk bulgusu oluşmadı.</div>'}`;
    }
  } catch (e) {
    console.warn("Güvenlik verisi alınamadı:", e);
    renderLoadError("securityBody", "Güvenlik görünürlüğü alınamadı", e, "refreshSecurity()");
  }
}

function showSecurityRule(index) {
  const rule = (S.securityData?.rules || [])[Number(index)];
  if (!rule) return toast("Kural kanıtı artık mevcut değil; ekranı yenileyin.", "warn");
  openModal(`<h3>${esc(rule.name || rule.title || "Güvenlik bulgusu")}</h3>
    <div class="sub">Yalnız ölçülen yerel güvenlik verisi gösterilir.</div>
    <div class="device-learning" style="margin-top:12px"><b>Durum / Kanıt</b><div>${esc(rule.status || rule.detail || "Ayrıntı sağlanmadı.")}</div></div>
    <div style="display:flex;justify-content:flex-end;margin-top:16px"><button class="mini-btn blue" onclick="closeModalForce()">Kapat</button></div>`);
}

async function inspectSecurityCapability(kind) {
  try {
    const [security, readiness] = await Promise.all([get("/api/security"), get("/api/system/readiness")]);
    const capability = (readiness.items || []).find(item => item.id === kind);
    const title = kind === "firewall" ? "Yerel Güvenlik Duvarı Ölçümü" : "Web Filtresi Entegrasyonu";
    const detail = kind === "firewall" ? (security.firewall_desc || "Güvenlik duvarı durumu doğrulanamadı.") : (capability?.detail || "Bu sürümde web filtresi bağlayıcısı yok.");
    openModal(`<h3>${esc(title)}</h3><div class="device-learning ${capability?.state === 'unavailable' ? 'warning' : ''}" style="margin-top:12px"><b>${esc(capability?.state === 'unavailable' ? "Kullanılamıyor" : "Gerçek ölçüm")}</b><div>${esc(detail)}</div></div>
      ${capability?.action ? `<div class="hint" style="margin-top:10px">${esc(capability.action)}</div>` : ""}
      <div style="display:flex;justify-content:flex-end;margin-top:16px"><button class="mini-btn blue" onclick="closeModalForce()">Kapat</button></div>`);
  } catch (e) { toast(e.message || "Güvenlik hazırlığı alınamadı.", "error"); }
}

Object.assign(globalThis, {
  logRowHtml,
  renderLogs,
  setLogLevel,
  setLogQuery,
  refreshLogs,
  clearLogs,
  renderLogsPage,
  renderPingPage,
  runNetworkCmd,
  _doPing,
  runPagePing,
  runPing,
  renderTraceroutePage,
  runTraceroute,
  showInfoModal,
  renderPortscanPage,
  runPortScan,
  gaugeHtml,
  renderGauges,
  runSpeedTest,
  renderSpeedtestPage,
  renderAnalystPage,
  refreshAnalyst,
  renderSecurityPage,
  refreshSecurity,
  showSecurityRule,
  inspectSecurityCapability,
});
