import "./topology-details.js";

async function refreshDashboardWidgets() {
  const ttContainer = $("dashboardTopTalkersList");
  if (ttContainer) {
    try {
      const data = await get("/api/traffic/top-talkers");
      const talkers = data?.top_talkers || [];
      const sampleMeta = `<div class="traffic-footnote" style="margin:0 0 9px;padding:0 0 8px"><span>Toplam: ${esc(data.total_bandwidth_display || "0 bps")} · ${Number(data.session_count || 0)} aktif soket</span><span>${data.sample_stale ? "Trafik örneği güncel değil" : `Sayaç ${esc(data.sample_time || "-")}`}</span></div>`;
      if (!talkers.length) {
        ttContainer.innerHTML = `${sampleMeta}<div style="color:var(--muted); font-size:12px; padding:12px; text-align:center">Aktif uzak soket bulunamadı. Bu durum arayüz trafiğinin sıfır olduğu anlamına gelmez.</div>`;
      } else {
        ttContainer.innerHTML = sampleMeta + talkers.slice(0, 4).map((t, idx) => {
          const activityDisplay = `${Number(t.active_conns || 0)} aktif bağlantı`;
          return `
          <div class="talker-row" style="margin-bottom:6px; padding:8px 10px;">
            <div class="talker-rank">#${idx + 1}</div>
            <div class="talker-info">
              <div class="talker-title">
                <span title="${esc(t.ip)}">${esc(t.hostname || t.ip)}</span>
                <span class="talker-proto-badge">${esc(t.primary_protocol)}</span>
                ${(t.local_processes || (t.local_process_name || t.process_name ? [t.local_process_name || t.process_name] : [])).length ? `<span class="talker-proto-badge" title="Bu uzak bağlantıyı yerel bilgisayarda açan uygulama" style="background:rgba(56,189,248,0.12); color:#38bdf8; border:1px solid rgba(56,189,248,0.3)">Yerel uygulama: ${esc((t.local_processes || [t.local_process_name || t.process_name]).join(", "))}</span>` : ""}
              </div>
              <div class="talker-bar-bg">
                <div class="talker-bar-fill" style="width:${Math.min(100, Math.max(4, Number(t.active_conns || 0) * 8))}%"></div>
              </div>
            </div>
            <div class="talker-speed">
              <b>${activityDisplay}</b>
              <span>gerçek soket</span>
            </div>
          </div>
        `;}).join("");
      }
    } catch (e) {
      renderLoadError(ttContainer, "Aktif oturum özeti yüklenemedi", e, "refreshDashboardWidgets()");
    }
  }

  const ipamContainer = $("dashboardIpamSummary");
  if (ipamContainer) {
    try {
      const data = await get("/api/ipam");
      const subnet = data?.subnets?.[0] || {};
      const conflicts = data?.conflicts || [];

      let conflictHtml = "";
      if (conflicts.length > 0) {
        conflictHtml = `
          <div style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.4); border-radius:8px; padding:8px 12px; margin-bottom:10px; display:flex; align-items:center; justify-content:space-between; animation:threatAuraPulse 1.8s infinite;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="color:#f87171; font-size:16px">🚨</span>
              <div>
                <b style="color:#f87171; font-size:12px">${conflicts.length} Adet IP Çakışması!</b>
                <span style="display:block; color:var(--txt-2); font-size:10.5px">${esc(conflicts[0].ip)} adresi çift MAC tarafından kullanılıyor</span>
              </div>
            </div>
            <button class="mini-btn" style="background:#ef4444; border-color:#dc2626; color:white;" onclick="go('ipam')">İncele</button>
          </div>
        `;
      }

      ipamContainer.innerHTML = `
        ${conflictHtml}
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px;">
          <span style="font-size:12px; font-weight:600; color:var(--txt)">${esc(subnet.cidr || "Yerel subnet ölçülmedi")}</span>
          <span style="font-size:11px; color:var(--cyan); font-weight:700">%${subnet.utilization_pct || 0} Dolu</span>
        </div>
        <div class="talker-bar-bg" style="height:8px; margin-bottom:10px;">
          <div class="talker-bar-fill" style="width:${subnet.utilization_pct || 0}%; background:linear-gradient(90deg, #10b981, #f59e0b, #ef4444)"></div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:6px; font-size:11px; text-align:center;">
          <div style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:6px; padding:6px;">
            <span style="color:var(--muted); font-size:9.5px; display:block">Kullanılan IP</span>
            <b style="color:var(--cyan); font-size:13px">${subnet.used_hosts || 0}</b>
          </div>
          <div style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:6px; padding:6px;">
            <span style="color:var(--muted); font-size:9.5px; display:block">Gözlenmeyen IP</span>
            <b style="color:#34d399; font-size:13px">${subnet.free_hosts || 0}</b>
          </div>
          <div style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:6px; padding:6px;">
            <span style="color:var(--muted); font-size:9.5px; display:block">Toplam Kapasite</span>
            <b style="color:var(--txt); font-size:13px">${subnet.total_hosts ?? "-"}</b>
          </div>
        </div>
      `;
    } catch (e) {
      renderLoadError(ipamContainer, "IPAM özeti yüklenemedi", e, "refreshDashboardWidgets()");
    }
  }
}

/* ============================================================
   IPAM & IP CONFLICT DETECTION PAGE
   ============================================================ */
function renderIpamPage() {
  const el = $("page-ipam");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div id="ipamConflictAlertArea"></div>

      <div class="grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px;">
        <div class="panel" style="padding:16px; border-left:4px solid var(--cyan)">
          <span style="color:var(--muted); font-size:11px">Subnet Adresi & Ağ Maskesi</span>
          <h2 style="margin:4px 0 0; font-size:18px" id="ipamSubnetCidr">-</h2>
          <small style="color:var(--txt-2)" id="ipamGatewayIp">Gateway: -</small>
        </div>
        <div class="panel" style="padding:16px; border-left:4px solid #10b981">
          <span style="color:var(--muted); font-size:11px">Kullanılan / Dolu IP</span>
          <h2 style="margin:4px 0 0; font-size:18px; color:#34d399" id="ipamUsedIps">-</h2>
          <small style="color:var(--txt-2)" id="ipamUtilPct">Doluluk: -</small>
        </div>
        <div class="panel" style="padding:16px; border-left:4px solid #818cf8">
          <span style="color:var(--muted); font-size:11px">Son Keşifte Gözlenmeyen IP'ler</span>
          <h2 style="margin:4px 0 0; font-size:18px; color:#a5b4fc" id="ipamFreeIps">-</h2>
          <small style="color:var(--txt-2)">Boş olduğu DHCP/ARP ile kesinleşmiş değildir</small>
        </div>
        <div class="panel" style="padding:16px; border-left:4px solid #f59e0b">
          <span style="color:var(--muted); font-size:11px">DHCP Dağıtım Aralığı (Doğrulanmış)</span>
          <h2 style="margin:4px 0 0; font-size:16px; color:#fbbf24" id="ipamDhcpRange">-</h2>
          <small style="color:var(--txt-2)">Dinamik IP Havuzu</small>
        </div>
      </div>

      <!-- INTERACTIVE IP MAP GRID -->
      <div class="panel" style="margin-top:16px">
        <div class="panel-head">
          <div style="display:flex;align-items:center;gap:10px">
            <h2 style="margin:0">İnteraktif Subnet IP Havuz Haritası (IP Map Grid)</h2>
            <div style="display:flex;gap:8px;font-size:11px;margin-left:12px">
              <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:2px;background:rgba(16,185,129,0.5)"></span> Gateway</span>
              <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:2px;background:rgba(56,189,248,0.5)"></span> Aktif / Dolu</span>
              <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:2px;background:rgba(239,68,68,0.7)"></span> Çakışma (Conflict)</span>
              <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:2px;background:rgba(255,255,255,0.06)"></span> Boş (Free)</span>
            </div>
          </div>
          <div class="right"><button class="mini-btn" onclick="refreshIpam()">Yenile</button></div>
        </div>
        <div class="panel-body">
          <div class="ipam-grid-map" id="ipamGridMap">
            <div class="skeleton-box" style="height:140px; width:100%; grid-column:1/-1"></div>
          </div>
        </div>
      </div>

      <!-- IP ALLOCATION LIST -->
      <div class="panel" style="margin-top:16px">
        <div class="panel-head">
          <h2>Tahsis Edilen IP Listesi ve Rezervasyonlar</h2>
          <div class="right">
            <input type="text" id="ipamSearchInput" placeholder="IP veya Hostname ara..." oninput="filterIpamAllocations(this.value)" style="width:200px" />
          </div>
        </div>
        <div class="panel-body" style="padding:0">
          <table class="table" style="width:100%">
            <thead>
              <tr>
                <th>IP Adresi</th>
                <th>Cihaz / Hostname</th>
                <th>MAC Adresi</th>
                <th>Cihaz Tipi</th>
                <th>Tahsis Türü</th>
                <th>Durum</th>
                <th>İşlem</th>
              </tr>
            </thead>
            <tbody id="ipamAllocationsTable">
              <tr><td colspan="7" class="skeleton-box" style="height:80px"></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }
}

let _ipamAllocationsCache = [];

function ipv4ToUint32(ip) {
  const octets = String(ip || "").split(".").map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  return ((((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0);
}

async function refreshDiscoverySchedule() {
  const el = $("discoveryScheduleCard"); if (!el) return;
  try {
    const s = await get("/api/discovery/schedule");
    const mins = Math.round(Number(s.interval_seconds || 0) / 60);
    const next = s.next_run ? new Date(s.next_run * 1000).toLocaleString() : "İlk çalışma bekleniyor";
    el.innerHTML = `<div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
      <div><b>⏱ Otomatik Ağ Keşfi</b> <span class="badge ${s.last_status==='failed'?'fail':s.last_status==='running'?'warn':'ok'}">${esc(s.last_status)}</span><div class="hint">Kapsam: ${esc(s.target_subnet)} · Her ${mins} dakika · Sonuç: ${Number(s.last_total||0)} cihaz</div></div>
      <div style="text-align:right"><small class="hint">Sonraki çalışma: ${esc(next)}</small><br>${s.can_manage?'<button class="mini-btn" onclick="go(\'settings\')">Zamanlamayı Düzenle</button>':'<button class="mini-btn" onclick="go(\'access\')">Gerekli Yetkiyi Gör</button>'}</div>
    </div>${s.last_error?`<div class="hint c-red" style="margin-top:6px">${esc(s.last_error)}</div>`:''}`;
  } catch(e) { el.innerHTML=`<div class="hint c-red">Keşif zamanlaması alınamadı: ${esc(e.message)}</div>`; }
}

function uint32ToIpv4(value) {
  const n = Number(value) >>> 0;
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

function ipv4HostsFromCidr(cidr, maxHosts = 4094) {
  const [rawIp, rawPrefix] = String(cidr || "").split("/");
  const ipNumber = ipv4ToUint32(rawIp);
  const prefixLength = Number(rawPrefix);
  if (ipNumber === null || !Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) {
    return { hosts: [], prefixLength, error: "Geçersiz IPv4 CIDR bilgisi." };
  }

  const addressCount = 2 ** (32 - prefixLength);
  const usableCount = prefixLength <= 30 ? Math.max(0, addressCount - 2) : addressCount;
  if (usableCount > maxHosts) {
    return {
      hosts: [],
      prefixLength,
      usableCount,
      error: `${usableCount.toLocaleString("tr-TR")} adres tek görünüm için çok büyük. En fazla ${maxHosts.toLocaleString("tr-TR")} adres gösterilebilir.`,
    };
  }

  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
  const networkNumber = (ipNumber & mask) >>> 0;
  const firstHost = prefixLength <= 30 ? networkNumber + 1 : networkNumber;
  const lastHost = prefixLength <= 30
    ? networkNumber + addressCount - 2
    : networkNumber + addressCount - 1;
  const hosts = [];
  for (let current = firstHost; current <= lastHost; current += 1) hosts.push(uint32ToIpv4(current));
  return { hosts, prefixLength, usableCount };
}

async function refreshIpam() {
  try {
    const data = await get("/api/ipam");
    const subnet = data?.subnets?.[0] || {};
    const conflicts = data?.conflicts || [];
    _ipamAllocationsCache = data?.allocations || [];

    const cEl = $("ipamSubnetCidr"); if (cEl) cEl.textContent = subnet.cidr || "-";
    const gEl = $("ipamGatewayIp"); if (gEl) gEl.textContent = "Gateway: " + (subnet.gateway || "-");
    const uEl = $("ipamUsedIps"); if (uEl) uEl.textContent = `${subnet.used_hosts || 0} Adet IP`;
    const utEl = $("ipamUtilPct"); if (utEl) utEl.textContent = `Doluluk: %${subnet.utilization_pct || 0}`;
    const fEl = $("ipamFreeIps"); if (fEl) fEl.textContent = `${subnet.free_hosts || 0} Gözlenmeyen IP`;
    const dEl = $("ipamDhcpRange"); if (dEl) dEl.textContent = subnet.dhcp_range || "DHCP sunucusundan doğrulanmadı";

    const alertArea = $("ipamConflictAlertArea");
    if (alertArea) {
      if (conflicts.length > 0) {
        alertArea.innerHTML = conflicts.map(c => `
          <div class="conflict-alert-card">
            <span style="font-size:24px">🚨</span>
            <div style="flex:1">
              <h3 style="margin:0 0 4px; color:#f87171; font-size:14px">KRİTİK IP ÇAKIŞMASI: ${esc(c.ip)}</h3>
              <p style="margin:0; font-size:12px; color:var(--txt-2)">
                ${esc(c.message)}
                <br/><b>İlişkili Cihazlar:</b> ${esc(c.hostnames.join(", "))} | <b>MAC Listesi:</b> <code>${esc(c.macs.join(" / "))}</code>
              </p>
            </div>
            <button class="mini-btn" style="background:#ef4444; border-color:#dc2626; color:white;" onclick="quickTraceroute('${c.ip}')">Yolu İncele (Trace)</button>
          </div>
        `).join("");
      } else {
        alertArea.innerHTML = `
          <div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3); border-radius:10px; padding:10px 16px; margin-bottom:14px; display:flex; align-items:center; gap:10px;">
            <span style="color:#34d399">✅</span>
            <span style="font-size:12.5px; color:#34d399"><b>Mevcut gözlem temiz:</b> Son keşif verilerinde aynı IP'yi kullanan birden fazla MAC görülmedi.</span>
          </div>
        `;
      }
    }

    const gridEl = $("ipamGridMap");
    if (gridEl) {
      const cidrStr = subnet.cidr || "";
      if (!cidrStr) {
        gridEl.innerHTML = `<div style="grid-column:1/-1;padding:20px;text-align:center;color:var(--muted)">Yerel subnet henüz ölçülmedi. Önce canlı ağ taraması başlatın.</div>`;
        renderIpamAllocationsTable(_ipamAllocationsCache);
        return;
      }
      const cidrHosts = ipv4HostsFromCidr(cidrStr);
      const prefixLength = cidrHosts.prefixLength;
      if (cidrHosts.error) {
        gridEl.classList.remove("multi-subnet");
        gridEl.innerHTML = `<div style="grid-column:1/-1;padding:20px;text-align:center;color:var(--muted)">${esc(cidrStr)}: ${esc(cidrHosts.error)} Gözlenen adresler aşağıdaki tabloda listeleniyor.</div>`;
        renderIpamAllocationsTable(_ipamAllocationsCache);
        return;
      }
      gridEl.classList.toggle("multi-subnet", prefixLength < 24);
      const conflictIps = new Set(conflicts.map(c => c.ip));
      const usedMap = new Map();
      _ipamAllocationsCache.forEach(a => usedMap.set(a.ip, a));

      let gridHtml = "";
      let currentBlock = "";
      for (const currentIp of cidrHosts.hosts) {
        const octets = currentIp.split(".");
        const block = `${octets.slice(0, 3).join(".")}.0/24`;
        if (prefixLength < 24 && block !== currentBlock) {
          currentBlock = block;
          gridHtml += `<div class="ipam-subnet-divider">${esc(block)}</div>`;
        }
        let statusCls = "free";
        let title = `${currentIp} - Son keşifte gözlenmedi (boş olduğu doğrulanmadı)`;

        if (conflictIps.has(currentIp)) {
          statusCls = "conflict";
          title = `🚨 ÇAKIŞMA: ${currentIp}`;
        } else if (currentIp === subnet.gateway) {
          statusCls = "gateway";
          title = `Gateway / Router: ${currentIp}`;
        } else if (usedMap.has(currentIp)) {
          statusCls = "used";
          const dev = usedMap.get(currentIp);
          title = `${currentIp} - ${dev.hostname} (${dev.type})`;
        }

        const nodeLabel = prefixLength === 24 ? `.${octets[3]}` : octets.slice(2).join(".");
        gridHtml += `<div class="ipam-ip-node ${statusCls}" title="${esc(title)}" onclick="handleIpamNodeClick('${esc(currentIp)}', '${statusCls}')">${esc(nodeLabel)}</div>`;
      }
      gridEl.innerHTML = gridHtml;
    }

    renderIpamAllocationsTable(_ipamAllocationsCache);
  } catch (err) {
    console.error("IPAM fetch error:", err);
  }
}

function handleIpamNodeClick(ip, status) {
  if (status === "free") {
    showFreeIpModal(ip);
  } else {
    inspectDevice(ip);
  }
}

function showFreeIpModal(ip) {
  openModal(`
    <div style="padding:12px">
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:14px;">
        <div style="width:44px; height:44px; border-radius:12px; background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.3); display:grid; place-items:center; font-size:22px;">
          🌐
        </div>
        <div>
          <h3 style="margin:0; font-size:16px; color:var(--txt)">${esc(ip)}</h3>
          <span style="font-size:11px; color:#34d399; font-weight:700">● Son Keşifte Gözlenmeyen IP</span>
        </div>
      </div>

      <div style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:8px; padding:12px; font-size:11.5px; color:var(--txt-2); margin-bottom:16px;">
        Bu IP adresi son keşifte gözlenmedi. ICMP yanıt vermemesi adresin kesin olarak boş olduğu anlamına gelmez; DHCP kira tablosunu ve ARP kayıtlarını doğrulamadan statik atama yapmayın.
        <div id="freeIpPingResult" style="margin-top:10px; display:none; padding:10px; border-radius:6px; background:var(--bg); border:1px solid var(--line);"></div>
      </div>

      <div style="display:flex; flex-direction:column; gap:8px;">
        <button class="mini-btn blue" id="btnPingFreeIp" style="padding:9px; justify-content:center" onclick="testFreeIpPing('${esc(ip)}')">⚡ Anlık Ping Testi Yap (Gizli Cihaz Kontrolü)</button>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
          <button class="mini-btn" style="justify-content:center" onclick="closeModalForce(); quickScan('${esc(ip)}')">🔍 Port Tara</button>
          <button class="mini-btn" style="justify-content:center" onclick="closeModalForce(); quickTraceroute('${esc(ip)}')">🛣️ Traceroute</button>
        </div>
      </div>
      <div style="margin-top:14px; text-align:right">
        <button class="mini-btn" onclick="closeModalForce()">Kapat</button>
      </div>
    </div>
  `);
}

window.testFreeIpPing = async function(ip) {
  const resBox = $("freeIpPingResult");
  const btn = $("btnPingFreeIp");
  if (btn) btn.disabled = true;
  if (resBox) {
    resBox.style.display = "block";
    resBox.innerHTML = `<span style="color:var(--cyan)">Pingleme yapılıyor (4 paket)...</span>`;
  }
  try {
    const data = await post("/api/tools/ping", { target: ip, count: 4 });
    const isUp = data?.success && (data?.alive || data?.received > 0);
    if (resBox) {
      if (isUp) {
        resBox.innerHTML = `
          <b style="color:#ef4444">⚠️ DİKKAT: Cihaz Yanıt Verdi!</b>
          <div style="color:var(--txt-2); margin-top:2px">Ortalama Gecikme: ${data.avg_rtt ?? data.rtt ?? "-"} ms · Paket Kaybı: %${data.packet_loss ?? "-"}</div>
          <small style="color:var(--muted)">Ağda kaydedilmemiş / statik bir cihaz bu IP'yi aktif olarak kullanıyor.</small>
        `;
      } else {
        resBox.innerHTML = `
          <b style="color:#f59e0b">⚠️ ICMP Yanıtı Alınamadı</b>
          <div style="color:var(--txt-2); margin-top:2px">Bu sonuç IP'nin boş olduğunu kanıtlamaz. DHCP kira tablosu ve ARP kayıtları ayrıca doğrulanmalıdır.</div>
        `;
      }
    }
  } catch (e) {
    if (resBox) resBox.innerHTML = `<span style="color:#ef4444">Hata: ${esc(e.message)}</span>`;
  } finally {
    if (btn) btn.disabled = false;
  }
};

function renderIpamAllocationsTable(list) {
  const tbody = $("ipamAllocationsTable");
  if (!tbody) return;
  if (!list || !list.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--muted)">Kayıtlı IP tahsisi bulunamadı.</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(a => `
    <tr>
      <td><b><code style="color:var(--cyan)">${esc(a.ip)}</code></b></td>
      <td><b>${esc(a.hostname)}</b></td>
      <td><code>${esc(a.mac || "-")}</code></td>
      <td><span class="badge ${a.type==='server'?'blue':a.type==='router'?'cyan':'gray'}">${esc(a.type || "unknown")}</span></td>
      <td><span class="badge ${a.allocation_type==='Infrastructure'?'purple':'blue'}">${esc(a.allocation_type || "Observed")}</span></td>
      <td><span class="badge ${a.status==='online'?'ok':'gray'}">${esc(a.status || "unknown")}</span></td>
      <td>
        <button class="mini-btn" onclick="quickTraceroute('${esc(a.ip)}')">Trace</button>
        <button class="mini-btn blue" onclick="inspectDevice('${esc(a.ip)}', '${esc(a.mac || "")}')">İncele</button>
      </td>
    </tr>
  `).join("");
}

function filterIpamAllocations(q) {
  const query = (q || "").toLowerCase();
  const filtered = _ipamAllocationsCache.filter(a =>
    (a.ip || "").toLowerCase().includes(query) ||
    (a.hostname || "").toLowerCase().includes(query) ||
    (a.mac || "").toLowerCase().includes(query)
  );
  renderIpamAllocationsTable(filtered);
}

/* ============================================================
   TOP TALKERS & BANDWIDTH LEADERBOARD PAGE
   ============================================================ */

Object.assign(globalThis, {
  refreshDashboardWidgets,
  renderIpamPage,
  _ipamAllocationsCache,
  ipv4ToUint32,
  refreshDiscoverySchedule,
  uint32ToIpv4,
  ipv4HostsFromCidr,
  refreshIpam,
  handleIpamNodeClick,
  showFreeIpModal,
  renderIpamAllocationsTable,
  filterIpamAllocations,
});
