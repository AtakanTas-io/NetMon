import "./dashboard.js";

function renderDeviceTable() {
  const body = $("devBody");
  if (!body) return;
  const q = ($("devFilter")?.value || "").toLowerCase().trim();

  // Alt Ağ (Subnet) Filtresini Dinamik Doldur
  const subnetSelect = $("devSubnetFilter");
  if (subnetSelect) {
    const currentVal = S.deviceSubnetFilter || "all";

    // Parse custom names from settings
    const subnetNames = {};
    if (S.settings && S.settings.subnet) {
       S.settings.subnet.split(',').forEach(s => {
          const parts = s.split('=');
          if (parts.length > 1) {
             const ipPart = parts[0].trim();
             const namePart = parts[1].trim();
             const prefix = ipPart.substring(0, ipPart.lastIndexOf('.'));
             subnetNames[prefix] = namePart;
          }
       });
    }

    const nets = [...new Set(S.devices.filter(d=>d.ip).map(d => {
      const parts = d.ip.split('.');
      return parts.length === 4 ? parts.slice(0,3).join('.') : 'Bilinmeyen';
    }))].filter(x => x !== 'Bilinmeyen').sort();

    let html = `<option value="all">🌐 Tüm Şirket Ağları (Tümü)</option>`;
    nets.forEach(prefix => {
       const val = prefix + ".*";
       const customName = subnetNames[prefix];
       const displayName = customName ? `${customName} (${prefix}.x)` : `Ağ Bloğu: ${prefix}.x`;
       html += `<option value="${val}" ${currentVal===val?'selected':''}>${esc(displayName)}</option>`;
    });
    subnetSelect.innerHTML = html;
  }

  const list = S.devices.filter((d) => {
    const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
    const hw = inv.hardware || {};
    const sw = inv.software || {};
    const text = [
      d.ip, d.hostname, d.friendly_name, d.mac, d.vendor, d.type, TYPE_LABEL[d.type], d.notes,
      hw.cpu_model, hw.gpu, hw.motherboard_maker, sw.os_name
    ].filter(Boolean).join(" ").toLowerCase();
    return !q || text.includes(q);
  });

  const tab = S.deviceTab || "all";
  const statusFilter = S.deviceStatusFilter || "all";
  const typeFilter = S.deviceTypeFilter || "all";
  const filteredList = list.filter((d) => {
    const st = deviceStatus(d);
    const tp = d?.type || "unknown";
    return (statusFilter === "all" || st === statusFilter) &&
           (typeFilter === "all" || tp === typeFilter);
  });

  // Grid/Kart Görünümü Modu
  if (S.deviceViewMode === "grid") {
    const tableEl = body.closest("table");
    const container = tableEl ? tableEl.parentElement : body.parentElement;
    if (tableEl) tableEl.style.display = "none";
    let gridWrap = $("devGridWrap");
    if (!gridWrap) {
      gridWrap = document.createElement("div");
      gridWrap.id = "devGridWrap";
      gridWrap.className = "device-card-grid";
      gridWrap.style.display = "grid";
      gridWrap.style.gridTemplateColumns = "repeat(auto-fill, minmax(320px, 1fr))";
      gridWrap.style.gap = "14px";
      gridWrap.style.padding = "14px";
      container.appendChild(gridWrap);
    }
    gridWrap.style.display = "grid";

    gridWrap.innerHTML = filteredList.length ? filteredList.map((d) => {
      const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
      const hw = inv.hardware || {};
      const sw = inv.software || {};
      const status = deviceStatus(d);
      const isVerified = Boolean(d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success");
      const name = deviceDisplayName(d);
      const type = TYPE_LABEL[d.type] || d.type || "Bilinmeyen";

      let cpuDisplay = hw.cpu_model || "";
      if (!cpuDisplay || cpuDisplay.toLowerCase().includes("none") || cpuDisplay.toLowerCase().startsWith("undefined")) {
        cpuDisplay = "Doğrulanamadı";
      }

      return `
        <div class="device-card" style="background:var(--panel-2);border:1px solid var(--line-soft);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:10px;position:relative;transition:all 0.2s">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div style="display:flex;align-items:center;gap:10px">
              <div style="width:40px;height:40px;border-radius:10px;background:var(--panel);border:1px solid var(--line);color:var(--blue);display:grid;place-items:center;font-size:20px">${ico(DEVICE_TYPE_ICON[d.type] || "cpu", 20)}</div>
              <div>
                <h4 style="margin:0;font-size:13.5px;color:var(--txt);font-weight:700">${esc(name)}</h4>
                <div style="font-size:10.5px;color:var(--muted);margin-top:2px">${esc(deviceVendorDisplay(d))} · ${esc(type)}</div>
              </div>
            </div>
            <span class="badge ${deviceStatusClass(status)}">${deviceStatusLabel(status)}</span>
          </div>

          <div style="background:var(--panel);border:1px solid var(--line-soft);border-radius:8px;padding:8px 12px;display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px">
            <div>
              <span style="color:var(--muted);font-size:9.5px;display:block">IP ADRESİ</span>
              <b style="color:var(--blue)">${esc(d.ip || "-")}</b>
              ${copyBtnHtml(d.ip)}
            </div>
            <div>
              <span style="color:var(--muted);font-size:9.5px;display:block">MAC ADRESİ</span>
              <b style="font-variant-numeric:tabular-nums">${esc(d.mac || "-")}</b>
              ${copyBtnHtml(d.mac)}
            </div>
          </div>

          <div style="font-size:11px;color:var(--txt-2);display:flex;flex-direction:column;gap:5px;background:rgba(255,255,255,0.01);padding:6px;border-radius:6px">
            <div style="display:flex;justify-content:space-between"><span>Donanım:</span><b style="color:var(--txt);font-size:10.5px">${esc(cpuDisplay)}</b></div>
            <div style="display:flex;justify-content:space-between"><span>Sistem / OS:</span><b>${esc(sw.os_name || d.os_fingerprint || "-")}</b></div>
            <div style="display:flex;justify-content:space-between;align-items:center"><span>Gecikme:</span><b>${d.latency != null ? d.latency + " ms" : "N/A"}</b></div>
            <div style="display:flex;justify-content:space-between;align-items:center"><span>Kimlik:</span><span class="badge ${isVerified ? 'ok' : 'gray'}" style="font-size:9.5px">${isVerified ? 'Envanter Doğrulandı' : 'Ajansız Profil'}</span></div>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:6px;margin-top:auto;padding-top:8px;border-top:1px solid var(--line-soft)">
            <button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
            ${rdpActionButtonHtml(d)}
            ${inventoryActionButtonHtml(d)}
            <button class="mini-btn" onclick="quickPing('${esc(d.ip || "")}')">Ping</button>
          </div>
        </div>
      `;
    }).join("") : `<div class="hint" style="grid-column:1/-1;padding:22px;text-align:center">Cihaz bulunamadı.</div>`;
    return;
  } else {
    const tableEl = body.closest("table");
    if (tableEl) tableEl.style.display = "table";
    const gridWrap = $("devGridWrap");
    if (gridWrap) gridWrap.style.display = "none";
  }

  if (tab === "network") {
    body.innerHTML = filteredList.length ? filteredList.map(d => {
      const iface = d.network_interfaces?.[0] || d.interface || {};
      return `<tr><td><span class="badge ${deviceStatusClass(deviceStatus(d))}">${esc(deviceStatusLabel(deviceStatus(d)))}</span></td><td><b>${esc(deviceDisplayName(d))}</b></td><td class="mono">${esc(d.ip || "-")}</td><td class="mono">${esc(d.mac || "-")}</td><td>${esc(d.vendor || "-")}</td><td>${esc(d.inventory_source || "Discovery")}</td><td><button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          ${rdpActionButtonHtml(d)}</td></tr>`;
    }).join("") : `<tr><td colspan="7" class="hint">Ağ envanteri bulunamadı.</td></tr>`;
    return;
  }
  if (tab === "security") {
    body.innerHTML = filteredList.length ? filteredList.map(d => {
      const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
      const sec = inv.security || {};
      return `<tr><td><span class="badge ${deviceStatusClass(deviceStatus(d))}">${esc(deviceStatusLabel(deviceStatus(d)))}</span></td><td><b>${esc(deviceDisplayName(d))}</b></td><td>${esc((inv.software || {}).os_name || d.os_fingerprint || "-")}</td><td>${esc(sec.firewall || "Bilinmiyor")}</td><td>${esc(sec.antivirus || "Bilinmiyor")}</td><td>${d.unified_inventory?.verified ? "Doğrulandı" : "Ağ profili"}</td><td>${esc(d.unified_inventory?.completeness ?? "-")}%</td><td><button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          ${rdpActionButtonHtml(d)}</td></tr>`;
    }).join("") : `<tr><td colspan="8" class="hint">Güvenlik verisi bulunamadı.</td></tr>`;
    return;
  }
  if (tab === "history") {
    body.innerHTML = filteredList.length ? filteredList.map(d => `<tr><td><span class="badge ${deviceStatusClass(deviceStatus(d))}">${esc(deviceStatusLabel(deviceStatus(d)))}</span></td><td><b>${esc(deviceDisplayName(d))}</b></td><td class="mono">${esc(d.ip || "-")}</td><td class="mono">${esc(d.mac || "-")}</td><td>${esc(formatSeen(d.last_seen || d.lastSeen || d.ts))}</td><td>${esc(d.inventory_source || "Discovery")}</td><td>${d.unified_inventory?.verified ? "Doğrulandı" : "Ağ profili"}</td><td><button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          ${rdpActionButtonHtml(d)}</td></tr>`).join("") : `<tr><td colspan="8" class="hint">Geçmiş verisi bulunamadı.</td></tr>`;
    return;
  }

  if (tab === "hardware") {
    body.innerHTML = filteredList.length
      ? filteredList.map((d) => {
          const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
          const hw = inv.hardware || {};
          const isVerified = Boolean(d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success");
          const disks = inv.storage || [];
          const diskSummary = disks.length
            ? disks.map(ds => `${ds.drive_letter || 'Disk'}: ${ds.total_gb}GB (${ds.free_gb}GB Boş)`).join(" · ")
            : "-";
          let cpuDisplay = hw.cpu_model || "";
          if (!cpuDisplay || cpuDisplay.toLowerCase().includes("none") || cpuDisplay.toLowerCase().startsWith("undefined")) {
            cpuDisplay = "Doğrulanamadı";
          }
          return `
        <tr>
          <td><span class="badge ${isVerified ? 'ok' : 'gray'}">${isVerified ? 'Envanter Doğrulandı' : 'Ağ Profili'}</span></td>
          <td><b>${esc(d.ip || "-")}</b> ${copyBtnHtml(d.ip)} ${d.is_self ? '<span class="badge info">bu cihaz</span>' : ''}</td>
          <td><b>${esc(deviceDisplayName(d))}</b>
    ${d.owner ? `<div class="sub" style="font-size:11px;color:var(--primary);margin-top:2px;">👤 Sahip: <b>${esc(d.owner)}</b></div>` : ''}
    <div class="sub" style="font-size:10.5px">${esc(d.vendor || "Bilinmeyen Üretici")}</div></td>
          <td>${esc(cpuDisplay)}${hw.cores ? " (" + hw.cores + " Çek)" : ""}</td>
          <td><b>${hw.ram_gb ? hw.ram_gb + " GB" : "-"}</b></td>
          <td>${esc(hw.gpu || "-")}</td>
          <td>${esc(hw.motherboard_maker || "-")} ${esc(hw.motherboard_model || "")}</td>
          <td style="font-size:11px">${esc(diskSummary)}</td>
          <td style="text-align:right;white-space:nowrap">
            <button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
            ${rdpActionButtonHtml(d)}
            ${inventoryActionButtonHtml(d)}
          </td>
        </tr>`;
        }).join("")
      : `<tr><td colspan="9" style="padding:22px;text-align:center" class="hint">Cihaz bulunamadı.</td></tr>`;
    return;
  }

  if (tab === "software") {
    body.innerHTML = filteredList.length
      ? filteredList.map((d) => {
          const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
          const sw = inv.software || {};
          const sec = inv.security || {};
          const isVerified = Boolean(d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success");
          const antivirusKnown = sec.antivirus && !["Bilinmiyor", "Bulunamadı"].includes(sec.antivirus);
          const firewallKnown = sec.firewall && sec.firewall !== "Bilinmiyor";
          const progCount = (sw.installed_programs || []).length;
          return `
        <tr>
          <td><span class="badge ${isVerified ? 'ok' : 'gray'}">${isVerified ? 'Envanter Doğrulandı' : 'Ağ Profili'}</span></td>
          <td><b>${esc(d.ip || "-")}</b> ${copyBtnHtml(d.ip)} ${d.is_self ? '<span class="badge info">bu cihaz</span>' : ''}</td>
          <td><b>${esc(deviceDisplayName(d))}</b><div class="sub" style="font-size:10.5px">${esc(d.hostname || d.vendor || "-")}</div></td>
          <td><b>${esc(sw.os_name || "-")}</b></td>
          <td>${esc(sec.active_user || "-")}</td>
          <td><span class="badge ${antivirusKnown ? 'ok' : 'warn'}">${esc(sec.antivirus || "Bilinmiyor")}</span></td>
          <td><span class="badge ${sec.firewall === 'Açık' ? 'ok' : firewallKnown ? 'warn' : 'gray'}">${esc(sec.firewall || "Bilinmiyor")}</span></td>
          <td><b>${progCount} Program/Servis</b></td>
          <td style="text-align:right;white-space:nowrap">
            <button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
            ${rdpActionButtonHtml(d)}
            ${inventoryActionButtonHtml(d)}
          </td>
        </tr>`;
        }).join("")
      : `<tr><td colspan="9" style="padding:22px;text-align:center" class="hint">Cihaz bulunamadı.</td></tr>`;
    return;
  }

  // All Devices view (default)
  body.innerHTML = filteredList.length
    ? filteredList.map((d) => {
        const name = deviceDisplayName(d);
        const subtitle = deviceSubtitle(d);
        const type = TYPE_LABEL[d.type] || d.type || "Bilinmeyen";
        const confidence = deviceConfidence(d);
        const status = deviceStatus(d);
        const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
        const osName = (inv.software?.os_name || d.os_fingerprint || "").toLowerCase();
        const isLegacyOs = osName.includes("windows 7") || osName.includes("windows 8") || osName.includes("windows server 2008") || osName.includes("xp");

        return `
      <tr>
        <td>
          <span class="badge ${deviceStatusClass(status)}">${deviceStatusLabel(status)}</span>
          ${d.is_new ? ' <span class="badge warn">Yeni</span>' : ""}
          ${isLegacyOs ? ' <span class="badge fail">Riskli OS</span>' : ""}
          <div style="font-size:10px;color:var(--muted);margin-top:4px">${esc(connectivityLabel(d))}</div>
        </td>
        <td><b>${esc(d.ip || "-")}</b> ${copyBtnHtml(d.ip)} ${d.is_self ? '<span class="badge info">bu cihaz</span>' : ""} ${d.is_gateway ? '<span class="badge info">gateway</span>' : ""}</td>
        <td>
          <div style="display:flex;align-items:center;gap:9px;">
            <div style="width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:var(--panel-2);color:var(--blue);flex:none;">${ico(DEVICE_TYPE_ICON[d.type] || "cpu", 17)}</div>
            <div style="min-width:0">
              <div style="font-weight:700;color:var(--txt);">${esc(name)}</div>
              ${subtitle ? `<div class="sub" style="font-size:11px;margin-top:2px">${esc(subtitle)}</div>` : ""}
              ${d.vendor ? `<div class="sub" style="font-size:10px;margin-top:2px">${esc(d.vendor)}</div>` : ""}
            </div>
          </div>
        </td>
        <td><span class="badge info">${esc(type)}</span>${confidence !== null ? `<div style="margin-top:4px;font-size:10px;color:var(--muted)">Güven %${confidence}</div>` : ""}</td>
        <td style="font-variant-numeric:tabular-nums">${esc(d.mac || "-")} ${copyBtnHtml(d.mac)}</td>
        <td>${d.latency !== null && d.latency !== undefined ? d.latency + " ms" : "-"}<div style="font-size:10px;color:var(--muted)">${d.packet_loss !== null && d.packet_loss !== undefined ? "ICMP kayıp %" + d.packet_loss : (d.icmp_reachable === false ? "ICMP yanıt yok" : "")}</div></td>
        <td style="font-size:11px;color:var(--muted)">${formatSeen(d.last_seen)}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          ${rdpActionButtonHtml(d)}
          ${inventoryActionButtonHtml(d)}
          ${hasPermission("devices.manage") && d.mac ? `<button class="mini-btn" onclick="openDeviceEditModal('${esc(d.mac)}')">Adlandır</button>` : ""}
          <button class="mini-btn" onclick="quickPing('${esc(d.ip || "")}')">Ping</button>
        </td>
      </tr>`;
      }).join("")
    : `<tr><td colspan="8" style="padding:22px;text-align:center" class="hint">${S.scanning ? "Ağ taranıyor…" : S.deviceScanError ? `Tarama başarısız: ${esc(S.deviceScanError)}` : 'Cihaz bulunamadı. "Yeniden Tara" ile taramayı başlatın.'}</td></tr>`;

  const note = $("devNote");
  if (note) {
    const unknown = S.devices.filter(d => (d.type || "unknown") === "unknown").length;
    const discovered = S.devices.filter(d => deviceStatus(d) === "discovered").length;
    const offline = S.devices.filter(d => deviceStatus(d) === "offline").length;
    note.innerHTML = S.scanning
      ? `${ico("refresh", 13, "spin")} taranıyor…`
      : `${S.devices.length} cihaz · ${unknown} tipi bilinmeyen · ${discovered} ICMP doğrulanamadı · ${offline} uzun süredir görülmedi${S.devicesTs ? " · " + new Date(S.devicesTs * 1000).toLocaleTimeString("tr-TR") : ""}`;
  }
}

function inventoryProtocolForDevice(device = {}) {
  const type = String(device.type || "").toLowerCase();
  const osName = String(device.os_fingerprint || device.wmi_inventory?.software?.os_name || "").toLowerCase();
  const ports = new Set(device.classification?.open_ports || []);
  if (["router", "switch", "access_point", "firewall", "printer", "network_device"].includes(type)) return "snmp";
  if (osName.includes("linux") || osName.includes("ubuntu") || osName.includes("debian") || type === "linux") return "ssh";
  if (osName.includes("windows") || ["computer", "pc", "laptop", "server"].includes(type) || [...ports].some(p => [135, 445, 3389, 5985, 5986].includes(Number(p)))) return "windows";
  return "auto";
}

function inventoryActionButtonHtml(device = {}) {
  if (!hasPermission("inventory.scan")) return "";
  const protocol = inventoryProtocolForDevice(device);
  const labels = { windows: "🔑 Windows Envanter", ssh: "🔑 SSH Envanter", snmp: "🔑 SNMP Envanter", auto: "🔑 Protokol Seç" };
  return `<button class="mini-btn" onclick="openWmiScanModal('${esc(device.ip || "")}', '${protocol}')">${labels[protocol]}</button>`;
}

function rdpActionButtonHtml(device = {}) {
  if (inventoryProtocolForDevice(device) !== "windows") return "";
  return `<button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(device.ip || "")}', '${esc(device.hostname || device.ip || "Cihaz")}')">💻 RDP</button>`;
}

function openWmiScanModal(targetIp, suggestedProtocol = "auto") {
  const ip = targetIp || "";
  const allowedProtocols = new Set(["auto", "windows", "ssh", "snmp"]);
  const selectedProtocol = allowedProtocols.has(suggestedProtocol) ? suggestedProtocol : "auto";
  openModal(`
    <h3>🔑 Yetkili Cihaz Envanteri</h3>
    <div class="sub">Windows için WMI/WinRM, Linux için SSH, ağ cihazları için SNMP kullanır.</div>
    <div class="field-label" style="margin-top:12px">Hedef Cihaz IP Adresi</div>
    <input id="wmiTargetIp" value="${esc(ip)}" placeholder="Örn. 192.168.1.50" />
    <div class="field-label" style="margin-top:10px">Protokol</div>
    <select id="inventoryProtocol"><option value="auto" ${selectedProtocol === "auto" ? "selected" : ""}>Otomatik Algıla</option><option value="windows" ${selectedProtocol === "windows" ? "selected" : ""}>Windows WMI / WinRM</option><option value="ssh" ${selectedProtocol === "ssh" ? "selected" : ""}>Linux SSH</option><option value="snmp" ${selectedProtocol === "snmp" ? "selected" : ""}>SNMP Ağ Cihazı</option></select>
    <div class="field-label" style="margin-top:10px">Yetkili Kullanıcı Adı</div>
    <input id="wmiUser" name="netmon-inventory-user" placeholder="DOMAIN\\kullanıcı veya SSH kullanıcısı" autocomplete="off" spellcheck="false" data-lpignore="true" data-1p-ignore />
    <div class="field-label" style="margin-top:10px">Parola</div>
    <input id="wmiPass" name="netmon-inventory-secret" type="password" placeholder="Şifre" autocomplete="new-password" data-lpignore="true" data-1p-ignore />
    <div class="field-label" style="margin-top:10px">SNMP Community</div>
    <input id="inventorySnmp" name="netmon-inventory-snmp-secret" type="password" placeholder="Yalnızca SNMP için" autocomplete="new-password" data-lpignore="true" data-1p-ignore />
    <div class="hint" style="margin-top:10px;font-size:11px">Boş bırakılan alanlarda Ayarlar panelindeki DPAPI ile korunan kimlik bilgileri kullanılır.</div>
    <div id="inventoryPreflightResult" style="margin-top:10px"></div>
    <div id="inventoryScanError" class="hint c-red" style="margin-top:8px"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
      <button class="mini-btn" onclick="closeModalForce()">İptal</button>
      <button id="inventoryPreflightButton" class="mini-btn" onclick="executeInventoryPreflight()">Yetkiyi Test Et</button>
      <button id="inventoryScanButton" class="mini-btn blue" onclick="executeWmiScanFromModal()">Taramayı Başlat</button>
    </div>
  `);
}

function inventoryPreflightHtml(data = {}) {
  const checks = data.checks || [];
  const statusIcon = status => status === "pass" ? "✓" : status === "warn" ? "!" : "×";
  return `
    <div class="preflight-card ${data.ready ? "ready" : "blocked"}">
      <div class="preflight-head">
        <div><span>YETKİ HAZIRLIK TESTİ</span><b>${esc(data.summary || "Test tamamlandı")}</b></div>
        <span class="badge ${data.ready ? "ok" : "fail"}">${data.ready ? "HAZIR" : "ENGEL VAR"}</span>
      </div>
      <div class="preflight-checks">${checks.map(check => `
        <div class="preflight-check ${esc(check.status || "fail")}">
          <i>${statusIcon(check.status)}</i>
          <div><b>${esc(check.label || "Kontrol")}</b><span>${esc(check.detail || "-")}</span>${check.error_code ? `<code>${esc(check.error_code)}</code>` : ""}</div>
        </div>`).join("")}</div>
      ${data.ready ? `<div class="preflight-ready-note">${ico("check", 14)} Bu hedefte gerçek envanter taraması başlatılabilir.</div>` : inventoryDiagnosticHtml({ error_code: data.diagnostics?.error_code, diagnostics: data.diagnostics, error_message: checks.at(-1)?.detail })}
    </div>`;
}

async function executeInventoryPreflight() {
  const ip = $("wmiTargetIp")?.value.trim();
  const username = $("wmiUser")?.value.trim() || "";
  const password = $("wmiPass")?.value || "";
  const protocol = $("inventoryProtocol")?.value || "auto";
  const snmpCommunity = $("inventorySnmp")?.value || "";
  if (!ip) {
    toast("Lütfen hedef IP adresi girin.", "warn");
    return;
  }
  const button = $("inventoryPreflightButton");
  const target = $("inventoryPreflightResult");
  if (button) { button.disabled = true; button.textContent = "Test ediliyor…"; }
  if (target) target.innerHTML = '<div class="hint">Bağlantı ve yetkilendirme aşamaları kontrol ediliyor…</div>';
  try {
    const data = await post("/api/devices/inventory/preflight", {
      ip, protocol, username, password, snmp_community: snmpCommunity,
    });
    if (target) target.innerHTML = inventoryPreflightHtml(data);
    toast(data.ready ? "Hedef yetkili envanter taramasına hazır." : "Hazırlık testinde bir engel bulundu.", data.ready ? "success" : "warn");
  } catch (e) {
    if (target) target.innerHTML = inventoryDiagnosticHtml({ error_code: "preflight_request_failed", error_message: e.message, diagnostics: { cause: "Hazırlık testi tamamlanamadı.", recommended_actions: ["Hedef IP, oturum yetkisi ve NetMon servis durumunu kontrol edin."] } });
  } finally {
    if (button && document.body.contains(button)) { button.disabled = false; button.textContent = "Yetkiyi Test Et"; }
  }
}

async function executeWmiScanFromModal() {
  const ip = $("wmiTargetIp")?.value.trim();
  const username = $("wmiUser")?.value.trim() || "";
  const password = $("wmiPass")?.value || "";
  const protocol = $("inventoryProtocol")?.value || "auto";
  const snmpCommunity = $("inventorySnmp")?.value || "";
  if (!ip) {
    toast("Lütfen hedef IP adresi girin.", "warn");
    return;
  }
  const button = $("inventoryScanButton");
  const errorBox = $("inventoryScanError");
  if (errorBox) errorBox.textContent = "";
  if (button) {
    button.disabled = true;
    button.textContent = "Taranıyor…";
  }
  try {
    await startDeepWmiScan(ip, username, password, protocol, snmpCommunity);
  } finally {
    if (button && document.body.contains(button)) {
      button.disabled = false;
      button.textContent = "Taramayı Başlat";
    }
  }
}

function inventoryDiagnosticHtml(result = {}) {
  const d = result.diagnostics || {};
  const failure = d.failure || {};
  const winrmFailure = d.winrm_failure || {};
  const code = result.error_code || d.error_code || failure.error_code || "inventory_failed";
  const cause = d.cause || failure.cause || result.error_message || result.error || "Neden belirlenemedi.";
  const actions = d.recommended_actions || failure.recommended_actions || [];
  const ports = Array.isArray(d.management_ports) && d.management_ports.length ? d.management_ports.join(", ") : "Açık yönetim portu gözlenmedi";
  const transports = Array.isArray(d.transport_attempts) && d.transport_attempts.length ? d.transport_attempts.join(" → ") : String(d.effective_protocol || "-").toUpperCase();
  const sourceLabel = ({ request: "Bu taramada girilen kimlik", stored_dpapi: "Ayarlar panelindeki DPAPI kaydı", none: "Kimlik bilgisi yok" })[d.credential_source] || "Belirtilmedi";
  const raw = failure.native_error || d.raw_error || result.error_message || result.error || "";
  const winrmRaw = winrmFailure.native_error || "";
  return `
    <div class="inventory-diagnostic-card">
      <div class="inventory-diagnostic-head">
        <div><span>ENVANTER TEŞHİSİ</span><b>${esc(code)}</b></div>
        <span class="badge fail">Başarısız</span>
      </div>
      <div class="inventory-cause"><b>Net neden</b><span>${esc(cause)}</span></div>
      <div class="inventory-evidence-grid">
        <div><span>Hedef / Protokol</span><b>${esc(d.target || "-")} · ${esc(String(d.effective_protocol || "-").toUpperCase())}</b></div>
        <div><span>Denenen taşıma</span><b>${esc(transports)}</b></div>
        <div><span>Açık yönetim portları</span><b>${esc(ports)}</b></div>
        <div><span>Kimlik kaynağı</span><b>${esc(sourceLabel)}${d.account ? ` · ${esc(d.account)}` : ""}</b></div>
      </div>
      ${actions.length ? `<div class="inventory-actions"><b>BT yöneticisinin kontrol etmesi gerekenler</b><ol>${actions.map(item => `<li>${esc(item)}</li>`).join("")}</ol></div>` : ""}
      ${raw || winrmRaw ? `<details class="inventory-raw"><summary>Ham teknik hata ve Windows kanıtı</summary>${winrmRaw ? `<div><b>WinRM:</b> ${esc(winrmRaw)}</div>` : ""}${raw ? `<div><b>Son aşama:</b> ${esc(raw)}</div>` : ""}${failure.os_error_code ? `<div><b>Windows hata kodu:</b> ${esc(failure.os_error_code)}</div>` : ""}</details>` : ""}
    </div>`;
}

async function startDeepWmiScan(ip, username = "", password = "", protocol = "auto", snmpCommunity = "") {
  if (!ip) return;
  toast(`[${ip}] Yetkili envanter taraması başlatıldı…`, "info");
  try {
    const res = await post("/api/devices/inventory", {
      ip: ip,
      protocol: protocol,
      username: username,
      password: password,
      snmp_community: snmpCommunity
    });
    const scanResult = res?.result || {};
    if (res?.ok && scanResult.status === "Success") {
      toast(`[${ip}] ${String(res.protocol || "").toUpperCase()} envanteri başarıyla alındı.`, "success");
      const back = $("modalBack");
      if (back) back.dataset.locked = "0";
      closeModalForce();
      await refreshDevices();
      showDeviceDetails(null, ip);
    } else {
      const message = scanResult.error_message || scanResult.error || "Yönetim protokolü veya yetki bulunamadı.";
      const errorBox = $("inventoryScanError");
      if (errorBox) errorBox.innerHTML = inventoryDiagnosticHtml(scanResult);
      await refreshDevices();
      toast(`[${ip}] Envanter alınamadı: ${message}`, "error");
    }
  } catch (e) {
    const message = e.message || String(e);
    const errorBox = $("inventoryScanError");
    if (errorBox) errorBox.innerHTML = inventoryDiagnosticHtml({ error_code: "request_failed", error_message: message, diagnostics: { cause: "NetMon API isteği tamamlanamadı.", recommended_actions: ["NetMon servisinin çalıştığını, oturum yetkisini ve ağ bağlantısını kontrol edin."] } });
    toast(`Yetkili tarama başarısız: ${message}`, "error");
  }
}

function inspectDevice(ip, mac) {
  if (!ip && !mac) return;
  showDeviceDetails(mac, ip);
}
window.inspectDevice = inspectDevice;

function showDeviceDetails(mac, ip) {
  let d = (S.devices || []).find(x => (mac && x.mac === mac) || (ip && x.ip === ip));
  if (!d) {
    const ipamItem = (_ipamAllocationsCache || []).find(x => (ip && x.ip === ip) || (mac && x.mac === mac));
    d = {
      ip: ip || ipamItem?.ip || "-",
      mac: mac || ipamItem?.mac || "-",
      hostname: ipamItem?.hostname || (ip ? `Gözlenen uç (${ip})` : "Bilinmeyen Cihaz"),
      friendly_name: ipamItem?.hostname || "",
      type: ipamItem?.type || "unknown",
      status: ipamItem?.status || "unknown",
      vendor: "",
      discovery_sources: ipamItem?.discovery_sources || ["active_socket"],
      last_seen: ipamItem?.last_seen || null,
      first_seen: null,
      latency: null,
      packet_loss: null,
      wmi_inventory: {
        status: "Idle",
        hardware: {},
        software: {},
        security: {},
        storage: []
      }
    };
  }
  const type = TYPE_LABEL[d.type] || d.type || "Bilinmeyen";
  const confidence = deviceConfidence(d);
  const reasons = d.classification?.reason || d.classification?.method || [];
  const sources = d.discovery_sources || d.classification?.method || [];
  const unknown = (d.type || "unknown") === "unknown";
  const status = deviceStatus(d);
  const evidence = d.classification?.evidence || [];
  const tips = unknown
    ? `<div class="device-learning warning"><b>Cihaz tipi neden bilinmiyor?</b><div>${esc(d.identification_reason || "NetMon cihazın ağda olduğunu görebiliyor ancak türünü kesinleştirecek yeterli kanıt bulamadı.")}</div></div>`
    : `<div class="device-learning"><b>Bu cihaz nasıl tanımlandı?</b><div>${reasons.length ? reasons.map(esc).join(" · ") : "Birden fazla ağ kanıtı kullanıldı."}</div></div>`;

  const evidenceHtml = evidence.length
    ? `<div class="device-learning"><b>Keşif kanıtları</b><div>${evidence.map(e => `<div style="margin-top:3px">✓ ${esc(e.text || e)}</div>`).join("")}</div></div>`
    : "";
  const breakdown = d.classification?.score_breakdown || [];
  const confidenceLabel = d.classification?.confidence_label || (confidence == null ? "bilinmiyor" : (confidence >= 80 ? "yüksek" : confidence >= 55 ? "orta" : "düşük"));
  const breakdownHtml = breakdown.length
    ? `<div class="device-learning"><b>Sınıflandırma güveni: ${esc(confidenceLabel)}${confidence != null ? ` (%${confidence})` : ""}</b><div style="margin-top:6px">${breakdown.map(x => `<div style="display:flex;justify-content:space-between;gap:10px;margin-top:4px"><span>${esc(TYPE_LABEL[x.type] || x.type)}</span><span style="color:var(--muted)">${Number(x.score || 0).toFixed(2)}</span></div>`).join("")}</div><div style="margin-top:6px;color:var(--muted);font-size:10px">En yüksek aday ile ikinci aday arasındaki fark: ${Number(d.classification?.margin || 0).toFixed(2)}</div></div>`
    : "";

  const renderWmiInfo = () => {
    const w = d.wmi_inventory;
    const isWmiSuccess = w && w.status === "Success";
    const isVerified = Boolean(d.unified_inventory?.verified || isWmiSuccess || d.deep_inventory?.status === "Success");
    const inv = isWmiSuccess ? w : (d.deep_inventory?.status === "Success" ? d.deep_inventory : (d.fallback_inventory || {}));

    const hw = inv.hardware || {};
    const sw = inv.software || {};
    const sec = inv.security || {};
    const storageList = inv.storage || [];

    let programsList = sw.installed_programs || [];
    let programsHtml = programsList.map(p =>
      `<div style="padding:3px 0;border-bottom:1px solid var(--line-soft);display:flex;justify-content:space-between;font-size:11px">
        <span>${esc(p.name)}</span>
        <span style="color:var(--muted);margin-left:8px;white-space:nowrap">${esc(p.version || "-")}</span>
      </div>`
    ).join('');

    if (!programsHtml) programsHtml = `<div class="hint" style="padding:6px">Program listesi doğrulanamadı veya hedef bu bilgiyi paylaşmıyor.</div>`;
    else programsHtml = `<div style="max-height:110px;overflow-y:auto;background:var(--panel-2);border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin-top:4px">${programsHtml}</div>`;

    let disksHtml = (storageList || []).map(ds => {
      const pct = ds.total_gb ? Math.min(100, Math.round((ds.used_gb / ds.total_gb) * 100)) : 0;
      const barColor = pct > 85 ? "var(--red)" : pct > 70 ? "var(--orange)" : "var(--blue)";
      return `<div style="margin-top:6px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:7px 9px">
        <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
          <b>${esc(ds.drive_letter || "Disk")} ${ds.total_gb} GB</b>
          <span style="color:var(--muted)">${ds.free_gb} GB Boş (%${100 - pct})</span>
        </div>
        <div style="height:6px;background:var(--bg);border-radius:3px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${barColor};border-radius:3px"></div>
        </div>
      </div>`;
    }).join('');
    if (!disksHtml) disksHtml = `<div class="hint">Disk verisi bulunamadı.</div>`;

    const statusBadgeHtml = isVerified
      ? `<span class="badge ok">${esc(d.unified_inventory?.inventory_source || inv.inventory_source || "Envanter")} Doğrulandı</span>`
      : `<span class="badge warn">Ayrıntılı envanter doğrulanamadı</span>`;
    const limitations = (inv.limitations || []).map(item => `<div>• ${esc(item)}</div>`).join("");
    const inventoryError = d.inventory_error?.message
      ? (d.inventory_error.diagnostics
          ? inventoryDiagnosticHtml({ error_code: d.inventory_error.code, error_message: d.inventory_error.message, diagnostics: d.inventory_error.diagnostics })
          : `<div class="device-learning warning" style="margin-bottom:10px"><b>Son envanter hatası</b><div>${esc(d.inventory_error.message)}</div></div>`)
      : "";

    return `
      <div style="margin-bottom:10px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px">
        <div>${statusBadgeHtml}</div>
        <button class="mini-btn blue" onclick="openWmiScanModal('${esc(d.ip)}', '${inventoryProtocolForDevice(d)}')">🔑 ${inventoryProtocolForDevice(d) === "snmp" ? "SNMP" : inventoryProtocolForDevice(d) === "ssh" ? "SSH" : inventoryProtocolForDevice(d) === "windows" ? "Windows" : "Yetkili"} Envanteri Al</button>
      </div>
      ${inventoryError}
      ${limitations ? `<div class="hint" style="margin-bottom:10px">${limitations}</div>` : ""}
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; font-size:11.5px;">
        <div style="background:var(--panel-2);border:1px solid var(--line-soft);border-radius:10px;padding:10px 12px">
          <h4 style="margin:0 0 8px; color:var(--blue); font-size:12px; text-transform:uppercase; letter-spacing:0.5px">🖥️ DONANIM ÖZELLİKLERİ</h4>
          <div style="margin-bottom:4px">İşlemci (CPU): <b>${esc(hw.cpu_model || hw.cpu_name || "-")} ${hw.cores ? "(" + hw.cores + " Çekirdek)" : ""}</b></div>
          <div style="margin-bottom:4px">Sistem Belleği (RAM): <b>${hw.ram_gb ? hw.ram_gb + " GB" : "-"}</b></div>
          <div style="margin-bottom:4px">Ekran Kartı (GPU): <b>${esc(hw.gpu || "-")}</b></div>
          <div style="margin-bottom:4px">Anakart Üretici / Model: <b>${esc(hw.motherboard_maker || "-")} ${esc(hw.motherboard_model || "")}</b></div>
          <div style="margin-top:8px; font-weight:600; color:var(--txt)">Depolama & Disk Durumu:</div>
          ${disksHtml}
        </div>
        <div style="background:var(--panel-2);border:1px solid var(--line-soft);border-radius:10px;padding:10px 12px">
          <h4 style="margin:0 0 8px; color:var(--cyan); font-size:12px; text-transform:uppercase; letter-spacing:0.5px">💻 YAZILIM & GÜVENLİK PROFiLİ</h4>
          <div style="margin-bottom:4px">İşletim Sistemi: <b>${esc(sw.os_name || "-")}</b></div>
          <div style="margin-bottom:4px">Lisans Anahtarı: <b>${esc(sw.product_key || "-")}</b></div>
          <div style="margin-bottom:4px">Aktif Oturum Kullanıcısı: <b>${esc(sec.active_user || "-")}</b></div>
          <div style="margin-bottom:4px">Antivirüs Koruması: <b class="${sec.antivirus && !['Bilinmiyor','Bulunamadı'].includes(sec.antivirus) ? 'c-green' : 'c-orange'}">${esc(sec.antivirus || "Bilinmiyor")}</b></div>
          <div style="margin-bottom:4px">Güvenlik Duvarı (Firewall): <b class="${sec.firewall === 'Açık' ? 'c-green' : 'c-orange'}">${esc(sec.firewall || "Bilinmiyor")}</b></div>
          <div style="margin-top:8px; font-weight:600; color:var(--txt)">Yüklü Programlar (${programsList.length}):</div>
          ${programsHtml}
        </div>
      </div>
    `;
  };

  const hardwareInfo = `<div class="device-learning" style="border-color:var(--blue-2)">
        <b style="font-size:13px;color:var(--txt)">📡 Cihaz Donanım & Yazılım Envanter Paneli</b>
        <div style="margin-top:8px">
          ${renderWmiInfo()}
        </div>
       </div>`;

  openModal(`
    <div class="device-detail-head">
      <div class="device-detail-icon">${ico(DEVICE_TYPE_ICON[d.type] || "cpu", 28)}</div>
      <div><h3 style="margin-bottom:4px">${esc(deviceDisplayName(d))}</h3><div class="sub">${esc(type)}${d.vendor ? " · " + esc(d.vendor) : ""}</div></div>
    </div>
    <div class="device-status-row"><span class="badge ${deviceStatusClass(status)}">${deviceStatusLabel(status)}</span>${d.is_new ? '<span class="badge warn">Yeni cihaz</span>' : ""}${d.classification_source === "manual" ? '<span class="badge info">Manuel tanım</span>' : ""}</div>
    <div class="device-detail-grid">
      <div><span>IP</span><b>${esc(d.ip || "-")}</b></div>
      <div><span>MAC</span><b>${esc(d.mac || "-")}</b></div>
      <div><span>Hostname</span><b>${esc(d.hostname || "-")}</b></div>
      <div><span>Üretici (Vendor)</span><b>${esc(d.vendor || "Bilinmiyor")}</b></div>
      ${d.unified_inventory?.switch_port ? `<div><span>Fiziksel Konum</span><b style="color:var(--blue)">${esc(d.unified_inventory.switch_port.switch_name)} (Port: ${d.unified_inventory.switch_port.port})</b></div>` : ""}
      <div><span>Gecikme</span><b>${d.latency ?? "-"}${d.latency !== null && d.latency !== undefined ? " ms" : ""}</b></div>
      <div><span>Paket Kaybı</span><b>${d.packet_loss ?? "-"}${d.packet_loss !== null && d.packet_loss !== undefined ? "%" : ""}</b></div>
      <div><span>Tanımlama Güveni</span><b>${confidence === null ? "-" : "%" + confidence}</b></div>
      <div><span>Bağlantı Durumu</span><b>${esc(connectivityLabel(d))}</b></div>
      <div><span>Tanımlama Durumu</span><b>${d.identification_status === "identified" ? "Tanımlandı" : "Türü belirsiz"}</b></div>
      <div><span>Durum Açıklaması</span><b>${esc(d.status_reason || "-")}</b></div>
      <div><span>ICMP</span><b>${d.icmp_reachable ? "Yanıt veriyor" : "Yanıt yok"}</b></div>
      <div><span>ARP</span><b>${d.arp_seen ? "Görüldü" : "Görülmedi"}</b></div>
      <div><span>Son Görülme</span><b>${formatSeen(d.last_seen)}</b></div>
      <div><span>İlk Görülme</span><b>${formatSeen(d.first_seen)}</b></div>
      <div><span>Son ARP</span><b>${formatSeen(d.last_arp_seen)}</b></div>
      <div><span>Son ICMP</span><b>${formatSeen(d.last_icmp_seen)}</b></div>
      <div><span>Keşif Kaynakları</span><b>${sources.length ? sources.map(discoveryLabel).map(esc).join(" · ") : "-"}</b></div>
    </div>
    ${d.notes ? `<div class="device-learning"><b>Not</b><div>${esc(d.notes)}</div></div>` : ""}
    ${tips}
    ${hardwareInfo}
    ${evidenceHtml}
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px;">
      ${d.ip ? `<button class="mini-btn" onclick="quickPing('${esc(d.ip)}')">Ping</button>` : ""}
      ${hasPermission("devices.manage") && d.mac ? `<button class="mini-btn" onclick="openDeviceEditModal('${esc(d.mac)}')">Düzenle</button>` : ""}
      <button class="mini-btn blue" onclick="closeModalForce()">Kapat</button>
    </div>
  `);
}

function openDeviceEditModal(mac) {
  const d = S.devices.find(x => x.mac === mac);
  if (!d || !hasPermission("devices.manage")) return;
  const options = ["unknown","computer","laptop","phone","tablet","printer","server","router","switch","access_point","network_device","iot","firewall"];
  openModal(`
    <h3>Cihazı Tanımla</h3>
    <div class="sub">${esc(d.ip || "-")} · ${esc(d.mac || "-")}</div>
    <div class="field-label" style="margin-top:12px">Manuel cihaz adı</div>
    <input id="editDeviceName" value="${esc(d.friendly_name || "")}" placeholder="Örn. Muhasebe PC" />
    <div class="field-label" style="margin-top:10px">Cihaz tipi</div>
    <select id="editDeviceType">${options.map(t => `<option value="${t}" ${t === d.type ? "selected" : ""}>${esc(TYPE_LABEL[t] || t)}</option>`).join("")}</select>
    <div class="field-label" style="margin-top:10px">Sahip / Sorumlu</div>
    <input id="editDeviceOwner" value="${esc(d.owner || "")}" placeholder="Örn. Atakan, Muhasebe Departmanı" />
    <div class="field-label" style="margin-top:10px">Not</div>
    <input id="editDeviceNotes" value="${esc(d.notes || "")}" placeholder="Örn. 2. kattaki yazıcı" />
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="saveDeviceEdit('${esc(mac)}')">Kaydet</button></div>
  `);
}

async function saveDeviceEdit(mac) {
  try {
    await post("/api/devices/rename", {
      mac,
      friendly_name: $("editDeviceName")?.value.trim() || null,
      owner: $("editDeviceOwner")?.value.trim() || null,
      device_type: $("editDeviceType")?.value || "unknown",
      notes: $("editDeviceNotes")?.value.trim() || "",
    });
    await refreshDevices();
    await refreshTopology();
    closeModalForce();
    toast("Cihaz bilgileri kaydedildi.", "success");
  } catch (e) { toast(e.message || "Cihaz güncellenemedi.", "error"); }
}

function sparkPath(values, w, h) {
  if (!values.length) return "";
  const max = Math.max(...values, 1);
  const step = w / Math.max(1, values.length - 1);
  return values
    .map(
      (v, i) =>
        `${i ? "L" : "M"}${(i * step).toFixed(1)},${(h - (v / max) * (h - 3) - 1.5).toFixed(1)}`,
    )
    .join(" ");
}

function sparkSvg(values, color) {
  const w = 260;
  const h = 30;
  const d = sparkPath(values, w, h);
  if (!d) return "";
  return `
    <svg class="stat-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <path d="${d} L${w},${h} L0,${h} Z" fill="${color}" opacity=".12"/>
      <path d="${d}" fill="none" stroke="${color}" stroke-width="1.6"/>
    </svg>
  `;
}

function renderStats() {
  const o = S.overview || {};
  const dev = o.devices || { total: 0, online: 0, offline: 0 };
  const inet = o.internet || {};
  const lat = o.latency || {};
  const con = S.connections || {};

  const latQuality = (v) =>
    v === null || v === undefined
      ? ["-", "c-muted"]
      : v < 30
        ? ["Çok İyi", "c-green"]
        : v < 80
          ? ["İyi", "c-green"]
          : v < 150
            ? ["Orta", "c-orange"]
            : ["Yüksek", "c-red"];
  const [latTxt, latCls] = latQuality(lat.average);

  const devSubParts = [
    `<span class="c-green">${dev.online || 0} Çevrimiçi</span>`,
    `<span class="c-red">${dev.offline || 0} Çevrimdışı</span>`
  ];
  if (dev.discovered) devSubParts.push(`<span class="c-orange">${dev.discovered} Keşif</span>`);
  if (dev.unknown) devSubParts.push(`<span class="c-muted">(${dev.unknown} Tanımsız)</span>`);

  const cards = [
    {
      ico: "monitor",
      cls: "i-blue",
      label: "Cihazlar",
      value: S.scanning && !dev.total ? "…" : dev.total,
      sub: devSubParts.join(" · "),
      action: "go('devices')",
      hint: "Cihaz Listesini Gör",
    },
    {
      ico: "globe",
      cls: inet.connected ? "i-green" : "i-red",
      label: "İnternet",
      value: inet.connected == null
        ? `<span class="c-muted">Ölçüm bekleniyor</span>`
        : `<span class="${inet.connected ? "c-green" : "c-red"}">${inet.connected ? "Bağlı" : "Yok"}</span>`,
      sub: esc(inet.target || "-"),
      action: "go('ping')",
      hint: "Ağ Teşhisini Aç",
    },
    {
      ico: "activity",
      cls: "i-green",
      label: "Gecikme (Ortalama)",
      value:
        lat.average === null || lat.average === undefined
          ? "-"
          : lat.average +
            ' <span style="font-size:12px;color:var(--muted)">ms</span>',
      sub: `<span class="${latCls}">${latTxt}</span> · ${o.packet_loss == null ? "Kayıp —" : "Kayıp %" + o.packet_loss} · Sağlık ${o.health?.score ?? "-"}/100`,
      action: "go('ping')",
      hint: "Ping & Gecikme Teşhisi",
    },
    {
      ico: "up",
      cls: "i-green",
      label: "Upload",
      value: fmtBandwidthRate(S.traffic.up),
      spark: sparkSvg(S.sparkUp, "#3ddc84"),
      action: "go('toptalkers')",
      hint: "Aktif Oturumlar & Trafik",
    },
    {
      ico: "down",
      cls: "i-blue",
      label: "Download",
      value: fmtBandwidthRate(S.traffic.down),
      spark: sparkSvg(S.sparkDown, "#3b9bff"),
      action: "go('toptalkers')",
      hint: "Aktif Oturumlar & Trafik",
    },
    {
      ico: "link",
      cls: "i-purple",
      label: "Aktif Bağlantılar",
      value: con.supported === false ? "-" : (con.total || 0),
      sub:
        con.supported === false
          ? "yönetici izni gerekli"
          : `TCP: ${con.tcp || 0} (Aktif) · UDP: ${con.udp || 0}${con.listen ? ` <span class="c-muted">(${con.listen} Dinleme)</span>` : ""}`,
      action: "go('toptalkers')",
      hint: "Bağlantı ve Süreç Detayları",
    },
  ];

  $("statRow").innerHTML = cards
    .map(
      (c) => `
    <div class="stat" style="cursor:pointer" onclick="${c.action}" title="Tıkla: ${c.hint || 'Detayları Gör'}">
      <div class="stat-ico ${c.cls}">${ico(c.ico, 19)}</div>
      <div class="stat-body">
        <div class="stat-label">${c.label}</div>
        <div class="stat-value">${c.value}</div>
        ${c.sub ? `<div class="stat-sub">${c.sub}</div>` : ""}
      </div>
      ${c.spark || ""}
    </div>
  `,
    )
    .join("");
}

function renderInventoryCommandCenter() {
  const list = Array.isArray(S.devices) ? S.devices : [];
  const hasDeviceObservations = list.length > 0 && Number(S.devicesTs || 0) > 0;
  const total = list.length;
  const online = list.filter((d) => deviceStatus(d) === "online").length;
  const unknown = list.filter((d) => (d.type || "unknown") === "unknown").length;
  const confirmed = list.filter((d) => d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success").length;
  const discovered = list.filter((d) => deviceStatus(d) === "discovered").length;
  const offline = list.filter((d) => deviceStatus(d) === "offline").length;

  // NMS Status Pills (Görsel 3 Referansı)
  if ($("nmsTotalCnt")) $("nmsTotalCnt").textContent = total;
  if ($("nmsOnlineCnt")) $("nmsOnlineCnt").textContent = online;
  if ($("nmsWarnCnt")) $("nmsWarnCnt").textContent = discovered;
  if ($("nmsCritCnt")) $("nmsCritCnt").textContent = offline;
  if ($("nmsUnknownCnt")) $("nmsUnknownCnt").textContent = unknown;
  renderDiscoveryStatus();

  // Radyal Göstergeler (Görsel 2 Referansı)
  renderRadialHealthGauges(list);

  const coverage = $("coveragePanel");
  if (coverage) coverage.innerHTML = `
    <div class="coverage-item"><span>Son Keşif</span><b>${S.devicesTs ? formatSeen(S.devicesTs) : "Henüz yok"}</b><small>${total ? total + " varlık kaydı" : "Ağı Keşfet ile başlayın"}</small></div>
    <div class="coverage-item"><span>Erişilebilirlik</span><b>${online} / ${total}</b><small>Çevrimiçi olarak doğrulanan cihaz</small></div>
    <div class="coverage-item"><span>Envanter Derinliği</span><b>${confirmed} / ${total}</b><small>WMI/WinRM, SSH veya SNMP ile doğrulanan cihaz</small></div>`;
  const focus = $("inventoryFocus");
  if (focus) focus.innerHTML = [
    [unknown, "Kimliklendirme bekleyen cihaz", "Tip, sahip ve not ekleyerek envanter kalitesini artırın.", "all"],
    [discovered, "Erişilebilirlik doğrulanamadı", "ARP/servis kanıtı var; ICMP yanıtı olmayabilir.", "all"],
    [Math.max(0, total - confirmed), "Derin envanter bekleyen cihaz", "Windows için WMI/WinRM, Linux için SSH veya ağ cihazı için SNMP yetkisi gerekir.", "hardware"],
  ].map(([count, title, detail, tab]) => `<div class="focus-row" style="cursor:pointer" onclick="go('devices'); setDeviceTab('${tab}')"><div class="focus-count">${count}</div><div><b>${title}</b><span>${detail}</span></div></div>`).join("");
}

function renderRadialHealthGauges(list) {
  const panel = $("healthPanel");
  if (!panel) return;
  const total = list.length;
  const online = list.filter((d) => deviceStatus(d) === "online").length;
  const healthPct = total ? Math.round((online / total) * 100) : null;
  const verified = list.filter((d) => d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success").length;
  const inventoryPct = total ? Math.round((verified / total) * 100) : null;

  const healthOffset = healthPct == null ? 251 : Math.round(251 - (251 * healthPct) / 100);
  const inventoryOffset = inventoryPct == null ? 251 : Math.round(251 - (251 * inventoryPct) / 100);

  panel.innerHTML = `
    <div class="radial-gauge-container">
      <div class="radial-gauge">
        <svg viewBox="0 0 100 100">
          <circle class="bg-circle" cx="50" cy="50" r="40"/>
          <circle class="progress-circle" cx="50" cy="50" r="40" stroke="url(#healthGrad)" style="stroke-dashoffset:${healthOffset}"/>
          <defs>
            <linearGradient id="healthGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#10b981"/>
              <stop offset="100%" stop-color="#00f2ff"/>
            </linearGradient>
          </defs>
        </svg>
        <div class="gauge-val" style="color:var(--green)">${healthPct == null ? "Veri yok" : "%"+healthPct}</div>
        <div class="gauge-lbl">Ağ Sağlığı</div>
      </div>

      <div class="radial-gauge">
        <svg viewBox="0 0 100 100">
          <circle class="bg-circle" cx="50" cy="50" r="40"/>
          <circle class="progress-circle" cx="50" cy="50" r="40" stroke="url(#uptimeGrad)" style="stroke-dashoffset:${inventoryOffset}"/>
          <defs>
            <linearGradient id="uptimeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#38bdf8"/>
              <stop offset="100%" stop-color="#a855f7"/>
            </linearGradient>
          </defs>
        </svg>
        <div class="gauge-val" style="color:var(--blue)">${inventoryPct == null ? "Veri yok" : "%"+inventoryPct}</div>
        <div class="gauge-lbl">Doğrulanmış Envanter</div>
      </div>
    </div>
  `;
}

/* ---------- Topoloji ---------- */

Object.assign(globalThis, {
  renderDeviceTable,
  inventoryProtocolForDevice,
  inventoryActionButtonHtml,
  rdpActionButtonHtml,
  openWmiScanModal,
  inventoryPreflightHtml,
  executeInventoryPreflight,
  executeWmiScanFromModal,
  inventoryDiagnosticHtml,
  startDeepWmiScan,
  inspectDevice,
  showDeviceDetails,
  openDeviceEditModal,
  saveDeviceEdit,
  sparkPath,
  sparkSvg,
  renderStats,
  renderInventoryCommandCenter,
  renderRadialHealthGauges,
});
