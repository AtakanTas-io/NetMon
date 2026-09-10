import "./notifications.js";

function ensureDeviceDrawer() {
  let drawer = $("deviceExperienceDrawer");
  if (drawer) return drawer;
  drawer = document.createElement("aside");
  drawer.id = "deviceExperienceDrawer";
  drawer.className = "device-experience-drawer";
  drawer.setAttribute("aria-label", "Cihaz ayrıntıları");
  document.body.appendChild(drawer);
  bindClickOutside("deviceExperienceDrawer", closeDeviceDrawer, null, "class");
  return drawer;
}

async function openDeviceDrawer(mac, ip, initialTab = "overview") {
  const device = S.devices.find(item => (ip && item.ip === ip) || (mac && item.mac === mac));
  if (!device) return toast("Cihaz güncel keşif listesinde bulunamadı.", "warn");
  const drawer = ensureDeviceDrawer();
  S.activeDeviceDrawer = device;
  drawer.classList.add("open");
  drawer.innerHTML = `
    <header><div><small>${esc(TYPE_LABEL[device.type] || device.type || "Cihaz")}</small><h3>${esc(deviceDisplayName(device))}</h3><span>${esc(device.ip || "-")} · ${esc(device.mac || "-")}</span></div><button onclick="closeDeviceDrawer()">✕</button></header>
    <nav>${[["overview","Genel Bakış"],["hardware","Donanım"],["software","Yazılım"],["history","Geçmiş"],["configs","Config Değişiklikleri"],["alerts","İlişkili Alarmlar"]].map(([id,label]) => `<button data-device-tab="${id}" onclick="selectDeviceDrawerTab('${id}')">${label}</button>`).join("")}</nav>
    <div class="device-drawer-content" id="deviceDrawerContent"></div>`;
  selectDeviceDrawerTab(initialTab);
}

function closeDeviceDrawer() { ensureDeviceDrawer().classList.remove("open"); }

function deviceDrawerInventory(device) {
  if (device.wmi_inventory?.status === "Success" || device.wmi_inventory?.status === "Partial") {
    return { data: device.wmi_inventory, verified: device.wmi_inventory.status === "Success" };
  }
  if (device.deep_inventory?.status === "Success") return { data: device.deep_inventory, verified: true };
  return { data: device.fallback_inventory || {}, verified: false };
}

function deviceDrawerInventoryHeader(device, inventory, verified) {
  const source = inventory.inventory_source || device.unified_inventory?.inventory_source || "Ağ keşfi";
  const needsDetailRefresh = verified && Number(inventory.inventory_schema_version || 0) < 2;
  const action = hasPermission("inventory.scan") && typeof openWmiScanModal === "function"
    ? `<button class="mini-btn blue" onclick="openWmiScanModal('${esc(device.ip || "")}', '${esc(inventoryProtocolForDevice(device))}')">Yetkili Envanteri Yenile</button>`
    : "";
  const detailHint = needsDetailRefresh ? `<div class="hint" style="margin-top:5px">Ayrıntılı donanım alanları için yetkili envanteri yenileyin.</div>` : "";
  return `<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px"><div><span class="badge ${verified ? "ok" : "warn"}">${verified ? "Doğrulanmış envanter" : "Sınırlı envanter"}</span><div class="hint" style="margin-top:5px">Kaynak: ${esc(source)}</div>${detailHint}</div>${action}</div>`;
}

function inventoryText(value, suffix = "") {
  return value === null || value === undefined || value === "" ? "-" : `${esc(value)}${suffix}`;
}

function inventoryDate(value) {
  if (!value) return "-";
  const normalized = /^\d{8}$/.test(String(value))
    ? `${String(value).slice(0, 4)}-${String(value).slice(4, 6)}-${String(value).slice(6, 8)}`
    : value;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? esc(value) : date.toLocaleString("tr-TR");
}

function inventorySection(title, icon, body, count = null) {
  return `<section class="device-inventory-section"><header><div><span>${icon}</span><h4>${esc(title)}</h4></div>${count === null ? "" : `<b>${esc(count)}</b>`}</header>${body}</section>`;
}

function inventoryFacts(items) {
  return `<div class="device-inventory-facts">${items.map(([label, value]) => `<div><span>${esc(label)}</span><b>${value || "-"}</b></div>`).join("")}</div>`;
}

function renderDeviceDrawerHardware(device) {
  const { data: inventory, verified } = deviceDrawerInventory(device);
  const hardware = inventory.hardware || {};
  const system = inventory.system || {};
  const storage = Array.isArray(inventory.storage) ? inventory.storage : [];
  const memoryModules = Array.isArray(hardware.memory_modules) ? hardware.memory_modules : [];
  const gpus = Array.isArray(hardware.gpus) ? hardware.gpus : [];
  const physicalDisks = Array.isArray(hardware.physical_disks) ? hardware.physical_disks : [];
  const adapters = Array.isArray(hardware.network_adapters) ? hardware.network_adapters : [];
  const bios = hardware.bios || {};
  const hasHardware = Object.values(hardware).some(value => value !== null && value !== undefined && value !== "") || storage.length;
  if (!hasHardware) {
    return `${deviceDrawerInventoryHeader(device, inventory, verified)}<div class="device-learning warning"><b>Donanım bilgisi kullanılamıyor</b><div>${esc((inventory.limitations || ["Windows için WMI/WinRM, Linux için SSH veya ağ cihazı için SNMP yetkisi gerekir."]).join(" "))}</div></div>`;
  }
  const cpuBody = inventoryFacts([
    ["Model", inventoryText(hardware.cpu_model || hardware.cpu_name)],
    ["Fiziksel çekirdek", inventoryText(hardware.cores)],
    ["Mantıksal işlemci", inventoryText(hardware.logical_processors || hardware.cores)],
    ["Azami hız", inventoryText(hardware.max_clock_mhz, hardware.max_clock_mhz ? " MHz" : "")],
  ]);
  const memoryBody = memoryModules.length ? `<div class="device-inventory-list">${memoryModules.map((item, index) => `
    <article><div><b>${esc(item.bank || `Bellek ${index + 1}`)}</b><small>${inventoryText(item.manufacturer)} · ${inventoryText(item.part_number)}</small></div><div><b>${inventoryText(item.capacity_gb, " GB")}</b><small>${inventoryText(item.speed_mhz, item.speed_mhz ? " MHz" : "")}</small></div></article>`).join("")}</div>` : `<p class="hint">Modül ayrıntısı paylaşılmadı.</p>`;
  const gpuBody = (gpus.length ? gpus : [{ name: hardware.gpu }]).map(item => inventoryFacts([
    ["Model", inventoryText(item.name || hardware.gpu)],
    ["Bellek", inventoryText(item.adapter_ram_gb, item.adapter_ram_gb ? " GB" : "")],
    ["Sürücü", inventoryText(item.driver_version)],
    ["Çözünürlük", inventoryText(item.current_resolution)],
  ])).join("");
  const logicalDiskBody = storage.length ? `<div class="device-storage-list">${storage.map(disk => {
    const total = Number(disk.total_gb || 0);
    const used = Number(disk.used_gb ?? Math.max(0, total - Number(disk.free_gb || 0)));
    const percent = total ? Math.min(100, Math.round((used / total) * 100)) : 0;
    return `<article><div><b>${esc(disk.drive_letter || disk.name || "Disk")} ${disk.volume_name ? `· ${esc(disk.volume_name)}` : ""}</b><small>${inventoryText(disk.file_system)} · ${inventoryText(disk.free_gb, " GB boş")}</small></div><span>${inventoryText(disk.total_gb, " GB")}</span><div class="device-storage-meter"><i style="width:${percent}%"></i></div></article>`;
  }).join("")}</div>` : `<p class="hint">Bölüm bilgisi paylaşılmadı.</p>`;
  const physicalDiskBody = physicalDisks.length ? `<div class="device-inventory-list">${physicalDisks.map((disk, index) => `<article><div><b>${esc(disk.model || `Fiziksel disk ${index + 1}`)}</b><small>${inventoryText(disk.interface_type)} · ${inventoryText(disk.media_type)}</small></div><div><b>${inventoryText(disk.size_gb, " GB")}</b><small>Seri: ${inventoryText(disk.serial_number)}</small></div></article>`).join("")}</div>` : "";
  const adapterBody = adapters.length ? `<div class="device-inventory-list">${adapters.map(adapter => `<article><div><b>${inventoryText(adapter.description)}</b><small>${(adapter.ip_addresses || []).map(esc).join(", ") || "IP yok"}</small></div><div><b>${inventoryText(adapter.mac_address)}</b><small>DHCP: ${adapter.dhcp_enabled === true ? "Açık" : adapter.dhcp_enabled === false ? "Kapalı" : "-"}</small></div></article>`).join("")}</div>` : `<p class="hint">Etkin adaptör ayrıntısı paylaşılmadı.</p>`;
  return `${deviceDrawerInventoryHeader(device, inventory, verified)}
    <div class="device-inventory-summary">
      <div><span>Sistem</span><b>${esc([system.manufacturer, system.model].filter(Boolean).join(" ") || "Bilinmiyor")}</b></div>
      <div><span>İşlemci</span><b>${inventoryText(hardware.logical_processors || hardware.cores, " iş parçacığı")}</b></div>
      <div><span>Bellek</span><b>${inventoryText(hardware.ram_gb, " GB")}</b></div>
      <div><span>Disk</span><b>${storage.length || physicalDisks.length || "-"}</b></div>
    </div>
    ${inventorySection("İşlemci", "◉", cpuBody)}
    ${inventorySection("Bellek modülleri", "▥", memoryBody, memoryModules.length || null)}
    ${inventorySection("Ekran kartları", "▣", gpuBody, gpus.length || null)}
    ${inventorySection("Disk kullanımı", "◫", logicalDiskBody + physicalDiskBody, storage.length || null)}
    ${inventorySection("Anakart ve BIOS", "◇", inventoryFacts([
      ["Anakart", inventoryText([hardware.motherboard_maker, hardware.motherboard_model].filter(Boolean).join(" / "))],
      ["BIOS", inventoryText([bios.manufacturer, bios.version].filter(Boolean).join(" / "))],
      ["Cihaz seri numarası", inventoryText(bios.serial_number || hardware.serial_number || inventory.serial_number)],
      ["BIOS tarihi", inventoryDate(bios.release_date)],
    ]))}
    ${inventorySection("Etkin ağ adaptörleri", "⌁", adapterBody, adapters.length || null)}`;
}

function renderDeviceDrawerSoftware(device) {
  const { data: inventory, verified } = deviceDrawerInventory(device);
  const software = inventory.software || {};
  const security = inventory.security || {};
  const programs = Array.isArray(software.installed_programs) ? software.installed_programs : [];
  const license = software.license || {};
  const hasSoftware = Boolean(
    software.os_name || software.os_build || software.os_version || programs.length || security.active_user || license.status
  );
  if (!hasSoftware) {
    return `${deviceDrawerInventoryHeader(device, inventory, verified)}<div class="device-learning warning"><b>Yazılım bilgisi kullanılamıyor</b><div>${esc((inventory.limitations || ["Yetkili işletim sistemi envanteri alınamadı."]).join(" "))}</div></div>`;
  }
  const programRows = programs.map(program => {
    const item = typeof program === "string" ? { name: program } : program;
    const search = `${item.name || ""} ${item.version || ""} ${item.publisher || ""}`.toLocaleLowerCase("tr-TR");
    return `<div class="device-software-row" data-software-search="${esc(search)}"><div><b>${esc(item.name || "Bilinmeyen yazılım")}</b><small>${inventoryText(item.publisher)}</small></div><div><b>${inventoryText(item.version)}</b><small>${inventoryDate(item.install_date)}</small></div></div>`;
  }).join("");
  return `${deviceDrawerInventoryHeader(device, inventory, verified)}
    <div class="device-inventory-summary">
      <div><span>İşletim sistemi</span><b>${esc(software.os_name || "-")}</b></div>
      <div><span>Sürüm / build</span><b>${esc([software.os_version, software.os_build].filter(Boolean).join(" / ") || "-")}</b></div>
      <div><span>Mimari</span><b>${inventoryText(software.os_architecture)}</b></div>
      <div><span>Kurulu yazılım</span><b>${programs.length}</b></div>
    </div>
    ${inventorySection("Windows ve oturum", "⊞", inventoryFacts([
      ["Aktif kullanıcı", inventoryText(security.active_user)],
      ["Kayıtlı kullanıcı", inventoryText(software.registered_user)],
      ["Kurulum tarihi", inventoryDate(software.install_date)],
      ["Son açılış", inventoryDate(software.last_boot_time)],
    ]))}
    ${inventorySection("Güvenlik durumu", "⬡", inventoryFacts([
      ["Antivirüs", inventoryText(security.antivirus || "Bilinmiyor")],
      ["Güvenlik duvarı", inventoryText(security.firewall || "Bilinmiyor")],
    ]))}
    <section class="device-license-card ${license.licensed === true ? "licensed" : license.licensed === false ? "unlicensed" : "unknown"}">
      <div><span>Microsoft Windows lisansı</span><b>${esc(license.status || "Bilgi alınamadı")}</b></div>
      <span class="badge ${license.licensed === true ? "ok" : license.licensed === false ? "fail" : "warn"}">${license.licensed === true ? "ETKİN" : license.licensed === false ? "ETKİN DEĞİL" : "DOĞRULANAMADI"}</span>
      <small>${esc(license.name || license.description || "SoftwareLicensingProduct verisi paylaşılmadı.")}</small>
      <small>${license.channel ? `Kanal: ${esc(license.channel)}` : ""}${license.partial_product_key ? ` · Anahtar sonu: •••••-${esc(license.partial_product_key)}` : ""}</small>
    </section>
    <div class="device-software-heading"><div><h4>Yüklü yazılımlar <span id="deviceSoftwareCount">(${programs.length})</span></h4><small class="hint">Ad, üretici veya sürüme göre filtreleyin</small></div><input type="search" placeholder="Yazılım ara…" oninput="filterDeviceSoftware(this.value)" /></div>
    <div class="device-software-list">${programRows || '<div class="hint" style="padding:18px;text-align:center">Program listesi paylaşılmadı.</div>'}</div>`;
}

function filterDeviceSoftware(query) {
  const needle = String(query || "").trim().toLocaleLowerCase("tr-TR");
  let visible = 0;
  document.querySelectorAll(".device-software-row").forEach(row => {
    const matches = !needle || (row.dataset.softwareSearch || "").includes(needle);
    row.hidden = !matches;
    if (matches) visible += 1;
  });
  const count = $("deviceSoftwareCount");
  if (count) count.textContent = `(${visible})`;
}

async function selectDeviceDrawerTab(tab) {
  const device = S.activeDeviceDrawer;
  const content = $("deviceDrawerContent");
  if (!device || !content) return;
  document.querySelectorAll("[data-device-tab]").forEach(button => button.classList.toggle("active", button.dataset.deviceTab === tab));
  if (tab === "overview") {
    const score = deviceConfidence(device);
    content.innerHTML = `<div class="device-drawer-grid">${[["Durum",deviceStatusLabel(deviceStatus(device))],["IP",device.ip],["MAC",device.mac],["Hostname",device.hostname],["Rol",TYPE_LABEL[device.type] || device.type],["Güven skoru",score == null ? "Ölçülmedi" : `%${score}`],["Üretici",device.vendor],["Son görülme",formatSeen(device.last_seen)]].map(([label,value]) => `<div><span>${esc(label)}</span><b>${esc(value || "-")}</b></div>`).join("")}</div>`;
    return;
  }
  if (tab === "hardware") {
    content.innerHTML = renderDeviceDrawerHardware(device);
    return;
  }
  if (tab === "software") {
    content.innerHTML = renderDeviceDrawerSoftware(device);
    return;
  }
  content.innerHTML = `<div class="empty-note">Veriler yükleniyor…</div>`;
  try {
    if (tab === "history") {
      const data = await get("/api/history?range=7d");
      const points = data.points || [];
      content.innerHTML = `<h4>7 günlük operasyon eğilimi</h4><div class="device-trend-bars">${points.slice(-24).map(point => `<i style="height:${Math.max(4, Math.min(100, Number(point.online || 0) * 5))}%" title="${new Date(point.ts * 1000).toLocaleString('tr-TR')}: ${point.online} çevrimiçi"></i>`).join("") || "Ölçüm bulunamadı."}</div><p class="hint">Cihaz ${esc(formatSeen(device.last_seen))} tarihinde son kez görüldü.</p>`;
    } else if (tab === "configs") {
      const data = await get(`/api/ncm/configs?ip=${encodeURIComponent(device.ip || "")}`);
      content.innerHTML = `<div class="drawer-list">${(data.configs || []).map(item => `<button onclick="go('ncm');closeDeviceDrawer()"><b>${esc(item.version_label)}</b><span>${esc(item.created_at_fmt)} · ${item.size_bytes} bayt</span></button>`).join("") || "Bu cihaz için config yedeği yok."}</div>`;
    } else if (tab === "alerts") {
      const data = await get("/api/alerts/inbox?limit=200");
      const related = (data.alerts || []).filter(item => String(item.message).includes(device.ip || "__none__"));
      content.innerHTML = `<div class="drawer-list">${related.map(item => `<button onclick="openAlertDevice('${esc(item.id)}')"><b>${esc(item.message)}</b><span>${new Date(item.ts * 1000).toLocaleString("tr-TR")}</span></button>`).join("") || "Bu cihazla ilişkili alarm yok."}</div>`;
    }
  } catch (error) { content.innerHTML = `<div class="empty-note">Veri alınamadı: ${esc(error.message)}</div>`; }
}

function levenshteinDistance(a, b) {
  const left = String(a || "").toLowerCase(), right = String(b || "").toLowerCase();
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i++) {
    let previous = row[0]; row[0] = i;
    for (let j = 1; j <= right.length; j++) {
      const old = row[j]; row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (left[i - 1] === right[j - 1] ? 0 : 1)); previous = old;
    }
  }
  return row[right.length];
}

function globalDeviceMatches(query) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [];
  return S.devices.map(device => {
    const fields = [device.ip, device.hostname, device.friendly_name, device.mac].filter(Boolean).map(String);
    const substring = fields.some(value => value.toLowerCase().includes(q));
    const distance = Math.min(...fields.map(value => levenshteinDistance(q, value.toLowerCase().slice(0, Math.max(q.length, 1)))));
    return { device, score: substring ? -100 : distance };
  }).filter(item => item.score <= Math.max(3, Math.ceil(q.length / 3)) || item.score === -100).sort((a,b) => a.score - b.score).slice(0, 12);
}

let _globalSearchTimer = null;
let _globalSearchSequence = 0;

function ensureGlobalSearchPanel() {
  let panel = $("globalSearchResults");
  const input = $("globalSearchInput");
  if (!panel && input) {
    panel = document.createElement("div");
    panel.id = "globalSearchResults";
    panel.className = "global-search-results";
    input.parentElement.appendChild(panel);
    bindClickOutside("globalSearchResults", () => { panel.hidden = true; }, "globalSearchInput");
  }
  return panel;
}

function handleGlobalSearch(query) {
  const panel = ensureGlobalSearchPanel();
  if (!panel) return;
  clearTimeout(_globalSearchTimer);
  panel.hidden = false;
  panel.innerHTML = `<div class="empty-note">${query ? "Birleşik indeks aranıyor…" : "Kayıtlı aramalar yükleniyor…"}</div>`;
  const sequence = ++_globalSearchSequence;
  _globalSearchTimer = setTimeout(() => runGlobalSearch(query, sequence), query ? 220 : 0);
}

async function runGlobalSearch(query, sequence) {
  const panel = ensureGlobalSearchPanel();
  if (!panel) return;
  try {
    if (!String(query || "").trim()) {
      const saved = await get("/api/search/saved");
      if (sequence !== _globalSearchSequence) return;
      panel.innerHTML = `<div class="global-search-group">Kayıtlı Aramalar</div>${(saved.searches||[]).map(item=>`<button onclick="applySavedSearch(${item.id})"><b>${esc(item.name)}</b><span>${esc(item.query)}</span></button>`).join("") || '<div class="empty-note">Kayıtlı arama yok. Yapılandırılmış bir sorgu yazıp kaydedebilirsiniz.</div>'}`;
      S.savedSearches = saved.searches || [];
      return;
    }
    const started = performance.now();
    const data = await get(`/api/search?q=${encodeURIComponent(query)}&page_size=30`);
    if (sequence !== _globalSearchSequence) return;
    const categoryLabel = {identity:"Kimlik",network:"Ağ Konumu",inventory:"Envanter",security:"Güvenlik",configuration:"Konfigürasyon",performance:"Performans"};
    const grouped = {};
    (data.results||[]).forEach(item => {
      const group = item.categories?.[0] || "identity";
      (grouped[group] ||= []).push(item);
    });
    panel.innerHTML = Object.entries(grouped).map(([group,items])=>`<div class="global-search-group">${esc(categoryLabel[group]||group)} · ${items.length}</div>${items.map(item=>`<button onclick="openSearchResult('${esc(item.ip||'')}');$('globalSearchResults').hidden=true"><b>${esc(item.hostname||item.ip||item.mac||'Cihaz')}</b><span>${esc(item.ip||'-')} · ${esc(item.mac||'-')} · ${esc(item.device_type||'unknown')} · eşleşme: ${esc((item.matched_fields||[]).join(', '))}</span></button>`).join('')}`).join('') || '<div class="empty-note">Sorguyla eşleşen kayıt bulunamadı.</div>';
    panel.innerHTML += `<div class="global-search-actions"><button onclick="saveCurrentSearch()">Aramayı Kaydet</button><button onclick="exportCurrentSearch('csv')">CSV</button><button onclick="exportCurrentSearch('json')">JSON</button><span>${data.total} sonuç · ${Number(performance.now()-started).toFixed(0)} ms</span></div>`;
    panel.dataset.searchMs = (performance.now() - started).toFixed(2);
  } catch (error) {
    if (sequence === _globalSearchSequence) panel.innerHTML = `<div class="empty-note c-red">${esc(error.message || "Arama yapılamadı.")}</div>`;
  }
}

function openSearchResult(ip) {
  const device = (S.devices||[]).find(item => item.ip === ip);
  if (device) openDeviceDrawer(device.mac || "", ip);
  else { go("devices"); const filter=$("devFilter"); if(filter){filter.value=ip;renderDeviceTable();} }
}

async function saveCurrentSearch() {
  const query = $("globalSearchInput")?.value.trim();
  if (!query) return toast("Kaydetmek için bir sorgu yazın.", "warn");
  const name = prompt("Kayıtlı arama adı:", query.slice(0, 50));
  if (!name) return;
  try { await post("/api/search/saved", {name,query,sort:"last_seen",order:"desc"}); toast("Arama kaydedildi.", "success"); }
  catch (error) { toast(error.message || "Arama kaydedilemedi.", "error"); }
}

function applySavedSearch(id) {
  const saved = (S.savedSearches||[]).find(item => item.id === Number(id));
  if (!saved) return;
  $("globalSearchInput").value = saved.query;
  handleGlobalSearch(saved.query);
}

async function exportCurrentSearch(format) {
  const query = $("globalSearchInput")?.value.trim() || "";
  try {
    const token = getToken();
    const response = await fetch(`/api/search/export?q=${encodeURIComponent(query)}&format=${format}`, {headers:{Authorization:`Bearer ${token}`}});
    if (!response.ok) throw new Error("Dışa aktarım hazırlanamadı.");
    const blob = await response.blob(), link = document.createElement("a");
    link.href = URL.createObjectURL(blob); link.download = `netmon-search.${format}`; link.click(); URL.revokeObjectURL(link.href);
  } catch (error) { toast(error.message || "Dışa aktarım başarısız.", "error"); }
}

function initCommandSearch() {
  document.addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); $("globalSearchInput")?.focus(); $("globalSearchInput")?.select(); }
    if (event.key === "Escape") $("globalSearchResults")?.setAttribute("hidden", "");
  });
}

function renderVirtualDeviceList(devices) {
  const body = $("devBody"), table = body?.closest("table"), host = table?.parentElement;
  if (!body || !table || !host) return false;
  table.style.display = "none";
  let viewport = $("virtualDeviceViewport");
  if (!viewport) { viewport = document.createElement("div"); viewport.id = "virtualDeviceViewport"; viewport.className = "virtual-device-viewport"; viewport.innerHTML = `<div></div>`; host.appendChild(viewport); }
  viewport.style.display = "block";
  const rowHeight = 58, overscan = 8, inner = viewport.firstElementChild;
  inner.style.height = `${devices.length * rowHeight}px`;
  const paint = () => {
    const start = Math.max(0, Math.floor(viewport.scrollTop / rowHeight) - overscan), end = Math.min(devices.length, start + Math.ceil(viewport.clientHeight / rowHeight) + overscan * 2);
    inner.innerHTML = devices.slice(start, end).map((device,index) => `<button class="virtual-device-row" style="transform:translateY(${(start + index) * rowHeight}px)" onclick="openDeviceDrawer('${esc(device.mac || "")}','${esc(device.ip || "")}')"><span class="badge ${deviceStatusClass(deviceStatus(device))}">${esc(deviceStatusLabel(deviceStatus(device)))}</span><b>${esc(deviceDisplayName(device))}</b><code>${esc(device.ip || "-")}</code><code>${esc(device.mac || "-")}</code><span>${esc(TYPE_LABEL[device.type] || device.type || "Bilinmeyen")}</span></button>`).join("");
  };
  viewport.onscroll = () => requestAnimationFrame(paint); paint();
  return true;
}

initCommandSearch();
Object.assign(globalThis, { ensureDeviceDrawer, openDeviceDrawer, closeDeviceDrawer, selectDeviceDrawerTab, deviceDrawerInventory, renderDeviceDrawerHardware, renderDeviceDrawerSoftware, filterDeviceSoftware, levenshteinDistance, globalDeviceMatches, handleGlobalSearch, runGlobalSearch, openSearchResult, saveCurrentSearch, applySavedSearch, exportCurrentSearch, initCommandSearch, renderVirtualDeviceList });
