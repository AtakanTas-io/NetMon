import "./notifications.js";

function ensureDeviceDrawer() {
  let drawer = $("deviceExperienceDrawer");
  if (drawer) return drawer;
  drawer = document.createElement("aside");
  drawer.id = "deviceExperienceDrawer";
  drawer.className = "device-experience-drawer";
  drawer.setAttribute("aria-label", "Cihaz ayrıntıları");
  document.body.appendChild(drawer);
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
    <nav>${[["overview","Genel Bakış"],["history","Geçmiş"],["configs","Config Değişiklikleri"],["alerts","İlişkili Alarmlar"]].map(([id,label]) => `<button data-device-tab="${id}" onclick="selectDeviceDrawerTab('${id}')">${label}</button>`).join("")}</nav>
    <div class="device-drawer-content" id="deviceDrawerContent"></div>`;
  selectDeviceDrawerTab(initialTab);
}

function closeDeviceDrawer() { ensureDeviceDrawer().classList.remove("open"); }

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

function handleGlobalSearch(query) {
  let panel = $("globalSearchResults");
  const input = $("globalSearchInput");
  if (!panel && input) { panel = document.createElement("div"); panel.id = "globalSearchResults"; panel.className = "global-search-results"; input.parentElement.appendChild(panel); }
  if (!panel) return;
  const started = performance.now();
  const matches = globalDeviceMatches(query);
  panel.innerHTML = matches.map(({device}) => `<button onclick="openDeviceDrawer('${esc(device.mac || "")}','${esc(device.ip || "")}');$('globalSearchResults').hidden=true"><b>${esc(deviceDisplayName(device))}</b><span>${esc(device.ip || "-")} · ${esc(device.mac || "-")}</span></button>`).join("") || `<div class="empty-note">${query ? "Eşleşen cihaz yok." : "IP, hostname veya MAC yazın."}</div>`;
  panel.hidden = !query;
  panel.dataset.searchMs = (performance.now() - started).toFixed(2);
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
Object.assign(globalThis, { ensureDeviceDrawer, openDeviceDrawer, closeDeviceDrawer, selectDeviceDrawerTab, levenshteinDistance, globalDeviceMatches, handleGlobalSearch, initCommandSearch, renderVirtualDeviceList });
