import "./topology-details.js";

S.alertInbox = S.alertInbox || [];
S.showSuppressedAlerts = S.showSuppressedAlerts || false;
S.downloadItems = S.downloadItems || [];

function ensureDownloadCenterUi() {
  if ($("downloadCenterButton")) return;
  const host = document.querySelector(".topbar-right");
  if (!host) return;
  const wrap = document.createElement("div");
  wrap.className = "download-center-wrap";
  wrap.innerHTML = `
    <button class="icon-btn download-center-button" id="downloadCenterButton" onclick="toggleDownloadCenter()" aria-label="İndirilenler" aria-expanded="false" title="İndirilenler">
      <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M12 3v11m0 0 4-4m-4 4-4-4M5 18h14"/></svg>
    </button>
    <section class="download-center-popover" id="downloadCenterPopover" hidden>
      <header><div><b>İndirilenler</b><small>NetMon tarafından kaydedilen dosyalar</small></div><button class="mini-btn" onclick="openDownloadsFolder()">Klasörü aç</button></header>
      <div class="download-center-list" id="downloadCenterList"><div class="empty-note">Henüz indirilen dosya yok.</div></div>
    </section>`;
  host.prepend(wrap);
  bindClickOutside("downloadCenterPopover", closeDownloadCenter, "downloadCenterButton");
}

function formatDownloadSize(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function renderDownloadCenter() {
  ensureDownloadCenterUi();
  const list = $("downloadCenterList");
  if (!list) return;
  list.innerHTML = S.downloadItems.length ? S.downloadItems.map(item => `
    <article class="download-center-item">
      <span class="download-file-icon">XLSX</span>
      <div><b title="${esc(item.path)}">${esc(item.filename)}</b><span>${formatDownloadSize(item.sizeBytes)} · ${Number(item.deviceCount || 0)} cihaz${Number(item.connectionCount || 0) ? ` · ${Number(item.connectionCount)} bağlantı` : ""}</span><small>${esc(item.path)}</small></div>
      <button class="mini-btn" onclick="openDownloadsFolder()">Klasörde göster</button>
    </article>`).join("") : `<div class="empty-note">Henüz indirilen dosya yok.</div>`;
}

function recordDownload(result) {
  ensureDownloadCenterUi();
  S.downloadItems.unshift({
    filename: result.filename || "netmon-raporu.xlsx",
    path: result.saved_path || "",
    sizeBytes: result.size_bytes || 0,
    deviceCount: result.count || 0,
    connectionCount: result.connection_count || 0,
  });
  S.downloadItems = S.downloadItems.slice(0, 8);
  renderDownloadCenter();
  const popover = $("downloadCenterPopover");
  const button = $("downloadCenterButton");
  if (popover) popover.hidden = false;
  if (button) button.setAttribute("aria-expanded", "true");
}

function closeDownloadCenter() {
  const popover = $("downloadCenterPopover");
  const button = $("downloadCenterButton");
  if (popover) popover.hidden = true;
  if (button) button.setAttribute("aria-expanded", "false");
}

function toggleDownloadCenter() {
  ensureDownloadCenterUi();
  const popover = $("downloadCenterPopover");
  const button = $("downloadCenterButton");
  if (!popover || !button) return;
  popover.hidden = !popover.hidden;
  button.setAttribute("aria-expanded", String(!popover.hidden));
}

function ensureAlertInboxUi() {
  if ($("alertInboxButton")) return;
  const host = document.querySelector(".topbar-right");
  if (!host) return;
  const wrap = document.createElement("div");
  wrap.className = "alert-inbox-wrap";
  wrap.innerHTML = `
    <button class="icon-btn alert-inbox-button" id="alertInboxButton" onclick="toggleAlertInbox()" aria-label="Alarm gelen kutusu" aria-expanded="false">
      <span aria-hidden="true">🔔</span><b id="alertUnreadBadge" hidden>0</b>
    </button>
    <section class="alert-inbox-popover" id="alertInboxPopover" hidden>
      <header><div><b>Alarm Gelen Kutusu</b><small>Canlı ve kalıcı bildirimler</small></div><button class="mini-btn" onclick="markAllAlertsRead()">Tümünü okundu yap</button></header>
      <label class="alert-inbox-filter"><input id="showSuppressedAlerts" type="checkbox" onchange="S.showSuppressedAlerts=this.checked;renderAlertInbox()"> Bastırılmışları göster</label>
      <div class="alert-inbox-list" id="alertInboxList"><div class="empty-note">Alarmlar yükleniyor…</div></div>
    </section>`;
  host.prepend(wrap);
  bindClickOutside("alertInboxPopover", closeAlertInbox, "alertInboxButton");
}

function closeAlertInbox() {
  const popover = $("alertInboxPopover");
  const button = $("alertInboxButton");
  if (popover) popover.hidden = true;
  if (button) button.setAttribute("aria-expanded", "false");
}

function renderAlertInbox() {
  ensureAlertInboxUi();
  const list = $("alertInboxList");
  const badge = $("alertUnreadBadge");
  if (!list || !badge) return;
  const visible = S.alertInbox.filter(item => S.showSuppressedAlerts || !item.suppressed);
  const unread = visible.filter(item => !item.is_read).length;
  badge.textContent = unread > 99 ? "99+" : String(unread);
  badge.hidden = unread === 0;
  list.innerHTML = visible.length ? visible.map(item => `
    <article class="alert-inbox-item ${item.is_read ? "" : "unread"} ${item.suppressed ? "suppressed" : ""} level-${esc(item.level)}" onclick="openAlertDevice('${esc(item.id)}')">
      <i></i><div><b>${esc(item.message)}</b><span>${esc(item.source || "NetMon")} · ${new Date(Number(item.ts) * 1000).toLocaleString("tr-TR")}</span></div>
      <div class="alert-inbox-actions">
        <button title="${item.is_read ? "Okunmadı yap" : "Okundu yap"}" onclick="event.stopPropagation();setAlertState('${esc(item.id)}',{is_read:${!item.is_read}})">${item.is_read ? "○" : "✓"}</button>
        ${item.suppressed
          ? `<button title="Alarmı yeniden gelen kutusunda göster" onclick="event.stopPropagation();setAlertState('${esc(item.id)}',{suppressed:false})">Tekrar göster</button>`
          : `<button title="Bu, alarmı kalıcı olarak silmez, yalnızca listeden gizler" onclick="event.stopPropagation();setAlertState('${esc(item.id)}',{suppressed:true,is_read:true})">Gizle (tekrar gösterme)</button>`}
      </div>
    </article>`).join("") : `<div class="empty-note">Gösterilecek alarm yok.</div>`;
  const filter = $("showSuppressedAlerts");
  if (filter) filter.checked = Boolean(S.showSuppressedAlerts);
}

async function refreshAlertInbox() {
  ensureAlertInboxUi();
  try {
    const data = await get("/api/alerts/inbox?limit=100");
    S.alertInbox = data.alerts || [];
    renderAlertInbox();
  } catch (error) {
    const list = $("alertInboxList");
    if (list) list.innerHTML = `<div class="empty-note">Alarm listesi alınamadı: ${esc(error.message)}</div>`;
  }
}

function toggleAlertInbox() {
  ensureAlertInboxUi();
  const popover = $("alertInboxPopover");
  const button = $("alertInboxButton");
  if (!popover || !button) return;
  popover.hidden = !popover.hidden;
  button.setAttribute("aria-expanded", String(!popover.hidden));
  if (!popover.hidden) refreshAlertInbox();
}

async function setAlertState(id, state) {
  try {
    await apiFetch(`/api/alerts/${encodeURIComponent(id)}/state`, { method: "PUT", body: state });
    const item = S.alertInbox.find(alert => String(alert.id) === String(id));
    if (item) Object.assign(item, state);
    renderAlertInbox();
    return true;
  } catch (error) {
    toast(`Alarm güncellenemedi: ${error.message}`, "error");
    return false;
  }
}

async function markAllAlertsRead() {
  const unread = S.alertInbox.filter(item => !item.is_read && !item.suppressed);
  try {
    await Promise.all(unread.map(item => apiFetch(`/api/alerts/${encodeURIComponent(item.id)}/state`, { method: "PUT", body: { is_read: true } })));
    unread.forEach(item => { item.is_read = true; });
    renderAlertInbox();
  } catch (error) {
    toast(`Alarmlar güncellenemedi: ${error.message}`, "error");
    await refreshAlertInbox();
  }
}

function receiveLiveAlert(message) {
  const ts = Number(message.ts || Date.now() / 1000);
  if (message.id == null) { refreshAlertInbox(); return; }
  const item = { id: Number(message.id), ts, level: message.level || "warning", message: message.message || "Yeni alarm", source: message.source || "NetMon", is_read: false, suppressed: false };
  if (!S.alertInbox.some(existing => String(existing.id) === String(item.id))) S.alertInbox.unshift(item);
  renderAlertInbox();
}

function openAlertDevice(id) {
  const item = S.alertInbox.find(alert => String(alert.id) === String(id));
  if (!item) return;
  if (!item.is_read) setAlertState(id, { is_read: true });
  const ip = String(item.message || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  if (ip) openDeviceDrawer(null, ip, "alerts");
}

function initAlarmInbox() {
  ensureAlertInboxUi();
  ensureDownloadCenterUi();
  refreshAlertInbox();
}

Object.assign(globalThis, { ensureAlertInboxUi, closeAlertInbox, renderAlertInbox, refreshAlertInbox, toggleAlertInbox, setAlertState, markAllAlertsRead, receiveLiveAlert, openAlertDevice, initAlarmInbox, ensureDownloadCenterUi, renderDownloadCenter, recordDownload, closeDownloadCenter, toggleDownloadCenter });
