import "./topology-details.js";

S.alertInbox = S.alertInbox || [];

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
      <div class="alert-inbox-list" id="alertInboxList"><div class="empty-note">Alarmlar yükleniyor…</div></div>
    </section>`;
  host.prepend(wrap);
}

function renderAlertInbox() {
  ensureAlertInboxUi();
  const list = $("alertInboxList");
  const badge = $("alertUnreadBadge");
  if (!list || !badge) return;
  const visible = S.alertInbox.filter(item => !item.suppressed);
  const unread = visible.filter(item => !item.is_read).length;
  badge.textContent = unread > 99 ? "99+" : String(unread);
  badge.hidden = unread === 0;
  list.innerHTML = visible.length ? visible.map(item => `
    <article class="alert-inbox-item ${item.is_read ? "" : "unread"} level-${esc(item.level)}" onclick="openAlertDevice('${esc(item.id)}')">
      <i></i><div><b>${esc(item.message)}</b><span>${esc(item.source || "NetMon")} · ${new Date(Number(item.ts) * 1000).toLocaleString("tr-TR")}</span></div>
      <div class="alert-inbox-actions">
        <button title="${item.is_read ? "Okunmadı yap" : "Okundu yap"}" onclick="event.stopPropagation();setAlertState('${esc(item.id)}',{is_read:${!item.is_read}})">${item.is_read ? "○" : "✓"}</button>
        <button title="Bastır" onclick="event.stopPropagation();setAlertState('${esc(item.id)}',{suppressed:true,is_read:true})">⊘</button>
      </div>
    </article>`).join("") : `<div class="empty-note">Gösterilecek alarm yok.</div>`;
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
  await apiFetch(`/api/alerts/${encodeURIComponent(id)}/state`, { method: "PUT", body: state });
  const item = S.alertInbox.find(alert => alert.id === id);
  if (item) Object.assign(item, state);
  renderAlertInbox();
}

async function markAllAlertsRead() {
  const unread = S.alertInbox.filter(item => !item.is_read && !item.suppressed);
  await Promise.all(unread.map(item => setAlertState(item.id, { is_read: true })));
}

function receiveLiveAlert(message) {
  const ts = Number(message.ts || Date.now() / 1000);
  const item = { id: ts.toFixed(6), ts, level: message.level || "warning", message: message.message || "Yeni alarm", source: message.source || "NetMon", is_read: false, suppressed: false };
  if (!S.alertInbox.some(existing => existing.id === item.id)) S.alertInbox.unshift(item);
  renderAlertInbox();
}

function openAlertDevice(id) {
  const item = S.alertInbox.find(alert => alert.id === id);
  if (!item) return;
  if (!item.is_read) setAlertState(id, { is_read: true });
  const ip = String(item.message || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  if (ip) showDeviceDetails(null, ip);
}

function initAlarmInbox() {
  ensureAlertInboxUi();
  refreshAlertInbox();
}

Object.assign(globalThis, { ensureAlertInboxUi, renderAlertInbox, refreshAlertInbox, toggleAlertInbox, setAlertState, markAllAlertsRead, receiveLiveAlert, openAlertDevice, initAlarmInbox });
