
window.addEventListener('error', function(e) {
  console.warn("NetMon Auto-Recover (Error):", e.message);
  e.preventDefault();
});
window.addEventListener('unhandledrejection', function(e) {
  console.warn("NetMon Auto-Recover (Promise):", e.reason);
  e.preventDefault();
});

/* ============================================================
   NETMON — APP.JS (TAM VE TEMİZLENMİŞ HALİ)
   ============================================================ */

function $(id) {
  return document.getElementById(id);
}
const S = {
  page: "dashboard",
  user: null,
  auto: true,
  scanning: false,
  devices: [],
  devicesTs: 0,
  deviceScanError: null,
  topology: null,
  traffic: { up: 0, down: 0 },
  sparkUp: [],
  sparkDown: [],
  connections: { tcp: 0, udp: 0, total: 0, supported: true },
  overview: {},
  logs: [],
  inventoryAssets: [],
  inventoryAssetDetail: null,
};

function esc(str) {
  return String(str ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
}

function fmtMbps(v) {
  const n = Number(v || 0);
  return n < 10
    ? n.toFixed(2)
    : n < 100
      ? n.toFixed(1)
      : Math.round(n).toString();
}

function nowTime() {
  return new Date().toLocaleTimeString("tr-TR");
}

function isRandomizedMac(mac) {
  if (!mac || typeof mac !== "string") return false;
  const clean = mac.replace(/[^a-fA-F0-9]/g, "");
  if (clean.length < 2) return false;
  const secondHex = parseInt(clean.charAt(1), 16);
  return (secondHex & 2) !== 0; // Local bit set (2, 6, A, E)
}

function deviceDisplayName(d) {
  if (d?.friendly_name) return d.friendly_name;
  if (d?.is_self && d?.hostname) return d.hostname;
  if (d?.hostname && d.hostname !== d.ip) return d.hostname;
  
  const type = d?.type || "unknown";
  const vendor = d?.vendor && d.vendor !== "Bilinmeyen Üretici" ? d.vendor : "";
  const ip = d?.ip || "";
  const osStr = String(d?.os_fingerprint || d?.classification?.os || "").toLowerCase();
  const hostStr = String(d?.hostname || d?.friendly_name || "").toLowerCase();
  const vStr = String(d?.vendor || "").toLowerCase();
  const fullCheck = osStr + " " + hostStr + " " + vStr;

  const isApple = fullCheck.includes("apple") || fullCheck.includes("ios") || fullCheck.includes("iphone") || fullCheck.includes("ipad");
  const isAndroid = fullCheck.includes("android") || fullCheck.includes("samsung") || fullCheck.includes("xiaomi") || fullCheck.includes("huawei");
  const ipSuffix = ip ? ` (.${ip.split('.').pop()})` : '';

  if (type === "phone" || type === "mobile") {
    if (isApple) return vendor ? `${vendor} iPhone` : "iPhone (Apple iOS)";
    if (isAndroid) return vendor ? `${vendor} Android Telefon` : "Android Telefon";
    return vendor ? `${vendor} Telefon` : `Mobil Telefon${ipSuffix}`;
  }
  if (type === "tablet") {
    if (isApple) return "iPad (Apple iOS)";
    if (isAndroid) return "Android Tablet";
    return vendor ? `${vendor} Tablet` : `Tablet${ipSuffix}`;
  }
  if (type === "tv" || type === "smart_tv") return vendor ? `${vendor} Smart TV` : `Smart TV${ipSuffix}`;
  if (type === "printer") return vendor ? `${vendor} Yazıcı` : `Ağ Yazıcısı${ipSuffix}`;
  if (type === "router" || type === "access_point" || type === "switch") return vendor ? `${vendor} Ağ Donanımı` : `Ağ Cihazı${ipSuffix}`;
  
  if (vendor) return `${vendor} Cihazı`;
  if (ip) return `Cihaz (${ip})`;
  if (d?.mac) return `MAC-${String(d.mac).replace(/[^a-fA-F0-9]/g, "").slice(-6).toUpperCase()}`;
  return "Bilinmeyen Cihaz";
}

function deviceVendorDisplay(d) {
  if (d?.vendor && d.vendor !== "Bilinmeyen Üretici") return d.vendor;
  const osStr = String(d?.os_fingerprint || "").toLowerCase();
  const hostStr = String(d?.hostname || "").toLowerCase();
  if (osStr.includes("apple") || osStr.includes("ios") || hostStr.includes("iphone")) return "Apple Inc.";
  if (osStr.includes("android") || hostStr.includes("android")) return "Android OS";
  if (isRandomizedMac(d?.mac)) return "Gizli MAC (iOS / Android)";
  const dt = d?.type || "unknown";
  if (dt === "phone" || dt === "mobile" || dt === "tablet") return "Mobil Cihaz Üreticisi";
  if (dt === "tv" || dt === "smart_tv") return "Smart TV Üreticisi";
  return "Bilinmeyen Üretici";
}

function deviceSubtitle(d) {
  return d.friendly_name && d.hostname ? d.hostname : d.ip || "";
}

function deviceConfidence(d) {
  const raw = d?.confidence ?? d?.classification?.confidence;
  if (raw === null || raw === undefined) return null;
  return Math.round(Number(raw) * 100);
}

function formatSeen(ts) {
  if (!ts) return "-";
  try { return new Date(Number(ts) * 1000).toLocaleTimeString("tr-TR"); } catch (e) { return "-"; }
}

function discoveryLabel(source) {
  return ({
    arp: "ARP",
    icmp: "ICMP",
    dns: "DNS",
    hostname: "Hostname",
    netbios: "NetBIOS",
    oui: "Üretici/OUI",
    mdns: "mDNS",
    ssdp: "SSDP",
    snmp: "SNMP",
    lldp: "LLDP / CDP",
    wmi: "WMI / WinRM",
    ad: "Active Directory",
    nmap: "Nmap",
    services: "Servis Port",
    self: "Yerel Makine"
  })[source] || source;
}

function deviceStatus(d) {
  if (d?.status) return d.status;
  return d?.online ? "online" : "offline";
}

function deviceStatusLabel(status) {
  return ({
    online: "Çevrimiçi",
    discovered: "Yanıt doğrulanamadı",
    offline: "Çevrimdışı",
    unknown: "Belirsiz",
    stale: "Eski kayıt",
  })[status] || "Belirsiz";
}

function deviceStatusClass(status) {
  return ({ online: "ok", discovered: "warn", offline: "gray", stale: "gray", unknown: "gray" })[status] || "gray";
}

function connectivityLabel(d) {
  const s = d?.connectivity_status || (d?.status === "online" ? "online" : d?.status === "offline" ? "offline" : "unknown");
  return ({
    online: "Ağ erişimi doğrulandı",
    reachable_but_icmp_blocked: "Ağda görüldü · ICMP yanıtı yok",
    offline: "Uzun süredir keşfedilmedi",
    unknown: "Erişilebilirlik doğrulanamadı",
  })[s] || "Erişilebilirlik doğrulanamadı";
}

const TYPE_LABEL = {
  internet: "İnternet",
  router: "Router",
  firewall: "Firewall",
  server: "Sunucu",
  printer: "Yazıcı",
  mobile: "Mobil",
  phone: "Telefon",
  tablet: "Tablet",
  laptop: "Laptop",
  pc: "Bilgisayar",
  computer: "Bilgisayar",
  iot: "IoT",
  http: "Web Cihazı",
  network_device: "Ağ Cihazı",
  switch: "Switch",
  access_point: "Access Point",
  smart_tv: "Smart TV",
  camera: "Kamera",
  nas: "NAS / Depolama",
  iot: "IoT",
  unknown: "Bilinmeyen",
};

const DEVICE_TYPE_ICON = {
  internet: "cloud",
  router: "router",
  firewall: "shield",
  server: "server",
  printer: "printer",
  mobile: "smartphone",
  phone: "smartphone",
  tablet: "tablet",
  laptop: "laptop",
  pc: "monitor",
  computer: "monitor",
  iot: "wifi",
  http: "globe",
  network_device: "router",
  switch: "switch",
  access_point: "wifi",
  smart_tv: "monitor",
  camera: "eye",
  nas: "server",
  unknown: "cpu",
};

const ICON = {
  monitor:
    '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  globe:
    '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20"/>',
  activity: '<path d="M22 12h-4l-3 9-6-18-3 9H2"/>',
  up: '<path d="M12 19V5M5 12l7-7 7 7"/>',
  down: '<path d="M12 5v14M5 12l7 7 7-7"/>',
  link: '<path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/>',
  refresh:
    '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M20.5 9A9 9 0 0 0 5 5.5L1 10m22 4-4 4.5A9 9 0 0 1 3.5 15"/>',
  wifi: '<path d="M5 12.5a11 11 0 0 1 14 0M8.5 16a6 6 0 0 1 7 0M12 19.5h.01"/>',
  question:
    '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2-3 4M12 17h.01"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  alert:
    '<path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
  cloud:
    '<path d="M17.5 19H9a5 5 0 1 1 1.3-9.8A6 6 0 0 1 22 12a4 4 0 0 1-4.5 7Z"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>',
  save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z"/><path d="M17 21v-8H7v8M7 3v5h8"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8Z"/><circle cx="12" cy="12" r="3"/>',
  router:
    '<rect x="2" y="9" width="20" height="8" rx="2"/><path d="M6 17v2M18 17v2M8 9V6M16 9V6"/><circle cx="7" cy="13" r="1"/>',
  server:
    '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  smartphone:
    '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>',
  tablet:
    '<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M11 19h2"/>',
  printer:
    '<path d="M6 9V3h12v6"/><rect x="4" y="9" width="16" height="8" rx="2"/><path d="M6 17h12v5H6z"/>',
  laptop:
    '<rect x="3" y="4" width="18" height="12" rx="1"/><path d="M2 19h20"/>',
  switch:
    '<rect x="2" y="8" width="20" height="8" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/>',
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  gauge:
    '<path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM12 2a10 10 0 1 0 10 10"/><path d="m12 12 5-5"/>',
  lock: '<rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  logout:
    '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  trash:
    '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m2 0-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  calendar:
    '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  route:
    '<circle cx="6" cy="19" r="3"/><circle cx="18" cy="5" r="3"/><path d="M9 19h8a3 3 0 0 0 0-6H7a3 3 0 0 1 0-6h2"/>',
  shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  report:
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M9 13h6M9 17h6"/>',
  users:
    '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  chevrondown: '<path d="m6 9 6 6 6-6"/>',
  book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z"/>',
};

function ico(name, size, cls) {
  const body = ICON[name] || ICON.question;
  const s = size || 16;
  return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="${cls || ""}">${body}</svg>`;
}

/* ---------- Oturum / token yönetimi ---------- */
const TOKEN_KEY = "netmon_token";

function getToken() {
  try {
    return (
      localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || ""
    );
  } catch (e) {
    return "";
  }
}

function setToken(token, remember) {
  try {
    if (remember === false) {
      sessionStorage.setItem(TOKEN_KEY, token || "");
      localStorage.removeItem(TOKEN_KEY);
    } else {
      localStorage.setItem(TOKEN_KEY, token || "");
    }
  } catch (e) {}
}

function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(TOKEN_KEY);
  } catch (e) {}
}

/* ---------- fetch yardımcıları ---------- */
async function apiFetch(path, options) {
  const opts = Object.assign({}, options);
  opts.headers = Object.assign({}, opts.headers);

  const token = getToken();
  if (token) opts.headers["Authorization"] = "Bearer " + token;

  if (opts.body && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }

  const res = await fetch(path, opts);
  if (res.status === 401) {
    clearToken();
    S.user = null;
    showLogin();
    throw new Error("Oturum sona erdi, lütfen tekrar giriş yapın.");
  }

  let data = null;
  try {
    data = await res.json();
  } catch (e) {}
  if (!res.ok)
    throw new Error(
      (data && (data.error || data.detail)) || "İstek başarısız oldu.",
    );
  return data;
}

function get(path) {
  return apiFetch(path, { method: "GET" });
}
function post(path, body) {
  return apiFetch(path, { method: "POST", body: body || {} });
}
function del(path) {
  return apiFetch(path, { method: "DELETE" });
}

/* ---------- Toast ve Modal ---------- */
function toast(message, kind) {
  const wrap = $("toasts");
  if (!wrap) return;
  const el = document.createElement("div");
  el.className = "toast " + (kind || "info");
  el.textContent = message;
  wrap.appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 300);
  }, 3200);
}

function openModal(html) {
  const back = $("modalBack");
  const box = $("modalBox");
  if (!back || !box) return;
  box.innerHTML = html;
  back.classList.remove("open");
  back.classList.add("show");
}

function closeModal(event) {
  closeModalForce();
}
function closeModalForce() {
  const back = $("modalBack");
  if (back?.dataset?.locked === "1") return;
  if (back) {
    back.classList.remove("show");
    back.classList.remove("open");
  }
}

/* ---------- Giriş / Çıkış ---------- */
function showLogin() {
  const screen = $("loginScreen");
  const app = $("app");
  if (screen) screen.style.display = "grid";
  if (app) app.classList.add("auth-hidden");
}

function hideLogin() {
  const screen = $("loginScreen");
  const app = $("app");
  if (screen) screen.style.display = "none";
  if (app) app.classList.remove("auth-hidden");
}

async function logout() {
  try {
    await post("/api/auth/logout", {});
  } catch (e) {}
  clearToken();
  S.user = null;
  try {
    if (typeof stopAutoRefresh === "function") stopAutoRefresh();
    if (networkSocket) networkSocket.close();
  } catch (e) {}
  const modalBack = $("modalBack");
  if (modalBack) modalBack.dataset.locked = "0";
  closeModalForce();
  showLogin();
}

function openProfile() {
  if (!S.user) return;
  openModal(`
    <h3>${esc(S.user.username || "Kullanıcı")}</h3>
    <div class="sub">${S.user.role === "admin" ? "Yönetici" : "Kullanıcı"}</div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:18px;">
      <button class="mini-btn" onclick="closeModalForce()">Kapat</button>
      <button class="mini-btn" onclick="openPasswordChangeModal(false)">Parolayı Değiştir</button>
      <button class="mini-btn blue" onclick="logout()">${ico("logout", 14)} Çıkış Yap</button>
    </div>
  `);
}

function openPasswordChangeModal(forced = false) {
  openModal(`
    <h3>${forced ? "Güvenlik için parola değişikliği gerekli" : "Parolayı Değiştir"}</h3>
    <div class="sub">Yeni parola en az 12 karakter olmalıdır.</div>
    <div class="field-label" style="margin-top:12px">Mevcut Parola</div>
    <input id="currentPassword" type="password" autocomplete="current-password" />
    <div class="field-label" style="margin-top:10px">Yeni Parola</div>
    <input id="newPassword" type="password" autocomplete="new-password" />
    <div class="field-label" style="margin-top:10px">Yeni Parola (Tekrar)</div>
    <input id="newPasswordAgain" type="password" autocomplete="new-password" />
    <div id="passwordChangeError" class="hint c-red" style="margin-top:8px"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
      ${forced ? "" : '<button class="mini-btn" onclick="closeModalForce()">İptal</button>'}
      <button class="mini-btn blue" onclick="submitPasswordChange()">Parolayı Kaydet</button>
    </div>
  `);
  const back = $("modalBack");
  if (back) back.dataset.locked = forced ? "1" : "0";
}

async function submitPasswordChange() {
  const currentPassword = $("currentPassword")?.value || "";
  const newPassword = $("newPassword")?.value || "";
  const again = $("newPasswordAgain")?.value || "";
  const error = $("passwordChangeError");
  if (newPassword.length < 12) {
    if (error) error.textContent = "Yeni parola en az 12 karakter olmalıdır.";
    return;
  }
  if (newPassword !== again) {
    if (error) error.textContent = "Yeni parolalar eşleşmiyor.";
    return;
  }
  try {
    await post("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword });
    if (S.user) S.user.must_change_password = false;
    const back = $("modalBack");
    if (back) back.dataset.locked = "0";
    closeModalForce();
    toast("Parola güvenli biçimde değiştirildi.", "success");
    boot();
  } catch (e) {
    if (error) error.textContent = e.message || "Parola değiştirilemedi.";
  }
}

function applyRolePermissions() {
  const isAdmin = S.user && S.user.role === "admin";
  document.querySelectorAll(".admin-only").forEach((el) => {
    el.style.display = isAdmin ? "" : "none";
  });
  const nameEl = $("userName");
  const roleEl = $("userRole");
  if (nameEl) nameEl.textContent = S.user ? S.user.username : "-";
  if (roleEl) roleEl.textContent = isAdmin ? "Yönetici" : "Kullanıcı";
}

/* ---------- Navigasyon ---------- */
const NAV_ITEMS = [
  { id: "dashboard", label: "Kontrol Merkezi", icon: "monitor" },
  { id: "devices", label: "BT Varlık Envanteri", icon: "list" },
  { id: "topology", label: "Ağ Keşfi ve Topoloji", icon: "wifi" },
  { id: "security", label: "Güvenlik Görünürlüğü", icon: "shield" },
  { id: "analyst", label: "Analist Merkezi", icon: "shield" },
  { id: "purpleteam", label: "Cyber Lab", icon: "shield" },
  { id: "egitim", label: "NetMon Academy", icon: "book" },
  { id: "settings", label: "Ayarlar", icon: "gear", admin: true },
  { id: "management", label: "Yönetim", icon: "users", admin: true },
];

const PAGE_TITLES = Object.fromEntries(NAV_ITEMS.map((n) => [n.id, n.label]));
Object.assign(PAGE_TITLES, {
  dashboard: "Kontrol Merkezi",
  devices: "BT Varlık Envanteri",
  topology: "Ağ Keşfi ve Topoloji",
  ping: "Ağ Sağlığı ve Teşhis",
  security: "Güvenlik Görünürlüğü",
  analyst: "Analist Merkezi",
  logs: "Operasyon Kayıtları",
});

function buildNav() {
  const nav = $("nav");
  if (!nav) return;
  const isAdmin = S.user && S.user.role === "admin";
  nav.innerHTML = NAV_ITEMS.filter((item) => !item.admin || isAdmin)
    .map(
      (item) => `
        <button class="nav-item ${S.page === item.id ? "active" : ""}" data-page="${item.id}" onclick="go('${item.id}')">
          ${ico(item.icon, 17)}
          <span>${esc(item.label)}</span>
        </button>
      `,
    )
    .join("");
}

function go(page) {
  if (!PAGE_TITLES[page]) page = "dashboard";
  S.page = page;

  document
    .querySelectorAll(".page")
    .forEach((el) => el.classList.remove("active"));
  const target = $("page-" + page);
  if (target) target.classList.add("active");

  document.querySelectorAll(".nav-item").forEach((el) => {
    el.classList.toggle("active", el.dataset.page === page);
  });

  const title = $("pageTitle");
  if (title) title.textContent = PAGE_TITLES[page] || page;

  try {
    switch (page) {
      case "topology":
        renderTopologyPage();
        refreshTopology();
        break;
      case "devices":
        renderDevicesPage();
        refreshDevices();
        break;
      case "ping":
        renderPingPage();
        break;
      case "traceroute":
        renderTraceroutePage();
        break;
      case "portscan":
        renderPortscanPage();
        break;
      case "speedtest":
        renderSpeedtestPage();
        break;
      case "security":
        renderSecurityPage();
        refreshSecurity();
        break;
      case "analyst":
        renderAnalystPage();
        refreshAnalyst();
        break;
      case "logs":
        renderLogsPage();
        refreshLogs();
        break;
      case "purpleteam":
        renderPurpleTeamPage();
        break;
      case "egitim":
        const egEl = $("page-egitim");
        if (egEl) egEl.dataset.built = "";
        renderEgitimPage();
        setTimeout(startInternetConnectionSim, 300);
        break;
      case "settings":
        renderSettingsPage();
        break;
      case "management":
        renderManagementPage();
        break;
      default:
        refreshAll();
    }
  } catch (e) {
    console.error("Sayfa yüklenirken hata:", e);
  }

  if (window.innerWidth < 900) {
    document.body.classList.remove("sidebar-open");
    const app = $("app");
    if (app) app.classList.remove("collapsed");
  }
}

/* ---------- Üst çubuk / Sidebar kontrolleri ---------- */
function toggleSidebar() {
  const app = $("app");
  if (app) app.classList.toggle("collapsed");
  document.body.classList.toggle("sidebar-open");
}

function updateThemeIcon() {
  const btn = $("themeBtn");
  if (!btn) return;
  const isLight =
    document.documentElement.getAttribute("data-theme") === "light";
  btn.innerHTML = ico(isLight ? "moon" : "sun", 17);
}

function toggleTheme() {
  const root = document.documentElement;
  const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
  if (next === "light") {
    root.setAttribute("data-theme", "light");
  } else {
    root.removeAttribute("data-theme");
  }
  try {
    localStorage.setItem("netmon_theme", next);
  } catch (e) {}
  updateThemeIcon();
}

function initStaticIcons() {
  const map = {
    burgerBtn: () => ico("menu", 18),
    gearBtn: () => ico("gear", 18),
    brandLogo: () => ico("wifi", 20),
    avatarIco: () => ico("users", 16),
    chevIco: () => ico("chevrondown", 14),
    calIco: () => ico("calendar", 14),
    simIco: () => ico("alert", 16),
  };
  Object.keys(map).forEach((id) => {
    const el = $(id);
    if (el && !el.innerHTML.trim()) {
      try {
        el.innerHTML = map[id]();
      } catch (e) {}
    }
  });
  updateThemeIcon();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initStaticIcons, {
    once: true,
  });
} else {
  initStaticIcons();
}

function toggleAuto() {
  S.auto = !S.auto;
  const el = $("autoSwitch");
  if (el) el.classList.toggle("on", S.auto);
}

/* ---------- Saat ---------- */
function tickClock() {
  const d = new Date();
  const dateEl = $("clockDate");
  const timeEl = $("clockTime");
  if (dateEl) dateEl.textContent = d.toLocaleDateString("tr-TR");
  if (timeEl) timeEl.textContent = d.toLocaleTimeString("tr-TR");
}

/* ---------- Loglar (Tüm Sayfalar ve Canlı Akış İçin) ---------- */
function logRowHtml(l) {
  const level = l.level || "info";
  const cls =
    level === "error"
      ? "red"
      : level === "warn"
        ? "orange"
        : level === "ok"
          ? "green"
          : "";
  return `
    <div class="log-row">
      <span class="log-time">${esc(l.time || "")}</span>
      <span class="log-level ${cls}">${esc(level)}</span>
      <span class="log-msg">${esc(l.message || "")}</span>
    </div>
  `;
}

function renderLogs() {
  const list = $("logList");
  if (list) {
    list.innerHTML =
      (S.logs || []).slice(0, 60).map(logRowHtml).join("") ||
      `<div class="hint" style="padding:14px;text-align:center">Henüz log yok.</div>`;
  }
  const pageList = $("logsPageList");
  if (pageList) {
    pageList.innerHTML =
      (S.logs || []).map(logRowHtml).join("") ||
      `<div class="hint" style="padding:14px;text-align:center">Henüz log yok.</div>`;
  }
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
  if (!(S.user && S.user.role === "admin")) {
    toast("Logları temizlemek için yönetici yetkisi gerekli.", "warn");
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
          <h2>Loglar</h2>
          <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;"><button class="mini-btn admin-only" onclick="clearLogs()">Temizle</button></div>
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
  if (!(S.user && S.user.role === "admin")) {
    toast("Port taraması yalnızca yönetici hesabında kullanılabilir.", "warn");
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
      return `<span class="badge fail">ERROR</span>`;
    };
    
    const rulesHtml = (data.rules || []).length > 0 ? (data.rules || []).map((r) => 
      `<div style="display:flex; justify-content:space-between; padding:12px; border:1px solid var(--line-soft); border-radius:8px; background:var(--panel-2); margin-bottom:8px; align-items:center;">
        <div style="display:flex; align-items:center; gap:10px;">
          <div style="color:var(--blue);">${ico("shield", 20)}</div>
          <span style="color:var(--txt); font-weight:600; font-size:13px;">${esc(r.name || r.title || "")}</span>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
          ${statusBadge(r.status)}
          <button class="mini-btn" onclick="alert('Kural detayları simüle ediliyor...')">İncele</button>
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
          <div style="margin-top:auto; padding-top:12px;"><button class="btn btn-sm" style="width:100%" onclick="alert('Firewall konfigürasyonu taranıyor...')">Yapılandırmayı Tara</button></div>
        </div>
        <div style="padding:16px; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; display:flex; flex-direction:column; gap:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px; color:var(--cyan); font-weight:bold;">${ico("globe", 20)} Web Filtresi</div>
            ${statusBadge(data.webfilter_desc)}
          </div>
          <div style="font-size:12px; color:var(--txt-2); line-height:1.5; margin-top:4px;">${esc(data.webfilter_desc || "")}</div>
          <div style="margin-top:auto; padding-top:12px;"><button class="btn btn-sm" style="width:100%" onclick="alert('Web filtre logları analiz ediliyor...')">Trafik Loglarını İncele</button></div>
        </div>
      </div>
      <h3 style="margin:0 0 12px; font-size:14px; color:var(--txt); border-bottom:1px solid var(--line-soft); padding-bottom:8px;">Politika İhlalleri & Güvenlik Logları</h3>
      ${rulesHtml}
    `;
  } catch (e) {
    console.warn("Güvenlik verisi alınamadı:", e);
  }
}

/* ---------- Raporlar ---------- */
const EGITIM_KAVRAMLAR = [
  { key: "ip", renk: "blue", ico: "monitor", ad: "IP Adresi", ozet: "Ağdaki her cihaza atanan benzersiz numaradır; paketlerin kime gideceğini belirler." },
  { key: "dns", renk: "cyan", ico: "wifi", ad: "DNS", ozet: "İnsan tarafından okunan alan adlarını (site.com) IP adresine çevirir." },
  { key: "port", renk: "orange", ico: "gauge", ad: "Port", ozet: "Aynı IP üzerinde birden çok servisi ayırt etmeye yarayan numaradır (80=HTTP, 443=HTTPS, 22=SSH)." },
  { key: "mac", renk: "purple", ico: "list", ad: "MAC Adresi", ozet: "Ağ kartının donanımsal, değiştirilemeyen fiziksel adresidir." },
  { key: "nat", renk: "green", ico: "route", ad: "NAT", ozet: "Birden çok özel IP'yi tek bir genel (public) IP arkasında internete çıkarır." },
  { key: "dhcp", renk: "blue", ico: "activity", ad: "DHCP", ozet: "Ağa yeni katılan cihazlara otomatik IP adresi atayan servistir." },
  { key: "packets", renk: "cyan", ico: "report", ad: "Paketler", ozet: "Veri ağ üzerinde küçük parçalara (paketlere) bölünerek iletilir." },
  { key: "osi", renk: "orange", ico: "route", ad: "OSI Modeli", ozet: "Ağ iletişimini 7 katmana ayıran kavramsal referans modelidir (Fiziksel'den Uygulama'ya)." },
  { key: "subnet", renk: "purple", ico: "shield", ad: "Subnetting / CIDR", ozet: "Büyük bir ağı, /24 gibi CIDR gösterimiyle daha küçük alt ağlara böler." },
  { key: "routersw", renk: "green", ico: "wifi", ad: "Router vs Switch", ozet: "Switch aynı ağ içindeki cihazları, router ise farklı ağları birbirine bağlar." },
  { key: "tcpudp", renk: "blue", ico: "activity", ad: "TCP vs UDP", ozet: "TCP güvenilir ve sıralı iletim sağlar; UDP daha hızlıdır ama teslim garantisi vermez." },
  { key: "http", renk: "cyan", ico: "monitor", ad: "HTTP / HTTPS", ozet: "Web trafiğinin protokolüdür; HTTPS, TLS ile şifrelenmiş halidir." },
  { key: "tls", renk: "orange", ico: "shield", ad: "TLS", ozet: "İstemci ile sunucu arasında el sıkışma yaparak trafiği şifreler." },
  { key: "firewall", renk: "purple", ico: "shield", ad: "Firewall", ozet: "Tanımlı kurallara göre trafiği izin verir veya engeller." },
  { key: "vpn", renk: "green", ico: "route", ad: "VPN", ozet: "İnternet üzerinden şifreli, özel bir tünel oluşturur." },
];

/* Her kavram için küçük, döngüsel animasyonlu SVG diyagramı (native SMIL
   <animate>/<animateMotion> kullanılıyor — ek kütüphane/JS animasyon
   döngüsü gerekmiyor, tarayıcı kendisi oynatıyor). */
function _c(key) {
  const map = { blue: "blue", cyan: "cyan", orange: "orange", purple: "purple", green: "green", red: "red" };
  return `var(--${map[key] || "blue"})`;
}
const DIAGRAMS = {
  ip: `<svg viewBox="0 0 220 90"><g fill="none" stroke="${_c("blue")}" stroke-width="1.6">
    <rect x="8" y="10" width="30" height="20" rx="2"/><rect x="8" y="35" width="30" height="20" rx="2"/><rect x="8" y="60" width="30" height="20" rx="2"/>
    <path d="M38 20H100M38 45H100M38 70H100"/><rect x="100" y="30" width="34" height="30" rx="4"/>
    </g>
    <circle r="3" fill="${_c("blue")}"><animateMotion dur="2s" repeatCount="indefinite" path="M38 20H100"/></circle>
    <circle r="3" fill="${_c("cyan")}"><animateMotion dur="2.4s" repeatCount="indefinite" path="M38 45H100"/></circle>
    <circle r="3" fill="${_c("green")}"><animateMotion dur="2.8s" repeatCount="indefinite" path="M38 70H100"/></circle>
    <text x="12" y="24" font-size="7" fill="var(--txt-2)">.4</text><text x="12" y="49" font-size="7" fill="var(--txt-2)">.7</text><text x="12" y="74" font-size="7" fill="var(--txt-2)">.9</text>
    <text x="106" y="49" font-size="7" fill="var(--txt)">192.168.1.x</text></svg>`,

  dns: `<svg viewBox="0 0 220 90"><g font-size="9" fill="var(--txt)">
    <rect x="6" y="35" width="60" height="20" rx="4" fill="none" stroke="${_c("green")}"/><text x="14" y="48">site.com</text>
    <rect x="80" y="35" width="60" height="20" rx="4" fill="none" stroke="${_c("cyan")}"/><text x="93" y="48">DNS</text>
    <rect x="154" y="35" width="60" height="20" rx="4" fill="none" stroke="${_c("blue")}"/><text x="160" y="48" font-size="8">203.0.113.5</text></g>
    <circle r="3" fill="${_c("cyan")}"><animateMotion dur="2.2s" repeatCount="indefinite" path="M66 45H80"/></circle>
    <circle r="3" fill="${_c("blue")}"><animateMotion dur="2.2s" repeatCount="indefinite" begin="1.1s" path="M140 45H154"/></circle></svg>`,

  port: `<svg viewBox="0 0 220 90"><rect x="70" y="10" width="70" height="70" rx="6" fill="none" stroke="${_c("orange")}" stroke-width="1.6"/>
    <text x="82" y="26" font-size="8" fill="var(--txt)">SERVER</text>
    <g font-size="8" fill="var(--txt-2)">
    <rect x="80" y="32" width="50" height="12" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="3s" repeatCount="indefinite"/></rect><text x="84" y="41">:80 HTTP</text>
    <rect x="80" y="47" width="50" height="12" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="3s" begin="1s" repeatCount="indefinite"/></rect><text x="84" y="56">:443 HTTPS</text>
    <rect x="80" y="62" width="50" height="12" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="3s" begin="2s" repeatCount="indefinite"/></rect><text x="84" y="71">:22 SSH</text></g></svg>`,

  mac: `<svg viewBox="0 0 220 90"><rect x="70" y="25" width="80" height="40" rx="6" fill="none" stroke="${_c("purple")}" stroke-width="1.6">
    <animate attributeName="stroke-opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite"/></rect>
    <text x="82" y="49" font-size="9" fill="var(--txt)">3C:22:FB:9A</text></svg>`,

  nat: `<svg viewBox="0 0 220 90"><g font-size="7" fill="var(--txt-2)">
    <rect x="6" y="8" width="42" height="14" rx="3" fill="none" stroke="${_c("green")}"/><text x="10" y="18">10.0.0.12</text>
    <rect x="6" y="38" width="42" height="14" rx="3" fill="none" stroke="${_c("green")}"/><text x="10" y="48">10.0.0.17</text>
    <rect x="6" y="68" width="42" height="14" rx="3" fill="none" stroke="${_c("green")}"/><text x="10" y="78">10.0.0.23</text></g>
    <rect x="90" y="35" width="44" height="20" rx="4" fill="none" stroke="${_c("orange")}" stroke-width="1.6"/><text x="98" y="48" font-size="8" fill="var(--txt)">NAT</text>
    <rect x="164" y="35" width="50" height="20" rx="4" fill="none" stroke="${_c("blue")}"/><text x="168" y="48" font-size="7" fill="var(--txt)">203.0.113.5</text>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.6s" repeatCount="indefinite" path="M48 15C70 15 70 45 90 45"/></circle>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.6s" begin=".5s" repeatCount="indefinite" path="M48 45H90"/></circle>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.6s" begin="1s" repeatCount="indefinite" path="M48 75C70 75 70 45 90 45"/></circle>
    <circle r="3" fill="${_c("blue")}"><animateMotion dur="1.6s" begin=".3s" repeatCount="indefinite" path="M134 45H164"/></circle></svg>`,

  dhcp: `<svg viewBox="0 0 220 90"><rect x="6" y="30" width="46" height="30" rx="4" fill="none" stroke="${_c("blue")}"/><text x="10" y="49" font-size="8" fill="var(--txt)">CLIENT</text>
    <rect x="168" y="30" width="46" height="30" rx="4" fill="none" stroke="${_c("green")}"/><text x="172" y="49" font-size="8" fill="var(--txt)">SERVER</text>
    <path d="M52 40H168" stroke="var(--line)"/>
    <circle r="3" fill="${_c("orange")}"><animateMotion dur="1s" repeatCount="indefinite" path="M52 40H168"/><animate attributeName="fill" values="${_c("orange")};${_c("orange")}" dur="1s" repeatCount="indefinite"/></circle>
    <path d="M52 52H168" stroke="var(--line)"/>
    <circle r="3" fill="${_c("cyan")}"><animateMotion dur="1s" begin="1s" repeatCount="indefinite" path="M168 52H52"/></circle>
    <text x="70" y="20" font-size="7" fill="var(--txt-3)">DISCOVER → OFFER → REQUEST → ACK</text></svg>`,

  packets: `<svg viewBox="0 0 220 90"><path d="M10 45H210" stroke="var(--line)"/>
    ${[0, 1, 2].map((i) => `<g><rect width="20" height="16" x="-10" y="-8" rx="3" fill="none" stroke="${_c(["blue", "cyan", "green"][i])}"><animateMotion dur="3s" begin="${i * 1}s" repeatCount="indefinite" path="M20 45H200"/></rect><text x="-4" y="4" font-size="8" fill="var(--txt)"><animateMotion dur="3s" begin="${i * 1}s" repeatCount="indefinite" path="M20 45H200"/>${i + 1}</text></g>`).join("")}
    </svg>`,

  osi: `<svg viewBox="0 0 220 96">${["Uygulama", "Sunum", "Oturum", "Taşıma", "Ağ", "Veri Bağı", "Fiziksel"]
    .map(
      (l, i) => `<rect x="30" y="${i * 13}" width="160" height="11" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="4.9s" begin="${i * 0.4}s" repeatCount="indefinite"/></rect><text x="34" y="${i * 13 + 9}" font-size="7" fill="var(--txt-2)">${l}</text>`,
    )
    .join("")}</svg>`,

  subnet: `<svg viewBox="0 0 220 60"><text x="10" y="14" font-size="8" fill="var(--txt)">192.168.1.0/24</text>
    <rect x="10" y="24" width="150" height="16" fill="${_c("purple")}" fill-opacity="0.35" stroke="${_c("purple")}"/>
    <rect x="160" y="24" width="50" height="16" fill="var(--panel-2)" stroke="var(--line)"/>
    <text x="55" y="35" font-size="7" fill="var(--txt)">network (21 bit)</text><text x="167" y="35" font-size="7" fill="var(--txt-2)">host</text>
    <rect x="10" y="24" width="4" height="16" fill="${_c("cyan")}"><animate attributeName="x" values="10;206;10" dur="4s" repeatCount="indefinite"/></rect></svg>`,

  routersw: `<svg viewBox="0 0 220 80"><text x="14" y="14" font-size="8" fill="var(--txt-2)">Router — farklı ağları bağlar</text>
    <circle cx="30" cy="40" r="10" fill="none" stroke="${_c("green")}"/><circle cx="80" cy="40" r="10" fill="none" stroke="${_c("green")}"/>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.8s" repeatCount="indefinite" path="M30 40 40 40"/></circle>
    <text x="120" y="14" font-size="8" fill="var(--txt-2)">Switch — aynı ağı bağlar</text>
    <rect x="130" y="35" width="70" height="10" fill="none" stroke="${_c("cyan")}"/>
    ${[0, 1, 2].map((i) => `<circle cx="${140 + i * 25}" cy="55" r="4" fill="none" stroke="${_c("cyan")}"/><line x1="${140 + i * 25}" y1="45" x2="${140 + i * 25}" y2="51" stroke="${_c("cyan")}"><animate attributeName="stroke-opacity" values="0.2;1;0.2" dur="1.5s" begin="${i * 0.3}s" repeatCount="indefinite"/></line>`).join("")}</svg>`,

  tcpudp: `<svg viewBox="0 0 220 70"><text x="6" y="12" font-size="8" fill="var(--txt-2)">TCP (sıralı)</text><path d="M10 24H210" stroke="var(--line)"/>
    ${[0, 1, 2].map((i) => `<circle r="3" fill="${_c("blue")}"><animateMotion dur="2.4s" begin="${i * 0.8}s" repeatCount="indefinite" path="M10 24H210"/></circle>`).join("")}
    <text x="6" y="48" font-size="8" fill="var(--txt-2)">UDP (hızlı, garantisiz)</text><path d="M10 60H210" stroke="var(--line)"/>
    ${[0, 1, 2, 3, 4].map((i) => `<circle r="2.5" fill="${_c("orange")}" fill-opacity="${i === 2 ? 0.25 : 1}"><animateMotion dur="1.1s" begin="${i * 0.22}s" repeatCount="indefinite" path="M10 60H210"/></circle>`).join("")}</svg>`,

  http: `<svg viewBox="0 0 220 70"><rect x="40" y="22" width="140" height="24" rx="12" fill="none" stroke="${_c("cyan")}"/>
    <text x="52" y="38" font-size="9" fill="var(--txt)">https://site.com</text>
    <path d="M154 22v-6a6 6 0 0 1 12 0v6" fill="none" stroke="${_c("green")}" stroke-width="2"><animate attributeName="stroke" values="${_c("green")};var(--red);${_c("green")}" dur="3s" repeatCount="indefinite"/></path>
    <rect x="152" y="22" width="16" height="12" rx="2" fill="${_c("green")}"><animate attributeName="fill" values="var(--green);var(--red);var(--green)" dur="3s" repeatCount="indefinite"/></rect></svg>`,

  tls: `<svg viewBox="0 0 220 80"><rect x="10" y="30" width="40" height="20" rx="4" fill="none" stroke="${_c("blue")}"/><text x="16" y="44" font-size="8" fill="var(--txt)">Client</text>
    <rect x="170" y="30" width="40" height="20" rx="4" fill="none" stroke="${_c("green")}"/><text x="176" y="44" font-size="8" fill="var(--txt)">Server</text>
    <path d="M50 34 L170 24" stroke="${_c("orange")}" stroke-dasharray="4 3"><animate attributeName="stroke-dashoffset" values="0;-14" dur="1.4s" repeatCount="indefinite"/></path>
    <path d="M170 46 L50 56" stroke="${_c("cyan")}" stroke-dasharray="4 3"><animate attributeName="stroke-dashoffset" values="0;-14" dur="1.4s" repeatCount="indefinite"/></path>
    <text x="80" y="18" font-size="7" fill="var(--txt-3)">hello / cert → şifreli kanal</text></svg>`,

  firewall: `<svg viewBox="0 0 220 80">${Array.from({ length: 9 }).map((_, i) => {
    const x = 60 + (i % 3) * 22, y = 15 + Math.floor(i / 3) * 22, blocked = i === 4;
    return `<rect x="${x}" y="${y}" width="16" height="16" fill="none" stroke="${blocked ? "var(--red)" : _c("green")}"><animate attributeName="stroke-opacity" values="1;0.3;1" dur="${blocked ? 1 : 2.4}s" repeatCount="indefinite" begin="${i * 0.1}s"/></rect>`;
  }).join("")}
    <text x="6" y="45" font-size="8" fill="var(--txt-2)">:443 ✓</text><text x="6" y="65" font-size="8" fill="var(--red)">:23 ✕</text></svg>`,

  vpn: `<svg viewBox="0 0 220 80"><rect x="8" y="30" width="34" height="22" rx="3" fill="none" stroke="${_c("blue")}"/><text x="10" y="44" font-size="7" fill="var(--txt)">PC</text>
    <path d="M42 40 C90 15 130 65 180 40" fill="none" stroke="${_c("green")}" stroke-width="2" stroke-dasharray="6 4"><animate attributeName="stroke-dashoffset" values="0;-20" dur="1.2s" repeatCount="indefinite"/></path>
    <circle cx="196" cy="40" r="20" fill="none" stroke="${_c("green")}"/><text x="186" y="44" font-size="7" fill="var(--txt)">🔒</text></svg>`,
};

function diagramFor(key) {
  return DIAGRAMS[key] || "";
}

/* ---------- CANLI DHCP DORA SİMÜLATÖRÜ ---------- */
let _dhcpSimTimer = null;
let _dhcpSimStep = 0;

function startDhcpSimulation() {
  if (_dhcpSimTimer) clearInterval(_dhcpSimTimer);
  _dhcpSimStep = 0;
  
  const steps = [
    { name: "DISCOVER", color: "#22d3ee", msg: "Aşama 1/4: DHCP DISCOVER — İstemci ağa 'DHCP Sunucusu Var mı?' yayını (broadcast) gönderiyor." },
    { name: "OFFER", color: "#f5a623", msg: "Aşama 2/4: DHCP OFFER — Sunucu teklif sunuyor: '192.168.1.100 IP adresini kullanabilirsin'." },
    { name: "REQUEST", color: "#3b9bff", msg: "Aşama 3/4: DHCP REQUEST — İstemci yanıt veriyor: '192.168.1.100 IP adresini kabul ediyorum'." },
    { name: "ACK", color: "#3ddc84", msg: "Aşama 4/4: DHCP ACK — Sunucu IP adresini istemciye başarıyla atadı ve onayladı!" }
  ];

  const packet = $("dhcpPacketAnim");
  const msgBox = $("dhcpSimMsg");
  const stepBadges = document.querySelectorAll(".dhcp-badge-step");

  function nextStep() {
    if (_dhcpSimStep >= steps.length) {
      clearInterval(_dhcpSimTimer);
      _dhcpSimTimer = null;
      if (packet) packet.style.opacity = "0";
      return;
    }

    const cur = steps[_dhcpSimStep];
    if (msgBox) {
      msgBox.style.display = "block";
      msgBox.style.borderColor = cur.color;
      msgBox.style.color = cur.color;
      msgBox.innerHTML = `<strong>[${cur.name}]</strong> ${cur.msg}`;
    }

    stepBadges.forEach((b, idx) => {
      if (idx === _dhcpSimStep) {
        b.style.background = cur.color;
        b.style.color = "#000";
        b.style.fontWeight = "bold";
        b.style.transform = "scale(1.1)";
      } else {
        b.style.background = "var(--panel-2)";
        b.style.color = "var(--txt-2)";
        b.style.transform = "scale(1)";
      }
    });

    if (packet) {
      packet.style.opacity = "1";
      packet.style.background = cur.color;
      if (_dhcpSimStep === 0 || _dhcpSimStep === 2) {
        packet.style.left = "20%";
        setTimeout(() => { if (packet) packet.style.left = "80%"; }, 50);
      } else {
        packet.style.left = "80%";
        setTimeout(() => { if (packet) packet.style.left = "20%"; }, 50);
      }
    }

    _dhcpSimStep++;
  }

  nextStep();
  _dhcpSimTimer = setInterval(nextStep, 2200);
}

/* ---------- SUBNET HESAPLAYICI ---------- */
function calculateSubnetCalc() {
  const ipStr = ($("subCalcIp")?.value || "").trim();
  let maskInput = ($("subCalcMask")?.value || "").trim();
  const resBox = $("subCalcResult");
  if (!resBox) return;

  if (!ipStr) {
    resBox.innerHTML = `<span style="color:var(--red)">Lütfen geçerli bir IP adresi girin.</span>`;
    return;
  }

  let cidr = 24;
  if (maskInput.startsWith("/")) {
    cidr = parseInt(maskInput.slice(1), 10);
  } else if (!isNaN(parseInt(maskInput, 10)) && parseInt(maskInput, 10) <= 32) {
    cidr = parseInt(maskInput, 10);
  } else if (maskInput.includes(".")) {
    const parts = maskInput.split(".").map(Number);
    const bin = parts.map(p => p.toString(2).padStart(8, '0')).join('');
    cidr = bin.indexOf('0') === -1 ? 32 : bin.indexOf('0');
  }

  if (isNaN(cidr) || cidr < 0 || cidr > 32) cidr = 24;

  try {
    const ipParts = ipStr.split(".").map(Number);
    if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) {
      throw new Error("Geçersiz IP formatı");
    }

    const ipNum = ((ipParts[0] << 24) >>> 0) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const maskNum = cidr === 0 ? 0 : ((0xFFFFFFFF << (32 - cidr)) >>> 0);
    const netNum = (ipNum & maskNum) >>> 0;
    const bcastNum = (netNum | (~maskNum >>> 0)) >>> 0;

    const numToIp = (num) => [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join(".");

    const maskStr = numToIp(maskNum);
    const netStr = numToIp(netNum);
    const bcastStr = numToIp(bcastNum);
    const firstUsableStr = cidr >= 31 ? netStr : numToIp(netNum + 1);
    const lastUsableStr = cidr >= 31 ? bcastStr : numToIp(bcastNum - 1);
    const usableHosts = cidr >= 31 ? (cidr === 31 ? 2 : 1) : Math.max(0, (2 ** (32 - cidr)) - 2);

    resBox.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:10px;margin-top:10px">
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Ağ Adresi (Network ID)</span><br/><strong style="color:var(--blue)">${netStr} /${cidr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Alt Ağ Maskesi (Subnet Mask)</span><br/><strong>${maskStr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Yayın Adresi (Broadcast)</span><br/><strong style="color:var(--orange)">${bcastStr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Kullanılabilir IP Aralığı</span><br/><strong style="color:var(--green)">${firstUsableStr} — ${lastUsableStr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Toplam Kullanılabilir Host</span><br/><strong style="color:var(--purple)">${usableHosts.toLocaleString()} cihaz</strong></div>
      </div>
    `;
  } catch (err) {
    resBox.innerHTML = `<span style="color:var(--red)">Hata: ${esc(err.message)}</span>`;
  }
}

const EGITIM_KISALTMALAR_CATEGORIZED = [
  {
    cat: "Basic Networking Terms (Temel Ağ Terimleri)",
    items: [
      ["IP", "Internet Protocol — Ağdaki cihazları adresleyen protokol"],
      ["MAC", "Media Access Control — Donanım kartının fiziksel adresi"],
      ["LAN", "Local Area Network — Yerel alan ağı (Ev/Ofis)"],
      ["WAN", "Wide Area Network — Geniş alan ağı (İnternet)"]
    ]
  },
  {
    cat: "Internet & Communication (İnternet ve İletişim)",
    items: [
      ["DNS", "Domain Name System — Alan adlarını IP adreslerine dönüştürür"],
      ["DHCP", "Dynamic Host Configuration Protocol — Otomatik IP atama servisi"],
      ["HTTP", "HyperText Transfer Protocol — Web içerik aktarım protokolü"],
      ["HTTPS", "HyperText Transfer Protocol Secure — Şifreli web protokolü"],
      ["FTP", "File Transfer Protocol — Dosya aktarım protokolü"]
    ]
  },
  {
    cat: "Security & Protection (Güvenlik ve Koruma)",
    items: [
      ["VPN", "Virtual Private Network — Şifreli özel sanal ağ tüneli"],
      ["SSL", "Secure Sockets Layer — Güvenli soket katmanı şifrelemesi"],
      ["TLS", "Transport Layer Security — Modern taşıma katmanı şifrelemesi"],
      ["IDS", "Intrusion Detection System — Saldırı tespit sistemi"],
      ["IPS", "Intrusion Prevention System — Saldırı önleme sistemi"]
    ]
  },
  {
    cat: "Routing & Switching (Yönlendirme ve Anahtarlama)",
    items: [
      ["TCP", "Transmission Control Protocol — Güvenilir bağlantılı iletim"],
      ["UDP", "User Datagram Protocol — Hızlı bağlantısız iletim"],
      ["ARP", "Address Resolution Protocol — IP adresini MAC adresine çözer"],
      ["VLAN", "Virtual Local Area Network — Mantıksal sanal yerel ağ"],
      ["NAT", "Network Address Translation — Özel IP'leri Genel IP'ye dönüştürür"]
    ]
  },
  {
    cat: "Advanced Concepts (Gelişmiş Konseptler)",
    items: [
      ["QoS", "Quality of Service — Ağ trafiği önceliklendirme kalitesi"],
      ["BGP", "Border Gateway Protocol — İnternet omurgaları arası yönlendirme"],
      ["OSPF", "Open Shortest Path First — En kısa yol odaklı iç yönlendirme"],
      ["MPLS", "Multiprotocol Label Switching — Etiket tabanlı hızlı yönlendirme"]
    ]
  }
];

function filterAbbreviations() {
  const q = ($("abbrSearchInput")?.value || "").toLowerCase().trim();
  const container = $("abbrGridContainer");
  if (!container) return;

  container.innerHTML = EGITIM_KISALTMALAR_CATEGORIZED.map(cat => {
    const filtered = cat.items.filter(item => !q || item[0].toLowerCase().includes(q) || item[1].toLowerCase().includes(q));
    if (!filtered.length) return "";
    return `
      <div style="margin-bottom:14px">
        <h4 style="color:var(--blue);margin:0 0 8px;font-size:12px">${esc(cat.cat)}</h4>
        <div class="kisaltma-grid">
          ${filtered.map(k => `<div class="kisaltma-item"><b>${esc(k[0])}</b><span class="hint">${esc(k[1])}</span></div>`).join("")}
        </div>
      </div>
    `;
  }).join("");
}

const EGITIM_KISALTMALAR = [
  ["IP", "Internet Protocol"], ["MAC", "Media Access Control"], ["LAN", "Local Area Network"], ["WAN", "Wide Area Network"],
  ["DNS", "Domain Name System"], ["DHCP", "Dynamic Host Configuration Protocol"], ["HTTP", "HyperText Transfer Protocol"], ["HTTPS", "HTTP Secure"], ["FTP", "File Transfer Protocol"],
  ["VPN", "Virtual Private Network"], ["SSL", "Secure Sockets Layer"], ["TLS", "Transport Layer Security"], ["IDS", "Intrusion Detection System"], ["IPS", "Intrusion Prevention System"],
  ["TCP", "Transmission Control Protocol"], ["UDP", "User Datagram Protocol"], ["ARP", "Address Resolution Protocol"], ["VLAN", "Virtual Local Area Network"], ["NAT", "Network Address Translation"],
  ["QoS", "Quality of Service"], ["BGP", "Border Gateway Protocol"], ["OSPF", "Open Shortest Path First"], ["MPLS", "Multiprotocol Label Switching"],
];

const EGITIM_KOMUTLAR = [
  ["ipconfig / ifconfig", "Ağ arayüzü yapılandırmasını gösterir"],
  ["ipconfig /all", "Ayrıntılı IP, MAC ve DNS bilgisini gösterir"],
  ["ping [hedef]", "Bir sunucuya erişilebilirliği test eder"],
  ["tracert / traceroute", "Hedefe giden rota üzerindeki her sıçramayı listeler"],
  ["nslookup [alan adı]", "Bir alan adının DNS kaydını sorgular"],
  ["netstat -an", "Aktif bağlantıları ve dinleyen portları listeler"],
  ["arp -a", "Yerel ARP önbelleğini (IP-MAC eşlemesi) gösterir"],
  ["hostname", "Bilgisayarın ağ üzerindeki adını gösterir"],
  ["netsh", "Windows'ta ağ ayarlarını yapılandırır"],
];

const DHCP_ADIMLAR = [
  { k: "DISCOVER", a: "İstemci ağda \"bana bir IP lazım\" diye yayın yapar." },
  { k: "OFFER", a: "DHCP sunucusu uygun bir IP adresi teklif eder." },
  { k: "REQUEST", a: "İstemci teklif edilen IP'yi resmen talep eder." },
  { k: "ACK", a: "Sunucu onaylar; IP artık istemciye atanmıştır." },
];

/* ---------- DETAYLI İNTERNETE BAĞLANMA SİMÜLASYONU ---------- */
let _inetSimTimer = null;
let _inetSimStep = 0;

const INET_SIM_STEPS = [
  {
    step: 1,
    title: "1. Adım: Fiziksel Bağlantı & DHCP ile IP Alma",
    from: "CLIENT (192.168.1.42)",
    to: "ROUTER (192.168.1.1)",
    packetColor: "#22d3ee",
    packetPos: "25%",
    desc: "Bilgisayar yerel ağa bağlandığında DHCP sunucusundan kendi IP adresini (192.168.1.42), ağ geçidini (192.168.1.1) ve DNS sunucularını (8.8.8.8) alır.",
    header: "DHCP DISCOVER / OFFER / REQUEST / ACK — UDP Port 67/68"
  },
  {
    step: 2,
    title: "2. Adım: ARP ile Router MAC Adresini Öğrenme",
    from: "CLIENT",
    to: "ROUTER MAC",
    packetColor: "#a855f7",
    packetPos: "50%",
    desc: "İstemci 'google.com IP'sine paket göndereceğim ama gateway'in MAC adresini bilmeliyim' der. Yerel ağa 'Who has 192.168.1.1?' ARP isteği yayınlar ve router MAC adresini (00:1A:2B:3C:4D:5E) öğrenir.",
    header: "ARP Request / Reply — Ethernet Frame L2 Broadcast"
  },
  {
    step: 3,
    title: "3. Adım: DNS Sorgusu (Domain Name System)",
    from: "ROUTER",
    to: "DNS SUNUCUSU (8.8.8.8)",
    packetColor: "#f5a623",
    packetPos: "75%",
    desc: "İstemci DNS sunucusuna 'google.com adresi hangi IP?' diye sorar. DNS sunucusu yanıt verir: 142.250.187.14.",
    header: "DNS Query — A Record google.com ➔ 142.250.187.14 (UDP Port 53)"
  },
  {
    step: 4,
    title: "4. Adım: TCP 3-Way Handshake (Üçlü El Sıkışma)",
    from: "CLIENT",
    to: "WEB SUNUCUSU (142.250.187.14:443)",
    packetColor: "#3b9bff",
    packetPos: "85%",
    desc: "Google sunucusuyla güvenilir taşıma katmanı bağlantısı kurulur: 1) SYN ➔ 2) SYN-ACK ➔ 3) ACK. Sıra numaraları senkronize edilir.",
    header: "TCP Flag: SYN ➔ SYN+ACK ➔ ACK (Port 443)"
  },
  {
    step: 5,
    title: "5. Adım: TLS / SSL Güvenlik El Sıkışması",
    from: "CLIENT",
    to: "GOOGLE SSL SERVER",
    packetColor: "#a855f7",
    packetPos: "92%",
    desc: "İstemci 'Client Hello' gönderir, sunucu SSL sertifikasını sunar. Şifreleme algoritmaları (AES-256-GCM) ve simetrik oturum anahtarları oluşturulur. Artık tüm trafik şifrelidir!",
    header: "TLS 1.3 Handshake — Cipher Suite: TLS_AES_256_GCM_SHA384"
  },
  {
    step: 6,
    title: "6. Adım: Şifreli HTTP GET İsteği & Web Sayfası Yükleme",
    from: "GOOGLE SUNUCUSU",
    to: "CLIENT (200 OK)",
    packetColor: "#3ddc84",
    packetPos: "100%",
    desc: "İstemci şifreli tünelden 'GET / HTTP/2' isteği gönderir. Google sunucusu HTML/CSS/JS web verilerini 'HTTP/2 200 OK' yanıtıyla iletir ve sayfa ekranda görüntülenir!",
    header: "HTTP/2 200 OK — Content-Type: text/html; charset=UTF-8"
  }
];

function startInternetConnectionSim() {
  if (_inetSimTimer) clearInterval(_inetSimTimer);
  _inetSimStep = 0;

  const packet = $("inetPacketAnim");
  const msgBox = $("inetSimMsg");
  const stepBadges = document.querySelectorAll(".inet-badge-step");

  function nextStep() {
    if (_inetSimStep >= INET_SIM_STEPS.length) {
      clearInterval(_inetSimTimer);
      _inetSimTimer = null;
      if (packet) packet.style.opacity = "0";
      return;
    }

    const cur = INET_SIM_STEPS[_inetSimStep];
    if (msgBox) {
      msgBox.style.display = "block";
      msgBox.style.borderColor = cur.packetColor;
      msgBox.innerHTML = `
        <div style="color:${cur.packetColor};font-weight:bold;font-size:13px;margin-bottom:4px">${esc(cur.title)}</div>
        <div style="font-size:11.5px;color:var(--txt);margin-bottom:6px">${esc(cur.desc)}</div>
        <div style="font-family:Consolas, monospace;font-size:10.5px;color:var(--muted);background:rgba(0,0,0,0.3);padding:4px 8px;border-radius:4px">📦 Başlık Bilgisi: ${esc(cur.header)}</div>
      `;
    }

    stepBadges.forEach((b, idx) => {
      if (idx === _inetSimStep) {
        b.style.background = cur.packetColor;
        b.style.color = "#000";
        b.style.fontWeight = "bold";
        b.style.transform = "scale(1.08)";
      } else {
        b.style.background = "var(--panel-2)";
        b.style.color = "var(--txt-2)";
        b.style.transform = "scale(1)";
      }
    });

    if (packet) {
      packet.style.opacity = "1";
      packet.style.background = cur.packetColor;
      packet.style.left = cur.packetPos;
    }

    _inetSimStep++;
  }

  nextStep();
  _inetSimTimer = setInterval(nextStep, 2600);
}

/* ---------- ETKİLEŞİMLİ KAVRAM MODALİ (CLICK TO ENLARGE) ---------- */
const CONCEPT_DETAILS = {
  ip: {
    title: "IP Adresi (Internet Protocol)",
    sub: "Ağ Katmanı (Katman 3)",
    desc: "IP adresi, ağa bağlı her cihaza atanan mantıksal numaradır. Veri paketlerinin kaynak ve hedef arasında yönlendirilmesini sağlar.",
    example: "Örnek: Evinizdeki bilgisayarın yerel IP'si 192.168.1.45 iken, internetteki genel IP'niz 185.12.34.56 olabilir.",
    details: ["IPv4: 32-bit (örn. 192.168.1.1) — yaklaşık 4.3 milyar adres kapasitesi.", "IPv6: 128-bit (örn. 2001:0db8:85a3::8a2e:0370:7334) — neredeyse sınırsız adres kapasitesi."]
  },
  dns: {
    title: "DNS (Domain Name System)",
    sub: "Uygulama Katmanı (Katman 7)",
    desc: "İnsanların hatırlayabileceği alan adlarını (örn. google.com) bilgisayarların anladığı IP adreslerine (142.250.187.14) çeviren küresel yönlendirme sistemidir.",
    example: "Örnek: Tarayıcıya 'google.com' yazdığınızda, işletim sisteminiz öncelikle DNS sunucusuna sorgu atarak doğru IP adresini öğrenir.",
    details: ["Önbellekleme: Sık ziyaret edilen siteler bilgisayarınızda önbelleğe alınır.", "Sorgu Tipleri: A Record (IPv4), AAAA Record (IPv6), CNAME (Alias), MX (Mail)."]
  },
  port: {
    title: "Port (Bağlantı Noktası)",
    sub: "Taşıma Katmanı (Katman 4)",
    desc: "Aynı IP adresi üzerinde çalışan farklı uygulamaları ve servisleri ayırt etmeye yarayan 0-65535 arasındaki sanal kanallardır.",
    example: "Örnek: Aynı sunucuda Web sitesi Port 80/443'te, E-posta Port 25'te, SSH erişimi Port 22'de çalışır.",
    details: ["Tanınmış Portlar (0-1023): HTTP(80), HTTPS(443), SSH(22), DNS(53).", "Kayıtlı Portlar (1024-49151): MySQL(3306), RDP(3389)."]
  },
  mac: {
    title: "MAC Adresi (Media Access Control)",
    sub: "Veri Bağlantı Katmanı (Katman 2)",
    desc: "Ağ kartına (NIC) üretim aşamasında kazınan 48-bitlik eşsiz fiziksel adrestir.",
    example: "Örnek: 00:1A:2B:3C:4D:5E — İlk 3 blok (00:1A:2B) üretici firmayı (OUI/Vendor) gösterir.",
    details: ["Fiziksel İletim: Aynı yerel ağ (LAN) içindeki paketler IP değil MAC adresiyle teslim edilir.", "Değiştirilemezlik: IP adresi değişse bile MAC adresi sabit kalır."]
  },
  nat: {
    title: "NAT (Network Address Translation)",
    sub: "Ağ / Router Katmanı",
    desc: "Evinizdeki onlarca cihazın tek bir genel (Public) IP adresi arkasından internete çıkmasını sağlayan adrese çevirme teknolojisidir.",
    example: "Örnek: 192.168.1.10 ve 192.168.1.20 cihazları internete çıkarken modem hepsini tek bir Kamu IP'sine (85.100.1.2) dönüştürür.",
    details: ["PAT (Port Address Translation): Her yerel istemcinin bağlantısını farklı bir dış kaynak portu ile eşleştirir.", "IPv4 Tasarrufu: Dünyadaki IP adresi tükenmesini önleyen en kritik teknolojidir."]
  },
  dhcp: {
    title: "DHCP (Dynamic Host Configuration Protocol)",
    sub: "Uygulama / Yönetim Katmanı",
    desc: "Ağa yeni katılan cihazlara otomatik olarak IP Adresi, Alt Ağ Maskesi, Gateway ve DNS bilgilerini kiralayan servistir.",
    example: "Örnek: Telefonunuzla Wi-Fi'ya bağlandığınız an DHCP sunucusu 192.168.1.105 IP'sini cihazınıza kiralar.",
    details: ["DORA Akışı: Discover ➔ Offer ➔ Request ➔ Acknowledge.", "Kira Süresi (Lease Time): Belirlenen süre sonunda cihaz IP'yi yeniler."]
  },
  packets: {
    title: "Ağ Paketleri (Packets)",
    sub: "Veri İletim Yapısı",
    desc: "İnternet üzerindeki veriler tek parça halinde değil, küçük paketlere bölünerek iletilir. Her pakette Başlık (Header) ve Veri (Payload) bulunur.",
    example: "Örnek: 10 MB'lık bir fotoğraf dosyası ağda yaklaşık 7,000 küçük veri paketine bölünerek hedefe aktarılır.",
    details: ["Header İçeriği: Kaynak IP, Hedef IP, Port Numaraları, Sıra No.", "Yeniden Birleştirme: Hedef cihaz gelen paketleri sıra numarasına göre doğru sırada birleştirir."]
  },
  osi: {
    title: "OSI Modeli (Open Systems Interconnection)",
    sub: "7 Katmanlı Referans Mimarisi",
    desc: "Ağ iletişimini 7 standart katmana bölen kavramsal modeldir: 7.Uygulama, 6.Sunum, 5.Oturum, 4.Taşıma, 3.Ağ, 2.Veri Bağlantı, 1.Fiziksel.",
    example: "Örnek: Web tarayıcısı Katman 7'de çalışırken, ağ kablosu ve elektrik sinyalleri Katman 1'dedir.",
    details: ["Kapsülleme (Encapsulation): Üst katmandan gelen veri alt katmanlara indikçe yeni başlıklar (headers) eklenir.", "Katman Ayrımı: Her katman yalnızca bir altındaki ve üstündeki katmanla iletişim kurar."]
  },
  subnet: {
    title: "Subnetting & CIDR",
    sub: "Alt Ağ Yönetimi",
    desc: "Büyük bir IP ağını mantıksal parçalara bölme işlemidir. CIDR gösterimi (/24 gibi) ağın kaç IP içerdiğini belirtir.",
    example: "Örnek: /24 ağı (255.255.255.0) toplam 256 IP içerir; 254 cihaz kullanılabilir.",
    details: ["Network ID: Ağın ilk adresidir.", "Broadcast ID: Ağın tüm cihazlara yayın yapan son adresidir."]
  },
  routersw: {
    title: "Router vs Switch",
    sub: "Ağ Donanımları",
    desc: "Switch aynı yerel ağdaki (LAN) cihazları birbirine bağlar. Router ise farklı ağları (LAN ➔ WAN / İnternet) birbirine bağlar ve yönlendirir.",
    example: "Örnek: Odadaki bilgisayarlar Switch'e bağlanır; Switch de internete çıkmak için Router'a bağlanır.",
    details: ["Switch (L2): MAC adresleri tablosuna (CAM Table) bakarak anahtarlama yapar.", "Router (L3): IP yönlendirme tablosuna bakarak en uygun rotayı seçer."]
  },
  tcpudp: {
    title: "TCP vs UDP",
    sub: "Taşıma Katmanı (Katman 4)",
    desc: "TCP güvenilir, kontrollü ve sıralı iletim sağlar. UDP ise onay beklemeden çok hızlı veri aktarır.",
    example: "Örnek: Web siteleri ve dosya indirme TCP kullanırken; canlı yayınlar ve online oyunlar UDP kullanır.",
    details: ["TCP: 3-Way Handshake, Kayıp Paket Yeniden Gönderimi, Akış Kontrolü.", "UDP: Düşük gecikme, Başlık boyutu küçük (8 byte vs TCP 20 byte)."]
  },
  http: {
    title: "HTTP / HTTPS",
    sub: "Web Protokolü",
    desc: "HTTP web içeriklerini aktarır. HTTPS ise bu trafiği TLS/SSL şifrelemesi ile koruma altına alır.",
    example: "Örnek: HTTPS kullanıldığında aradaki bir hacker şifrenizi veya kredi kartı bilginizi okuyamaz.",
    details: ["HTTP Portu: 80 (Düz metin / Açık).", "HTTPS Portu: 443 (Şifreli / Güvenli)."]
  },
  tls: {
    title: "TLS / SSL Şifreleme",
    sub: "Güvenli İletişim Katmanı",
    desc: "İstemci ile sunucu arasında el sıkışma yaparak verileri simetrik şifreleme (AES) ile koruyan protokoldür.",
    example: "Örnek: Banka sitelerinde tarayıcıda görünen yeşil kilit simgesi TLS el sıkışmasının başarılı olduğunu gösterir.",
    details: ["Sertifika Doğrulama: Sunucunun kimliği dijital sertifika ile doğrulanır.", "Asimetrik ➔ Simetrik: Anahtar değişimi asimetrik (RSA/ECC), veri iletimi simetrik (AES) yapılır."]
  },
  firewall: {
    title: "Firewall (Güvenlik Duvarı)",
    sub: "Ağ Güvenlik Sistemi",
    desc: "Belirlenen güvenlik kurallarına göre ağ trafiğini denetleyen, yetkisiz erişimleri engelleyen sistemdir.",
    example: "Örnek: Port 23 (Telnet) ve Port 21 (FTP) dış dünyadan gelen isteklere otomatik engellenir.",
    details: ["Packet Filtering: IP, Port ve Protokol bazlı engelleme.", "Stateful Inspection: Bağlantının durumunu takip ederek karar verme."]
  },
  vpn: {
    title: "VPN (Virtual Private Network)",
    sub: "Sanal Özel Ağ Tüneli",
    desc: "İnternet üzerinde uçtan uca şifreli uç nokta tüneli oluşturarak güvenli uzaktan erişim sağlar.",
    example: "Örnek: Evden çalışırken şirket içi sunuculara sanki ofisteymiş gibi güvenle bağlanmanızı sağlar.",
    details: ["Tünelleme Protokolleri: OpenVPN, WireGuard, IPsec.", "Gizlilik: İSS veya yetkisiz 3. kişilerin trafiğinizi izlemesini engeller."]
  }
};

function openConceptModal(key) {
  const c = CONCEPT_DETAILS[key] || CONCEPT_DETAILS.ip;
  const diagramSvg = diagramFor(key);

  openModal(`
    <div style="text-align:center;margin-bottom:14px">
      <div style="background:var(--panel-2);border:1px solid var(--line);border-radius:12px;padding:16px;display:inline-block;margin-bottom:10px">
        <div style="width:280px;height:120px;display:grid;place-items:center">${diagramSvg}</div>
      </div>
      <h2 style="margin:4px 0;font-size:18px">${esc(c.title)}</h2>
      <span class="badge info">${esc(c.sub)}</span>
    </div>

    <div style="background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:12px;margin-bottom:12px;font-size:12px;line-height:1.5">
      ${esc(c.desc)}
    </div>

    <div style="background:rgba(61,220,132,0.08);border:1px solid rgba(61,220,132,0.25);border-radius:10px;padding:10px 12px;margin-bottom:12px;font-size:11.5px;color:var(--green)">
      💡 <strong>Gerçek Hayat Örneği:</strong> ${esc(c.example)}
    </div>

    <div style="border-top:1px solid var(--line);padding-top:10px">
      <b style="font-size:11px;color:var(--muted);display:block;margin-bottom:6px">TEKNİK DETAYLAR & STANDARTLAR</b>
      ${c.details.map(d => `<div style="font-size:11px;color:var(--txt-2);margin-bottom:4px">✓ ${esc(d)}</div>`).join("")}
    </div>

    <div style="display:flex;justify-content:flex-end;margin-top:16px">
      <button class="mini-btn blue" onclick="closeModalForce()">Kapat</button>
    </div>
  `);
}

async function openAcademyQuiz(moduleId) {
  try {
    const data = await get(`/api/academy/modules/${encodeURIComponent(moduleId)}`);
    const q = data.quiz;
    openModal(`
      <div class="modal-head"><h3>${esc(data.title)} — Mini Quiz</h3><button class="modal-close" onclick="closeModalForce()">×</button></div>
      <div class="modal-body">
        <div class="device-learning" style="margin-bottom:12px"><b>${esc(q.question)}</b></div>
        <div id="academyQuizOptions" style="display:grid;gap:8px">
          ${q.options.map((opt,i)=>`<button class="mini-btn" style="text-align:left;padding:10px" onclick="submitAcademyQuiz('${esc(moduleId)}',${i},this)">${String.fromCharCode(65+i)}. ${esc(opt)}</button>`).join("")}
        </div>
        <div id="academyQuizResult" style="margin-top:12px"></div>
      </div>
    `);
  } catch (e) { toast(e.message || "Quiz yüklenemedi", "error"); }
}

async function submitAcademyQuiz(moduleId, answer, btn) {
  try {
    const result = await post("/api/academy/quiz", {module_id: moduleId, answer});
    document.querySelectorAll("#academyQuizOptions button").forEach(b => b.disabled = true);
    const box = $("academyQuizResult");
    if (box) box.innerHTML = `<div class="device-learning ${result.correct ? "success" : "warning"}"><b>${result.correct ? "✓ Doğru" : "✗ Tekrar dene"}</b><div>${esc(result.message)}</div></div>`;
    if (result.correct) {
      const done = JSON.parse(localStorage.getItem("netmon_academy_done") || "[]");
      if (!done.includes(moduleId)) { done.push(moduleId); localStorage.setItem("netmon_academy_done", JSON.stringify(done)); }
    }
  } catch (e) { toast(e.message || "Cevap gönderilemedi", "error"); }
}

function renderEgitimPage() {
  const el = $("page-egitim");
  if (el.dataset.built) return;
  el.dataset.built = "1";
  el.innerHTML = `
    <div class="panel">
      <div class="panel-head" style="justify-content:center;border-bottom:none;padding-bottom:0">
        <h2 style="font-size:24px;text-align:center"><span style="color:#fff">15 Must-Know</span> <span style="background:var(--green);color:#000;padding:2px 8px;border-radius:6px;font-weight:800">Networking Concepts</span></h2>
      </div>
      <div class="panel-body">
        <div class="egitim-grid" style="display:grid;grid-template-columns:repeat(auto-fill, minmax(240px, 1fr));gap:16px;">
          ${EGITIM_KAVRAMLAR.map(
            (k, index) => `
            <div class="egitim-card" onclick="openConceptModal('${k.key}')" style="cursor:pointer;background:#0d1117;border:1px solid #30363d;border-radius:12px;padding:16px;display:flex;flex-direction:column;align-items:center;transition:transform 0.2s" onmouseover="this.style.transform='translateY(-4px)'" onmouseout="this.style.transform='none'">
              <div style="color:var(--green);font-weight:800;font-size:15px;margin-bottom:12px;letter-spacing:0.5px">${index+1}. ${esc(k.ad)}</div>
              <div class="egitim-diagram" style="width:100%;height:100px;background:#010409;border:1px solid #21262d;border-radius:8px;display:flex;align-items:center;justify-content:center;overflow:hidden">${diagramFor(k.key)}</div>
              <div style="color:#8b949e;font-size:11.5px;text-align:center;margin-top:12px;line-height:1.4">${esc(k.ozet)}</div>
              
            </div>`
          ).join("")}
        </div>
      </div>
    </div>

    <!-- DETAYLI İNTERNETE BAĞLANMA SİMÜLASYONU -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
        <h2>Detaylı İnternete Bağlanma Akış Simülasyonu</h2>
        <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">
          <button class="mini-btn blue" onclick="startInternetConnectionSim()">🚀 İnternete Bağlanma Akışını Başlat</button>
        </div>
      </div>
      <div class="panel-body">
        <div style="position:relative;background:#060a12;border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:12px;overflow:hidden">
          <div style="display:flex;justify-content:space-between;align-items:center;position:relative;z-index:2;flex-wrap:wrap;gap:10px">
            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">💻</div>
              <strong style="font-size:11px">İstemci PC</strong>
              <div style="font-size:9.5px;color:var(--muted)">192.168.1.42</div>
            </div>

            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">🔀</div>
              <strong style="font-size:11px;color:var(--cyan)">Ev Router</strong>
              <div style="font-size:9.5px;color:var(--muted)">192.168.1.1</div>
            </div>

            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">🌐</div>
              <strong style="font-size:11px;color:var(--orange)">DNS Sunucu</strong>
              <div style="font-size:9.5px;color:var(--muted)">8.8.8.8</div>
            </div>

            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">🔒</div>
              <strong style="font-size:11px;color:var(--green)">Google Web</strong>
              <div style="font-size:9.5px;color:var(--muted)">142.250.187.14</div>
            </div>
          </div>

          <div style="position:relative;height:4px;background:var(--line);margin:18px 0 12px">
            <div id="inetPacketAnim" style="position:absolute;width:14px;height:14px;border-radius:50%;background:var(--blue);top:-5px;left:0%;opacity:0;transition:left 2.2s ease-in-out, opacity 0.3s;box-shadow:0 0 12px currentColor"></div>
          </div>

          <div style="display:flex;justify-content:space-between;gap:6px;margin-top:14px;flex-wrap:wrap">
            ${INET_SIM_STEPS.map(
              (s) => `<div class="inet-badge-step" style="flex:1;min-width:90px;text-align:center;padding:5px 6px;border-radius:6px;background:var(--panel-2);color:var(--txt-2);font-size:10px;border:1px solid var(--line);transition:all 0.3s">${s.step}. ${s.title.split(":")[0]}</div>`
            ).join("")}
          </div>

          <div id="inetSimMsg" style="display:none;margin-top:14px;padding:12px;border-radius:8px;background:rgba(255,255,255,0.02);border:1px solid var(--line);"></div>
        </div>
      </div>
    </div>

    <!-- CANLI DHCP DORA SİMÜLATÖRÜ -->
    <div class="panel" style="margin-top:20px;background:#060a12;border:none">
      <div class="panel-body" style="padding:40px 20px;display:flex;flex-direction:column;align-items:center">
        
        <div style="text-align:left;width:100%;max-width:700px;margin-bottom:30px">
           <h1 style="color:#fff;font-size:20px;letter-spacing:1px;margin:0">DHCP &mdash; LIVE ANIMATED EXAMPLE</h1>
           <div id="dhcpSimSubtitle" style="color:var(--blue);font-size:12px;font-weight:bold;margin-top:6px">Step 1 of 4: DHCP DISCOVER</div>
        </div>

        <div style="display:flex;align-items:center;justify-content:center;width:100%;max-width:700px;position:relative">
           
           <!-- Client -->
           <div style="width:140px;height:140px;border:2px solid var(--blue);border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(59,155,255,0.05);z-index:2">
              <div style="font-size:40px;margin-bottom:10px">💻</div>
              <div style="color:var(--blue);font-weight:bold;font-size:11px;letter-spacing:0.5px">DHCP CLIENT</div>
           </div>

           <!-- Network Arrow Container -->
           <div style="flex:1;height:2px;background:var(--orange);margin:0 -2px;position:relative;display:flex;align-items:center;justify-content:center;z-index:1">
              <div style="position:absolute;width:120px;height:50px;border:1px solid #30363d;border-radius:50%;background:#0d1117;display:flex;align-items:center;justify-content:center;color:#8b949e;font-size:10px;font-weight:bold;letter-spacing:1px;z-index:2">NETWORK</div>
              <!-- Packet Dot -->
              <div id="dhcpPacketAnim" style="position:absolute;width:16px;height:16px;border-radius:50%;background:var(--orange);box-shadow:0 0 12px var(--orange);top:-7px;left:5%;opacity:0;transition:left 1.5s ease-in-out, opacity 0.2s;z-index:3"></div>
           </div>
           <div style="color:var(--orange);font-size:24px;margin-left:-15px;z-index:2;line-height:0;margin-top:-3px">▶</div>

           <!-- Server -->
           <div style="width:140px;height:140px;border:2px solid var(--green);border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(61,220,132,0.05);z-index:2;position:relative">
              <div style="font-size:40px;margin-bottom:10px">🗄️</div>
              <div style="color:var(--green);font-weight:bold;font-size:11px;letter-spacing:0.5px">DHCP SERVER</div>
              <div style="position:absolute;bottom:-10px;right:-10px;width:24px;height:24px;background:var(--green);color:#000;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:bold">25</div>
           </div>
        </div>

        <!-- Simulation Message -->
        <div id="dhcpSimMsg" style="color:#fff;font-size:14px;font-weight:bold;margin-top:30px;height:20px;text-align:center">Click a step below to animate</div>

        <!-- Buttons -->
        <div style="display:flex;gap:12px;margin-top:20px">
           <button class="mini-btn" style="background:#21262d;border:none;padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(1)">DISCOVER</button>
           <button class="mini-btn" style="background:#21262d;border:none;padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(2)">OFFER</button>
           <button class="mini-btn blue" style="padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(3)">REQUEST</button>
           <button class="mini-btn" style="background:#21262d;border:none;padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(4)">ACK</button>
        </div>
      </div>
    </div>

    <!-- SUBNETTING & CIDR HESAPLAYICI -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Subnetting & CIDR Hesaplayıcı</h2></div>
      <div class="panel-body">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <input type="text" id="subCalcIp" placeholder="IP Adresi (örn: 192.168.1.100)" value="192.168.1.100" style="flex:1;min-width:200px" />
          <input type="text" id="subCalcMask" placeholder="CIDR Prefix veya Maske (örn: /24 veya 255.255.255.0)" value="/24" style="width:220px" />
          <button class="mini-btn blue" onclick="calculateSubnetCalc()">Hesapla</button>
        </div>
        <div id="subCalcResult"></div>
      </div>
    </div>

    <!-- SIK KULLANILAN AĞ KOMUTLARI -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Sık Kullanılan Ağ Komutları</h2></div>
      <div class="panel-body" style="padding:0">
        <table>
          <thead><tr><th>Komut</th><th>Ne İşe Yarar</th></tr></thead>
          <tbody>
            ${EGITIM_KOMUTLAR.map((c) => `<tr><td><code>${esc(c[0])}</code></td><td>${esc(c[1])}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- KATEGORİK AĞ KISALTMALARI SÖZLÜĞÜ -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
        <h2>Ağ Kısaltmaları Sözlüğü</h2>
        <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">
          <input type="text" id="abbrSearchInput" placeholder="Kısaltma veya tanım ara..." oninput="filterAbbreviations()" style="padding:4px 8px;font-size:11px;width:180px" />
        </div>
      </div>
      <div class="panel-body" id="abbrGridContainer">
        ${EGITIM_KISALTMALAR_CATEGORIZED.map(cat => `
          <div style="margin-bottom:14px">
            <h4 style="color:var(--blue);margin:0 0 8px;font-size:12px">${esc(cat.cat)}</h4>
            <div class="kisaltma-grid">
              ${cat.items.map(k => `<div class="kisaltma-item"><b>${esc(k[0])}</b><span class="hint">${esc(k[1])}</span></div>`).join("")}
            </div>
          </div>
        `).join("")}
      </div>
    </div>
  `;

  setTimeout(calculateSubnetCalc, 100);
}

/* ---------- MOR TAKIM (XOC / SOC / NOC) MODÜLÜ ---------- */
let _purpleSimTimer = null;

function renderPurpleTeamPage() {
  const el = $("page-purpleteam");
  if (!el) return;
  if (el.dataset.built) return;
  el.dataset.built = "1";

  el.innerHTML = `
    <!-- HEADER & SKOR PANELERİ -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:12px;margin-bottom:14px">
      
      <!-- NOC PANELS -->
      <div class="panel" style="border-left:4px solid var(--blue)">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:20px">📡</span>
            <div>
              <h3 style="margin:0;font-size:14px;color:var(--blue)">NOC (Ağ Operasyon Merkezi)</h3>
              <div style="font-size:10.5px;color:var(--muted)">Network Operations Center — Trafik & Performans</div>
            </div>
          </div>
          <span class="badge info" id="nocStatusBadge">Aktif İzleme</span>
        </div>
        <div class="panel-body" style="font-size:12px">
          <div class="kv"><span>Aktif Bağlantı Hızı</span><b id="nocBwVal">Ölçüm bekleniyor</b></div>
          <div class="kv"><span>24 Saat Erişilebilirlik</span><b id="nocAvailabilityVal">Yeterli örnek yok</b></div>
          <div class="kv"><span>Router / Switch / AP</span><b id="nocNodesVal">Ölçüm bekleniyor</b></div>
        </div>
      </div>

      <!-- SOC PANELS -->
      <div class="panel" style="border-left:4px solid var(--red)">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:20px">🛡️</span>
            <div>
              <h3 style="margin:0;font-size:14px;color:var(--red)">SOC (Güvenlik Operasyon Merkezi)</h3>
              <div style="font-size:10.5px;color:var(--muted)">Yerel güvenlik durumu ve operasyon kayıtları</div>
            </div>
          </div>
          <span class="badge warn" id="socAlertBadge">0 Anomali</span>
        </div>
        <div class="panel-body" style="font-size:12px">
          <div class="kv"><span>Yerel Güvenlik Duvarı</span><b id="socFirewallVal">Ölçüm bekleniyor</b></div>
          <div class="kv"><span>SIEM / Otomatik Engelleme</span><b id="socEngineVal" style="color:var(--muted)">Bu sürümde yok</b></div>
          <div class="kv"><span>Son 24 Saatlik Alarmlar</span><b id="socAlertsVal">Ölçüm bekleniyor</b></div>
        </div>
      </div>

      <!-- XOC / ISOC BÜTÜNLEŞİK MOR TAKIM PANELS -->
      <div class="panel" style="border-left:4px solid var(--purple)">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:20px">🟣</span>
            <div>
              <h3 style="margin:0;font-size:14px;color:var(--purple)">XOC / ISOC (Bütünleşik Mor Takım)</h3>
              <div style="font-size:10.5px;color:var(--muted)">Integrated Security & Ops Center — Red + Blue Synergy</div>
            </div>
          </div>
          <span class="badge warn" style="background:rgba(168,85,247,0.15);color:var(--purple);border-color:rgba(168,85,247,0.3)">Eğitim / Simülasyon</span>
        </div>
        <div class="panel-body" style="font-size:12px">
          <div class="kv"><span>Kırmızı Takım Senaryoları</span><b style="color:var(--orange)">Yalnız görsel demo</b></div>
          <div class="kv"><span>Mavi Takım Yakalama</span><b style="color:var(--muted)">Gerçek SIEM bağlantısı yok</b></div>
          <div class="kv"><span>Mor Takım Doğrulama</span><b style="color:var(--muted)">Gerçek güvenlik kontrolü yapmaz</b></div>
        </div>
      </div>
    </div>

    <!-- İNTERAKTİF SİMÜLATÖR EKRANI -->
    <div class="panel">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
        <h2>🟣 Mor Takım (Purple Team) Saldırı & Savunma Canlı Doğrulayıcı</h2>
      </div>
      <div class="panel-body">
        <div class="device-learning warning" style="margin-bottom:14px"><b>Simülasyon laboratuvarı</b><div>Bu bölüm gerçek saldırı üretmez, SIEM alarmı açmaz, ağa paket göndermez ve firewall kuralı uygulamaz. Gösterilen saldırı/savunma adımları yalnız eğitim amaçlıdır; her senaryo gerçek MITRE ATT&amp;CK taktik kodlarıyla etiketlenmiştir ama tekniklerin uygulama detayını içermez — amaç "bu saldırı nasıl görünür, hangi savunma onu durdurur" farkındalığını öğretmektir.</div></div>

        <!-- KATEGORİ FİLTRESİ -->
        <div id="purpleCategoryChips" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px"></div>

        <!-- SENARYO KARTLARI -->
        <div id="purpleScenarioGrid" style="display:grid;grid-template-columns:repeat(auto-fill, minmax(240px, 1fr));gap:8px;margin-bottom:16px"></div>
        
        <!-- ANİMASYONLU XOC AKIŞ BARI -->
        <div style="position:relative;background:#050811;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:16px;overflow:hidden">
          
          <div style="display:flex;justify-content:space-between;align-items:center;position:relative;z-index:2;flex-wrap:wrap;gap:12px">
            
            <!-- RED TEAM -->
            <div style="text-align:center;background:rgba(242,88,91,0.1);border:1px solid rgba(242,88,91,0.3);padding:14px;border-radius:10px;min-width:140px">
              <div style="font-size:28px">🔴</div>
              <strong style="color:var(--red);font-size:12px">RED TEAM</strong>
              <div style="font-size:10px;color:var(--muted)">Saldırı & BAS Simülasyonu</div>
              <div id="redTeamState" class="badge fail" style="margin-top:6px;font-size:9.5px">Beklemede</div>
            </div>

            <!-- PURPLE MATCHING ENGINE -->
            <div style="text-align:center;background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);padding:14px;border-radius:10px;min-width:160px">
              <div style="font-size:28px">🟣</div>
              <strong style="color:var(--purple);font-size:12px">XOC PURPLE ENGINE</strong>
              <div style="font-size:10px;color:var(--muted)">Korelasyon & Doğrulama</div>
              <div id="purpleEngineState" class="badge gray" style="margin-top:6px;font-size:9.5px">Hazır</div>
            </div>

            <!-- BLUE TEAM -->
            <div style="text-align:center;background:rgba(59,155,255,0.1);border:1px solid rgba(59,155,255,0.3);padding:14px;border-radius:10px;min-width:140px">
              <div style="font-size:28px">🔵</div>
              <strong style="color:var(--blue);font-size:12px">BLUE TEAM</strong>
              <div style="font-size:10px;color:var(--muted)">Simüle SIEM / Log Adımı</div>
              <div id="blueTeamState" class="badge info" style="margin-top:6px;font-size:9.5px">İzlemede</div>
            </div>

          </div>

          <!-- ANIMATED PULSE WAVE -->
          <div style="position:relative;height:6px;background:var(--line);margin:20px 0 14px;border-radius:3px">
            <div id="purplePulseAnim" style="position:absolute;width:18px;height:18px;border-radius:50%;background:var(--purple);top:-6px;left:0%;opacity:0;transition:left 1.8s ease-in-out, opacity 0.3s;box-shadow:0 0 14px currentColor"></div>
          </div>

          <!-- LIVE SIMULATION CONSOLE LOG -->
          <div id="purpleConsole" style="background:#020408;border:1px solid var(--line);border-radius:8px;padding:12px;font-family:Consolas, monospace;font-size:11px;color:var(--txt-2);min-height:90px">
            <span style="color:var(--muted)">[XOC PURPLE TEAM] Simülasyon başlatmak için yukarıdaki butonlardan birine tıklayın...</span>
          </div>

        </div>

        <!-- ADMIN XOC LIVE NOC/SOC & PENTEST SIMULATOR -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px">
          
          <!-- ANOMALİ VE SALDIRI TESPİTİ (BLACKING / SOC) -->
          <div class="panel">
            <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
              <h2>🛡️ IP İzleme Listesi (Firewall Engeli Değildir)</h2>
            </div>
            <div class="panel-body">
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="xocBlacklistIp" placeholder="Şüpheli IP (örn: 192.168.1.150)" style="flex:1" />
                <button class="mini-btn" onclick="addXocBlacklist()">👁 İzleme Listesine Ekle</button>
              </div>
              <div id="xocBlacklistContainer" style="background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:11.5px">
                <div class="hint">İzleme listesinde IP yok. Liste yalnız bu çalışma süresince tutulur.</div>
              </div>
            </div>
          </div>

          <!-- SİMÜLE EDİLMİŞ DOS TEST MODÜLÜ (PENTEST) -->
          <div class="panel">
            <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
              <h2>💥 DoS Eğitim Senaryosu (Paket Göndermez)</h2>
            </div>
            <div class="panel-body">
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="xocDosTargetIp" placeholder="Hedef IP / Kullanıcı (örn: 10.33.254.12)" style="flex:1" />
                <button class="mini-btn blue" onclick="startXocDosSimulation()">🚀 Simülasyonu Başlat</button>
              </div>
              <div id="xocDosResultBox" style="background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:11.5px;min-height:48px">
                <span class="hint">Kontrollü stres testi simülasyonu başlatmak için hedef IP girin.</span>
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  `;

  renderPurpleCategoryChips();
  renderPurpleScenarioGrid();
  loadAdminXocMetrics();
}

async function loadAdminXocMetrics() {
  try {
    const data = await get("/api/admin/xoc/metrics");
    if (data.ok) {
      const setText = (id, value) => { const el = $(id); if (el) el.textContent = value; };
      const noc = data.noc || {};
      const soc = data.soc || {};
      setText("nocBwVal", noc.link_speed_mbps == null ? "Ölçülemedi" : `${noc.link_speed_mbps} Mbps`);
      setText("nocAvailabilityVal", noc.availability_24h == null ? "Yeterli örnek yok" : `%${noc.availability_24h}`);
      setText("nocNodesVal", `${noc.infrastructure_online ?? 0} erişilebilir altyapı cihazı`);
      const firewallState = soc.firewall?.state || "unknown";
      setText("socFirewallVal", firewallState === "enabled" ? "Açık" : firewallState === "disabled" ? "Kapalı" : "Doğrulanamadı");
      setText("socEngineVal", soc.siem_enabled ? "Bağlı" : "Bu sürümde yok");
      const alertCounts = soc.alert_counts_24h || {};
      setText("socAlertsVal", `${alertCounts.critical || 0} kritik / ${alertCounts.warning || 0} uyarı`);
      setText("socAlertBadge", `${Object.values(alertCounts).reduce((sum, count) => sum + Number(count || 0), 0)} alarm`);
      const container = $("xocBlacklistContainer");
      const watchlist = soc.watchlist_ips || soc.blacklisted_ips || [];
      if (container) {
        if (watchlist.length === 0) {
          container.innerHTML = `<div class="hint">İzleme listesinde IP yok. Firewall engeli uygulanmaz.</div>`;
        } else {
          container.innerHTML = watchlist.map(ip => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--line-soft)">
              <span style="font-weight:bold">👁 ${esc(ip)}</span>
              <button class="mini-btn" onclick="removeXocBlacklist('${esc(ip)}')">Listeden Çıkar</button>
            </div>
          `).join("");
        }
      }
    }
  } catch (e) {}
}

async function addXocBlacklist() {
  const ip = ($("xocBlacklistIp")?.value || "").trim();
  if (!ip) return toast("Lütfen geçerli bir IP adresi girin.", "error");
  try {
    await post("/api/admin/xoc/blacklist/add", { ip, reason: "Yönetici manuel izleme kaydı" });
    toast(`${ip} izleme listesine eklendi; firewall engeli uygulanmadı.`, "success");
    if ($("xocBlacklistIp")) $("xocBlacklistIp").value = "";
    loadAdminXocMetrics();
  } catch (e) {
    toast(e.message || "IP izleme listesine eklenemedi.", "error");
  }
}

async function removeXocBlacklist(ip) {
  try {
    await post("/api/admin/xoc/blacklist/remove", { ip });
    toast(`${ip} izleme listesinden çıkarıldı.`, "success");
    loadAdminXocMetrics();
  } catch (e) {
    toast(e.message || "İzleme listesi güncellenemedi.", "error");
  }
}

async function startXocDosSimulation() {
  const target_ip = ($("xocDosTargetIp")?.value || "").trim();
  if (!target_ip) return toast("Lütfen hedef IP girin.", "error");
  try {
    const res = await post("/api/admin/xoc/simulate-dos", { target_ip, intensity: "high" });
    toast(`DoS eğitim senaryosu tamamlandı; gerçek paket gönderilmedi: ${target_ip}`, "info");
    const box = $("xocDosResultBox");
    if (box && res.simulation) {
      box.innerHTML = `
        <div style="color:var(--cyan);font-weight:bold">✅ EĞİTİM SENARYOSU TAMAMLANDI (ID: ${esc(res.simulation.id)})</div>
        <div>Hedef etiketi: <b>${esc(res.simulation.target)}</b> · Sanal paket: <b>${Number(res.simulation.simulated_packets || 0).toLocaleString()}</b></div>
        <div style="font-size:10.5px;color:var(--muted);margin-top:4px">${esc(res.simulation.note)}</div>
      `;
    }
  } catch (e) {
    toast(e.message || "Simülasyon başlatılamadı.", "error");
  }
}

/* ---------- SALDIRI / SAVUNMA KATALOĞU (MITRE ATT&CK referanslı, salt eğitim amaçlı) ----------
   Her senaryo gerçek bir MITRE ATT&CK taktiğine etiketlenir ama TEKNİK UYGULAMA DETAYI
   İÇERMEZ (nasıl yapılır anlatılmaz). Amaç: "bu saldırı SOC ekranında nasıl görünür,
   hangi savunma katmanı onu durdurur" farkındalığı kazandırmaktır. */
const PURPLE_CATEGORIES = [
  { id: "recon",      label: "🔍 Keşif",              color: "#06b6d4" },
  { id: "access",     label: "🚪 İlk Erişim",          color: "#f59e0b" },
  { id: "credential", label: "🔑 Kimlik Bilgisi",      color: "#ef4444" },
  { id: "lateral",    label: "↔️ Yanal Hareket",       color: "#38bdf8" },
  { id: "c2",         label: "📡 Komuta & Kontrol",    color: "#8b5cf6" },
  { id: "exfil",      label: "📤 Veri Sızdırma",       color: "#f97316" },
  { id: "impact",     label: "💥 Etki (DoS/Ransom)",   color: "#dc2626" },
  { id: "web",        label: "🌐 Web Uygulama",        color: "#10b981" },
];

const PURPLE_CATALOG = [
  {
    id: "portscan", category: "recon", mitre: "TA0043 · T1595 Active Scanning",
    title: "Gizli SYN Stealth Port Tarama (Nmap tarzı)",
    red: "10.33.254.0/23 aralığında 1-65535 arası tüm portlar taranıyor...",
    purple: "XOC Güvenlik Skoru: Açık 3 servis tespit edildi (HTTP-80, HTTPS-443, SSH-22).",
    blue: "Simüle firewall adımı: 'SYN Port Scan Detected' kaydı ve geçici engel örneklendi.",
    defense: "Gerçek korunma: kullanılmayan servisleri kapatın, dışa açık olmayan portları router/firewall'da filtreleyin, IDS/IPS ile tarama paternlerini alarma bağlayın.",
    color: "#06b6d4",
  },
  {
    id: "sniffing", category: "recon", mitre: "TA0043 · T1040 Network Sniffing",
    title: "Ağ Trafiği Dinleme (Şifresiz Protokol Avı)",
    red: "Aynı ağ segmentinde ARP tablosu izlenerek şifresiz HTTP/FTP trafiği aranıyor...",
    purple: "XOC Korelasyonu: Promiscuous mod şüphesiyle switch port anomalisi işaretlendi.",
    blue: "Simüle SOC adımı: 'Olası Paket Dinleme' uyarısı ve segment izolasyonu örneklendi.",
    defense: "Gerçek korunma: her yerde TLS/HTTPS zorunlu kılın, kritik segmentleri VLAN ile ayırın, switch port security ve DHCP snooping açın.",
    color: "#06b6d4",
  },
  {
    id: "phishing", category: "access", mitre: "TA0001 · T1566 Phishing",
    title: "Kimlik Avı E-postası ile İlk Erişim",
    red: "'Fatura Ekli' konulu, meşru görünen bir e-posta 40 kullanıcıya gönderildi...",
    purple: "XOC Korelasyonu: Aynı ekli dosya hash'i 6 farklı posta kutusunda eşleşti.",
    blue: "Simüle e-posta ağ geçidi adımı: eki karantinaya alma ve kullanıcı uyarısı örneklendi.",
    defense: "Gerçek korunma: e-posta filtreleme/DMARC-SPF-DKIM, ekleri sandbox'ta patlatma, düzenli phishing farkındalık eğitimi (Academy modülü bunun için var).",
    color: "#f59e0b",
  },
  {
    id: "eviltwin", category: "access", mitre: "TA0001 · T1200 / Rogue Wi-Fi",
    title: "Sahte Erişim Noktası (Evil Twin Wi-Fi)",
    red: "Aynı SSID adıyla daha güçlü sinyalli sahte bir erişim noktası yayında...",
    purple: "XOC Anomali Analizi: aynı SSID için iki farklı BSSID/MAC eşleşmesi bulundu.",
    blue: "Simüle NOC adımı: 'Rogue AP Şüphesi' uyarısı ve kullanıcı bilgilendirmesi örneklendi.",
    defense: "Gerçek korunma: WPA3 + 802.1X kurumsal kimlik doğrulama kullanın, bilinmeyen AP'leri WIDS ile tespit edin, kullanıcıları halka açık/bilinmeyen ağlara VPN'siz bağlanmaması için eğitin.",
    color: "#f59e0b",
  },
  {
    id: "bruteforce", category: "credential", mitre: "TA0006 · T1110 Brute Force",
    title: "SSH / RDP Brute-Force Parola Saldırısı",
    red: "Port 22 & 3389 üzerine saniyede 150 hatalı parola deneniyor...",
    purple: "XOC Korelasyonu: 10.33.254.42 ➔ Port 22 çoklu yetkisiz giriş başarısızlığı eşleşti.",
    blue: "Simüle SIEM adımı: 'Brute-Force Saldırısı Tespiti' alarmı ve geçici IP engeli örneklendi.",
    defense: "Gerçek korunma: hesap kilitleme eşiği + artan bekleme süresi (NetMon'un kendi login kilidi bunu uygular), MFA, RDP/SSH'ı doğrudan internete açmayın (VPN arkasına alın).",
    color: "#ef4444",
  },
  {
    id: "credstuffing", category: "credential", mitre: "TA0006 · T1110.004 Credential Stuffing",
    title: "Sızmış Parola Listeleriyle Otomatik Deneme",
    red: "Farklı bir sızıntıdan elde edilen 50.000 kullanıcı/parola çifti otomatik deneniyor...",
    purple: "XOC Korelasyonu: Çok sayıda farklı kullanıcı adı, tek IP'den art arda denendi.",
    blue: "Simüle adım: 'Credential Stuffing Paterni' alarmı ve CAPTCHA/IP kısıtlama örneklendi.",
    defense: "Gerçek korunma: her sistemde farklı ve güçlü parola (parola yöneticisi), MFA, sızıntı veritabanlarına karşı parola kontrolü (haveibeenpwned tarzı).",
    color: "#ef4444",
  },
  {
    id: "lateral", category: "lateral", mitre: "TA0008 · T1021 Remote Services",
    title: "SMB/RDP ile Yanal Hareket",
    red: "Ele geçirilen bir istemciden iç ağdaki diğer sunuculara SMB ile bağlanmaya çalışılıyor...",
    purple: "XOC Korelasyonu: Tek bir host'tan kısa sürede 12 farklı iç IP'ye SMB bağlantı denemesi.",
    blue: "Simüle SOC adımı: 'Anormal İç Ağ Yayılımı' alarmı ve host izolasyonu örneklendi.",
    defense: "Gerçek korunma: ağ segmentasyonu (VLAN/mikro-segmentasyon), en az ayrıcalık ilkesi, iç trafikte de EDR/anomali izleme.",
    color: "#38bdf8",
  },
  {
    id: "privesc", category: "lateral", mitre: "TA0004 · T1068 Privilege Escalation",
    title: "Yerel Yetki Yükseltme Denemesi",
    red: "Standart bir kullanıcı hesabından yönetici (admin/root) yetkisine çıkmaya çalışılıyor...",
    purple: "XOC Korelasyonu: Kısa sürede çok sayıda başarısız yetki yükseltme çağrısı görüldü.",
    blue: "Simüle EDR adımı: 'Şüpheli Yetki Yükseltme' alarmı ve süreç sonlandırma örneklendi.",
    defense: "Gerçek korunma: işletim sistemi ve uygulamaları güncel tutun (patch yönetimi), günlük kullanıcıları admin yapmayın, EDR ile şüpheli süreç davranışlarını izleyin.",
    color: "#38bdf8",
  },
  {
    id: "c2beacon", category: "c2", mitre: "TA0011 · T1071 C2 Beacon Traffic",
    title: "Komuta-Kontrol (C2) Sinyal Trafiği",
    red: "Ele geçirilmiş bir cihaz, dışarıdaki bir sunucuya her 60 saniyede kısa 'yoklama' istekleri gönderiyor...",
    purple: "XOC Anomali Analizi: Periyodik/düzenli aralıklı düşük hacimli dış trafik paterni tespit edildi.",
    blue: "Simüle SOC adımı: 'Olası C2 Beacon' alarmı ve DNS/IP itibar kontrolü örneklendi.",
    defense: "Gerçek korunma: çıkış (egress) trafiği filtreleme, DNS sinkhole/itibar listeleri, bilinmeyen dış bağlantılar için uyarı kuralları.",
    color: "#8b5cf6",
  },
  {
    id: "exfiltration", category: "exfil", mitre: "TA0010 · T1041 Exfiltration Over C2",
    title: "Gece Yarısı Yüksek Hacimli Veri Çıkışı",
    red: "Dış bir IP'ye saat 03:14'te 4.2 GB veri transferi başlatıldı...",
    purple: "XOC Anomali Analizi: Mesai dışı saatte alışılmadık dış trafik akışı doğrulandı.",
    blue: "Simüle NOC/SOC adımı: 'Şüpheli Veri Sızıntısı' alarmı ve bant kısıtlama örneklendi.",
    defense: "Gerçek korunma: DLP (veri kaybı önleme) kuralları, büyük/mesai dışı transferler için alarm eşiği, hassas veriyi şifreleme.",
    color: "#f97316",
  },
  {
    id: "dos", category: "impact", mitre: "TA0040 · T1498 Network DoS",
    title: "Hizmet Dışı Bırakma (DoS/DDoS) Yük Testi",
    red: "Hedef servise normalin çok üzerinde istek gönderilerek kaynaklar tüketilmeye çalışılıyor...",
    purple: "XOC Korelasyonu: Tek/az sayıda kaynaktan anormal yüksek istek oranı görüldü.",
    blue: "Simüle adım: 'Olası DoS' alarmı ve hız sınırlama (rate limiting) örneklendi.",
    defense: "Gerçek korunma: rate limiting/WAF, CDN veya DDoS koruma servisi, kaynak kullanımı için otomatik ölçekleme ve alarm eşikleri.",
    color: "#dc2626",
  },
  {
    id: "ransomware", category: "impact", mitre: "TA0040 · T1486 Data Encrypted for Impact",
    title: "Fidye Yazılımı (Ransomware) Şifreleme Davranışı",
    red: "Kısa sürede çok sayıda dosya uzantısı değiştiriliyor ve toplu şifreleme paterni gözleniyor...",
    purple: "XOC Korelasyonu: Saniyede yüzlerce dosya değişikliği + yeni/bilinmeyen dosya uzantısı eşleşti.",
    blue: "Simüle EDR adımı: 'Toplu Dosya Şifreleme Paterni' alarmı ve süreç durdurma örneklendi.",
    defense: "Gerçek korunma: düzenli ve izole (offline/immutable) yedekleme, EDR ile davranış tabanlı tespit, e-posta/USB gibi giriş noktalarını sıkılaştırma.",
    color: "#dc2626",
  },
  {
    id: "webattack", category: "web", mitre: "TA0001 · T1190 Exploit Public-Facing App (SQLi/XSS paterni)",
    title: "Web Uygulamasına Otomatik Zafiyet Denemesi",
    red: "Giriş formuna art arda SQL enjeksiyonu ve script enjeksiyonu paternleri deneniyor...",
    purple: "XOC Korelasyonu: Tek IP'den kısa sürede çok sayıda anormal karakter dizisi içeren istek.",
    blue: "Simüle WAF adımı: 'Enjeksiyon Paterni Tespit Edildi' kaydı ve istek engelleme örneklendi.",
    defense: "Gerçek korunma: parametreli sorgular/ORM kullanımı (bu projede zaten uygulanıyor), girdi doğrulama, WAF, düzenli bağımlılık/güvenlik taraması.",
    color: "#10b981",
  },
];

function renderPurpleCategoryChips() {
  const wrap = $("purpleCategoryChips");
  if (!wrap) return;
  const active = _purpleActiveCategory || "all";
  const chips = [{ id: "all", label: "🗂️ Tümü", color: "var(--muted)" }, ...PURPLE_CATEGORIES];
  wrap.innerHTML = chips.map(c => {
    const isActive = c.id === active;
    return `<button class="mini-btn" onclick="setPurpleCategory('${c.id}')"
      style="border-color:${c.color};${isActive ? `background:${c.color};color:#000;font-weight:bold` : `color:${c.color}`}">${esc(c.label)}</button>`;
  }).join("");
}

function setPurpleCategory(catId) {
  _purpleActiveCategory = catId;
  renderPurpleCategoryChips();
  renderPurpleScenarioGrid();
}

function renderPurpleScenarioGrid() {
  const grid = $("purpleScenarioGrid");
  if (!grid) return;
  const active = _purpleActiveCategory || "all";
  const list = active === "all" ? PURPLE_CATALOG : PURPLE_CATALOG.filter(s => s.category === active);
  grid.innerHTML = list.map(s => `
    <button class="mini-btn blue" onclick="runPurpleSimulation('${s.id}')" style="text-align:left;padding:10px;border-left:3px solid ${s.color}">
      <div style="font-weight:bold;font-size:11.5px">${esc(s.title)}</div>
      <div style="font-size:9.5px;color:rgba(255,255,255,0.75);margin-top:3px">${esc(s.mitre)}</div>
    </button>
  `).join("");
}

let _purpleActiveCategory = "all";

function runPurpleSimulation(type) {
  if (_purpleSimTimer) clearInterval(_purpleSimTimer);

  const redBadge = $("redTeamState");
  const purpleBadge = $("purpleEngineState");
  const blueBadge = $("blueTeamState");
  const pulse = $("purplePulseAnim");
  const consoleEl = $("purpleConsole");

  const scn = PURPLE_CATALOG.find(s => s.id === type) || PURPLE_CATALOG[0];

  if (redBadge) { redBadge.textContent = "Sanal Senaryo"; redBadge.className = "badge fail"; }
  if (purpleBadge) { purpleBadge.textContent = "Demo Analizi"; purpleBadge.className = "badge warn"; }
  if (blueBadge) { blueBadge.textContent = "Demo Tamamlandı"; blueBadge.className = "badge ok"; }

  if (pulse) {
    pulse.style.opacity = "1";
    pulse.style.background = scn.color;
    pulse.style.left = "0%";
    setTimeout(() => { if (pulse) pulse.style.left = "50%"; }, 100);
    setTimeout(() => { if (pulse) pulse.style.left = "100%"; }, 1200);
  }

  if (consoleEl) {
    consoleEl.innerHTML = `
      <div style="color:${scn.color};font-weight:bold;margin-bottom:2px">🔴 RED TEAM: ${esc(scn.title)}</div>
      <div style="color:var(--muted);font-size:10px;margin-bottom:6px">MITRE ATT&amp;CK: ${esc(scn.mitre)}</div>
      <div style="color:var(--txt);margin-bottom:4px">└─ ${esc(scn.red)}</div>
      <div style="color:var(--purple);margin-bottom:4px">🟣 XOC PURPLE ENGINE: ${esc(scn.purple)}</div>
      <div style="color:var(--green);font-weight:bold;margin-bottom:6px">🔵 BLUE TEAM: ${esc(scn.blue)}</div>
      <div style="border-top:1px dashed var(--line);padding-top:6px;color:var(--cyan)">🛡️ GERÇEK HAYATTA KORUNMA: ${esc(scn.defense)}</div>
    `;
  }
}

function renderReportsPage() {
  const el = $("page-reports");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Raporlar</h2></div>
        <div class="panel-body" id="reportsBody"><div class="hint">Genel bakış verileri buradan özetlenir.</div></div>
      </div>
    `;
  }
  const o = S.overview || {};
  const body = $("reportsBody");
  if (body) {
    body.innerHTML = `
      <div class="info-card" style="margin-bottom:8px"><span>Toplam Cihaz</span><b>${o.devices?.total ?? "-"}</b></div>
      <div class="info-card" style="margin-bottom:8px"><span>Çevrimiçi</span><b>${o.devices?.online ?? "-"}</b></div>
      <div class="info-card" style="margin-bottom:8px"><span>İnternet Durumu</span><b>${o.internet?.connected == null ? "Ölçüm bekleniyor" : o.internet.connected ? "Bağlı" : "Yok"}</b></div>
      <div class="info-card"><span>Ortalama Gecikme</span><b>${o.latency?.average ?? "-"} ms</b></div>
    `;
  }
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
    const isAdmin = S.user && S.user.role === "admin";
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
        <h4 style="margin:0 0 4px;color:var(--blue);font-size:13px">🔑 Yetkili Envanter Kimlik Bilgileri</h4>
        <div class="hint" style="margin-bottom:10px">Windows için WMI/WinRM, Linux için SSH ve ağ cihazları için SNMP salt-okuma bilgileri kullanılır.</div>
        <div class="field-label">WMI Yönetici Kullanıcı Adı</div>
      <input id="setWmiUser" name="netmon-wmi-user" type="text" value="${esc(s.wmi_username || "")}" placeholder="Örn. DOMAIN\\Administrator veya Administrator" autocomplete="off" spellcheck="false" data-lpignore="true" data-1p-ignore ${isAdmin ? "" : "disabled"} />
      <div class="field-label" style="margin-top:10px">WMI Yönetici Şifresi</div>
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
      wmi_username: $("setWmiUser")?.value.trim() ?? undefined,
      ssh_username: $("setSshUser")?.value.trim() ?? undefined,
      public_ip_lookup: Boolean($("setPublicIpLookup")?.checked),
      winrm_verify_tls: Boolean($("setWinrmVerifyTls")?.checked),
    };
    const wmiPassword = $("setWmiPass")?.value || "";
    const sshPassword = $("setSshPass")?.value || "";
    const snmpCommunity = $("setSnmpCommunity")?.value || "";
    if ($("clearWmiPass")?.checked) payload.wmi_password = "";
    else if (wmiPassword) payload.wmi_password = wmiPassword;
    if ($("clearSshPass")?.checked) payload.ssh_password = "";
    else if (sshPassword) payload.ssh_password = sshPassword;
    if ($("clearSnmpCommunity")?.checked) payload.snmp_community = "";
    else if (snmpCommunity) payload.snmp_community = snmpCommunity;
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
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <h2>Kullanıcı Yönetimi</h2>
          <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;"><button class="mini-btn blue" onclick="openCreateUserModal()">${ico("plus", 14)} Yeni Kullanıcı</button></div>
        </div>
        <div class="panel-body" style="padding:0">
          <table>
            <thead><tr><th>Kullanıcı Adı</th><th>Rol</th><th>Durum</th><th></th></tr></thead>
            <tbody id="usersBody"></tbody>
          </table>
        </div>
      </div>
    `;
  }
  loadUsers();
}

async function loadUsers() {
  const body = $("usersBody");
  if (!body) return;
  try {
    const data = await get("/api/admin/users");
    const users = data.users || [];
    body.innerHTML = users
      .map(
        (u) => `
      <tr>
        <td>${esc(u.username)}</td>
        <td>${u.role === "admin" ? "Yönetici" : "Kullanıcı"}</td>
        <td><span class="badge ${u.active ? "ok" : "gray"}">${u.active ? "Aktif" : "Pasif"}</span>${u.must_change_password ? ' <span class="badge warn">Parola değişmeli</span>' : ''}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="mini-btn" onclick="changeUserRole(${u.id}, '${u.role === "admin" ? "user" : "admin"}')">${u.role === "admin" ? "Kullanıcı Yap" : "Yönetici Yap"}</button>
          <button class="mini-btn" onclick="openResetUserPasswordModal(${u.id}, '${esc(u.username)}')">Parola Sıfırla</button>
          <button class="mini-btn" onclick="toggleUserActive(${u.id}, ${u.active ? "false" : "true"})">${u.active ? "Devre Dışı Bırak" : "Etkinleştir"}</button>
          <button class="mini-btn" onclick="deleteUser(${u.id})">${ico("trash", 14)}</button>
        </td>
      </tr>
    `,
      )
      .join("");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="4" class="hint">Kullanıcılar alınamadı: ${esc(e.message)}</td></tr>`;
  }
}

function openCreateUserModal() {
  openModal(`
    <h3>Yeni Kullanıcı</h3>
    <div class="field-label" style="margin-top:10px">Kullanıcı Adı</div>
    <input id="newUserName" type="text" autocomplete="off" />
    <div class="field-label" style="margin-top:10px">Şifre</div>
    <input id="newUserPass" type="password" minlength="12" autocomplete="new-password" />
    <div class="hint" style="margin-top:5px">En az 12 karakter. Kullanıcı ilk girişte bu parolayı değiştirmek zorundadır.</div>
    <div class="field-label" style="margin-top:10px">Rol</div>
    <select id="newUserRole"><option value="user">Kullanıcı</option><option value="admin">Yönetici</option></select>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px"><button class="mini-btn" onclick="closeModalForce()">İptal</button><button class="mini-btn blue" onclick="createUser()">Oluştur</button></div>
  `);
}

async function createUser() {
  const username = $("newUserName")?.value.trim();
  const password = $("newUserPass")?.value;
  const role = $("newUserRole")?.value || "user";
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
    loadUsers();
  } catch (e) {
    toast(e.message || "Kullanıcı oluşturulamadı.", "error");
  }
}

async function toggleUserActive(id, active) {
  try {
    await post(`/api/admin/users/${id}`, { active });
    loadUsers();
  } catch (e) {
    toast(e.message || "İşlem başarısız.", "error");
  }
}

async function changeUserRole(id, role) {
  try {
    await post(`/api/admin/users/${id}`, { role });
    toast("Kullanıcı rolü güncellendi.", "success");
    loadUsers();
  } catch (e) {
    toast(e.message || "Rol güncellenemedi.", "error");
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
    loadUsers();
  } catch (e) {
    toast(e.message || "Parola sıfırlanamadı.", "error");
  }
}

async function deleteUser(id) {
  if (!window.confirm("Bu kullanıcıyı ve tüm açık oturumlarını silmek istediğinize emin misiniz?")) return;
  try {
    await del(`/api/admin/users/${id}`);
    toast("Kullanıcı silindi.", "success");
    loadUsers();
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
let _trafficChartInstance = null;

function drawTrafficChart() {
  const canvas = $("trafficChart");
  if (!canvas || typeof Chart === "undefined") return;

  const labels = S.sparkUp.map((_, i) => i);

  if (_trafficChartInstance) {
    _trafficChartInstance.data.labels = labels;
    _trafficChartInstance.data.datasets[0].data = S.sparkUp;
    _trafficChartInstance.data.datasets[1].data = S.sparkDown;
    _trafficChartInstance.update("none");
    return;
  }

  const ctx = canvas.getContext("2d");
  const gradUp = ctx.createLinearGradient(0, 0, 0, 150);
  gradUp.addColorStop(0, "rgba(61, 220, 132, 0.4)");
  gradUp.addColorStop(1, "rgba(61, 220, 132, 0.05)");

  const gradDown = ctx.createLinearGradient(0, 0, 0, 150);
  gradDown.addColorStop(0, "rgba(59, 155, 255, 0.4)");
  gradDown.addColorStop(1, "rgba(59, 155, 255, 0.05)");

  _trafficChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Upload (Mbps)",
          data: S.sparkUp,
          borderColor: "#3ddc84",
          backgroundColor: gradUp,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          label: "Download (Mbps)",
          data: S.sparkDown,
          borderColor: "#3b9bff",
          backgroundColor: gradDown,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { display: false },
        y: {
          beginAtZero: true,
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#93a4bd" },
        },
      },
      plugins: {
        legend: { labels: { color: "#e7eefb" } },
        tooltip: { backgroundColor: "rgba(13, 22, 38, 0.95)" },
      },
    },
  });
}

S.deviceTab = S.deviceTab || "all";
S.deviceViewMode = S.deviceViewMode || "table";

function copyToClipboard(text, btn) {
  if (!text) return;
  const doCopy = () => {
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
      btn.style.borderColor = "var(--green)";
      btn.style.color = "var(--green)";
      setTimeout(() => {
        btn.innerHTML = orig;
        btn.style.borderColor = "";
        btn.style.color = "";
      }, 1500);
    }
    toast(`Kopyalandı: ${text}`, "success");
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(doCopy).catch(doCopy);
  } else {
    doCopy();
  }
}

function copyBtnHtml(text) {
  if (!text) return "";
  return `<button class="copy-btn" onclick="copyToClipboard('${esc(text)}', this)" title="Kopyala: ${esc(text)}">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
  </button>`;
}

function handleGlobalSearch(query) {
  const q = (query || "").trim();
  if (S.page !== "devices") {
    go("devices");
  }
  const filter = $("devFilter");
  if (filter) {
    filter.value = q;
    renderDeviceTable();
  }
}

function setDeviceViewMode(mode) {
  S.deviceViewMode = mode;
  const page = $("page-devices");
  if (page) page.dataset.built = "";
  renderDevicesPage();
}

function setDeviceTab(tab) {
  S.deviceTab = tab;
  const page = $("page-devices");
  if (page) page.dataset.built = "";
  renderDevicesPage();
}


window.downloadRdp = async function(ip) {
    if(!ip) return toast("IP adresi bulunamadı", "error");
    try {
        const res = await fetch(`/api/tools/rdp?ip=${encodeURIComponent(ip)}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${S.token}` }
        });
        const data = await res.json();
        if(!res.ok) throw new Error(data.error || "RDP başlatılamadı.");
        toast(data.message || "RDP Başlatıldı.", "success");
    } catch(err) {
        toast(err.message, "error");
    }
};

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
  const statusFilter = S.deviceStatusFilter || "online";
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
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button>
            <button class="mini-btn" onclick="openWmiScanModal('${esc(d.ip || "")}')">🔑 Yetkili Envanter</button>
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
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button></td></tr>`;
    }).join("") : `<tr><td colspan="7" class="hint">Ağ envanteri bulunamadı.</td></tr>`;
    return;
  }
  if (tab === "security") {
    body.innerHTML = filteredList.length ? filteredList.map(d => {
      const inv = d.wmi_inventory?.status === "Success" ? d.wmi_inventory : (d.fallback_inventory || {});
      const sec = inv.security || {};
      return `<tr><td><span class="badge ${deviceStatusClass(deviceStatus(d))}">${esc(deviceStatusLabel(deviceStatus(d)))}</span></td><td><b>${esc(deviceDisplayName(d))}</b></td><td>${esc((inv.software || {}).os_name || d.os_fingerprint || "-")}</td><td>${esc(sec.firewall || "Bilinmiyor")}</td><td>${esc(sec.antivirus || "Bilinmiyor")}</td><td>${d.unified_inventory?.verified ? "Doğrulandı" : "Ağ profili"}</td><td>${esc(d.unified_inventory?.completeness ?? "-")}%</td><td><button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button></td></tr>`;
    }).join("") : `<tr><td colspan="8" class="hint">Güvenlik verisi bulunamadı.</td></tr>`;
    return;
  }
  if (tab === "history") {
    body.innerHTML = filteredList.length ? filteredList.map(d => `<tr><td><span class="badge ${deviceStatusClass(deviceStatus(d))}">${esc(deviceStatusLabel(deviceStatus(d)))}</span></td><td><b>${esc(deviceDisplayName(d))}</b></td><td class="mono">${esc(d.ip || "-")}</td><td class="mono">${esc(d.mac || "-")}</td><td>${esc(formatSeen(d.last_seen || d.lastSeen || d.ts))}</td><td>${esc(d.inventory_source || "Discovery")}</td><td>${d.unified_inventory?.verified ? "Doğrulandı" : "Ağ profili"}</td><td><button class="mini-btn blue" onclick="showDeviceDetails('${esc(d.mac || "")}', '${esc(d.ip || "")}')">Detay</button>
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button></td></tr>`).join("") : `<tr><td colspan="8" class="hint">Geçmiş verisi bulunamadı.</td></tr>`;
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
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button>
            <button class="mini-btn" onclick="openWmiScanModal('${esc(d.ip || "")}')">🔑 Yetkili Envanter</button>
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
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button>
            <button class="mini-btn" onclick="openWmiScanModal('${esc(d.ip || "")}')">🔑 Yetkili Envanter</button>
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
          <button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp('${esc(d.ip || "")}', '${esc(d.hostname || d.ip)}')">💻 RDP</button>
          <button class="mini-btn" onclick="openWmiScanModal('${esc(d.ip || "")}')">🔑 Yetkili Envanter</button>
          ${S.user && S.user.role === "admin" && d.mac ? `<button class="mini-btn" onclick="openDeviceEditModal('${esc(d.mac)}')">Adlandır</button>` : ""}
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

function openWmiScanModal(targetIp) {
  const ip = targetIp || "";
  openModal(`
    <h3>🔑 Yetkili Cihaz Envanteri</h3>
    <div class="sub">Windows için WMI/WinRM, Linux için SSH, ağ cihazları için SNMP kullanır.</div>
    <div class="field-label" style="margin-top:12px">Hedef Cihaz IP Adresi</div>
    <input id="wmiTargetIp" value="${esc(ip)}" placeholder="Örn. 192.168.1.50" />
    <div class="field-label" style="margin-top:10px">Protokol</div>
    <select id="inventoryProtocol"><option value="auto">Otomatik Algıla</option><option value="windows">Windows WMI / WinRM</option><option value="ssh">Linux SSH</option><option value="snmp">SNMP Ağ Cihazı</option></select>
    <div class="field-label" style="margin-top:10px">Yetkili Kullanıcı Adı</div>
    <input id="wmiUser" name="netmon-inventory-user" placeholder="DOMAIN\\kullanıcı veya SSH kullanıcısı" autocomplete="off" spellcheck="false" data-lpignore="true" data-1p-ignore />
    <div class="field-label" style="margin-top:10px">Parola</div>
    <input id="wmiPass" name="netmon-inventory-secret" type="password" placeholder="Şifre" autocomplete="new-password" data-lpignore="true" data-1p-ignore />
    <div class="field-label" style="margin-top:10px">SNMP Community</div>
    <input id="inventorySnmp" name="netmon-inventory-snmp-secret" type="password" placeholder="Yalnızca SNMP için" autocomplete="new-password" data-lpignore="true" data-1p-ignore />
    <div class="hint" style="margin-top:10px;font-size:11px">Boş bırakılan alanlarda Ayarlar panelindeki DPAPI ile korunan kimlik bilgileri kullanılır.</div>
    <div id="inventoryScanError" class="hint c-red" style="margin-top:8px"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
      <button class="mini-btn" onclick="closeModalForce()">İptal</button>
      <button id="inventoryScanButton" class="mini-btn blue" onclick="executeWmiScanFromModal()">Taramayı Başlat</button>
    </div>
  `);
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
      if (errorBox) errorBox.textContent = `Envanter alınamadı: ${message}`;
      await refreshDevices();
      toast(`[${ip}] Envanter alınamadı: ${message}`, "error");
    }
  } catch (e) {
    const message = e.message || String(e);
    const errorBox = $("inventoryScanError");
    if (errorBox) errorBox.textContent = `Yetkili tarama başarısız: ${message}`;
    toast(`Yetkili tarama başarısız: ${message}`, "error");
  }
}

function showDeviceDetails(mac, ip) {
  const d = S.devices.find(x => (mac && x.mac === mac) || (ip && x.ip === ip));
  if (!d) return;
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
      ? `<div class="device-learning warning" style="margin-bottom:10px"><b>Son envanter hatası</b><div>${esc(d.inventory_error.message)}</div></div>`
      : "";

    return `
      <div style="margin-bottom:10px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px">
        <div>${statusBadgeHtml}</div>
        <button class="mini-btn blue" onclick="openWmiScanModal('${esc(d.ip)}')">🔑 Yetkili Cihaz Envanteri Al</button>
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
      ${S.user?.role === "admin" && d.mac ? `<button class="mini-btn" onclick="openDeviceEditModal('${esc(d.mac)}')">Düzenle</button>` : ""}
      <button class="mini-btn blue" onclick="closeModalForce()">Kapat</button>
    </div>
  `);
}

function openDeviceEditModal(mac) {
  const d = S.devices.find(x => x.mac === mac);
  if (!d || S.user?.role !== "admin") return;
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

  const cards = [
    {
      ico: "monitor",
      cls: "i-blue",
      label: "Cihazlar",
      value: S.scanning && !dev.total ? "…" : dev.total,
      sub: `<span class="c-green">${dev.online} Çevrimiçi</span> <span class="c-orange">${dev.discovered || 0} Keşfedildi</span> <span class="c-red">${dev.offline || 0} Çevrimdışı</span> <span class="c-blue">${dev.unknown || 0} Bilinmeyen</span>`,
    },
    {
      ico: "globe",
      cls: inet.connected ? "i-green" : "i-red",
      label: "İnternet",
      value: inet.connected == null
        ? `<span class="c-muted">Ölçüm bekleniyor</span>`
        : `<span class="${inet.connected ? "c-green" : "c-red"}">${inet.connected ? "Bağlı" : "Yok"}</span>`,
      sub: esc(inet.target || "-"),
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
    },
    {
      ico: "up",
      cls: "i-green",
      label: "Upload",
      value:
        fmtMbps(S.traffic.up) +
        ' <span style="font-size:12px;color:var(--muted)">Mbps</span>',
      spark: sparkSvg(S.sparkUp, "#3ddc84"),
    },
    {
      ico: "down",
      cls: "i-blue",
      label: "Download",
      value:
        fmtMbps(S.traffic.down) +
        ' <span style="font-size:12px;color:var(--muted)">Mbps</span>',
      spark: sparkSvg(S.sparkDown, "#3b9bff"),
    },
    {
      ico: "link",
      cls: "i-purple",
      label: "Aktif Bağlantılar",
      value: con.supported === false ? "-" : con.total || 0,
      sub:
        con.supported === false
          ? "yönetici izni gerekli"
          : `TCP: ${con.tcp || 0} <span>UDP: ${con.udp || 0}</span>`,
    },
  ];

  $("statRow").innerHTML = cards
    .map(
      (c) => `
    <div class="stat">
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
  const total = list.length;
  const online = list.filter((d) => deviceStatus(d) === "online").length;
  const unknown = list.filter((d) => (d.type || "unknown") === "unknown").length;
  const confirmed = list.filter((d) => d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success").length;
  const discovered = list.filter((d) => deviceStatus(d) === "discovered").length;
  const offline = list.filter((d) => deviceStatus(d) === "offline").length;

  // NMS Status Pills (Görsel 3 Referansı)
  if ($("nmsTotalCnt")) $("nmsTotalCnt").textContent = total;
  if ($("nmsOnlineCnt")) $("nmsOnlineCnt").textContent = online;
  if ($("nmsWarnCnt")) $("nmsWarnCnt").textContent = discovered + unknown;
  if ($("nmsCritCnt")) $("nmsCritCnt").textContent = offline;

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
  const total = list.length || 1;
  const online = list.filter((d) => deviceStatus(d) === "online").length;
  const healthPct = Math.round((online / total) * 100);
  const verified = list.filter((d) => d.unified_inventory?.verified || d.wmi_inventory?.status === "Success" || d.deep_inventory?.status === "Success").length;
  const inventoryPct = Math.round((verified / total) * 100);

  const healthOffset = Math.round(251 - (251 * healthPct) / 100);
  const inventoryOffset = Math.round(251 - (251 * inventoryPct) / 100);

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
        <div class="gauge-val" style="color:var(--green)">%${healthPct}</div>
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
        <div class="gauge-val" style="color:var(--blue)">%${inventoryPct}</div>
        <div class="gauge-lbl">Doğrulanmış Envanter</div>
      </div>
    </div>
  `;
}

/* ---------- Topoloji ---------- */
const TOPO = { k: 1, x: 0, y: 0, drag: null };
const STATUS_COLOR = {
  online: "#3ddc84",
  discovered: "#f5a623",
  warn: "#f5a623",
  offline: "#f2585b",
  unknown: "#5a6b88",
};

function layoutTopology(data) {
  const backboneIds = new Set(["internet", "router", "gateway", "switch", "lan"]);
  const pos = {};

  const gatewayId = data.nodes.some(n => n.id === "gateway") ? "gateway" : "router";
  const hasSwitch = data.nodes.some(n => n.id === "switch" || n.id === "lan");
  const lanId = data.nodes.some(n => n.id === "lan") ? "lan" : "switch";

  const clients = data.nodes.filter(n => !backboneIds.has(n.id));
  const groups = { network: [], computers: [], mobile: [], other: [] };
  clients.forEach(n => {
    const t = n.type || "unknown";
    if (["router","switch","access_point","network_device","firewall"].includes(t)) groups.network.push(n);
    else if (["pc","computer","laptop","server"].includes(t)) groups.computers.push(n);
    else if (["phone","mobile","tablet"].includes(t)) groups.mobile.push(n);
    else groups.other.push(n);
  });

  Object.values(groups).forEach(a => a.sort((x, y) =>
    String(x.ip || x.mac || x.id).localeCompare(String(y.ip || y.mac || y.id), undefined, { numeric: true })
  ));

  const colsFor = (n) => (n <= 2 ? 1 : n <= 6 ? 2 : n <= 12 ? 3 : 4);
  const nodeGapX = 220;   // horizontal distance between node centers
  const rowGapY = 160;    // vertical distance between node centers (zero overlap)

  const columns = [
    { key: "network", title: "🌐 AĞ CİHAZLARI" },
    { key: "computers", title: "🖥️ BİLGİSAYARLAR" },
    { key: "mobile", title: "📱 MOBİL CİHAZLAR" },
    { key: "other", title: "📟 DİĞER / IoT" },
  ];

  const groupWidths = columns.map(col => {
    const n = groups[col.key].length;
    const cols = n === 0 ? 1 : colsFor(n);
    return Math.max(nodeGapX, cols * nodeGapX);
  });
  const groupPad = 60;
  const totalWidth = groupWidths.reduce((a, b) => a + b, 0) + groupPad * (columns.length - 1);
  const W = Math.max(1200, totalWidth + 140);

  // İnternet akışı adım pozisyonları (WAN ➔ Gateway ➔ Switch)
  pos.internet = { x: W / 2, y: 70 };
  if (data.nodes.some(n => n.id === gatewayId)) pos[gatewayId] = { x: W / 2, y: 185 };
  if (hasSwitch && data.nodes.some(n => n.id === lanId)) pos[lanId] = { x: W / 2, y: 295 };

  // Kategori başlık şeritleri: Tam uç cihaz sütunlarının 80px üstüne entegre
  const headerY = hasSwitch ? 410 : 295;
  const startY = headerY + 85; // 495px (tam sütun başı)

  let maxRows = 1;
  let cursorX = 70;
  columns.forEach((col, idx) => {
    const arr = groups[col.key];
    const n = arr.length;
    const cols = n === 0 ? 1 : colsFor(n);
    const groupWidth = groupWidths[idx];
    const centerX = cursorX + groupWidth / 2;
    col.x = centerX;
    col.headerY = headerY;
    col.count = n;
    const rows = Math.max(1, Math.ceil(n / cols));
    maxRows = Math.max(maxRows, rows);
    const rowStartX = centerX - ((cols - 1) * nodeGapX) / 2;
    arr.forEach((node, i) => {
      const row = Math.floor(i / cols);
      const colInRow = i % cols;
      pos[node.id] = {
        x: rowStartX + colInRow * nodeGapX,
        y: startY + row * rowGapY,
      };
    });
    cursorX += groupWidth + groupPad;
  });

  const H = Math.max(720, startY + maxRows * rowGapY + 90);
  return { pos, W, H, groups, columns };
}

S.topoLayout = S.topoLayout || "tree";
S.topoActiveOnly = S.topoActiveOnly !== undefined ? S.topoActiveOnly : true;

function setTopoLayout(layoutMode) {
  S.topoLayout = layoutMode;
  const page = $("page-topology");
  if (page) page.dataset.built = "";
  renderTopologyPage();
}

function toggleTopoActiveOnly(checked) {
  S.topoActiveOnly = checked;
  const page = $("page-topology");
  if (page) page.dataset.built = "";
  renderTopologyPage();
}

function computeMeshTopologyLayout(data) {
  const pos = {};
  const nodes = data.nodes || [];
  const W = 1300, H = 820;
  const cx = W / 2, cy = H / 2 + 30;

  pos.internet = { x: cx, y: 70 };

  const gatewayNode = nodes.find(n => n.type === "router" || n.type === "gateway" || n.is_gateway || n.id === "gateway" || n.id === "router");
  const gatewayId = gatewayNode ? gatewayNode.id : "gateway";
  pos[gatewayId] = { x: cx, y: 175 };

  const swNodes = nodes.filter(n => ["switch", "access_point", "lan"].includes(n.type) || ["switch", "lan"].includes(n.id));
  if (swNodes.length) {
    swNodes.forEach((s, idx) => {
      const angle = (idx / Math.max(1, swNodes.length)) * 2 * Math.PI - Math.PI / 2;
      pos[s.id] = { x: cx + 220 * Math.cos(angle), y: cy - 20 + 120 * Math.sin(angle) };
    });
  }

  const endpointNodes = nodes.filter(n => n.id !== "internet" && n.id !== gatewayId && !swNodes.some(s => s.id === n.id));
  const total = endpointNodes.length;

  endpointNodes.forEach((n, idx) => {
    const angle = (idx / Math.max(1, total)) * 2 * Math.PI - Math.PI / 2;
    const rX = Math.max(380, Math.min(540, total * 30));
    const rY = Math.max(220, Math.min(320, total * 18));
    pos[n.id] = {
      x: cx + rX * Math.cos(angle),
      y: cy + rY * Math.sin(angle)
    };
  });

  return { pos, W, H, columns: [] };
}

function topologyDeviceName(node) {
  const dev = S.devices.find(d => d.ip && node.ip && d.ip === node.ip);
  const candidate = dev || node;
  const nodeIp = String(candidate?.ip || node?.ip || "").trim();
  const isSelf = Boolean(candidate?.is_self || node?.is_self);

  // İnternet, gateway ve LAN düğümleri fiziksel uç cihaz değildir. Backend
  // bunlara anlamlı bir label gönderir; IP/MAC taşımadıkları için genel uç
  // cihaz isimlendirmesine düşüp "Bilinmeyen cihaz" olarak gösterilmemelidir.
  if (node?.id === "internet" || node?.type === "internet") return node.label || "İnternet";
  if (node?.id === "lan" || (node?.logical && node?.type === "switch")) {
    return node.label || "LAN / Erişim Katmanı";
  }
  if (node?.id === "gateway" || node?.is_gateway) {
    const gatewayName = candidate?.friendly_name || candidate?.hostname || node?.friendly_name || node?.hostname;
    if (gatewayName) return gatewayName;
    return node.label ? `${node.label} / Ağ Geçidi` : "Ağ Geçidi";
  }

  if (isSelf) return candidate.friendly_name || candidate.hostname || nodeIp || "Bu cihaz";

  const selfDevice = S.devices.find(d => d.is_self);
  const selfNames = new Set(
    [selfDevice?.friendly_name, selfDevice?.hostname]
      .filter(Boolean)
      .map(s => String(s).trim().toLowerCase())
  );

  if (candidate?.classification_source === "manual") {
    const name = candidate.friendly_name || node.friendly_name;
    if (name && !selfNames.has(String(name).trim().toLowerCase())) {
      const same = S.devices.filter(d => d.friendly_name === name && d.ip);
      if (same.length <= 1) return name;
    }
  }

  const friendly = String(candidate?.friendly_name || node?.friendly_name || "").trim();
  if (friendly && !selfNames.has(friendly.toLowerCase())) {
    const same = S.devices.filter(d => d.friendly_name === friendly && d.ip);
    if (same.length <= 1) return friendly;
  }

  const hostname = String(candidate?.hostname || node?.hostname || "").trim();
  if (hostname && nodeIp && !selfNames.has(hostname.toLowerCase())) return hostname;

  if (candidate?.vendor && (candidate?.type || "unknown") === "unknown") return candidate.vendor;
  if (candidate?.vendor) return candidate.vendor;
  if (node?.vendor) return node.vendor;
  if (nodeIp) return nodeIp;
  if (candidate?.mac || node?.mac) return `MAC-${String(candidate?.mac || node?.mac).replace(/[^a-fA-F0-9]/g, "").slice(-6).toUpperCase()}`;
  return "Bilinmeyen cihaz";
}

function topologyTypeTitle(type) {
  return ({
    internet: "İnternet", gateway: "Ağ Geçidi", lan: "Mantıksal LAN",
    router: "Router", firewall: "Firewall", switch: "Switch", access_point: "Access Point",
    network_device: "Ağ Cihazı", pc: "Bilgisayar", computer: "Bilgisayar", laptop: "Laptop",
    server: "Sunucu", phone: "Telefon", mobile: "Mobil", tablet: "Tablet", printer: "Yazıcı",
    iot: "IoT", http: "Web Cihazı", unknown: "Bilinmeyen"
  })[type] || "Cihaz";
}

function nodeSvg(node, p) {
  const dev = S.devices.find(d => d.ip === node.ip) || node;
  const status = node.status || "unknown";
  const color = STATUS_COLOR[status] || STATUS_COLOR.unknown;
  const icon = DEVICE_TYPE_ICON[node.type] || "cpu";
  const r = 36;
  const label = topologyDeviceName(node);
  const ip = node.ip || "";
  const os = esc(dev.os_fingerprint || dev.type || "Bilinmiyor");
  const lat = dev.latency != null ? `${dev.latency}ms` : (node.latency != null ? `${node.latency}ms` : null);
  const safeId = String(node.id).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const typeTitle = esc(topologyTypeTitle(node.type));

  const isRogueDhcp = Boolean(dev?.is_rogue_dhcp || node?.is_rogue_dhcp || dev?.rogue_dhcp);
  const isRiskyOs = Boolean(dev?.risky_os || /windows (xp|7|8|server 2008)/i.test(String(dev?.os_fingerprint || node?.os_fingerprint || "")));
  const switchPort = node.switch_port || dev?.switch_port;
  const openPorts = dev?.classification?.open_ports || node?.classification?.open_ports || [];
  const openPortsCount = openPorts.length;
  const hasThreat = isRogueDhcp || isRiskyOs;

  // Badges calculation
  let threatBadges = "";
  if (isRogueDhcp) {
    threatBadges += `
      <g transform="translate(0, ${-r - 11})">
        <rect x="-38" y="-9" width="76" height="18" rx="9" fill="#ef4444" stroke="#ffffff" stroke-width="1.2"/>
        <text x="0" y="3.5" font-size="8.5" font-weight="800" fill="#ffffff" text-anchor="middle">🚨 ROGUE DHCP</text>
      </g>`;
  } else if (isRiskyOs) {
    threatBadges += `
      <g transform="translate(0, ${-r - 11})">
        <rect x="-34" y="-9" width="68" height="18" rx="9" fill="#f97316" stroke="#ffffff" stroke-width="1.2"/>
        <text x="0" y="3.5" font-size="8.5" font-weight="800" fill="#ffffff" text-anchor="middle">⚠️ RİSKLİ OS</text>
      </g>`;
  }

  // Switch Port indicator (Top-Left)
  let switchPortBadge = "";
  if (switchPort) {
    switchPortBadge = `
      <g transform="translate(${-r + 4}, ${-r + 4})">
        <rect x="-16" y="-7" width="32" height="14" rx="7" fill="#0891b2" stroke="rgba(255,255,255,0.9)" stroke-width="0.8"/>
        <text x="0" y="3.5" font-size="8" font-weight="700" fill="#ffffff" text-anchor="middle">P${esc(switchPort)}</text>
      </g>`;
  }

  // Open ports indicator (Bottom-Right)
  let openPortsBadge = "";
  if (openPortsCount > 0) {
    openPortsBadge = `
      <g transform="translate(${r - 6}, ${r - 6})">
        <rect x="-14" y="-7" width="28" height="14" rx="7" fill="#6366f1" stroke="rgba(255,255,255,0.7)" stroke-width="0.8"/>
        <text x="0" y="3.5" font-size="8" font-weight="700" fill="#ffffff" text-anchor="middle">🔒${openPortsCount}p</text>
      </g>`;
  }

  return `
    <g class="net-tak-node ${hasThreat ? 'threat-pulse' : ''}" transform="translate(${p.x.toFixed(1)}, ${p.y.toFixed(1)})" onclick="showNode('${safeId}'); event.stopPropagation();">
      <!-- Outer Glow Ring -->
      <circle cx="0" cy="0" r="${r + 4}" fill="none" stroke="${isRogueDhcp ? '#ef4444' : (node.is_self ? '#00f2ff' : color)}" stroke-width="${node.is_self || isRogueDhcp ? '2.5' : '1.5'}" stroke-opacity="0.85" stroke-dasharray="${node.is_gateway ? '6 3' : 'none'}"/>
      
      <!-- Main Pod Circle -->
      <circle class="pod-circle" cx="0" cy="0" r="${r}" fill="#0f172a" stroke="${isRogueDhcp ? '#ef4444' : (isRiskyOs ? '#f97316' : 'var(--line-soft)')}" stroke-width="1.5"/>
      
      <!-- Center Icon -->
      <g transform="translate(-11, -11)" style="color:${isRogueDhcp ? '#ef4444' : color}">${ico(icon, 22, "")}</g>
      
      <!-- Status Badge Dot -->
      <circle cx="${r - 5}" cy="${-r + 5}" r="5" fill="${isRogueDhcp ? '#ef4444' : color}" stroke="var(--bg)" stroke-width="2"/>
      
      ${threatBadges}
      ${switchPortBadge}
      ${openPortsBadge}
      
      <!-- Device Name Badge below Node -->
      <rect x="-65" y="${r + 5}" width="130" height="20" rx="10" fill="rgba(15, 23, 42, 0.94)" stroke="${hasThreat ? (isRogueDhcp ? '#ef4444' : '#f97316') : 'var(--line-soft)'}" stroke-width="0.8"/>
      <text x="0" y="${r + 19}" font-size="10.5" font-weight="700" fill="var(--txt)" text-anchor="middle">${esc(label)}</text>
      
      <!-- IP and Latency below Node -->
      <text x="0" y="${r + 34}" font-size="9.5" fill="var(--blue)" font-weight="600" text-anchor="middle">${esc(ip)} ${lat ? '· ' + lat : ''}</text>
    </g>`;
}

function setTopoCategory(cat) {
  S.topoCategoryFilter = cat;
  document.querySelectorAll(".topo-cat-btn").forEach(b => {
    b.classList.toggle("blue", b.dataset.cat === cat);
  });
  drawTopology();
}

function drawTopology(targetId) {
  if (typeof topoCloseDetails === "function") topoCloseDetails();
  const svg = $(targetId || "topoSvg2") || $("topoSvg");
  if (!svg) return;
  
  let rawData = S.topology || { nodes: [], edges: [] };
  
  // Filter active-only devices if S.topoActiveOnly is true
  let filteredNodes = rawData.nodes || [];
  if (S.topoActiveOnly) {
    filteredNodes = filteredNodes.filter(n => {
      if (["internet", "gateway", "router", "switch", "lan"].includes(n.id)) return true;
      const dev = S.devices.find(d => d.ip === n.ip);
      const status = dev?.status || n.status || "unknown";
      return status === "online" || status === "discovered" || Boolean(n.is_self);
    });
  }

  // Category filter
  if (S.topoCategoryFilter && S.topoCategoryFilter !== "all") {
    filteredNodes = filteredNodes.filter(n => {
      if (["internet", "gateway", "router", "switch", "lan"].includes(n.id)) return true;
      const dev = S.devices.find(d => d.ip === n.ip) || n;
      if (S.topoCategoryFilter === "threats") {
        const isRogueDhcp = Boolean(dev?.is_rogue_dhcp || n?.is_rogue_dhcp || dev?.rogue_dhcp);
        const isRiskyOs = Boolean(dev?.risky_os || /windows (xp|7|8|server 2008)/i.test(String(dev?.os_fingerprint || n?.os_fingerprint || "")));
        const hasOpenPorts = (dev?.classification?.open_ports || []).length > 0;
        return isRogueDhcp || isRiskyOs || hasOpenPorts;
      }
      if (S.topoCategoryFilter === "network") {
        return ["router", "firewall", "switch", "access_point", "network_device"].includes(dev.type);
      }
      if (S.topoCategoryFilter === "servers") {
        return dev.type === "server";
      }
      if (S.topoCategoryFilter === "clients") {
        return ["pc", "computer", "laptop", "phone", "mobile", "tablet"].includes(dev.type);
      }
      return true;
    });
  }

  const activeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = (rawData.edges || []).filter(e => activeIds.has(e.from) && activeIds.has(e.to));
  const data = { nodes: filteredNodes, edges: filteredEdges };

  const isMesh = S.topoLayout === "mesh";
  const layout = data && data.nodes?.length 
    ? (isMesh ? computeMeshTopologyLayout(data) : layoutTopology(data))
    : { pos: {}, W: 1100, H: 620, columns: [] };
  const { pos, W, H } = layout;

  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
  if (!data || !data.nodes || !data.nodes.length) {
    svg.innerHTML = `<text class="empty-note" x="${W / 2}" y="${H / 2}">${S.scanning ? "Ağ taranıyor…" : "Topoloji bekleniyor..."}</text>`;
    return;
  }

  const defs = `
    <defs>
      <pattern id="cyberGrid" width="40" height="40" patternUnits="userSpaceOnUse">
        <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(59, 155, 255, 0.05)" stroke-width="1"/>
        <circle cx="40" cy="40" r="1" fill="rgba(59, 155, 255, 0.12)"/>
      </pattern>
      <linearGradient id="edgeGradOnline" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#3b9bff"/>
        <stop offset="100%" stop-color="#3ddc84"/>
      </linearGradient>
    </defs>
  `;

  let edgePills = "";
  const edges = data.edges.map(e => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return "";
    const backbone = ["router","gateway","switch","lan","internet"].includes(e.from) && ["router","gateway","switch","lan","internet"].includes(e.to);
    const color = e.status === "online"
      ? (backbone ? "url(#edgeGradOnline)" : "#10b981")
      : e.status === "discovered"
        ? "#f5a623"
        : e.status === "offline"
          ? "#f2585b"
          : "#5a6b88";
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 + (backbone ? 0 : 10);
    const pathD = `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
    
    if (e.label) {
      edgePills += `
        <g class="topo-edge-port-pill" transform="translate(${mx.toFixed(1)}, ${my.toFixed(1)})">
          <rect x="-28" y="-9" width="56" height="18" rx="9" fill="rgba(15, 23, 42, 0.95)" stroke="#06b6d4" stroke-width="1.2"/>
          <text x="0" y="3.5" font-size="9" font-weight="700" fill="#22d3ee" text-anchor="middle">🔌 ${esc(e.label)}</text>
        </g>`;
    }
    
    return `<path class="edge ${e.status === 'online' ? 'flow' : ''}" stroke="${color}" stroke-width="${backbone ? '2.8' : '1.8'}" fill="none" stroke-dasharray="${e.status === 'online' ? '6 4' : 'none'}" d="${pathD}"/>`;
  }).join("");

  const labels = layout.columns.map(c => {
    if (!c.count) return "";
    return `
    <g transform="translate(${c.x}, ${c.headerY || 410})">
      <rect x="-85" y="-14" width="170" height="28" rx="14" fill="rgba(7, 18, 36, 0.95)" stroke="rgba(0, 240, 255, 0.6)" stroke-width="1.2"/>
      <text font-size="11" font-weight="700" fill="var(--cyan)" text-anchor="middle" dominant-baseline="central" letter-spacing="0.8">${esc(c.title)} (${c.count})</text>
    </g>`;
  }).join("");

  const nodes = data.nodes.map(n => pos[n.id] ? nodeSvg(n, pos[n.id]) : "").join("");

  svg.innerHTML = `
    ${defs}
    <rect width="100%" height="100%" fill="url(#cyberGrid)"/>
    <g id="topoLayer" transform="translate(${TOPO.x},${TOPO.y}) scale(${TOPO.k})">${labels}${edges}${edgePills}${nodes}</g>
  `;
  applyTopoTransform();
}

function topoFit(reset = true) {
  TOPO.x = 0;
  TOPO.y = 0;
  TOPO.k = 1;
  applyTopoTransform();
}

function topoZoom(f) {
  TOPO.k = Math.min(3, Math.max(0.4, TOPO.k * f));
  applyTopoTransform();
}

function topoReset() { topoFit(true); }

function applyTopoTransform() {
  document
    .querySelectorAll("#topoLayer")
    .forEach((l) =>
      l.setAttribute(
        "transform",
        `translate(${TOPO.x}, ${TOPO.y}) scale(${TOPO.k})`,
      ),
    );
}

function topoFullscreen() {
  const el = $("topoWrap");
  if (document.fullscreenElement) document.exitFullscreen();
  else if (el && el.requestFullscreen) el.requestFullscreen();
}

function bindTopoDrag(svg) {
  if (!svg || svg.dataset.bound) return;
  svg.dataset.bound = "1";
  svg.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      topoZoom(e.deltaY < 0 ? 1.12 : 1 / 1.12);
    },
    { passive: false },
  );
  svg.addEventListener("mousedown", (e) => {
    TOPO.drag = { x: e.clientX - TOPO.x, y: e.clientY - TOPO.y };
  });
  window.addEventListener("mousemove", (e) => {
    if (!TOPO.drag) return;
    TOPO.x = e.clientX - TOPO.drag.x;
    TOPO.y = e.clientY - TOPO.drag.y;
    applyTopoTransform();
  });
  window.addEventListener("mouseup", () => {
    TOPO.drag = null;
  });
}

function topoCloseDetails() {
  const d = $("topoDetailDrawer");
  if (d) d.classList.remove("open");
}

function showNode(id) {
  const n = (S.topology?.nodes || []).find(x => x.id === id);
  if (!n) return;
  const dev = S.devices.find(d => d.ip === n.ip);
  const displayName = topologyDeviceName(n);
  const type = dev?.type || n.type || "unknown";
  const typeLabel = TYPE_LABEL[type] || topologyTypeTitle(type);
  const status = dev?.status || n.status || "unknown";
  const statusLabel = deviceStatusLabel(status);
  const confidence = deviceConfidence(dev) ?? Math.round(Number(n.confidence || 0) * 100);
  const evidence = dev?.classification?.evidence || n.classification?.evidence || [];
  const reasons = dev?.classification?.reason || n.classification?.reason || [];
  const sources = dev?.discovery_sources || n.discovery_sources || [];
  const services = dev?.classification?.services || n.classification?.services || [];
  const ports = dev?.classification?.open_ports || n.classification?.open_ports || [];
  const statusReason = dev?.status_reason || n.status_reason || "N/A";
  
  const w = dev?.wmi_inventory || {};
  const isWmiSuccess = w.status === "Success";
  const inv = isWmiSuccess ? w : (dev?.fallback_inventory || {});
  
  const hw = inv.hardware || {};
  const sw = inv.software || { os_name: dev?.os_fingerprint || null, installed_programs: [] };
  const sec = inv.security || { active_user: null, antivirus: "Bilinmiyor", firewall: "Bilinmiyor" };

  const isRogueDhcp = Boolean(dev?.is_rogue_dhcp || n?.is_rogue_dhcp || dev?.rogue_dhcp);
  const isRiskyOs = Boolean(dev?.risky_os || /windows (xp|7|8|server 2008)/i.test(String(dev?.os_fingerprint || n?.os_fingerprint || "")));
  const switchIp = dev?.switch_ip || n?.switch_ip;
  const switchPort = dev?.switch_port || n?.switch_port;

  const drawer = $("topoDetailDrawer");
  if (!drawer) return;

  window._switchDrawerTab = function(tabId) {
    document.querySelectorAll('.drawer-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.drawer-tab-pane').forEach(p => p.style.display = 'none');
    const btn = document.getElementById('dt-btn-' + tabId);
    const pane = document.getElementById('dt-pane-' + tabId);
    if (btn) btn.classList.add('active');
    if (pane) pane.style.display = 'block';
  };

  const getVal = (val, suffix="") => val ? esc(val) + suffix : "N/A";

  const overviewGateway = S.overview?.gateway || {};
  const overviewInternet = S.overview?.internet || {};
  const gatewayIp = overviewGateway.ip || null;
  const gatewayLatency = overviewGateway.latency != null ? `${overviewGateway.latency} ms` : "N/A";
  const deviceIp = n.ip || dev?.ip || null;
  const latencyVal = dev?.latency != null ? `${dev.latency} ms` : "N/A";
  const internetLatency = overviewInternet.latency != null ? `${overviewInternet.latency} ms` : "N/A";
  const internetState = overviewInternet.connected == null ? "Ölçüm bekleniyor" : overviewInternet.connected ? "Bağlı" : "Erişim yok";
  const internetBadge = overviewInternet.connected == null ? "gray" : overviewInternet.connected ? "ok" : "fail";
  const deviceReachability = ["online", "discovered"].includes(status) ? "Erişilebilir" : status === "offline" ? "Erişilemiyor" : "Bilinmiyor";

  const internetPathHtml = `
    <div style="background:var(--panel-2);border:1px solid var(--line-soft);border-radius:12px;padding:12px 14px;margin-bottom:16px;position:relative;overflow:hidden">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <strong style="font-size:11px;color:var(--cyan);letter-spacing:0.5px;display:flex;align-items:center;gap:6px">
          <span style="font-size:14px">🌐</span> MANTIKSAL ERİŞİM ÖZETİ
        </strong>
        <span class="badge ${internetBadge}" style="font-size:9px">${esc(internetState)}</span>
      </div>

      <!-- Hop-by-Hop Path Nodes -->
      <div style="display:flex;align-items:center;justify-content:space-between;position:relative;padding:6px 0;z-index:2">
        
        <!-- Hop 1: WAN Internet -->
        <div style="text-align:center;flex:1">
          <div style="width:34px;height:34px;border-radius:50%;background:var(--bg);border:1.5px solid var(--cyan);display:grid;place-items:center;margin:0 auto;box-shadow:0 0 10px rgba(0,242,255,0.4)">
            <span style="font-size:15px">🌐</span>
          </div>
          <div style="font-size:9.5px;font-weight:700;color:var(--txt);margin-top:4px">İnternet WAN</div>
          <div style="font-size:8.5px;color:var(--muted)">${esc(overviewInternet.target || "Hedef bilinmiyor")} · ${esc(internetLatency)}</div>
        </div>

        <!-- Animated Flow Line 1 -->
        <div style="flex:1;height:2px;background:var(--line);position:relative;margin:0 -4px;margin-top:-14px">
          <div style="position:absolute;width:8px;height:8px;border-radius:50%;background:var(--cyan);top:-3px;box-shadow:0 0 6px var(--cyan);animation:pathFlow 1.6s linear infinite"></div>
        </div>

        <!-- Hop 2: Modem / Router Gateway -->
        <div style="text-align:center;flex:1">
          <div style="width:34px;height:34px;border-radius:50%;background:var(--bg);border:1.5px solid var(--blue);display:grid;place-items:center;margin:0 auto;box-shadow:0 0 8px rgba(59,155,255,0.3)">
            <span style="font-size:15px">🔀</span>
          </div>
          <div style="font-size:9.5px;font-weight:700;color:var(--txt);margin-top:4px">Gateway</div>
          <div style="font-size:8.5px;color:var(--muted)">${esc(gatewayIp || "Bilinmiyor")} · ${esc(gatewayLatency)}</div>
        </div>

        <!-- Animated Flow Line 2 -->
        <div style="flex:1;height:2px;background:var(--line);position:relative;margin:0 -4px;margin-top:-14px">
          <div style="position:absolute;width:8px;height:8px;border-radius:50%;background:var(--green);top:-3px;box-shadow:0 0 6px var(--green);animation:pathFlow 1.6s linear infinite 0.8s"></div>
        </div>

        <!-- Hop 3: Target Device -->
        <div style="text-align:center;flex:1">
          <div style="width:34px;height:34px;border-radius:50%;background:var(--bg);border:1.5px solid var(--green);display:grid;place-items:center;margin:0 auto;box-shadow:0 0 10px rgba(16,185,129,0.5)">
            <span style="font-size:15px">${ico(DEVICE_TYPE_ICON[type] || "cpu", 17)}</span>
          </div>
          <div style="font-size:9.5px;font-weight:700;color:var(--green);margin-top:4px">${esc(displayName.slice(0, 12))}</div>
          <div style="font-size:8.5px;color:var(--muted)">${esc(deviceIp || "Bilinmiyor")} · ${esc(latencyVal)}</div>
        </div>

      </div>

      <!-- Info Strip -->
      <div style="margin-top:8px;padding-top:6px;border-top:1px solid var(--line-soft);display:flex;justify-content:space-between;font-size:9px;color:var(--txt-2)">
        <span>Gösterim: <b style="color:var(--cyan)">mantıksal, traceroute değildir</b></span>
        <span>Hedef durumu: <b>${esc(deviceReachability)}</b></span>
      </div>
    </div>
  `;

  drawer.innerHTML = `
    <style>
      @keyframes pathFlow {
        0% { left: 0%; opacity: 0; }
        20% { opacity: 1; }
        80% { opacity: 1; }
        100% { left: 100%; opacity: 0; }
      }
      .drawer-header { padding: 16px; background: var(--bg-2); border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 10; }
      .drawer-tabs { display: flex; gap: 8px; padding: 0 16px; border-bottom: 1px solid var(--line); background: var(--panel); position: sticky; top: 100px; z-index: 9; }
      .drawer-tab-btn { background: transparent; border: none; padding: 12px 4px; color: var(--muted); font-size: 11px; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; }
      .drawer-tab-btn:hover { color: var(--txt); }
      .drawer-tab-btn.active { color: var(--blue); border-bottom-color: var(--blue); }
      .drawer-body { padding: 16px; overflow-y: auto; flex: 1; }
      .drawer-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--line-soft); font-size: 11.5px; }
      .drawer-row span:first-child { color: var(--muted); }
      .drawer-row span:last-child { color: var(--txt); font-weight: 600; text-align: right; word-break: break-all; max-width: 65%; }
      .drawer-footer { padding: 12px 16px; border-top: 1px solid var(--line); background: var(--bg-2); position: sticky; bottom: 0; display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; z-index: 10; }
    </style>
    
    <div class="drawer-header">
      <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div style="display:flex; gap:12px; align-items:center;">
          <div class="device-detail-icon" style="width:40px;height:40px;border-radius:10px;background:var(--bg);border:1px solid var(--line);display:grid;place-items:center;color:var(--blue);">${ico(DEVICE_TYPE_ICON[type] || "cpu", 22)}</div>
          <div>
            <h3 style="margin:0 0 4px 0; font-size:15px; color:var(--txt);">${esc(displayName)}</h3>
            <div style="color:var(--muted); font-size:11px;">${esc(typeLabel)} · ${esc(n.ip || "N/A")}</div>
          </div>
        </div>
        <button class="mini-btn" style="padding:4px 8px; background:transparent; border-color:transparent; color:var(--txt-2); font-size:14px;" onclick="topoCloseDetails()">✕</button>
      </div>
      <div style="margin-top:12px; display:flex; gap:6px; flex-wrap:wrap;">
        <span class="badge ${deviceStatusClass(status)}">${esc(statusLabel)}</span>
        <span class="badge info">${esc(connectivityLabel(dev || n))}</span>
        ${isRogueDhcp ? `<span class="badge fail">🚨 ROGUE DHCP</span>` : ''}
        ${isRiskyOs ? `<span class="badge warn">⚠️ Riskli / EOL OS</span>` : ''}
        ${dev?.unified_inventory?.verified ? `<span class="badge ok">${esc(dev.unified_inventory.inventory_source || "Envanter")} Doğrulandı</span>` : ''}
      </div>
    </div>

    <div class="drawer-tabs">
      <button class="drawer-tab-btn active" id="dt-btn-overview" onclick="_switchDrawerTab('overview')">Genel Bakış</button>
      <button class="drawer-tab-btn" id="dt-btn-hardware" onclick="_switchDrawerTab('hardware')">Donanım & Yazılım</button>
      <button class="drawer-tab-btn" id="dt-btn-network" onclick="_switchDrawerTab('network')">Ağ & Portlar</button>
    </div>

    <div class="drawer-body">
      <!-- OVERVIEW TAB -->
      <div id="dt-pane-overview" class="drawer-tab-pane" style="display:block;">
        ${internetPathHtml}
        
        <!-- Physical Switch Location Card -->
        <div style="background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.3);border-radius:10px;padding:10px 12px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;font-weight:700">Fiziksel Switch Bağlantısı</div>
            <div style="font-size:12px;font-weight:700;color:var(--cyan);margin-top:2px">
              ${switchIp ? `Switch: ${esc(switchIp)}` : 'Switch: Mantıksal LAN'} · ${switchPort ? `<span style="color:#22d3ee;background:rgba(6,182,212,0.2);padding:2px 6px;border-radius:4px">Port ${esc(switchPort)}</span>` : 'Port: Dinamik'}
            </div>
          </div>
          <span style="font-size:18px">🔌</span>
        </div>

        <div class="topo-detail-grid" style="margin-top:0;">
          <div><span>IP Adresi</span><b>${getVal(n.ip)}</b></div>
          <div><span>MAC Adresi</span><b>${getVal(dev?.mac || n.mac)}</b></div>
          <div><span>Hostname</span><b>${getVal(dev?.hostname || n.hostname)}</b></div>
          <div><span>Üretici (Vendor)</span><b>${getVal(dev?.vendor || n.vendor)}</b></div>
          <div><span>İşletim Sistemi</span><b>${getVal(dev?.os_fingerprint)}</b></div>
          <div><span>Tanımlama Güveni</span><b>${confidence}%</b></div>
        </div>
        <div class="topo-detail-section" style="margin-top:16px;"><b>Durum Analizi</b><p style="color:var(--txt-2);">${esc(statusReason)}</p></div>
        ${ports.length || services.length ? `<div class="topo-detail-section" style="margin-top:16px;"><b>Açık Portlar ve Servisler</b><p style="color:var(--txt-2);">${esc(services.map(s => s.service || s.name || s).join(", ") || "Port: " + ports.join(", "))}</p></div>` : ""}
      </div>

      <!-- HARDWARE TAB -->
      <div id="dt-pane-hardware" class="drawer-tab-pane" style="display:none;">
        <div class="topo-detail-section" style="margin-top:0; border-top:none; padding-top:0;">
          <h4 style="margin:0 0 10px 0; color:var(--blue); font-size:12px;">Sistem Bileşenleri</h4>
          <div class="drawer-row"><span>CPU Modeli</span><span>${getVal(hw.cpu_model || hw.cpu_name)}</span></div>
          <div class="drawer-row"><span>Çekirdek</span><span>${getVal(hw.cores)}</span></div>
          <div class="drawer-row"><span>RAM Kapasitesi</span><span>${getVal(hw.ram_gb, " GB")}</span></div>
          <div class="drawer-row"><span>GPU Modeli</span><span>${getVal(hw.gpu)}</span></div>
          <div class="drawer-row"><span>Anakart</span><span>${getVal(hw.motherboard_maker)} ${getVal(hw.motherboard_model)}</span></div>
        </div>
        <div class="topo-detail-section" style="margin-top:16px;">
          <h4 style="margin:0 0 10px 0; color:var(--cyan); font-size:12px;">Yazılım & Güvenlik</h4>
          <div class="drawer-row"><span>İşletim Sistemi</span><span>${getVal(sw.os_name)}</span></div>
          <div class="drawer-row"><span>Aktif Kullanıcı</span><span>${getVal(sec.active_user)}</span></div>
          <div class="drawer-row"><span>Antivirüs</span><span>${getVal(sec.antivirus)}</span></div>
          <div class="drawer-row"><span>Güvenlik Duvarı</span><span>${getVal(sec.firewall)}</span></div>
        </div>
      </div>

      <!-- NETWORK TAB -->
      <div id="dt-pane-network" class="drawer-tab-pane" style="display:none;">
        <div class="topo-detail-section" style="margin-top:0; border-top:none; padding-top:0;">
          <h4 style="margin:0 0 10px 0; color:var(--purple); font-size:12px;">Ağ Metrikleri & Port Detayları</h4>
          <div class="drawer-row"><span>Ortalama Gecikme</span><span>${dev?.latency != null ? dev.latency + " ms" : (n.latency != null ? n.latency + " ms" : "N/A")}</span></div>
          <div class="drawer-row"><span>Switch Konumu</span><span>${switchIp ? `${switchIp} (Port ${switchPort || '?'})` : 'Mantıksal LAN'}</span></div>
          <div class="drawer-row"><span>NetBIOS Adı</span><span>${getVal(dev?.netbios_name)}</span></div>
          <div class="drawer-row"><span>SNMP SysDescr</span><span>${getVal(dev?.snmp_sysdescr)}</span></div>
        </div>
        <div class="topo-detail-section" style="margin-top:16px;"><b>Keşif Yöntemleri</b><div class="source-pills" style="margin-top:6px">${sources.length ? sources.map(s => `<span>${esc(discoveryLabel(s))}</span>`).join("") : "<span>N/A</span>"}</div></div>
        ${reasons.length ? `<div class="topo-detail-section" style="margin-top:16px;"><b>Tanımlama Kanıtları</b><p style="color:var(--txt-2);">${reasons.map(esc).join(" · ")}</p></div>` : ""}
      </div>
    </div>

    <div class="drawer-footer">
      ${n.ip ? `<button class="mini-btn blue" onclick="quickPing('${esc(n.ip)}')">⚡ Ping</button>` : ""}
      ${n.ip ? `<button class="mini-btn" onclick="quickTraceroute('${esc(n.ip)}')">🛣️ Trace</button>` : ""}
      ${n.ip && S.user?.role === "admin" ? `<button class="mini-btn" onclick="quickScan('${esc(n.ip)}')">🔍 Port Tara</button>` : ""}
      ${n.ip && S.user?.role === "admin" ? `<button class="mini-btn" onclick="openWmiScanModal('${esc(n.ip)}')">🔑 Envanter</button>` : ""}
      ${n.ip ? `<button class="mini-btn" style="color:#0ea5e9;border-color:#0ea5e9;" onclick="downloadRdp(\'${esc(n.ip)}\', \'${esc(n.hostname || n.ip)}\')">💻 RDP</button>` : ""}
    </div>
  `;
  drawer.classList.add("open");
}

function quickPing(ip) {
  closeModalForce();
  go("ping");
  setTimeout(() => {
    const t = $("pgPingTarget");
    if (t) {
      t.value = ip;
      runPagePing();
    }
  }, 120);
}

function quickTraceroute(ip) {
  closeModalForce();
  go("traceroute");
  setTimeout(() => {
    const t = $("trTarget");
    if (t) {
      t.value = ip;
      runTraceroute();
    }
  }, 120);
}

function quickScan(ip) {
  if (S.user?.role !== "admin") return;
  closeModalForce();
  go("portscan");
  setTimeout(() => {
    const t = $("psTarget");
    if (t) {
      t.value = ip;
      runPortScan();
    }
  }, 120);
}

function renderTopologyPage() {
  const el = $("page-topology");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <h2 style="margin:0">Ağ Topolojisi</h2>
            <div style="display:flex;gap:4px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:3px">
              <button class="mini-btn ${S.topoLayout !== 'mesh' ? 'blue' : ''}" onclick="setTopoLayout('tree')">🌐 Katmanlı Hiyerarşi</button>
              <button class="mini-btn ${S.topoLayout === 'mesh' ? 'blue' : ''}" onclick="setTopoLayout('mesh')">🕸️ Örgü (Mesh) Topoloji</button>
            </div>
            <!-- NOC Kategori Filtreleri -->
            <div class="topo-filter-bar">
              <button class="mini-btn topo-cat-btn ${!S.topoCategoryFilter || S.topoCategoryFilter === 'all' ? 'blue' : ''}" data-cat="all" onclick="setTopoCategory('all')">Tümü</button>
              <button class="mini-btn topo-cat-btn ${S.topoCategoryFilter === 'threats' ? 'blue' : ''}" data-cat="threats" onclick="setTopoCategory('threats')">🚨 Tehdit & Riskler</button>
              <button class="mini-btn topo-cat-btn ${S.topoCategoryFilter === 'network' ? 'blue' : ''}" data-cat="network" onclick="setTopoCategory('network')">🔀 Ağ Donanımları</button>
              <button class="mini-btn topo-cat-btn ${S.topoCategoryFilter === 'servers' ? 'blue' : ''}" data-cat="servers" onclick="setTopoCategory('servers')">🖥️ Sunucular</button>
              <button class="mini-btn topo-cat-btn ${S.topoCategoryFilter === 'clients' ? 'blue' : ''}" data-cat="clients" onclick="setTopoCategory('clients')">💻 İstemciler</button>
            </div>
          </div>
          <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">
            <label style="font-size:11px;color:var(--txt-2);display:flex;align-items:center;gap:5px;cursor:pointer;background:var(--panel-2);border:1px solid var(--line-soft);padding:4px 8px;border-radius:6px">
              <input type="checkbox" id="topoActiveOnly" ${S.topoActiveOnly ? "checked" : ""} onchange="toggleTopoActiveOnly(this.checked)" />
              Sadece Aktif Cihazlar
            </label>
            <button class="mini-btn" onclick="topoZoom(1.2)">+</button>
            <button class="mini-btn" onclick="topoZoom(1/1.2)">−</button>
            <button class="mini-btn" onclick="topoReset()">Ortala</button>
            <button class="mini-btn" onclick="topoFit(true)">Sığdır</button>
            ${S.user?.role === "admin" ? `<button class="mini-btn blue" onclick="scanNetwork()">Ağı Tara</button>` : ""}
          </div>
        </div>
        <div class="topo-wrap" style="height:calc(100vh - 250px); min-height:460px" id="topoWrap2">
          <svg class="topo-svg" id="topoSvg2"></svg>
          <aside class="topo-detail-drawer" id="topoDetailDrawer"></aside>
        </div>
      </div>
    `;
    bindTopoDrag($("topoSvg2"));
  }
  drawTopology("topoSvg2");
}

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
            <button class="mini-btn" style="background:#10b981;border-color:#059669;color:white;margin-right:8px;" onclick="window.open('/api/export/devices', '_blank')">📊 Excel'e Aktar</button>
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
            ${S.user?.role === "admin" ? `<button class="mini-btn blue" id="devScanBtn" onclick="scanNetwork()">Ağı Tara</button>` : ""}
            ${S.user?.role === "admin" ? `<button class="mini-btn" onclick="openWmiScanModal()">🔑 Yetkili Envanter</button>` : ""}
            ${S.user?.role === "admin" ? `<button class="mini-btn" id="deepScanBtn" onclick="runDeepScan()">Port Tarama</button>` : ""}
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
  if (S.user?.role !== "admin" || S.scanning) return;
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
  } catch (e) {}
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
  } catch (e) { S.deviceScanError = e.message || null; }
}

async function refreshTopology() {
  try {
    const data = await get("/api/topology");
    S.topology = data.topology || data;
    drawTopology();
  } catch (e) {}
}

function renderSystemStatus(sys) {
  const quickRow = $("quickRow");
  if (quickRow && sys) {
    const percent = (value) => value == null ? "-" : `${value}%`;
    const netSpeed = sys.net_total_mbps == null ? "-" : `${Number(sys.net_total_mbps).toFixed(2)} Mbps`;
    quickRow.innerHTML = `
      <div class="quick"><span style="color:var(--blue); font-weight:bold;">${percent(sys.cpu)}</span><span>CPU</span></div>
      <div class="quick"><span style="color:var(--purple); font-weight:bold;">${percent(sys.ram)}</span><span>RAM</span></div>
      <div class="quick"><span style="color:var(--orange); font-weight:bold;">${percent(sys.disk)}</span><span>DİSK</span></div>
      <div class="quick"><span style="color:var(--green); font-weight:bold;">${netSpeed}</span><span>AĞ</span></div>
    `;
  }
}

async function refreshOverview() {
  try {
    const data = await get("/api/overview");
    S.overview = data.overview || data;
    renderStats();
    renderInventoryCommandCenter();
    renderNetworkHealth();
    if (S.overview.system) renderSystemStatus(S.overview.system);
  } catch (e) {}
}

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

async function refreshConnections() {
  try {
    const data = await get("/api/overview");
    const c = data.connections || {};
    S.connections = {
      tcp: Number(c.tcp || 0),
      udp: Number(c.udp || 0),
      total: Number(c.total || 0),
      supported: c.supported !== false,
    };
    renderStats();
  } catch (e) {}
}

// DÜZELTME: refreshAll() bu fonksiyonu çağırıyordu ama hiç tanımlı değildi
// (sessizce Promise.allSettled içinde yutuluyordu). "Ağ Trafiği (Son 5 Dakika)"
// grafiği bu yüzden sayfa açılışında hep boş kalıyordu; WebSocket üzerinden
// canlı örnek gelene kadar hiçbir veri yoktu. Artık geçmiş örnekleri
// /api/traffic'ten çekip sparkUp/sparkDown'ı dolduruyor ve grafiği çiziyor.
async function refreshTraffic() {
  try {
    const rows = await get("/api/traffic?minutes=5");
    const list = Array.isArray(rows) ? rows : rows.traffic || [];
    if (list.length) {
      S.sparkUp = list.map((r) => {
        const mbps = ((Number(r.wifi_sent) || 0) + (Number(r.eth_sent) || 0)) / 125000;
        return Number(mbps.toFixed(2));
      });
      S.sparkDown = list.map((r) => {
        const mbps = ((Number(r.wifi_recv) || 0) + (Number(r.eth_recv) || 0)) / 125000;
        return Number(mbps.toFixed(2));
      });
    }
    if (typeof drawTrafficChart === "function") drawTrafficChart();
  } catch (e) {}
}

async function refreshAll() {
  if (!S.auto) return;
  await Promise.allSettled([
    refreshOverview(),
    refreshTraffic(),
    refreshConnections(),
    refreshDevices(),
    refreshNetworkInfo(),
    refreshTopology(),
    refreshLogs(),
  ]);
  updateLastScan();
}

function updateLastScan() {
  const el = $("lastUpdate");
  if (el) el.textContent = nowTime();
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
    const traffic = message.traffic || message.data || {};
    S.traffic.up = Number(traffic.upload ?? traffic.up ?? 0);
    S.traffic.down = Number(traffic.download ?? traffic.down ?? 0);
    // DÜZELTME: sparkUp/sparkDown dizilerine hiç veri eklenmiyordu, bu yüzden
    // hem stat kartlarındaki mini-sparkline'lar hem "Ağ Trafiği (Son 5 Dakika)"
    // grafiği hep boştu. Son 60 örneği (yaklaşık 5 dk, 5 sn aralıkla) tutuyoruz.
    const MAX_POINTS = 60;
    S.sparkUp.push(S.traffic.up);
    S.sparkDown.push(S.traffic.down);
    if (S.sparkUp.length > MAX_POINTS) S.sparkUp.shift();
    if (S.sparkDown.length > MAX_POINTS) S.sparkDown.shift();
    if (typeof renderStats === "function") renderStats();
    if (typeof drawTrafficChart === "function") drawTrafficChart();
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
  }, 5000);
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
