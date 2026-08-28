
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
  sparkTs: [],
  trafficSampleTs: null,
  trafficSimulated: false,
  connections: { tcp: 0, udp: 0, total: 0, supported: true },
  overview: {},
  logs: [],
  logLevel: "all",
  logQuery: "",
  system: {},
  topoLayer: "all",
  inventoryAssets: [],
  inventoryAssetDetail: null,
  rbacRoles: [],
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

function fmtBandwidthRate(bps) {
  const b = Number(bps || 0);
  if (b <= 0) return `0.00 <span style="font-size:12px;color:var(--muted)">Mbps</span>`;
  if (b >= 1_000_000) {
    const mbps = b / 1_000_000;
    return `${mbps < 10 ? mbps.toFixed(2) : (mbps < 100 ? mbps.toFixed(1) : Math.round(mbps))} <span style="font-size:12px;color:var(--muted)">Mbps</span>`;
  }
  if (b >= 1_000) {
    const kbps = b / 1_000;
    return `${kbps < 100 ? kbps.toFixed(1) : Math.round(kbps)} <span style="font-size:12px;color:var(--muted)">kbps</span>`;
  }
  return `${Math.round(b)} <span style="font-size:12px;color:var(--muted)">bps</span>`;
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
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  git_diff: '<circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M6 9v12M13 6h3a2 2 0 0 1 2 2v7"/>',
  trending: '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>',
  zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
};

function ico(name, size, cls) {
  const body = ICON[name] || ICON.question;
  const s = size || 16;
  return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="${cls || ""}">${body}</svg>`;
}

/* ---------- Oturum / token yönetimi ---------- */

Object.assign(globalThis, {
  $,
  S,
  esc,
  fmtMbps,
  fmtBandwidthRate,
  nowTime,
  isRandomizedMac,
  deviceDisplayName,
  deviceVendorDisplay,
  deviceSubtitle,
  deviceConfidence,
  formatSeen,
  discoveryLabel,
  deviceStatus,
  deviceStatusLabel,
  deviceStatusClass,
  connectivityLabel,
  TYPE_LABEL,
  DEVICE_TYPE_ICON,
  ICON,
  ico,
});
