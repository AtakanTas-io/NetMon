import "./auth.js";

const NAV_ITEMS = [
  { id: "dashboard", label: "Kontrol Merkezi", icon: "monitor" },
  { id: "devices", label: "BT Varlık Envanteri", icon: "list" },
  { id: "topology", label: "Ağ Keşfi ve Topoloji", icon: "wifi" },
  { id: "ipam", label: "IPAM & Subnet Havuzu", icon: "grid" },
  { id: "toptalkers", label: "Aktif Oturumlar & Trafik", icon: "activity" },
  { id: "ncm", label: "Switch Config Diff", icon: "terminal" },
  { id: "security", label: "Güvenlik Görünürlüğü", icon: "shield" },
  { id: "reports", label: "Raporlama & SLA", icon: "report", permission: "reports.view" },
  { id: "locations", label: "Lokasyon Haritası", icon: "route", permission: "locations.view" },
  { id: "access", label: "Yetki ve Hazırlık", icon: "lock" },
  { id: "analyst", label: "Analist Merkezi", icon: "shield" },
  { id: "purpleteam", label: "Cyber Lab", icon: "shield" },
  { id: "egitim", label: "NetMon Academy", icon: "book" },
  { id: "settings", label: "Ayarlar", icon: "gear", permission: "system.settings.manage" },
  { id: "management", label: "Yönetim", icon: "users", permission: "users.manage" },
];

const PAGE_TITLES = Object.fromEntries(NAV_ITEMS.map((n) => [n.id, n.label]));
Object.assign(PAGE_TITLES, {
  dashboard: "Kontrol Merkezi",
  devices: "BT Varlık Envanteri",
  topology: "Ağ Keşfi ve Topoloji",
  ipam: "IPAM & Subnet Havuz Sağlığı",
  toptalkers: "AKTİF AĞ OTURUMLARI & TOPLAM TRAFİK",
  ncm: "Ağ Cihazı Konfigürasyon Yedeği & Diff",
  ping: "Ağ Sağlığı ve Teşhis",
  security: "Güvenlik Görünürlüğü",
  analyst: "Analist Merkezi",
  logs: "Operasyon Kayıtları",
  reports: "Operasyon, Kapasite ve SLA Raporları",
  locations: "Şube, Bina ve Kabinet Görünümü",
  access: "Yetki ve Hazırlık Merkezi",
});

function buildNav() {
  const nav = $("nav");
  if (!nav) return;
  nav.innerHTML = NAV_ITEMS.filter((item) => !item.permission || hasPermission(item.permission))
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
  const requestedItem = NAV_ITEMS.find(item => item.id === page);
  if (requestedItem?.permission && !hasPermission(requestedItem.permission)) {
    toast("Bu sayfa mevcut rolünüz için yetkili değil.", "warn");
    page = "dashboard";
  }
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
      case "dashboard":
        refreshDashboardWidgets();
        break;
      case "ipam":
        renderIpamPage();
        refreshIpam();
        break;
      case "toptalkers":
        renderTopTalkersPage();
        refreshTopTalkers();
        break;
      case "ncm":
        renderNcmPage();
        refreshNcm();
        break;
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
      case "reports":
        renderReportsPage();
        refreshReports();
        break;
      case "locations":
        renderLocationsPage();
        refreshLocations();
        break;
      case "access":
        renderAccessPage();
        refreshAccessCenter();
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

function applyThemePreference(theme) {
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
  else root.removeAttribute("data-theme");
  updateThemeIcon();
}

async function loadThemePreference() {
  try { const data = await get("/api/preferences"); S.theme = data.theme || "system"; applyThemePreference(S.theme); }
  catch (_) { applyThemePreference("system"); }
}

async function toggleTheme() {
  const currentLight = document.documentElement.getAttribute("data-theme") === "light" || (!document.documentElement.hasAttribute("data-theme") && matchMedia("(prefers-color-scheme: light)").matches);
  const next = currentLight ? "dark" : "light";
  applyThemePreference(next);
  S.theme = next;
  try { await apiFetch("/api/preferences", { method: "PUT", body: { theme: next } }); }
  catch (error) { toast(`Tema tercihi kaydedilemedi: ${error.message}`, "warn"); }
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

Object.assign(globalThis, { applyThemePreference, loadThemePreference });

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

Object.assign(globalThis, {
  NAV_ITEMS,
  PAGE_TITLES,
  buildNav,
  go,
  toggleSidebar,
  updateThemeIcon,
  toggleTheme,
  initStaticIcons,
  toggleAuto,
  tickClock,
});
