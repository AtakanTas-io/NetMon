import "./ipam.js";

function renderTopTalkersPage() {
  const el = $("page-toptalkers");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; gap:10px;">
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-size:20px; color:var(--cyan)">📊</span>
            <div>
              <h2 style="margin:0">Bu Bilgisayarın Canlı Ağ Bağlantıları</h2>
              <small style="color:var(--txt-2)">Hangi uygulamanın internet veya yerel ağdaki hangi adresle iletişim kurduğunu gösterir.</small>
            </div>
          </div>
          <div class="right" style="display:flex;align-items:center;gap:10px">
            <button class="mini-btn blue" id="talkersRefreshBtn" onclick="refreshTopTalkers(true)">⚡ Şimdi Güncelle</button>
          </div>
        </div>
        <div class="panel-body">
          <div class="traffic-page-intro">
            <div class="traffic-explainer">
              <b>Bu sayfa ne gösterir?</b>
              <p>Aşağıdaki her satır, bu bilgisayardaki bir uygulamanın açık TCP bağlantısını temsil eder. Bir uygulama aynı hedefe birden fazla bağlantı açabilir; bağlantı sayısı cihaz veya kullanıcı sayısı değildir.</p>
            </div>
            <div class="traffic-live-card">
              <b>Bilgisayarın anlık ağ kullanımı</b>
              <p>Ağ kartlarının toplam hızıdır; tek tek bağlantılara dağıtılmaz.</p>
              <div class="traffic-live-values">
                <span>Toplam<strong id="talkersTotalBandwidth">-</strong></span>
                <span>Alınan<strong id="talkersRxBandwidth">-</strong></span>
                <span>Gönderilen<strong id="talkersTxBandwidth">-</strong></span>
              </div>
              <p id="trafficSampleStatus">Ölçüm zamanı bekleniyor.</p>
            </div>
          </div>
          <div id="trafficPrivilegeBanner" style="display:none; margin-bottom:12px; padding:10px 12px; border-radius:8px; font-size:11.5px"></div>
          <div class="traffic-metric-grid">
            <div class="traffic-metric-card"><small>Açık TCP bağlantısı</small><strong id="trafficSessionCount" style="color:var(--cyan)">-</strong><p>Şu anda iletişime açık bağlantılar</p></div>
            <div class="traffic-metric-card"><small>Bağlanılan farklı adres</small><strong id="trafficRemoteCount">-</strong><p>Tekrarsız uzak IP adresi sayısı</p></div>
            <div class="traffic-metric-card"><small>Tespit edilen uygulama</small><strong id="trafficProcessCount">-</strong><p>Bağlantı sahibi görülebilen programlar</p></div>
          </div>
          <div class="traffic-filter-bar">
            <input id="trafficSessionSearch" type="search" placeholder="Uygulama, IP veya servis ara…" oninput="renderTrafficSessions()">
            <select id="trafficStateFilter" onchange="renderTrafficSessions()">
              <option value="all">Tüm bağlantı durumları</option>
              <option value="ESTABLISHED">Bağlantı açık</option>
              <option value="SYN_SENT">Bağlanıyor</option>
              <option value="CLOSE_WAIT">Kapanması bekleniyor</option>
            </select>
            <select id="trafficScopeFilter" onchange="renderTrafficSessions()">
              <option value="all">Tüm hedef türleri</option>
              <option value="internet">İnternet</option>
              <option value="local">Yerel/özel ağ</option>
              <option value="unknown">Bilinmeyen</option>
            </select>
            <span class="traffic-filter-result" id="trafficFilterResult">- bağlantı gösteriliyor</span>
          </div>
          <div id="topTalkersFullLeaderboard">
            <div class="skeleton-box skeleton-line" style="height:55px; margin-bottom:8px"></div>
            <div class="skeleton-box skeleton-line" style="height:55px; margin-bottom:8px"></div>
            <div class="skeleton-box skeleton-line" style="height:55px; margin-bottom:8px"></div>
            <div class="skeleton-box skeleton-line" style="height:55px"></div>
          </div>
        </div>
      </div>
    `;
  }
}

let trafficSessionsSnapshot = [];
const openTrafficSessionGroups = new Set();
let trafficSessionIds = null;
const trafficSessionFlashes = new Map();

function trafficSessionGroupKey(session) {
  return JSON.stringify([session.process_name || "", session.local_ip || "", session.pid ?? null]);
}

function trafficSessionKey(session) {
  return JSON.stringify([trafficSessionGroupKey(session), session.local_port, session.remote_ip,
    session.remote_port, session.protocol || "TCP"]);
}

function updateTrafficSessionsSnapshot(sessions) {
  const now = Date.now();
  const ids = new Set(sessions.map(trafficSessionKey));
  for (const id of ids) {
    if (trafficSessionIds && !trafficSessionIds.has(id)) trafficSessionFlashes.set(id, now + 1500);
  }
  for (const [id, until] of trafficSessionFlashes) {
    if (!ids.has(id) || until <= now) trafficSessionFlashes.delete(id);
  }
  trafficSessionIds = ids;
  trafficSessionsSnapshot = sessions;
}

function toggleTrafficSessionGroup(button) {
  const group = button.closest("tbody");
  const expanded = group.classList.toggle("is-open");
  if (expanded) openTrafficSessionGroups.add(group.dataset.groupKey);
  else openTrafficSessionGroups.delete(group.dataset.groupKey);
  button.setAttribute("aria-expanded", String(expanded));
  button.querySelector(".traffic-group-arrow").textContent = expanded ? "▾" : "▸";
  closeTrafficSessionMenus();
}

function closeTrafficSessionMenus() {
  document.querySelectorAll(".traffic-session-actions.is-open").forEach(menu => {
    menu.classList.remove("is-open");
    menu.querySelector(".traffic-menu-toggle").setAttribute("aria-expanded", "false");
  });
}

function toggleTrafficSessionMenu(button) {
  const menu = button.closest(".traffic-session-actions");
  const wasOpen = menu.classList.contains("is-open");
  closeTrafficSessionMenus();
  menu.classList.toggle("is-open", !wasOpen);
  button.setAttribute("aria-expanded", String(!wasOpen));
}

document.addEventListener("click", event => {
  if (!event.target.closest(".traffic-menu-toggle")) closeTrafficSessionMenus();
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    document.querySelector(".traffic-session-actions.is-open .traffic-menu-toggle")?.focus();
    closeTrafficSessionMenus();
  }
});

function renderTrafficSessions() {
  const container = $("topTalkersFullLeaderboard");
  if (!container) return;

  const query = ($("trafficSessionSearch")?.value || "").trim().toLocaleLowerCase("tr-TR");
  const selectedUser = $("trafficUserFilter")?.value || "all";
  const direction = $("trafficDirectionFilter")?.value || "all";
  const state = $("trafficStateFilter")?.value || "all";
  const scope = $("trafficScopeFilter")?.value || "all";
  const attention = $("trafficAttentionFilter")?.value || "all";
  const sessions = trafficSessionsSnapshot.filter(s => {
    const haystack = [
      s.process_username, s.process_name, s.destination_name, ...(s.dns_names || []),
      s.remote_ip, s.remote_port, s.local_ip, s.primary_protocol, s.app_category,
      s.attention_reason, s.pid,
    ]
      .filter(value => value !== null && value !== undefined)
      .join(" ")
      .toLocaleLowerCase("tr-TR");
    return (!query || haystack.includes(query))
      && (selectedUser === "all" || (s.process_username || "") === selectedUser)
      && (direction === "all" || s.direction === direction)
      && (state === "all" || s.state === state)
      && (scope === "all" || s.scope === scope)
      && (attention === "all" || s.attention_level === attention);
  });

  const result = $("trafficFilterResult");
  if (result) result.textContent = `${sessions.length} / ${trafficSessionsSnapshot.length} bağlantı gösteriliyor`;

  if (!trafficSessionsSnapshot.length) {
    container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--muted)">Uzak bir adrese bağlı açık TCP bağlantısı bulunamadı.</div>`;
    return;
  }
  if (!sessions.length) {
    container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--muted)">Seçilen arama ve filtrelerle eşleşen bağlantı yok.</div>`;
    return;
  }

  const endpointText = (ip, port) => `${String(ip || "").includes(":") ? `[${ip}]` : ip}:${port || 0}`;
  const stateLabel = {
    ESTABLISHED: "Bağlantı açık",
    SYN_SENT: "Bağlanıyor",
    CLOSE_WAIT: "Uygulamanın kapatması bekleniyor",
  };
  const stateHelp = {
    ESTABLISHED: "Bağlantı kuruldu ve veri alışverişine hazır.",
    SYN_SENT: "Uzak sistemden bağlantı yanıtı bekleniyor.",
    CLOSE_WAIT: "Uzak taraf kapattı; yerel uygulamanın bağlantıyı sonlandırması bekleniyor.",
  };
  const directionLabel = {
    outbound: "Giden bağlantı",
    inbound: "Gelen bağlantı",
    unknown: "Yön belirsiz",
  };
  const destinationSourceLabel = {
    inventory: "NetMon envanter eşleşmesi",
    dns_cache: "Windows DNS önbelleği adayı",
    ip_only: "Yalnızca socket IP bilgisi",
  };

  const groups = new Map();
  for (const session of sessions) {
    const key = trafficSessionGroupKey(session);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(session);
  }
  const isNew = session => (trafficSessionFlashes.get(trafficSessionKey(session)) || 0) > Date.now();
  container.innerHTML = `
    <div style="overflow:auto; max-height:590px; border:1px solid var(--line-soft); border-radius:9px">
      <table style="min-width:1260px">
        <thead><tr>
          <th>Kullanan hesap</th><th>Yerel uç</th><th>Bağlanılan hedef / Uzak uç</th><th>Servis / port</th><th>Yön</th><th>TCP durumu</th><th>Kapsam</th><th>İşlemler</th>
        </tr></thead>
        ${[...groups].map(([key, members]) => {
          const expanded = openTrafficSessionGroups.has(key);
          const first = members[0];
          return `<tbody class="traffic-session-group${expanded ? " is-open" : ""}" data-group-key="${esc(key)}">
            <tr class="traffic-group-heading${members.some(isNew) ? " highlight-flash" : ""}"><td colspan="8">
              <button class="mini-btn traffic-group-toggle" aria-expanded="${expanded}" onclick="toggleTrafficSessionGroup(this)">
                <span class="traffic-group-arrow" aria-hidden="true">${expanded ? "▾" : "▸"}</span>
                <b>${esc(first.process_name || "Uygulama adı okunamadı")}</b>
                <span>PID ${esc(first.pid ?? "-")}</span><code>${esc(first.local_ip || "-")}</code>
                <span>${members.length} bağlantı</span>
              </button>
            </td></tr>${members.map(s => {
          const remote = endpointText(s.remote_ip, s.remote_port);
          const local = endpointText(s.local_ip, s.local_port);
          const established = s.state === "ESTABLISHED";
          const processUser = s.process_username || "Hesap okunamadı";
          const destinationName = s.destination_name || "Alan adı eşleşmedi";
          const dnsNames = (s.dns_names || []).join(", ");
          const isOutbound = s.direction === "outbound";
          const directionClass = isOutbound ? "traffic-direction-outbound" : s.direction === "inbound" ? "traffic-direction-inbound" : "traffic-direction-unknown";
          const review = s.attention_level === "review";
          return `<tr class="traffic-session-row${isNew(s) ? " highlight-flash" : ""}">
            <td class="traffic-user-cell">
              <b>${esc(processUser)}</b>
              <small>${s.process_username ? "İşletim sistemi süreç sahibi" : "Yönetici yetkisi gerekebilir"}</small>
            </td>
            <td class="traffic-app-cell">
              <code>${esc(local)}</code>
              <details class="traffic-tech-details"><summary>Teknik ayrıntıları göster</summary><div>Bu bilgisayar: <code>${esc(local)}</code><br>Uzak uç: <code>${esc(remote)}</code><br>Hizmet portu: <code>${esc(s.service_port || "-")}</code><br>Yön kanıtı: ${esc(s.direction_evidence || "-")}<br>Ham TCP durumu: <code>${esc(s.state || "-")}</code>${dnsNames ? `<br>DNS adayları: ${esc(dnsNames)}` : ""}</div></details>
            </td>
            <td class="traffic-destination-cell">
              <b>${esc(destinationName)}</b>
              <code style="color:var(--txt)">${esc(s.remote_ip || "-")}:${esc(s.remote_port || "-")}</code>
              <small>${esc(destinationSourceLabel[s.destination_source] || destinationSourceLabel.ip_only)}</small>
              ${review ? `<span class="badge warn traffic-review-label" title="Bu bir kesin tehdit tespiti değildir.">İncele</span><small style="color:var(--orange)">${esc(s.attention_reason || "Bağlantıyı doğrulayın.")}</small>` : ""}
            </td>
            <td><span class="talker-proto-badge">${esc(s.primary_protocol || `TCP ${s.remote_port || ""}`)}</span><br><small style="color:var(--muted)">${esc(s.app_category || "Tanımlanamayan servis")}</small></td>
            <td>
              <span class="badge ${directionClass}" title="${esc(s.direction_evidence || "Bağlantı yönü")}">${isOutbound ? "→" : s.direction === "inbound" ? "←" : "↔"} ${esc(directionLabel[s.direction] || directionLabel.unknown)}</span>
            </td>
            <td><span class="badge ${established ? "ok" : "warn"}" title="${esc(stateHelp[s.state] || "TCP bağlantı durumu")}">${esc(stateLabel[s.state] || s.state || "-")}</span></td>
            <td>${s.scope === "local" ? "Yerel/özel ağ" : s.scope === "internet" ? "İnternet" : "Bilinmiyor"}</td>
            <td><div class="traffic-session-actions">
              <button class="mini-btn traffic-menu-toggle" aria-label="Bağlantı işlemleri" aria-expanded="false" onclick="toggleTrafficSessionMenu(this)">⋯</button>
              <div class="traffic-session-menu">
                <button class="mini-btn" data-ip="${esc(s.remote_ip)}" onclick="quickPing(this.dataset.ip)">Ping</button>
                <button class="mini-btn" data-ip="${esc(s.remote_ip)}" onclick="quickTraceroute(this.dataset.ip)">Yolu izle</button>
                ${s.destination_source === "inventory" ? `<button class="mini-btn" data-ip="${esc(s.remote_ip)}" onclick="openDeviceDrawer('', this.dataset.ip)">Cihaz</button>` : ""}
                <button class="mini-btn" data-address="${esc(remote)}" onclick="copyToClipboard(this.dataset.address, this)">Adresi kopyala</button>
              </div>
            </div></td>
          </tr>`;
        }).join("")}</tbody>`;
        }).join("")}
      </table>
    </div>
    <div style="margin-top:8px;color:var(--muted);font-size:10.5px">En fazla 100 açık bağlantı gösterilir. “İncele” etiketi kesin tehdit kararı değildir. Toplam ağ kullanımı bağlantı satırlarına ayrı ayrı dağıtılamaz.</div>`;
}

async function refreshTopTalkers(manual = false) {
  const btn = $("talkersRefreshBtn");
  if (manual && btn) {
    btn.disabled = true;
    btn.textContent = "Güncelleniyor...";
  }

  try {
    const data = await get("/api/traffic/top-talkers");
    const totalBwEl = $("talkersTotalBandwidth");
    if (totalBwEl) totalBwEl.textContent = data?.total_bandwidth_display || `${data?.total_bandwidth_mbps || 0} Mbps`;
    if ($("talkersRxBandwidth")) $("talkersRxBandwidth").textContent = data?.rx_display || `${data?.rx_mbps || 0} Mbps`;
    if ($("talkersTxBandwidth")) $("talkersTxBandwidth").textContent = data?.tx_display || `${data?.tx_mbps || 0} Mbps`;
    if ($("trafficSampleStatus")) {
      const age = Number(data?.sample_age_seconds || 0);
      $("trafficSampleStatus").textContent = data?.sample_time
        ? `Son ölçüm ${data.sample_time} · ${age < 2 ? "az önce" : `${age} saniye önce`}${data.sample_stale ? " · Veri güncel olmayabilir" : ""}`
        : "Henüz trafik ölçümü alınmadı.";
    }

    const container = $("topTalkersFullLeaderboard");
    if (!container) return;

    const sessions = data?.sessions || [];
    updateTrafficSessionsSnapshot(sessions);
    const setMetric = (id, value) => { const el = $(id); if (el) el.textContent = String(value ?? 0); };
    setMetric("trafficSessionCount", data?.session_count);
    setMetric("trafficRemoteCount", data?.distinct_remote_count);
    setMetric("trafficProcessCount", data?.distinct_process_count);

    const visibility = data?.runtime_visibility || {};
    const privilegeBanner = $("trafficPrivilegeBanner");
    if (privilegeBanner) {
      const elevated = visibility.is_elevated === true;
      privilegeBanner.style.display = "block";
      privilegeBanner.style.background = elevated ? "rgba(16,185,129,.09)" : "rgba(245,158,11,.10)";
      privilegeBanner.style.border = `1px solid ${elevated ? "rgba(16,185,129,.30)" : "rgba(245,158,11,.35)"}`;
      privilegeBanner.style.color = elevated ? "#34d399" : "#fbbf24";
      privilegeBanner.innerHTML = elevated
        ? `<b>Tüm uygulama bilgileri okunabiliyor.</b><div style="margin-top:3px;color:var(--txt-2)">NetMon yönetici yetkisiyle çalışıyor. Windows hesabı: <code>${esc(visibility.identity || "-")}</code></div>`
        : `<b>Bazı uygulama adları görünmeyebilir.</b><div style="margin-top:3px;color:var(--txt-2)">NetMon yönetici yetkisiyle çalışmıyor. Daha eksiksiz sonuç için uygulamayı “Yönetici olarak çalıştır” seçeneğiyle yeniden başlatın. Windows hesabı: <code>${esc(visibility.identity || "-")}</code></div>`;
    }
    renderTrafficSessions();

    if (manual) {
      updateLastScan();
      toast("Aktif ağ oturumları güncellendi.", "info");
    }
  } catch (err) {
    console.error("Top talkers error:", err);
  } finally {
    if (manual && btn) {
      btn.disabled = false;
      btn.textContent = "⚡ Şimdi Güncelle";
    }
  }
}

/* ============================================================
   SWITCH CONFIG DIFF & NCM PAGE
   ============================================================ */

Object.assign(globalThis, {
  renderTopTalkersPage,
  updateTrafficSessionsSnapshot,
  toggleTrafficSessionGroup,
  toggleTrafficSessionMenu,
  renderTrafficSessions,
  refreshTopTalkers,
});
