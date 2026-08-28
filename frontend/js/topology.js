import "./inventory.js";

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

function renderDiscoveryStatus() {
  const text = $("scanWaveText");
  const bar = $("scanWaveBar");
  if (!text || !bar) return;
  if (S.scanning) {
    text.textContent = "Ağ keşfi çalışıyor — doğrulanan sonuçlar geldikçe güncellenecek";
    bar.style.width = "65%";
    return;
  }
  const count = Array.isArray(S.devices) ? S.devices.length : 0;
  if (S.deviceScanError) {
    text.textContent = `Son keşif tamamlanamadı: ${S.deviceScanError}`;
    bar.style.width = "100%";
    bar.style.background = "var(--red)";
    return;
  }
  bar.style.background = "linear-gradient(90deg, var(--blue), var(--cyan))";
  text.textContent = S.devicesTs
    ? `Son keşif ${formatSeen(S.devicesTs)} · ${count} varlık kaydı`
    : "Henüz tamamlanmış ağ keşfi yok — Ağı Keşfet ile başlayın";
  bar.style.width = S.devicesTs ? "100%" : "0%";
}

function setTopoLayer(layer) {
  S.topoLayer = ["all", "l2", "l3"].includes(layer) ? layer : "all";
  document.querySelectorAll("[data-topo-layer]").forEach(btn => btn.classList.toggle("active", btn.dataset.topoLayer === S.topoLayer));
  drawTopology();
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

  if (S.topoLayer === "l2") {
    filteredNodes = filteredNodes.filter(n =>
      n.id === "gateway" || n.id === "lan" ||
      (!["internet", "router", "firewall"].includes(n.type) || n.type === "switch")
    );
  } else if (S.topoLayer === "l3") {
    filteredNodes = filteredNodes.filter(n =>
      n.id === "internet" || n.id === "gateway" ||
      ["router", "firewall", "server", "network_device"].includes(n.type)
    );
  }

  const activeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = (rawData.edges || []).filter(e =>
    activeIds.has(e.from) && activeIds.has(e.to) &&
    (S.topoLayer === "all" || (e.layer || (e.kind === "uplink" ? "l3" : "l2")) === S.topoLayer)
  );
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
  const edges = data.edges.map((e, edgeIndex) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return "";
    const backbone = ["router","gateway","switch","lan","internet"].includes(e.from) && ["router","gateway","switch","lan","internet"].includes(e.to);
    const edgeState = e.congested || e.mismatch || e.status === "warning" ? "warning" : e.status;
    const color = edgeState === "online"
      ? (backbone ? "url(#edgeGradOnline)" : "#10b981")
      : edgeState === "discovered" || edgeState === "warning"
        ? "#f5a623"
        : edgeState === "offline" || edgeState === "down"
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

    const fromName = topologyDeviceName(data.nodes.find(n => n.id === e.from) || { id: e.from });
    const toName = topologyDeviceName(data.nodes.find(n => n.id === e.to) || { id: e.to });
    const ports = e.source_port || e.target_port
      ? `${e.source_port || "Port doğrulanmadı"} → ${e.target_port || "Port doğrulanmadı"}`
      : "Port eşleşmesi keşfedilmedi";
    const tooltip = encodeURIComponent(JSON.stringify({
      title: `${fromName} → ${toName}`,
      ports,
      status: edgeState === "online" ? "Aktif" : edgeState === "warning" ? "Yoğun trafik / uyuşmazlık" : edgeState === "offline" || edgeState === "down" ? "Down" : "Doğrulanmadı",
      kind: e.logical ? "Mantıksal bağlantı" : "Fiziksel bağlantı"
    }));
    return `<g class="topo-edge-group"><path class="edge ${edgeState === 'online' ? 'flow' : ''}" stroke="${color}" stroke-width="${backbone ? '2.8' : '1.8'}" fill="none" stroke-dasharray="${edgeState === 'online' ? '6 4' : 'none'}" d="${pathD}"/><path class="topo-edge-hit" data-edge-tip="${tooltip}" data-edge-index="${edgeIndex}" d="${pathD}"/></g>`;
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
  bindTopologyEdgeTooltips(svg);
  applyTopoTransform();
}

function bindTopologyEdgeTooltips(svg) {
  const wrap = svg?.closest(".topo-wrap");
  if (!wrap) return;
  let tooltip = wrap.querySelector(".topo-edge-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "topo-edge-tooltip";
    wrap.appendChild(tooltip);
  }
  svg.querySelectorAll(".topo-edge-hit").forEach(path => {
    path.addEventListener("mouseenter", () => {
      let info = {};
      try { info = JSON.parse(decodeURIComponent(path.dataset.edgeTip || "")); } catch (_) {}
      tooltip.innerHTML = `<b>${esc(info.title || "Bağlantı")}</b><div>${esc(info.ports || "Port bilgisi yok")}</div><div style="color:var(--muted)">${esc(info.status || "")} · ${esc(info.kind || "")}</div>`;
      tooltip.style.display = "block";
    });
    path.addEventListener("mousemove", e => {
      const box = wrap.getBoundingClientRect();
      tooltip.style.left = `${Math.min(Math.max(8, box.width - 320), Math.max(8, e.clientX - box.left + 12))}px`;
      tooltip.style.top = `${Math.max(8, e.clientY - box.top - 58)}px`;
    });
    path.addEventListener("mouseleave", () => { tooltip.style.display = "none"; });
  });
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

Object.assign(globalThis, {
  TOPO,
  STATUS_COLOR,
  layoutTopology,
  setTopoLayout,
  toggleTopoActiveOnly,
  renderDiscoveryStatus,
  setTopoLayer,
  computeMeshTopologyLayout,
  topologyDeviceName,
  topologyTypeTitle,
  nodeSvg,
  setTopoCategory,
  drawTopology,
  bindTopologyEdgeTooltips,
  topoFit,
  topoZoom,
  topoReset,
  applyTopoTransform,
  topoFullscreen,
  bindTopoDrag,
});
