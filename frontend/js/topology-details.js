import "./topology.js";

function topoCloseDetails() {
  S.activeTopoNodeId = null;
  renderNocOverviewDrawer();
}

function renderNocOverviewDrawer() {
  const drawer = $("topoDetailDrawer");
  if (!drawer) return;
  drawer.onclick = (e) => e.stopPropagation();

  const o = S.overview || {};
  const gw = o.gateway || {};
  const inet = o.internet || {};
  const lat = o.latency || {};
  const devStats = o.devices || { total: 0, online: 0, offline: 0 };
  const list = Array.isArray(S.devices) ? S.devices : [];
  const hasDeviceObservations = list.length > 0 && Number(S.devicesTs || 0) > 0;

  const swCount = list.filter(d => ['switch', 'router', 'access_point', 'firewall'].includes(d.type)).length;
  const srvCount = list.filter(d => d.type === 'server').length;
  const clientCount = list.filter(d => ['pc', 'computer', 'laptop', 'phone', 'mobile', 'tablet'].includes(d.type)).length;
  const iotCount = list.filter(d => ['printer', 'iot', 'http', 'camera', 'unknown'].includes(d.type)).length;
  const rogueCount = list.filter(d => d.is_rogue_dhcp || d.rogue_dhcp).length;
  const riskyCount = list.filter(d => d.risky_os || /windows (xp|7|8|server 2008)/i.test(String(d.os_fingerprint || ""))).length;

  drawer.innerHTML = `
    <style>
      .noc-card-stat { background: var(--panel-2); border: 1px solid var(--line-soft); border-radius: 8px; padding: 8px 10px; }
      .noc-card-stat span { display: block; font-size: 10px; color: var(--muted); }
      .noc-card-stat b { display: block; font-size: 13px; color: var(--txt); margin-top: 2px; }
    </style>
    <div class="drawer-header" style="padding:14px 16px; background:var(--bg-2); border-bottom:1px solid var(--line);">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:18px">📡</span>
          <div>
            <h3 style="margin:0; font-size:13px; font-weight:800; color:var(--cyan); letter-spacing:0.5px">NOC AĞ OPERASYON MERKEZİ</h3>
            <span style="font-size:10px; color:var(--muted)">Canlı Ağ Durumu & Telemetri</span>
          </div>
        </div>
        <span class="badge ${hasDeviceObservations ? 'ok' : 'gray'}" style="font-size:9px">${hasDeviceObservations ? '🟢 Canlı Gözlem Var' : '⚪ Tarama Bekleniyor'}</span>
      </div>
    </div>

    <div class="drawer-body" style="padding:14px 16px; overflow-y:auto; flex:1; display:flex; flex-direction:column; gap:12px;">
      <!-- Gateway & WAN Health -->
      <div style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:10px; padding:10px 12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <span style="font-size:11px; font-weight:700; color:var(--txt)">🌐 Omurga & Gateway Sağlığı</span>
          <span class="badge ${inet.connected == null ? 'gray' : inet.connected ? 'ok' : 'fail'}" style="font-size:8.5px">${inet.connected == null ? 'Ölçüm Bekleniyor' : inet.connected ? 'İnternet Aktif' : 'İnternet Yok'}</span>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; font-size:11px;">
          <div class="noc-card-stat">
            <span>Gateway IP</span>
            <b style="color:var(--blue)">${esc(gw.ip || "Doğrulanamadı")}</b>
          </div>
          <div class="noc-card-stat">
            <span>Ortalama Gecikme</span>
            <b style="color:#34d399">${lat.average != null ? lat.average + " ms" : "Ölçülmedi"}</b>
          </div>
        </div>
      </div>

      <!-- Network Inventory Breakdown -->
      <div style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:10px; padding:10px 12px;">
        <span style="font-size:11px; font-weight:700; color:var(--txt); display:block; margin-bottom:8px">🖧 Katman Dağılımı (${devStats.total || list.length} Düğüm)</span>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
          <div class="noc-card-stat" style="cursor:pointer" onclick="setTopoCategory('network')">
            <span>🔀 Ağ Donanımları</span>
            <b style="color:var(--cyan)">${swCount} Adet</b>
          </div>
          <div class="noc-card-stat" style="cursor:pointer" onclick="setTopoCategory('servers')">
            <span>🖥️ Sunucular</span>
            <b style="color:#818cf8">${srvCount} Adet</b>
          </div>
          <div class="noc-card-stat" style="cursor:pointer" onclick="setTopoCategory('clients')">
            <span>💻 İstemciler</span>
            <b style="color:#34d399">${clientCount} Adet</b>
          </div>
          <div class="noc-card-stat" style="cursor:pointer" onclick="setTopoCategory('all')">
            <span>🖨️ IoT / Diğer</span>
            <b style="color:var(--txt)">${iotCount} Adet</b>
          </div>
        </div>
      </div>

      <!-- Security & Threat Indicators -->
      <div style="background:rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.25); border-radius:10px; padding:10px 12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span style="font-size:11px; font-weight:700; color:#f87171">🛡️ Tehdit & Risk Göstergeleri</span>
          <button class="mini-btn" style="padding:2px 6px; font-size:9px" onclick="setTopoCategory('threats')">İncele</button>
        </div>
        <div style="display:flex; flex-direction:column; gap:4px; font-size:11px;">
          <div style="display:flex; justify-content:space-between;">
            <span style="color:var(--muted)">Rogue DHCP:</span>
            <b style="color:${rogueCount > 0 ? '#ef4444' : hasDeviceObservations ? '#34d399' : 'var(--muted)'}">${rogueCount > 0 ? `🚨 ${rogueCount} TESPİT` : hasDeviceObservations ? 'Gözlenmedi (0)' : 'Ölçülmedi'}</b>
          </div>
          <div style="display:flex; justify-content:space-between;">
            <span style="color:var(--muted)">Riskli / EOL OS:</span>
            <b style="color:${riskyCount > 0 ? '#f97316' : hasDeviceObservations ? '#34d399' : 'var(--muted)'}">${riskyCount > 0 ? `⚠️ ${riskyCount} Cihaz` : hasDeviceObservations ? 'Gözlenmedi (0)' : 'Ölçülmedi'}</b>
          </div>
        </div>
      </div>

      <!-- Quick Shortcuts -->
      <div style="margin-top:auto; padding-top:6px; display:flex; flex-direction:column; gap:6px;">
        <button class="mini-btn blue" style="width:100%; justify-content:center; padding:8px" onclick="scanNetwork()">⚡ Canlı Ağ Taraması Başlat</button>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
          <button class="mini-btn" style="justify-content:center" onclick="go('ipam')">🌐 IPAM Havuzu</button>
          <button class="mini-btn" style="justify-content:center" onclick="go('toptalkers')">📊 Aktif Oturumlar</button>
        </div>
      </div>
    </div>
  `;
  drawer.classList.add("open");
}

function showNode(id) {
  S.activeTopoNodeId = id;
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
  drawer.onclick = (e) => e.stopPropagation();

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

  window.showNodeByIp = function(ip) {
    const target = (S.topology?.nodes || []).find(x => x.ip === ip);
    if (target) showNode(target.id);
  };

  let switchRackHtml = "";
  const isSwitchDevice = type === "switch" || Boolean(n.ports_matrix);
  if (isSwitchDevice) {
    const matrix = n.ports_matrix || [];
    const activeCount = matrix.filter(p => p.status === "up").length;
    const totalCount = matrix.length || 28;
    const rj45 = matrix.filter(p => !p.is_sfp);
    const sfp = matrix.filter(p => p.is_sfp);
    const topRow = rj45.filter((_, idx) => idx % 2 === 0);
    const bottomRow = rj45.filter((_, idx) => idx % 2 === 1);

    switchRackHtml = `
      <div style="background:#090d16;border:1px solid #1e293b;border-radius:12px;padding:14px;margin-bottom:16px;box-shadow:inset 0 2px 10px rgba(0,0,0,0.6)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:16px">🖧</span>
            <div>
              <div style="font-size:11px;font-weight:800;color:var(--cyan);letter-spacing:0.5px">24-PORT GIGABIT MANAGED SWITCH PANELİ</div>
              <div style="font-size:9.5px;color:var(--muted)">${esc(dev?.vendor || n.vendor || "Enterprise")} · ${activeCount}/${totalCount} Port Aktif</div>
            </div>
          </div>
          <span class="badge ok" style="font-size:9px">${activeCount} Bağlı Cihaz</span>
        </div>

        <!-- Switch Chassis Rack View -->
        <div style="background:#0f172a;border:1.5px solid #334155;border-radius:8px;padding:10px;display:flex;gap:12px;overflow-x:auto">
          <!-- RJ45 24-Port Block -->
          <div style="display:flex;flex-direction:column;gap:6px">
            <!-- Top Row: Odd Ports -->
            <div style="display:flex;gap:4px">
              ${topRow.map(p => `
                <div style="width:24px;height:24px;border-radius:4px;background:${p.status==='up'?'#064e3b':'#1e293b'};border:1px solid ${p.status==='up'?'#10b981':'#475569'};display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:pointer;position:relative" title="${esc(p.port_name)}: ${p.status==='up'?(esc(p.connected_name||p.connected_ip)):'Boş'}" onclick="${p.connected_ip?`showNodeByIp('${esc(p.connected_ip)}')`:''}">
                  <div style="width:4px;height:4px;border-radius:50%;background:${p.status==='up'?'#34d399':'#64748b'};box-shadow:${p.status==='up'?'0 0 6px #10b981':'none'}"></div>
                  <span style="font-size:8px;font-weight:700;color:${p.status==='up'?'#a7f3d0':'#94a3b8'};margin-top:1px">${p.port_number}</span>
                </div>
              `).join("")}
            </div>
            <!-- Bottom Row: Even Ports -->
            <div style="display:flex;gap:4px">
              ${bottomRow.map(p => `
                <div style="width:24px;height:24px;border-radius:4px;background:${p.status==='up'?'#064e3b':'#1e293b'};border:1px solid ${p.status==='up'?'#10b981':'#475569'};display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:pointer;position:relative" title="${esc(p.port_name)}: ${p.status==='up'?(esc(p.connected_name||p.connected_ip)):'Boş'}" onclick="${p.connected_ip?`showNodeByIp('${esc(p.connected_ip)}')`:''}">
                  <div style="width:4px;height:4px;border-radius:50%;background:${p.status==='up'?'#34d399':'#64748b'};box-shadow:${p.status==='up'?'0 0 6px #10b981':'none'}"></div>
                  <span style="font-size:8px;font-weight:700;color:${p.status==='up'?'#a7f3d0':'#94a3b8'};margin-top:1px">${p.port_number}</span>
                </div>
              `).join("")}
            </div>
          </div>

          <!-- SFP+ Uplink Block -->
          <div style="border-left:1px dashed #475569;padding-left:10px;display:flex;flex-direction:column;gap:6px">
            <div style="display:flex;gap:4px">
              ${sfp.slice(0,2).map(p => `
                <div style="width:24px;height:24px;border-radius:4px;background:${p.status==='up'?'#1e3a8a':'#1e293b'};border:1px solid ${p.status==='up'?'#3b82f6':'#475569'};display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:pointer" title="${esc(p.port_name)}: ${p.status==='up'?(esc(p.connected_name||p.connected_ip)):'Boş'}" onclick="${p.connected_ip?`showNodeByIp('${esc(p.connected_ip)}')`:''}">
                  <div style="width:4px;height:4px;border-radius:50%;background:${p.status==='up'?'#60a5fa':'#64748b'};box-shadow:${p.status==='up'?'0 0 6px #3b82f6':'none'}"></div>
                  <span style="font-size:7.5px;font-weight:700;color:${p.status==='up'?'#bfdbfe':'#94a3b8'};margin-top:1px">S${p.port_number-24}</span>
                </div>
              `).join("")}
            </div>
            <div style="display:flex;gap:4px">
              ${sfp.slice(2,4).map(p => `
                <div style="width:24px;height:24px;border-radius:4px;background:${p.status==='up'?'#1e3a8a':'#1e293b'};border:1px solid ${p.status==='up'?'#3b82f6':'#475569'};display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:pointer" title="${esc(p.port_name)}: ${p.status==='up'?(esc(p.connected_name||p.connected_ip)):'Boş'}" onclick="${p.connected_ip?`showNodeByIp('${esc(p.connected_ip)}')`:''}">
                  <div style="width:4px;height:4px;border-radius:50%;background:${p.status==='up'?'#60a5fa':'#64748b'};box-shadow:${p.status==='up'?'0 0 6px #3b82f6':'none'}"></div>
                  <span style="font-size:7.5px;font-weight:700;color:${p.status==='up'?'#bfdbfe':'#94a3b8'};margin-top:1px">S${p.port_number-24}</span>
                </div>
              `).join("")}
            </div>
          </div>
        </div>

        <!-- Detailed Switch Port Table -->
        <div style="margin-top:12px;max-height:220px;overflow-y:auto;border:1px solid var(--line-soft);border-radius:8px">
          <table style="width:100%;font-size:10.5px;border-collapse:collapse">
            <thead>
              <tr style="background:var(--panel-2);color:var(--muted);text-align:left">
                <th style="padding:6px 8px">Port</th>
                <th style="padding:6px 8px">Durum</th>
                <th style="padding:6px 8px">Hız</th>
                <th style="padding:6px 8px">Bağlı Cihaz / Hostname</th>
                <th style="padding:6px 8px">IP Adresi</th>
                <th style="padding:6px 8px">MAC Adresi</th>
              </tr>
            </thead>
            <tbody>
              ${matrix.map(p => `
                <tr style="border-top:1px solid var(--line-soft);${p.status==='up'?'background:rgba(16,185,129,0.05)':''};cursor:${p.connected_ip?'pointer':'default'}" onclick="${p.connected_ip?`showNodeByIp('${esc(p.connected_ip)}')`:''}">
                  <td style="padding:5px 8px;font-weight:700;color:${p.status==='up'?'var(--cyan)':'var(--muted)'}">${esc(p.port_name)}</td>
                  <td style="padding:5px 8px"><span class="badge ${p.status==='up'?'ok':'gray'}" style="font-size:8px">${p.status.toUpperCase()}</span></td>
                  <td style="padding:5px 8px;color:var(--txt-2)">${esc(p.speed)}</td>
                  <td style="padding:5px 8px;font-weight:600;color:${p.connected_name?'var(--txt)':'var(--muted)'}">${esc(p.connected_name || '-')}</td>
                  <td style="padding:5px 8px;color:var(--blue)">${esc(p.connected_ip || '-')}</td>
                  <td style="padding:5px 8px;font-family:monospace;color:var(--muted)">${esc(p.connected_mac || '-')}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  const webPort = ports.find(p => [80, 443, 8080, 8443, 8000, 9000, 5000, 3000].includes(Number(p)));
  const isHttps = [443, 8443].includes(Number(webPort));

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
        <button class="mini-btn" style="padding:6px 12px; font-size:11px; font-weight:700; border-radius:6px; cursor:pointer; display:flex; align-items:center; gap:4px;" onclick="topoCloseDetails()">✕ NOC Özet</button>
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
        ${switchRackHtml ? switchRackHtml : internetPathHtml}

        <!-- Physical Switch Location Card for endpoint devices -->
        ${!isSwitchDevice ? `
        <div style="background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.3);border-radius:10px;padding:10px 12px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;font-weight:700">Fiziksel Switch Bağlantısı</div>
            <div style="font-size:12px;font-weight:700;color:var(--cyan);margin-top:2px">
              ${switchIp ? `<span style="cursor:pointer;text-decoration:underline" onclick="showNodeByIp('${esc(switchIp)}')">Switch: ${esc(switchIp)}</span>` : 'Switch: Mantıksal LAN'} · ${switchPort ? `<span style="color:#22d3ee;background:rgba(6,182,212,0.2);padding:2px 6px;border-radius:4px">Port ${esc(switchPort)}</span>` : 'Port: Dinamik'}
            </div>
          </div>
          <span style="font-size:18px">🔌</span>
        </div>` : ''}

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
      ${webPort && n.ip ? `<a href="${isHttps ? 'https' : 'http'}://${esc(n.ip)}${webPort === 80 || webPort === 443 ? '' : ':' + webPort}" target="_blank" class="mini-btn" style="color:#10b981;border-color:#10b981;text-decoration:none;display:inline-flex;align-items:center;gap:4px">🌐 Web UI (${webPort})</a>` : ''}
      ${(isSwitchDevice || type === 'switch' || type === 'router') ? `<button class="mini-btn" style="color:#818cf8;border-color:#818cf8" onclick="go('ncm')">📜 Switch Diff</button>` : ''}
      ${n.ip ? `<button class="mini-btn blue" onclick="quickPing('${esc(n.ip)}')">⚡ Ping</button>` : ""}
      ${n.ip ? `<button class="mini-btn" onclick="quickTraceroute('${esc(n.ip)}')">🛣️ Trace</button>` : ""}
      ${n.ip && hasPermission("diagnostics.run") ? `<button class="mini-btn" onclick="quickScan('${esc(n.ip)}')">🔍 Port Tara</button>` : ""}
      ${n.ip ? inventoryActionButtonHtml(n) : ""}
      ${n.ip ? rdpActionButtonHtml(n) : ""}
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
  if (!hasPermission("diagnostics.run")) return;
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
            <div class="topo-layer-switch" aria-label="Topoloji katmanı">
              <button class="${S.topoLayer === 'all' ? 'active' : ''}" data-topo-layer="all" onclick="setTopoLayer('all')">Tüm Katmanlar</button>
              <button class="${S.topoLayer === 'l2' ? 'active' : ''}" data-topo-layer="l2" onclick="setTopoLayer('l2')">L2 · Switching / VLAN</button>
              <button class="${S.topoLayer === 'l3' ? 'active' : ''}" data-topo-layer="l3" onclick="setTopoLayer('l3')">L3 · Routing</button>
            </div>
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
            <button class="mini-btn ${!S.activeTopoNodeId ? 'blue' : ''}" onclick="renderNocOverviewDrawer()">📡 NOC Paneli</button>
            <label style="font-size:11px;color:var(--txt-2);display:flex;align-items:center;gap:5px;cursor:pointer;background:var(--panel-2);border:1px solid var(--line-soft);padding:4px 8px;border-radius:6px">
              <input type="checkbox" id="topoActiveOnly" ${S.topoActiveOnly ? "checked" : ""} onchange="toggleTopoActiveOnly(this.checked)" />
              Sadece Aktif Cihazlar
            </label>
            <button class="mini-btn" onclick="topoZoom(1.2)">+</button>
            <button class="mini-btn" onclick="topoZoom(1/1.2)">−</button>
            <button class="mini-btn" onclick="topoReset()">Ortala</button>
            <button class="mini-btn" onclick="topoFit(true)">Sığdır</button>
            ${hasPermission("inventory.scan") ? `<button class="mini-btn blue" onclick="scanNetwork()">Ağı Tara</button>` : ""}
          </div>
        </div>
        <div id="discoveryScheduleCard" style="margin:10px 12px 0;padding:10px 12px;border:1px solid var(--line-soft);border-radius:9px;background:var(--panel-2)"><span class="hint">Otomatik keşif zamanlaması yükleniyor…</span></div>
        <div class="topo-wrap" style="height:calc(100vh - 250px); min-height:460px" id="topoWrap2">
          <div class="topo-network" id="topoNetwork2" role="img" aria-label="Keşfedilen cihazların bağlantı haritası"></div>
          <div class="topo-status-legend" aria-label="Bağlantı durumları">
            <span><i style="background:#10b981"></i>Aktif</span>
            <span><i style="background:#ef4444"></i>Down</span>
            <span><i style="background:#f59e0b"></i>Yoğun / Uyuşmazlık</span>
            <span><i style="background:#64748b"></i>Doğrulanmadı</span>
          </div>
          <aside class="topo-detail-drawer" id="topoDetailDrawer"></aside>
        </div>
      </div>
    `;
  }
  drawTopology("topoNetwork2");
  refreshDiscoverySchedule();
  if (!S.activeTopoNodeId) {
    renderNocOverviewDrawer();
  }
}

/* ============================================================
   DASHBOARD WIDGETS (TOP TALKERS & IPAM SUMMARY)
   ============================================================ */

Object.assign(globalThis, {
  topoCloseDetails,
  renderNocOverviewDrawer,
  showNode,
  quickPing,
  quickTraceroute,
  quickScan,
  renderTopologyPage,
});
