from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def frontend_source() -> str:
    files = [ROOT / "frontend" / "app.js", *sorted((ROOT / "frontend" / "js").glob("*.js"))]
    return "\n".join(path.read_text(encoding="utf-8") for path in files)


def test_login_form_never_embeds_a_default_password():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    login_password = index_html.split('id="loginPass"', 1)[1].split("/>", 1)[0]

    assert "value=" not in login_password
    assert "admin1234" not in index_html
    assert "initial_admin_password.txt" in index_html


def test_frontend_uses_small_native_es_modules():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    module_files = sorted((ROOT / "frontend" / "js").glob("*.js"))

    assert '<script type="module" src="/static/app.js' in index_html
    assert module_files
    assert all(len(path.read_text(encoding="utf-8").splitlines()) < 1000 for path in module_files)
    assert all(
        f'import "./js/{path.name}";' in (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        for path in module_files
    )


def test_ipam_grid_supports_real_multi_24_cidr_ranges():
    app_js = frontend_source()
    assert "function ipv4HostsFromCidr" in app_js
    assert "prefixLength !== 24" not in app_js
    assert 'class="ipam-subnet-divider"' in app_js
    assert "for (const currentIp of cidrHosts.hosts)" in app_js


def test_active_sessions_use_network_engineer_table_contract():
    app_js = frontend_source()
    assert "Bu Bilgisayarın Canlı Ağ Bağlantıları" in app_js
    assert "Bilgisayarın anlık ağ kullanımı" in app_js
    assert "Açık TCP bağlantısı" in app_js
    assert "Bağlanılan hedef" in app_js
    assert "Teknik ayrıntıları göster" in app_js
    assert "trafficSessionSearch" in app_js
    assert "trafficStateFilter" in app_js
    assert "trafficScopeFilter" in app_js
    assert "trafficUserFilter" in app_js
    assert "trafficDirectionFilter" in app_js
    assert "trafficAttentionFilter" in app_js
    assert "Kullanan hesap" in app_js
    assert "Windows DNS önbelleği adayı" in app_js
    assert "İncelenmesi önerilenler" in app_js
    assert "Bu bir kesin tehdit tespiti değildir" in app_js
    assert "runtime_visibility" in app_js
    assert "tek tek bağlantılara dağıtılmaz" in app_js


def test_inventory_actions_are_device_protocol_aware():
    app_js = frontend_source()
    assert "function inventoryProtocolForDevice" in app_js
    assert 'return "snmp"' in app_js
    assert "function rdpActionButtonHtml" in app_js
    assert "SNMP Envanter" in app_js


def test_topology_uses_node_link_contract_and_large_network_simplification():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    topology_js = (ROOT / "frontend" / "js" / "topology.js").read_text(encoding="utf-8")

    assert "vis-network@9.1.9" in index_html
    assert "new globalThis.vis.Network" in topology_js
    assert "rawData?.nodes" in topology_js
    assert "rawData?.edges" in topology_js
    assert "nodes.length > 200" in topology_js
    assert "edge.source_port" in topology_js
    assert "openDeviceDrawer(node.mac" in topology_js


def test_topology_defaults_to_current_network_and_can_select_history():
    source = frontend_source()

    assert 'topologyScope: "current_network"' in source
    assert "Yalnızca mevcut ağ" in source
    assert "Tüm bilinen ağlar" in source
    assert "function setTopologyScope" in source
    assert "function selectTopologyNetwork" in source
    assert 'params.set("network_id"' in source


def test_alarm_inbox_uses_websocket_and_persistent_state_api():
    source = frontend_source()
    assert 'channels: ["devices", "traffic", "connections", "topology", "alerts"]' in source
    assert "function receiveLiveAlert" in source
    assert 'get("/api/alerts/inbox?limit=100")' in source
    assert "/api/alerts/${encodeURIComponent(id)}/state" in source
    assert "scheduleSocketReconnect" in source
    assert "Math.pow(2" in source
    assert "Gizle (tekrar gösterme)" in source
    assert "Bu, alarmı kalıcı olarak silmez" in source
    assert "Bastırılmışları göster" in source
    assert "suppressed:false" in source


def test_live_pages_poll_only_as_disconnected_websocket_fallback():
    source = frontend_source()
    assert "networkSocket?.readyState === WebSocket.OPEN" in source
    assert "if (!socketConnected) refreshAll();" in source
    assert 'type === "devices"' in source
    assert 'type === "topology"' in source
    assert "renderDeviceTable();" in source
    assert "drawTopology();" in source


def test_ncm_uses_line_diff_and_collapses_large_unchanged_blocks():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    source = frontend_source()
    assert "diff@7.0.0" in index_html
    assert "globalThis.Diff.diffLines(before, after)" in source
    assert 'type: "collapse"' in source
    assert "satır değişmedi, göster" in source
    assert "expandUnchangedBlock" in source


def test_shared_device_drawer_search_and_virtual_list_contracts():
    source = frontend_source()
    assert "function openDeviceDrawer" in source
    assert "Genel Bakış" in source and "Config Değişiklikleri" in source and "İlişkili Alarmlar" in source
    assert "openDeviceDrawer(node.mac" in source
    assert 'openDeviceDrawer(null, ip, "alerts")' in source
    assert 'event.key.toLowerCase() === "k"' in source
    assert "function levenshteinDistance" in source
    assert "performance.now()" in source
    assert "filteredList.length >= 500" in source
    assert "requestAnimationFrame(paint)" in source
    assert "function bindClickOutside" in source
    assert 'bindClickOutside("deviceExperienceDrawer"' in source
    assert 'bindClickOutside("alertInboxPopover"' in source
    assert 'bindClickOutside("globalSearchResults"' in source
    assert 'bindClickOutside("topoDetailDrawer"' in source
    assert "clickOutsideBindings.has(elementId)" in source
    assert 'document.addEventListener("click", closeWhenOpen, true)' in source


def test_empty_inventory_onboarding_and_backend_theme_preference_contracts():
    source = frontend_source()
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "function maybeShowOnboarding" in source
    assert "Atla, manuel devam et" in source
    assert 'await post("/api/settings", settings)' in source
    assert "await scanNetwork()" in source
    assert 'apiFetch("/api/preferences", { method: "PUT"' in source
    assert 'localStorage.setItem("netmon_theme"' not in source
    assert "/static/css/tokens.css" in index_html


def test_clock_starts_immediately_and_refreshes_every_second():
    runtime = (ROOT / "frontend" / "js" / "runtime.js").read_text(encoding="utf-8")
    dom_ready = runtime.split('document.addEventListener("DOMContentLoaded", () => {', 1)[1]

    assert "tickClock();" in dom_ready
    assert "setInterval(tickClock, 1000);" in dom_ready


def test_frontend_exposes_stable_test_selectors_and_traceable_api_errors():
    core = (ROOT / "frontend" / "js" / "core.js").read_text(encoding="utf-8")
    api = (ROOT / "frontend" / "js" / "api.js").read_text(encoding="utf-8")

    assert "function applyStableTestSelectors" in core
    assert 'querySelectorAll?.("[id]")' in core
    assert "element.dataset.testid = element.id" in core
    assert "new MutationObserver" in core
    assert "data.message || data.error || data.detail" in api
    assert 'res.headers.get("X-Trace-ID")' in api
    assert "requestError.traceId" in api


def test_dashboard_exposes_phase2_network_visibility_contract():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    dashboard = (ROOT / "frontend" / "js" / "dashboard.js").read_text(encoding="utf-8")
    ipam = (ROOT / "frontend" / "js" / "ipam.js").read_text(encoding="utf-8")

    assert "networkQualityChart" in index_html
    assert "dashboardSecurityScore" in index_html
    assert "dashboardCertificateDhcp" in index_html
    assert "Gecikme, Jitter ve Paket Kaybı Trendi" in index_html
    assert "function drawNetworkQualityChart" in dashboard
    assert 'yAxisID: "latency"' in dashboard
    assert 'yAxisID: "loss"' in dashboard
    assert "function renderSecurityScore" in dashboard
    assert "function renderCertificateDhcp" in dashboard
    assert "get(`/api/visibility/summary?range=" in dashboard
    assert "await refreshPhase2Visibility()" in ipam


def test_frontend_exposes_phase3_assurance_workflows():
    diagnostics = (ROOT / "frontend" / "js" / "diagnostics.js").read_text(encoding="utf-8")
    ncm = (ROOT / "frontend" / "js" / "ncm.js").read_text(encoding="utf-8")

    assert "securityAssuranceBody" in diagnostics
    assert 'post("/api/security/cve-scan"' in diagnostics
    assert 'post("/api/discovery/passive-snapshot"' in diagnostics
    assert 'post("/api/security/credential-audit"' in diagnostics
    assert 'post("/api/discovery/exemptions"' in diagnostics
    assert "acknowledge_authorized:true" in diagnostics
    assert "runNcmCompliance" in ncm
    assert 'post("/api/ncm/compliance"' in ncm


def test_frontend_exposes_phase4_command_search_contract():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    search_ui = (ROOT / "frontend" / "js" / "device-experience.js").read_text(encoding="utf-8")

    assert "Ctrl+K" in index_html
    assert "ip:, type:, port:, cve:" in index_html
    assert "function runGlobalSearch" in search_ui
    assert "get(`/api/search?q=" in search_ui
    assert 'get("/api/search/saved")' in search_ui
    assert 'post("/api/search/saved"' in search_ui
    assert "/api/search/export" in search_ui


def test_phase5_license_change_approval_and_mobile_drawer_contracts():
    index_html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    device = (ROOT / "frontend" / "js" / "device-experience.js").read_text(encoding="utf-8")
    ncm = (ROOT / "frontend" / "js" / "ncm.js").read_text(encoding="utf-8")

    assert "Microsoft Windows lisansı" in device
    assert "partial_product_key" in device
    assert "filterDeviceSoftware" in device
    assert "memory_modules" in device
    assert "physical_disks" in device
    assert "network_adapters" in device
    assert "Windows ve oturum" in device
    assert "device-license-card" in index_html
    assert "device-inventory-section" in index_html
    assert "@media(max-width:480px)" in index_html
    assert "box-shadow:none;transform:translateX(105%);visibility:hidden;pointer-events:none" in index_html
    assert (
        ".device-experience-drawer.open{transform:none;visibility:visible;pointer-events:auto;box-shadow:" in index_html
    )
    assert "/api/ncm/change-requests" in ncm
    assert "Talep sahibi kendi değişikliğini onaylayamaz" in ncm


def test_excel_export_reports_only_verified_disk_save():
    dashboard = (ROOT / "frontend" / "js" / "dashboard.js").read_text(encoding="utf-8")
    notifications = (ROOT / "frontend" / "js" / "notifications.js").read_text(encoding="utf-8")
    traffic = (ROOT / "frontend" / "js" / "traffic.js").read_text(encoding="utf-8")

    assert "const token = getToken();" in dashboard
    assert "!saveResult.ok || !saveResult.saved_path" in dashboard
    assert "İndirilenler klasörünüze kaydedildi" not in dashboard
    assert "recordDownload(saveResult);" in dashboard
    assert "downloadCenterPopover" in notifications
    assert "Klasörde göster" in notifications
    assert "downloadCenterBadge" not in notifications
    assert "Kanıt kapsamı ve veri minimizasyonu" in traffic
    assert "URL, sayfa içeriği, mesaj, parola veya paket içeriği toplamaz" in traffic
