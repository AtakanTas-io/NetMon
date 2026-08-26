from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ipam_grid_supports_real_multi_24_cidr_ranges():
    app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert "function ipv4HostsFromCidr" in app_js
    assert "prefixLength !== 24" not in app_js
    assert 'class="ipam-subnet-divider"' in app_js
    assert "for (const currentIp of cidrHosts.hosts)" in app_js


def test_active_sessions_use_network_engineer_table_contract():
    app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert "Aktif Ağ Oturumları" in app_js
    assert "Yerel uygulama / PID" in app_js
    assert "Yerel uç" in app_js
    assert "Uzak uç" in app_js
    assert "runtime_visibility" in app_js
    assert "Uç nokta başına bant genişliği tahmini yapılmaz" in app_js


def test_inventory_actions_are_device_protocol_aware():
    app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert "function inventoryProtocolForDevice" in app_js
    assert 'return "snmp"' in app_js
    assert "function rdpActionButtonHtml" in app_js
    assert "SNMP Envanter" in app_js
