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
    assert "Bu Bilgisayarın Canlı Ağ Bağlantıları" in app_js
    assert "Bilgisayarın anlık ağ kullanımı" in app_js
    assert "Açık TCP bağlantısı" in app_js
    assert "Bağlanılan hedef" in app_js
    assert "Teknik ayrıntıları göster" in app_js
    assert "trafficSessionSearch" in app_js
    assert "trafficStateFilter" in app_js
    assert "trafficScopeFilter" in app_js
    assert "runtime_visibility" in app_js
    assert "tek tek bağlantılara dağıtılmaz" in app_js


def test_inventory_actions_are_device_protocol_aware():
    app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert "function inventoryProtocolForDevice" in app_js
    assert 'return "snmp"' in app_js
    assert "function rdpActionButtonHtml" in app_js
    assert "SNMP Envanter" in app_js
