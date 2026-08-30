from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def frontend_source() -> str:
    files = [ROOT / "frontend" / "app.js", *sorted((ROOT / "frontend" / "js").glob("*.js"))]
    return "\n".join(path.read_text(encoding="utf-8") for path in files)


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
    assert 'showNode(params.nodes[0])' in topology_js
