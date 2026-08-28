import os

os.environ.setdefault("NETMON_TEST_MODE", "1")


def test_academy_content_and_quiz_endpoint():
    import server

    assert "ip" in server.ACADEMY_CONTENT
    assert server.ACADEMY_CONTENT["ip"]["quiz"]["answer"] == 0
    assert len(server.ACADEMY_CONTENT) >= 8


def test_scan_run_table_exists():
    import server

    server.init_db()
    conn = server.db_conn()
    row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='inventory_scan_runs'").fetchone()
    conn.close()
    assert row is not None


def test_cross_platform_discovery_method_exists():
    import netdiag_core

    assert hasattr(netdiag_core.NetworkDiagnostics, "_get_connected_devices_generic")
    assert hasattr(netdiag_core.NetworkDiagnostics, "_local_ipv4_networks")


def test_cross_platform_discovery_is_not_windows_only():
    import netdiag_core

    source = open(netdiag_core.__file__, encoding="utf-8").read()
    assert "_get_connected_devices_generic" in source
    assert "return self._get_connected_devices_generic(subnet_override)" in source


def test_server_discovers_all_local_scopes_when_no_override():
    import server

    original = server.diag._local_ipv4_networks
    original_scan = server.diag.get_connected_devices
    try:
        server.diag._local_ipv4_networks = lambda: [
            __import__("ipaddress").ip_network("192.168.1.0/24"),
            __import__("ipaddress").ip_network("10.0.0.0/24"),
        ]
        calls = []
        server.diag.get_connected_devices = lambda subnet_override="": calls.append(subnet_override) or []
        result = server._discover_configured_devices()
        assert set(calls) == {"192.168.1.0/24", "10.0.0.0/24"}
        assert result == []
    finally:
        server.diag._local_ipv4_networks = original
        server.diag.get_connected_devices = original_scan
