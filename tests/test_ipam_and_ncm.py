from types import SimpleNamespace

import pytest
import server
from conftest import persistent_test_client


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch, test_portal):
    db_path = tmp_path / "netmon-test.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server._local_wmi_cache.update({"ts": 0, "data": None})
    server.init_db()
    with persistent_test_client(server.app, test_portal) as client:
        yield client, db_path, password_path


def _bootstrap_admin(client, password_path):
    initial_password = password_path.read_text(encoding="utf-8").splitlines()[1]
    login = client.post("/api/auth/login", json={"username": "admin", "password": initial_password})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "New-Company-Pass-2026!"},
    )
    return headers


def test_operations_modules_expose_real_data_and_permission_guidance(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = [
        {"ip": "10.20.0.10", "hostname": "legacy-switch", "type": "switch", "status": "online", "open_ports": [22, 23]},
        {"ip": "10.20.0.50", "hostname": "unknown-client", "type": "unknown", "status": "online"},
    ]

    access = client.get("/api/access/capabilities", headers=headers)
    assert access.status_code == 200
    assert access.json()["is_admin"] is True
    assert {item["id"] for item in access.json()["capabilities"]} == {
        "automatic_discovery",
        "reports",
        "configuration_backup",
        "security_posture",
        "locations",
    }

    report = client.get("/api/reports/operations", headers=headers)
    assert report.status_code == 200
    assert report.json()["summary"]["assets"] == 0
    assert report.json()["summary"]["estimated_sla_pct"] is None

    posture = client.get("/api/security/posture", headers=headers)
    assert posture.status_code == 200
    assert posture.json()["assets_evaluated"] == 2
    assert any("TCP/23" in item["evidence"] for item in posture.json()["findings"])


def test_ncm_change_request_requires_second_person_approval(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    with server.db_conn() as conn:
        conn.execute(
            "INSERT INTO device_configs(ip,hostname,device_type,config_text,config_hash,version_label,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            ("10.0.0.1", "core-sw", "switch", "hostname core-sw", "abc", "Planlanan", 1.0),
        )
        config_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()

    created = client.post(
        "/api/ncm/change-requests",
        headers=admin_headers,
        json={"config_id": config_id, "title": "VLAN erişim değişikliği", "reason": "Bakım", "risk": "high"},
    )
    assert created.status_code == 200
    request_id = created.json()["id"]
    self_review = client.post(
        f"/api/ncm/change-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approved", "note": ""},
    )
    assert self_review.status_code == 409

    reviewer_password = "Reviewer-Initial-2026!"
    assert (
        client.post(
            "/api/admin/users",
            headers=admin_headers,
            json={"username": "reviewer", "password": reviewer_password, "role": "noc_operator"},
        ).status_code
        == 200
    )
    login = client.post("/api/auth/login", json={"username": "reviewer", "password": reviewer_password}).json()
    reviewer_headers = {"Authorization": f"Bearer {login['token']}"}
    assert (
        client.post(
            "/api/auth/change-password",
            headers=reviewer_headers,
            json={"current_password": reviewer_password, "new_password": "Reviewer-Changed-2026!"},
        ).status_code
        == 200
    )
    approved = client.post(
        f"/api/ncm/change-requests/{request_id}/decision",
        headers=reviewer_headers,
        json={"decision": "approved", "note": "Kontrol edildi"},
    )
    assert approved.status_code == 200
    listed = client.get("/api/ncm/change-requests?ip=10.0.0.1", headers=admin_headers).json()["requests"]
    assert listed[0]["status"] == "approved"
    assert listed[0]["reviewed_by"] == "reviewer"


def test_location_assignment_roundtrip(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    now = 1_700_000_000.0
    with server.db_conn() as conn:
        conn.execute(
            """INSERT INTO inventory_assets(identity_key,hostname,ip_address,device_type,status,first_seen,last_seen,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("mac:aa", "core-sw", "10.0.0.1", "switch", "online", now, now, now, now),
        )
        asset_id = conn.execute("SELECT asset_id FROM inventory_assets WHERE identity_key='mac:aa'").fetchone()[0]
        conn.commit()

    saved = client.post(
        "/api/locations/assign",
        headers=headers,
        json={"asset_id": asset_id, "location": "İstanbul > A Blok > Kat 3 > Kabinet 3A"},
    )
    assert saved.status_code == 200
    summary = client.get("/api/locations/summary", headers=headers).json()
    assert summary["sites"][0]["location"] == "İstanbul > A Blok > Kat 3 > Kabinet 3A"
    assert summary["sites"][0]["total"] == 1


def test_ipam_calculates_subnets_and_detects_conflicts(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    # Seed devices with an IP conflict (2 distinct MACs on same IP 192.168.1.50)
    server._devices_cache["data"] = [
        {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:01",
            "hostname": "Gateway-Router",
            "type": "router",
            "status": "online",
            "is_gateway": True,
        },
        {
            "ip": "192.168.1.50",
            "mac": "AA:BB:CC:DD:EE:50",
            "hostname": "WS-FINANCE-01",
            "type": "pc",
            "status": "online",
        },
        {
            "ip": "192.168.1.50",
            "mac": "FF:EE:DD:CC:BB:AA",
            "hostname": "ROGUE-CLONE",
            "type": "unknown",
            "status": "online",
        },
        {
            "ip": "192.168.1.100",
            "mac": "AA:BB:CC:DD:EE:60",
            "hostname": "SRV-DB-01",
            "type": "server",
            "status": "online",
        },
    ]

    res = client.get("/api/ipam", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "subnets" in data
    assert len(data["subnets"]) >= 1
    subnet = data["subnets"][0]
    assert subnet["cidr"] == "192.168.1.0/24"
    assert subnet["used_hosts"] >= 3
    assert subnet["free_hosts"] > 0
    assert subnet["status"] == "conflict"

    assert len(data["conflicts"]) == 1
    conflict = data["conflicts"][0]
    assert conflict["ip"] == "192.168.1.50"
    assert len(conflict["macs"]) == 2
    assert "AA:BB:CC:DD:EE:50" in conflict["macs"]
    assert "FF:EE:DD:CC:BB:AA" in conflict["macs"]


def test_ipam_does_not_invent_network_dns_or_dhcp(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = []
    monkeypatch.setattr(
        server.diag,
        "get_network_context",
        lambda: {
            "cidr": None,
            "gateway": None,
            "dns_servers": [],
        },
    )
    monkeypatch.setitem(server._last_status, "gateway", None)

    data = client.get("/api/ipam", headers=headers).json()
    assert data["subnets"] == []
    assert data["allocations"] == []


def test_ipam_preserves_real_23_network_capacity(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    monkeypatch.setattr(
        server.diag,
        "get_network_context",
        lambda: {
            "cidr": "10.33.214.0/23",
            "gateway": "10.33.215.254",
            "dns_servers": ["10.33.214.10"],
        },
    )
    server._devices_cache["data"] = [
        {"ip": "10.33.214.20", "mac": "00:11:22:33:44:20", "hostname": "first-half", "status": "online"},
        {"ip": "10.33.215.20", "mac": "00:11:22:33:44:21", "hostname": "second-half", "status": "online"},
    ]

    data = client.get("/api/ipam", headers=headers).json()
    subnet = data["subnets"][0]
    assert subnet["cidr"] == "10.33.214.0/23"
    assert subnet["total_hosts"] == 510
    assert subnet["used_hosts"] == 3
    assert subnet["free_hosts"] == 507
    assert subnet["gateway"] == "10.33.215.254"


def test_ping_contract_contains_ui_and_diagnostics_fields(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    completed = SimpleNamespace(
        stdout="Reply from 1.1.1.1: bytes=32 time=12ms TTL=57\nReply from 1.1.1.1: bytes=32 time=18ms TTL=57",
        stderr="",
        returncode=0,
    )
    monkeypatch.setattr(server.subprocess, "run", lambda *args, **kwargs: completed)

    data = client.post("/api/tools/ping", headers=headers, json={"target": "1.1.1.1", "count": 2}).json()
    assert data["success"] is True
    assert data["alive"] is True
    assert data["received"] == 2
    assert data["average"] == data["avg_rtt"] == 15.0
    assert data["loss"] == data["packet_loss"] == 0


def test_traffic_anomaly_window_handles_more_than_minimum_samples(isolated_server, monkeypatch):
    _, _, _ = isolated_server
    server._traffic_window.clear()
    monkeypatch.setattr(server, "_last_anomaly_ts", 0.0)
    conn = server.db_conn()
    try:
        for i in range(server.ANOMALY_MIN_SAMPLES + 1):
            server._check_traffic_anomaly(10_000.0 + i, 2_000_000.0, conn)
    finally:
        conn.close()
        server._traffic_window.clear()


def test_top_talkers_returns_only_measured_traffic_and_real_sockets(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    server._devices_cache["data"] = [
        {
            "ip": "192.168.1.10",
            "mac": "11:22:33:44:55:66",
            "hostname": "SRV-BACKUP",
            "type": "server",
            "status": "online",
        }
    ]
    conn = server.db_conn()
    conn.execute(
        "INSERT INTO traffic (ts, wifi_sent, wifi_recv, eth_sent, eth_recv) VALUES (?, ?, ?, ?, ?)",
        (1.0, 100_000.0, 200_000.0, 300_000.0, 400_000.0),
    )
    conn.commit()
    conn.close()

    fake_conn = SimpleNamespace(
        status="ESTABLISHED",
        raddr=SimpleNamespace(ip="192.168.1.10", port=445),
        laddr=SimpleNamespace(ip="192.168.1.5", port=50123),
        pid=123,
    )
    monkeypatch.setattr(server.psutil, "net_connections", lambda kind="inet": [fake_conn])
    monkeypatch.setattr(
        server.psutil,
        "Process",
        lambda pid: SimpleNamespace(
            name=lambda: "sync-client.exe",
            username=lambda: "CORP\\backup.user",
            create_time=lambda: 1_700_000_000.0,
        ),
    )

    res = client.get("/api/traffic/top-talkers", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "total_bandwidth_mbps" in data
    assert "top_talkers" in data
    assert data["total_bandwidth_mbps"] == 1.0
    assert data["per_endpoint_bandwidth_supported"] is False
    assert len(data["top_talkers"]) == 1
    talker1 = data["top_talkers"][0]
    assert talker1["ip"] == "192.168.1.10"
    assert talker1["primary_protocol"] == "SMB (TCP 445)"
    assert talker1["active_conns"] == 1
    assert talker1["total_mbps"] is None
    assert talker1["share_pct"] is None
    assert talker1["local_processes"] == ["sync-client.exe"]
    assert talker1["local_users"] == ["CORP\\backup.user"]
    assert talker1["local_process_name"] == "sync-client.exe"
    assert "bu bilgisayarda açan uygulamaları" in data["note"]
    assert data["session_count"] == 1
    assert data["distinct_remote_count"] == 1
    assert data["distinct_process_count"] == 1
    assert data["distinct_user_count"] == 1
    assert data["outbound_session_count"] == 1
    assert data["inbound_session_count"] == 0
    session = data["sessions"][0]
    assert session["process_name"] == "sync-client.exe"
    assert session["process_username"] == "CORP\\backup.user"
    assert session["process_started_at"] == 1_700_000_000.0
    assert session["pid"] == 123
    assert session["local_ip"] == "192.168.1.5"
    assert session["local_port"] == 50123
    assert session["remote_ip"] == "192.168.1.10"
    assert session["remote_port"] == 445
    assert session["state"] == "ESTABLISHED"
    assert session["scope"] == "local"
    assert session["direction"] == "outbound"
    assert session["destination_name"] == "SRV-BACKUP"
    assert session["destination_source"] == "inventory"
    assert session["service_port"] == 445
    assert session["attention_level"] == "normal"
    assert "is_elevated" in data["runtime_visibility"]


def test_top_talkers_reports_users_direction_dns_candidates_and_review_flags(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = []

    listener = SimpleNamespace(
        status="LISTEN",
        raddr=None,
        laddr=SimpleNamespace(ip="0.0.0.0", port=8443),
        pid=77,
    )
    inbound = SimpleNamespace(
        status="ESTABLISHED",
        raddr=SimpleNamespace(ip="8.8.8.8", port=55000),
        laddr=SimpleNamespace(ip="192.168.1.5", port=8443),
        pid=77,
    )
    outbound_review = SimpleNamespace(
        status="ESTABLISHED",
        raddr=SimpleNamespace(ip="1.1.1.1", port=445),
        laddr=SimpleNamespace(ip="192.168.1.5", port=50100),
        pid=88,
    )
    monkeypatch.setattr(server.psutil, "net_connections", lambda kind="inet": [listener, inbound, outbound_review])
    monkeypatch.setattr(
        server.psutil,
        "Process",
        lambda pid: SimpleNamespace(
            name=lambda: "web-server.exe" if pid == 77 else "sync.exe",
            username=lambda: "CORP\\service.web" if pid == 77 else "CORP\\atakan",
            create_time=lambda: 1_700_000_000.0 + pid,
        ),
    )
    monkeypatch.setattr(
        server,
        "_traffic_dns_names_by_ip",
        lambda ips: {"8.8.8.8": ["dns.google"], "1.1.1.1": ["one.one.one.one"]},
    )

    data = client.get("/api/traffic/top-talkers", headers=headers).json()

    assert data["session_count"] == 2
    assert data["distinct_user_count"] == 2
    assert data["outbound_session_count"] == 1
    assert data["inbound_session_count"] == 1
    assert data["unknown_direction_count"] == 0
    assert data["attention_count"] == 1

    incoming = next(item for item in data["sessions"] if item["direction"] == "inbound")
    assert incoming["process_username"] == "CORP\\service.web"
    assert incoming["destination_name"] == "dns.google"
    assert incoming["destination_source"] == "dns_cache"
    assert incoming["dns_names"] == ["dns.google"]
    assert incoming["service_port"] == 8443
    assert incoming["primary_protocol"] == "HTTPS (TCP 8443)"

    review = next(item for item in data["sessions"] if item["attention_level"] == "review")
    assert review["direction"] == "outbound"
    assert review["service_port"] == 445
    assert "SMB" in review["attention_reason"]


def test_traffic_dns_cache_maps_only_valid_ip_records(monkeypatch):
    monkeypatch.setattr(server.platform, "system", lambda: "Windows")
    monkeypatch.setattr(server, "_TRAFFIC_DNS_CACHE", {"ts": 0.0, "names_by_ip": {}})
    monkeypatch.setattr(
        server.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='[{"Entry":"example.test","Data":"8.8.8.8"},{"Entry":"ignored.test","Data":"not-an-ip"}]',
        ),
    )

    result = server._traffic_dns_names_by_ip({"8.8.8.8", "1.1.1.1"})

    assert result == {"8.8.8.8": ["example.test"]}


def test_top_talkers_does_not_invent_idle_baseline(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    monkeypatch.setattr(server.psutil, "net_connections", lambda kind="inet": [])

    data = client.get("/api/traffic/top-talkers", headers=headers).json()
    assert data["total_bandwidth_mbps"] == 0
    assert data["top_talkers"] == []
    assert data["sessions"] == []
    assert data["session_count"] == 0
    assert data["total_bandwidth_display"] == "0 bps"


def test_ncm_backup_and_diff_roundtrip(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    # 1. Take initial backup
    cfg1 = "hostname Switch-Core\ninterface GigabitEthernet0/1\n switchport access vlan 10\n"
    res1 = client.post(
        "/api/ncm/backup",
        headers=headers,
        json={"ip": "192.168.1.254", "version_label": "v1.0-Initial", "manual_config": cfg1},
    )
    assert res1.status_code == 200
    v1_id = res1.json()["id"]

    # 2. Take modified backup
    cfg2 = "hostname Switch-Core\ninterface GigabitEthernet0/1\n switchport access vlan 20\n spanning-tree portfast\n"
    res2 = client.post(
        "/api/ncm/backup",
        headers=headers,
        json={"ip": "192.168.1.254", "version_label": "v2.0-Vlan20", "manual_config": cfg2},
    )
    assert res2.status_code == 200
    v2_id = res2.json()["id"]

    # 3. List configs
    list_res = client.get("/api/ncm/configs?ip=192.168.1.254", headers=headers)
    assert list_res.status_code == 200
    assert len(list_res.json()["configs"]) == 2

    # 4. Compare diff
    diff_res = client.get(f"/api/ncm/diff?ip=192.168.1.254&v1_id={v1_id}&v2_id={v2_id}", headers=headers)
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert diff_data["config_before"] == cfg1
    assert diff_data["config_after"] == cfg2
    assert diff_data["stats"]["additions"] >= 1
    assert diff_data["stats"]["deletions"] >= 1
    assert any(line["type"] == "add" and "vlan 20" in line["content"] for line in diff_data["diff_lines"])
    assert any(line["type"] == "delete" and "vlan 10" in line["content"] for line in diff_data["diff_lines"])


def test_ncm_never_fabricates_config_when_ssh_is_unconfigured(isolated_server, monkeypatch):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    monkeypatch.setattr(server, "SSH_USERNAME", "")

    response = client.post(
        "/api/ncm/backup",
        headers=headers,
        json={"ip": "192.168.1.254"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "SERVICE_UNAVAILABLE"
    assert response.json()["detail"] == "İstek işlenirken beklenmeyen bir hata oluştu."
    assert response.json()["trace_id"] == response.headers["X-Trace-ID"]
    assert "SSH kullanıcı adı" not in response.text
    with server.sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM device_configs").fetchone()[0] == 0
