import pytest
from fastapi.testclient import TestClient
import server


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch):
    db_path = tmp_path / "netmon-test.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server._local_wmi_cache.update({"ts": 0, "data": None})
    server.init_db()
    return TestClient(server.app), db_path, password_path


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


def test_ipam_calculates_subnets_and_detects_conflicts(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    # Seed devices with an IP conflict (2 distinct MACs on same IP 192.168.1.50)
    server._devices_cache["data"] = [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:01", "hostname": "Gateway-Router", "type": "router", "status": "online", "is_gateway": True},
        {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:50", "hostname": "WS-FINANCE-01", "type": "pc", "status": "online"},
        {"ip": "192.168.1.50", "mac": "FF:EE:DD:CC:BB:AA", "hostname": "ROGUE-CLONE", "type": "unknown", "status": "online"},
        {"ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:60", "hostname": "SRV-DB-01", "type": "server", "status": "online"},
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


def test_top_talkers_returns_bandwidth_breakdown(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    server._devices_cache["data"] = [
        {"ip": "192.168.1.10", "mac": "11:22:33:44:55:66", "hostname": "SRV-BACKUP", "type": "server", "status": "online"},
        {"ip": "192.168.1.20", "mac": "22:33:44:55:66:77", "hostname": "CAM-ENTRANCE", "type": "camera", "status": "online"},
        {"ip": "192.168.1.30", "mac": "33:44:55:66:77:88", "hostname": "WS-DEVELOPER", "type": "pc", "status": "online"},
    ]

    res = client.get("/api/traffic/top-talkers", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "total_bandwidth_mbps" in data
    assert "top_talkers" in data
    assert len(data["top_talkers"]) == 3
    talker1 = data["top_talkers"][0]
    assert talker1["ip"] == "192.168.1.10"
    assert talker1["primary_protocol"] == "SMB (TCP 445)"
    assert talker1["total_mbps"] > 0


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
    assert diff_data["stats"]["additions"] >= 1
    assert diff_data["stats"]["deletions"] >= 1
    assert any(line["type"] == "add" and "vlan 20" in line["content"] for line in diff_data["diff_lines"])
    assert any(line["type"] == "delete" and "vlan 10" in line["content"] for line in diff_data["diff_lines"])
