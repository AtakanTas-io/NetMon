import server
import pytest

from conftest import persistent_test_client


@pytest.fixture()
def network_server(tmp_path, monkeypatch, test_portal):
    db_path = tmp_path / "network-context.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    server._devices_cache.update({
        "ts": 0,
        "data": [],
        "error": None,
        "scan_status": "idle",
        "active_networks": [],
    })
    server.init_db()
    with persistent_test_client(server.app, test_portal) as client:
        yield client, password_path
    server._devices_cache["active_networks"] = []


def _admin_headers(client, password_path):
    initial_password = password_path.read_text(encoding="utf-8").splitlines()[1]
    login = client.post("/api/auth/login", json={"username": "admin", "password": initial_password})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    changed = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "Network-Context-2026!"},
    )
    assert changed.status_code == 200
    return headers


def test_current_network_is_default_and_known_networks_can_be_selected(network_server):
    client, password_path = network_server
    headers = _admin_headers(client, password_path)
    server._devices_cache.update({
        "ts": 10**12,
        "active_networks": [{"id": 2, "subnet_cidr": "192.168.10.0/24"}],
        "data": [
            {"ip": "10.20.0.8", "mac": "00:11:22:33:44:55", "network_id": 1, "status": "online", "type": "server"},
            {"ip": "192.168.10.8", "mac": "00:11:22:33:44:66", "network_id": 2, "status": "online", "type": "computer"},
        ],
    })

    current = client.get("/api/devices", headers=headers).json()["devices"]
    all_known = client.get("/api/devices?scope=all_known", headers=headers).json()["devices"]
    selected = client.get("/api/devices?scope=all_known&network_id=1", headers=headers).json()["devices"]
    overview = client.get("/api/overview", headers=headers).json()
    topology = client.get("/api/topology", headers=headers).json()

    assert [device["ip"] for device in current] == ["192.168.10.8"]
    assert {device["ip"] for device in all_known} == {"10.20.0.8", "192.168.10.8"}
    assert [device["ip"] for device in selected] == ["10.20.0.8"]
    assert overview["devices"]["total"] == 1
    assert {node.get("ip") for node in topology["nodes"] if node.get("ip")} <= {"192.168.10.8"}


def test_network_contexts_are_persisted_and_devices_are_tagged(network_server, monkeypatch):
    client, password_path = network_server
    headers = _admin_headers(client, password_path)
    monkeypatch.setattr(server.diag, "get_network_context", lambda: {
        "gateway": "192.168.10.1",
        "interface": "Ethernet",
    })
    devices = [
        {"ip": "192.168.10.1", "mac": "AA:BB:CC:DD:EE:01"},
        {"ip": "10.20.0.8", "mac": "AA:BB:CC:DD:EE:02"},
    ]

    contexts = server._register_network_contexts(["192.168.10.0/24", "10.20.0.0/24"], devices)
    response = client.get("/api/networks", headers=headers).json()

    assert len(contexts) == 2
    assert len({device["network_id"] for device in devices}) == 2
    assert {item["subnet_cidr"] for item in response["networks"]} == {"192.168.10.0/24", "10.20.0.0/24"}
    assert set(response["current"]) == {item["id"] for item in contexts}


def test_previous_network_devices_are_retained_as_network_changed(network_server):
    server._devices_cache.update({
        "active_networks": [{"id": 2, "subnet_cidr": "192.168.10.0/24"}],
        "data": [{"ip": "10.20.0.8", "mac": "00:11:22:33:44:55", "network_id": 1, "status": "online"}],
    })

    merged = server.merge_scan_into_inventory([
        {"ip": "192.168.10.8", "mac": "00:11:22:33:44:66", "network_id": 2, "status": "online"},
    ])
    previous = next(device for device in merged if device["ip"] == "10.20.0.8")

    assert previous["status"] == "network_changed"
    assert previous["connectivity_status"] == "network_changed"
