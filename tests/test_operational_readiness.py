from pathlib import Path

import pytest
import server
from conftest import persistent_test_client

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch, test_portal):
    db_path = tmp_path / "netmon-readiness.db"
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
        json={"current_password": initial_password, "new_password": "Readiness-Pass-2026!"},
    )
    return headers


def test_device_owner_is_persisted_and_reflected_in_cache(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    mac = "AA:BB:CC:DD:EE:10"
    with server.db_conn() as conn:
        conn.execute(
            "INSERT INTO known_devices(mac, first_seen, last_seen, last_ip) VALUES(?,?,?,?)",
            (mac, 1.0, 1.0, "10.0.0.10"),
        )
        conn.commit()
    server._devices_cache["data"] = [{"mac": mac, "ip": "10.0.0.10", "type": "unknown"}]

    response = client.post(
        "/api/devices/rename",
        headers=headers,
        json={"mac": mac, "friendly_name": "Muhasebe PC", "owner": "Muhasebe", "notes": "Kat 2"},
    )

    assert response.status_code == 200
    with server.db_conn() as conn:
        assert conn.execute("SELECT owner FROM known_devices WHERE mac=?", (mac,)).fetchone()[0] == "Muhasebe"
    assert server._devices_cache["data"][0]["owner"] == "Muhasebe"


def test_ad_and_authorized_dhcp_settings_roundtrip(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    saved = client.post(
        "/api/settings",
        headers=headers,
        json={
            "authorized_dhcp_servers": "10.0.0.2, 10.0.0.1, 10.0.0.2",
            "ad_server": "dc.corp.local",
            "ad_domain": "corp.local",
        },
    )

    assert saved.status_code == 200
    settings = client.get("/api/settings", headers=headers).json()["settings"]
    assert settings["authorized_dhcp_servers"] == "10.0.0.1,10.0.0.2"
    assert settings["ad_server"] == "dc.corp.local"
    assert settings["ad_domain"] == "corp.local"
    assert (
        client.post("/api/settings", headers=headers, json={"authorized_dhcp_servers": "not-an-ip"}).status_code == 400
    )


def test_readiness_contract_distinguishes_real_and_unavailable_features(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    monkeypatch.setattr(server, "get_dhcp_monitor_status", lambda: {"running": False, "error": "UDP/68 kullanımda"})

    response = client.get("/api/system/readiness", headers=headers)

    assert response.status_code == 200
    data = response.json()
    by_id = {item["id"]: item for item in data["items"]}
    assert by_id["database"]["state"] == "ready"
    assert by_id["dhcp_monitor"]["state"] == "error"
    assert by_id["web_filter"]["state"] == "unavailable"
    assert by_id["siem"]["state"] == "unavailable"
    assert "password" not in response.text.lower()


def test_frontend_uses_real_actions_and_page_scoped_refresh():
    app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert 'owner: $("editDeviceOwner")' in app_js
    assert 'authorized_dhcp_servers: $("setAuthDhcp")' in app_js
    assert 'ad_server: $("setAdServer")' in app_js
    assert "Kural detayları simüle ediliyor" not in app_js
    assert "Firewall konfigürasyonu taranıyor" not in app_js
    assert "const tasksByPage" in app_js
    assert "}, 10000);" in app_js
