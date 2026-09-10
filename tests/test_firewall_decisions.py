from types import SimpleNamespace

import pytest
import server
from conftest import persistent_test_client


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch, test_portal):
    db_path = tmp_path / "netmon-firewall-decisions.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    monkeypatch.setattr(server, "HAS_PSUTIL", False)
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server._local_wmi_cache.update({"ts": 0, "data": None})
    server.init_db()
    with persistent_test_client(server.app, test_portal) as client:
        yield SimpleNamespace(client=client, password_path=password_path)


def _bootstrap_admin(client, password_path):
    initial_password = password_path.read_text(encoding="utf-8").splitlines()[1]
    login = client.post("/api/auth/login", json={"username": "admin", "password": initial_password})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    changed = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "New-Company-Pass-2026!"},
    )
    assert changed.status_code == 200
    return headers


def test_firewall_decisions_are_unavailable_outside_windows(isolated_server, monkeypatch):
    headers = _bootstrap_admin(isolated_server.client, isolated_server.password_path)
    monkeypatch.setattr(server.platform, "system", lambda: "Linux")

    response = isolated_server.client.get("/api/security/firewall-decisions", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "status": "unavailable",
        "scope": "local_machine",
        "source": "windows_security_event_log",
        "decisions": [],
        "reason": "Firewall karar geçmişi Windows gerektirir; bu veri yalnız yerel Windows makinesinden okunabilir.",
    }
