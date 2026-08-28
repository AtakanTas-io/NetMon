import sqlite3
import platform

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch):
    db_path = tmp_path / "netmon-test.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    monkeypatch.setattr(server, "USER_DATA_DIR", tmp_path)
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server._local_wmi_cache.update({"ts": 0, "data": None})
    server.init_db()
    return TestClient(server.app), db_path, password_path


def _bootstrap_admin(client, password_path):
    initial_password = password_path.read_text(encoding="utf-8").splitlines()[1]
    assert initial_password != "admin1234"
    login = client.post("/api/auth/login", json={"username": "admin", "password": initial_password})
    assert login.status_code == 200
    assert login.json()["user"]["must_change_password"] is True
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/status", headers=headers).status_code == 428
    assert client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "short"},
    ).status_code == 400
    changed = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "New-Company-Pass-2026!"},
    )
    assert changed.status_code == 200
    assert not password_path.exists()
    return headers


def test_first_login_forces_random_password_change(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    assert client.get("/api/status", headers=headers).status_code == 200
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT must_change_password FROM users WHERE username='admin'").fetchone()
    assert row == (0,)


def test_management_secret_is_encrypted_and_never_returned(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    secret = "Domain-Inventory-Secret!"
    response = client.post(
        "/api/settings",
        headers=headers,
        json={"wmi_username": "DOMAIN\\netmon-ro", "wmi_password": secret},
    )
    assert response.status_code == 200
    assert "wmi_password" not in response.json()["settings"]
    assert response.json()["settings"]["wmi_password_configured"] is True
    with sqlite3.connect(db_path) as conn:
        stored = conn.execute("SELECT value FROM settings WHERE key='wmi_password'").fetchone()[0]
    expected_prefix = "dpapi:" if platform.system() == "Windows" else "fernet:"
    assert stored.startswith(expected_prefix)
    assert secret not in stored
    public = client.get("/api/settings", headers=headers).json()["settings"]
    assert "wmi_password" not in public


def test_ad_login_failure_logs_server_and_error_type_without_password(isolated_server, monkeypatch, caplog):
    client, db_path, password_path = isolated_server
    _bootstrap_admin(client, password_path)
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            [("ad_server", "broken-dc.corp.local"), ("ad_domain", "corp.local")],
        )
        conn.commit()

    import ldap3

    class AdConnectionFailure(Exception):
        pass

    def fail_connection(*args, **kwargs):
        raise AdConnectionFailure("password=Loglara-Girmemeli-2026!")

    monkeypatch.setattr(ldap3, "Connection", fail_connection)
    with caplog.at_level("WARNING", logger="netmon.server"):
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "New-Company-Pass-2026!"},
        )

    assert response.status_code == 200
    assert "sunucu=broken-dc.corp.local" in caplog.text
    assert "hata_türü=AdConnectionFailure" in caplog.text
    assert "Loglara-Girmemeli-2026" not in caplog.text


def test_wmi_username_rejects_forward_slash_domain_format(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.post(
        "/api/settings",
        headers=headers,
        json={"wmi_username": "DOMAIN/service.account"},
    )
    assert response.status_code == 400
    assert "DOMAIN\\kullanıcı" in response.json()["error"]


def test_user_update_audit_does_not_store_password(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    created = client.post(
        "/api/admin/users",
        headers=headers,
        json={"username": "tester.user", "password": "Temporary-Pass-2026!", "role": "user"},
    )
    assert created.status_code == 200
    user_id = client.get("/api/admin/users", headers=headers).json()["users"][1]["id"]
    reset = client.post(
        f"/api/admin/users/{user_id}",
        headers=headers,
        json={"new_password": "Second-Temporary-2026!"},
    )
    assert reset.status_code == 200
    with sqlite3.connect(db_path) as conn:
        detail = conn.execute(
            "SELECT detail FROM audit_log WHERE action='user_update' ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        must_change = conn.execute("SELECT must_change_password FROM users WHERE id=?", (user_id,)).fetchone()[0]
    assert "Second-Temporary-2026!" not in detail
    assert "***" in detail
    assert must_change == 1
    deleted = client.delete(f"/api/admin/users/{user_id}", headers=headers)
    assert deleted.status_code == 200
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE id=?", (user_id,)).fetchone()[0] == 0


def test_settings_bounds_and_private_inventory_target(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    bad_interval = client.post("/api/settings", headers=headers, json={"scan_interval": 5})
    assert bad_interval.status_code == 400
    public_target = client.post(
        "/api/devices/inventory",
        headers=headers,
        json={"ip": "8.8.8.8", "protocol": "windows"},
    )
    assert public_target.status_code == 400


def test_verified_inventory_is_persisted(isolated_server, monkeypatch):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    class FakeScanner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def scan_network(self, targets, max_workers=1):
            return [{
                "ip_address": targets[0],
                "status": "Success",
                "inventory_source": "WinRM/CIM",
                "computer_name": "REMOTE-PC",
                "hardware": {"cpu_model": "Verified CPU", "ram_gb": 16},
                "software": {"os_name": "Windows 11", "installed_programs": []},
                "storage": [],
                "security": {"firewall": "Açık", "antivirus": "Defender"},
            }]

    monkeypatch.setattr(server, "WmiNetworkScanner", FakeScanner)
    response = client.post(
        "/api/devices/inventory",
        headers=headers,
        json={"ip": "192.168.50.25", "protocol": "windows", "username": "DOMAIN\\reader", "password": "secret"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT status, source, payload FROM device_inventory WHERE ip=?", ("192.168.50.25",)).fetchone()
    assert row is not None
    assert row[0:2] == ("Success", "WinRM/CIM")
    assert "Verified CPU" in row[2]
    assert all("secret" not in str(device) for device in server._devices_cache["data"])
    cached = next(device for device in server._devices_cache["data"] if device["ip"] == "192.168.50.25")
    assert cached["type"] == "computer"
    assert cached["classification_source"] == "verified_inventory"


def test_failed_authorized_inventory_is_audited_as_failure(isolated_server, monkeypatch):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache.update({
        "ts": 0,
        "data": [{
            "ip": "192.168.50.26",
            "type": "computer",
            "classification": {"open_ports": [135]},
            "discovery_sources": ["test"],
        }],
        "error": None,
        "scan_status": "idle",
    })

    class FailingScanner:
        def __init__(self, **kwargs):
            pass

        def scan_network(self, targets, max_workers=1):
            return [{
                "ip_address": targets[0],
                "status": "Failed",
                "error_code": "access_denied",
                "error_message": "Yetki reddedildi.",
            }]

    monkeypatch.setattr(server, "WmiNetworkScanner", FailingScanner)
    response = client.post(
        "/api/devices/inventory",
        headers=headers,
        json={"ip": "192.168.50.26", "protocol": "windows", "username": "DOMAIN\\reader", "password": "secret"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is False
    diagnostics = response.json()["result"]["diagnostics"]
    assert diagnostics["target"] == "192.168.50.26"
    assert diagnostics["effective_protocol"] == "windows"
    assert diagnostics["credential_source"] == "request"
    assert diagnostics["account"] == "DOMAIN\\reader"
    assert diagnostics["management_ports"] == [135]
    assert diagnostics["recommended_actions"]
    assert "secret" not in str(diagnostics)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT success, detail FROM audit_log WHERE action='authorized_inventory' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row[0] == 0
    assert "status=Failed" in row[1]


def test_inventory_preflight_reports_steps_without_persisting_secrets(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    class ReadyScanner:
        def __init__(self, **kwargs):
            assert kwargs["username"] == "DOMAIN\\reader"

        def test_access(self, ip):
            return {
                "ip_address": ip,
                "status": "Success",
                "management_ports": [135],
                "diagnostics": {"selected_transport": "WMI/DCOM"},
            }

    monkeypatch.setattr(server, "WmiNetworkScanner", ReadyScanner)
    monkeypatch.setattr(server.socket, "create_connection", lambda *args, **kwargs: type("Connection", (), {"__enter__": lambda self: self, "__exit__": lambda self, *exc: None})())
    response = client.post(
        "/api/devices/inventory/preflight",
        headers=headers,
        json={"ip": "192.168.50.27", "protocol": "windows", "username": "DOMAIN\\reader", "password": "secret"},
    )
    payload = response.json()
    assert response.status_code == 200
    assert payload["ready"] is True
    assert payload["protocol"] == "windows"
    assert [item["id"] for item in payload["checks"]] == ["target", "ports", "protocol", "credentials", "authorization"]
    assert payload["checks"][-1]["status"] == "pass"
    assert "secret" not in str(payload)


def test_remote_windows_inventory_requires_credentials(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = [{
        "ip": "192.168.50.74", "type": "computer", "classification": {"open_ports": [135]},
    }]
    monkeypatch.setattr(server, "WMI_USERNAME", "")
    monkeypatch.setattr(server, "WMI_PASSWORD", "")

    response = client.post(
        "/api/devices/inventory", headers=headers,
        json={"ip": "192.168.50.74", "protocol": "windows"},
    )
    result = response.json()["result"]
    assert response.json()["ok"] is False
    assert result["error_code"] == "missing_credentials"
    assert "kullanıcı adı ve parola gerekli" in result["error_message"]


def test_firewall_rejects_windows_inventory_protocol(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = [{
        "ip": "192.168.50.254", "type": "firewall", "classification": {"open_ports": []},
    }]

    response = client.post(
        "/api/devices/inventory", headers=headers,
        json={"ip": "192.168.50.254", "protocol": "windows", "username": "DOMAIN\\reader", "password": "secret"},
    )
    result = response.json()["result"]
    assert response.json()["ok"] is False
    assert result["error_code"] == "protocol_mismatch"
    assert "SNMP envanteri" in result["error_message"]


def test_repeated_wmi_access_denied_is_rate_limited(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._wmi_auth_failure_cooldowns.clear()
    server._devices_cache["data"] = [{
        "ip": "192.168.50.75", "type": "computer", "classification": {"open_ports": [135]},
    }]
    calls = []

    class DeniedScanner:
        def __init__(self, **kwargs):
            pass

        def scan_network(self, targets, max_workers=1):
            calls.append(targets[0])
            return [{
                "ip_address": targets[0], "status": "Failed",
                "error_code": "access_denied", "error_message": "Erişim Engellendi",
            }]

    monkeypatch.setattr(server, "WmiNetworkScanner", DeniedScanner)
    payload = {"ip": "192.168.50.75", "protocol": "windows", "username": "PC\\reader", "password": "wrong"}
    first = client.post("/api/devices/inventory", headers=headers, json=payload).json()
    second = client.post("/api/devices/inventory", headers=headers, json=payload).json()
    assert first["result"]["error_code"] == "access_denied"
    assert second["result"]["error_code"] == "credential_cooldown"
    assert second["result"]["retry_after_seconds"] > 0
    assert calls == ["192.168.50.75"]
    server._wmi_auth_failure_cooldowns.clear()


def test_unavailable_inventory_has_no_fabricated_hardware():
    inventory = server._unavailable_inventory({"classification": {"open_ports": [80]}})
    assert inventory["status"] == "Unavailable"
    assert inventory["hardware"] == {}
    assert inventory["storage"] == []


def test_verified_inventory_uses_windows_role_and_preserves_manual_type():
    inventory = {
        "status": "Success",
        "inventory_source": "WinRM/CIM",
        "computer_name": "FIELD-LAPTOP-01",
        "system": {"pc_system_type": 2, "domain_role": 1, "os_product_type": 1, "chassis_types": [10]},
        "software": {"os_name": "Microsoft Windows 11 Enterprise"},
    }
    device = {"ip": "192.168.1.20", "type": "unknown", "classification": {}, "classification_source": "auto"}
    inferred = server._apply_verified_inventory_identity(device, inventory, "WinRM/CIM")
    assert inferred == "laptop"
    assert device["type"] == "laptop"
    assert device["hostname"] == "FIELD-LAPTOP-01"
    assert device["identification_status"] == "identified"

    manual_device = {"ip": "192.168.1.21", "type": "printer", "classification_source": "manual"}
    assert server._apply_verified_inventory_identity(manual_device, inventory, "WinRM/CIM") is None
    assert manual_device["type"] == "printer"


def test_snmp_identity_distinguishes_enterprise_network_devices():
    cases = {
        "Cisco Catalyst 9300 Series Switch": "switch",
        "FortiGate-100F FortiOS": "firewall",
        "Ubiquiti UniFi AP wireless access point": "access_point",
        "HP LaserJet Enterprise Printer": "printer",
        "MikroTik RouterOS": "router",
    }
    for description, expected in cases.items():
        device = {"ip": "192.168.1.30", "type": "unknown", "classification": {}, "classification_source": "auto"}
        inventory = {
            "status": "Success",
            "inventory_source": "SNMP",
            "system": {"sys_descr": description, "sys_name": "test-device"},
        }
        assert server._apply_verified_inventory_identity(device, inventory, "SNMP") == expected
        assert device["type"] == expected


def test_application_lifespan_and_security_headers(isolated_server, monkeypatch):
    client, _, _ = isolated_server

    def idle_worker(stop_event):
        stop_event.wait(0.05)

    monkeypatch.setattr(server, "diagnostics_loop", idle_worker)
    monkeypatch.setattr(server, "device_scan_loop", idle_worker)
    monkeypatch.setattr(server, "traffic_sampler_loop", idle_worker)
    monkeypatch.setattr(server, "system_stats_loop", idle_worker)
    with client:
        response = client.get("/")
        assert response.status_code == 200
        assert "NetMon" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["x-content-type-options"] == "nosniff"


def test_normalized_inventory_deduplicates_by_mac_and_updates_ip(isolated_server):
    _, db_path, _ = isolated_server
    d1 = {"ip": "192.168.10.20", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "PC-01", "type": "computer", "status": "online", "vendor": "Test"}
    inv = {"status": "Success", "ip_address": d1["ip"], "mac_address": d1["mac"], "computer_name": d1["hostname"], "inventory_source": "Agentless Discovery"}
    server._sync_normalized_inventory(d1, inv, "Agentless Discovery")
    d2 = dict(d1, ip="192.168.10.99")
    inv2 = dict(inv, ip_address=d2["ip"])
    server._sync_normalized_inventory(d2, inv2, "Agentless Discovery")
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT identity_key, ip_address FROM inventory_assets").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "mac:aa:bb:cc:dd:ee:ff"
    assert rows[0][1] == "192.168.10.99"


def test_inventory_asset_detail_returns_404_not_crash_when_missing(isolated_server):
    """Regresyon: HTTPException importu eksikti, 404 yolu NameError ile 500'e dönüyordu."""
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.get("/api/inventory/assets/999999", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Varlık bulunamadı"


def test_inventory_asset_metadata_get_and_put_return_404_not_crash_when_missing(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    get_resp = client.get("/api/inventory/assets/999999/metadata", headers=headers)
    assert get_resp.status_code == 404
    put_resp = client.put("/api/inventory/assets/999999/metadata", headers=headers, json={})
    assert put_resp.status_code == 404


def test_analyst_device_detail_returns_404_not_crash_when_missing(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.get("/api/analyst/device/10.0.0.99", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Cihaz bulunamadı"


def test_analyst_anomalies_uses_correct_db_connection(isolated_server):
    """Regresyon: undefined get_db() çağrısı NameError ile 500 üretiyordu; db_conn() olmalı."""
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.get("/api/analyst/anomalies", headers=headers)
    assert response.status_code == 200
    assert "anomalies" in response.json()


def test_device_scan_failure_does_not_crash_finally_block(isolated_server, monkeypatch):
    """Regresyon: /api/devices finally bloğunda tanımsız scan_run_id UnboundLocalError üretiyordu."""
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    def failing_scan(*args, **kwargs):
        raise RuntimeError("simulated scan failure")

    monkeypatch.setattr(server.diag, "get_network_configuration", failing_scan)
    response = client.get("/api/devices?force=true", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["devices"] == []
    assert body["error"]


# ---------- Kimlik doğrulama / yetkilendirme ----------

def test_missing_token_is_rejected(isolated_server):
    client, _, _ = isolated_server
    response = client.get("/api/status")
    assert response.status_code == 401


def test_malformed_authorization_header_is_rejected(isolated_server):
    client, _, _ = isolated_server
    response = client.get("/api/status", headers={"Authorization": "Basic xyz"})
    assert response.status_code == 401


def test_unknown_token_is_rejected(isolated_server):
    client, _, _ = isolated_server
    response = client.get("/api/status", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_expired_session_is_rejected_and_purged(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    token = headers["Authorization"].split(" ", 1)[1]
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE sessions SET expires_at=? WHERE token=?", (0, token))
        conn.commit()
    response = client.get("/api/status", headers=headers)
    assert response.status_code == 401
    with sqlite3.connect(db_path) as conn:
        remaining = conn.execute("SELECT COUNT(*) FROM sessions WHERE token=?", (token,)).fetchone()[0]
    assert remaining == 0


def test_disabled_account_is_rejected_even_with_valid_token(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE users SET active=0 WHERE username='admin'")
        conn.commit()
    response = client.get("/api/status", headers=headers)
    assert response.status_code == 403


def _create_regular_user(client, admin_headers, username="tester.user", password="Temporary-Pass-2026!"):
    created = client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"username": username, "password": password, "role": "user"},
    )
    assert created.status_code == 200
    return username, password


def _create_role_user(client, admin_headers, role, username, password="Temporary-Pass-2026!"):
    created = client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"username": username, "password": password, "role": role},
    )
    assert created.status_code == 200
    return username, password


def _login(client, username, password):
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['token']}"}


def _login_active_user(client, username, password, new_password="Post-Onboarding-Pass-2026!"):
    """Yeni oluşturulan kullanıcılar da must_change_password=1 ile başlar (admin ile aynı akış)."""
    headers = _login(client, username, password)
    changed = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": password, "new_password": new_password},
    )
    assert changed.status_code == 200
    return headers, new_password


def test_rbac_roles_expose_permissions_and_enforce_operation_boundaries(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    roles_response = client.get("/api/admin/roles", headers=admin_headers)
    assert roles_response.status_code == 200
    roles = {item["id"]: item for item in roles_response.json()["roles"]}
    assert roles["admin"]["permissions"] == ["*"]
    assert "inventory.scan" in roles["noc_operator"]["permissions"]
    assert roles["viewer"]["permissions"] == []

    username, password = _create_role_user(client, admin_headers, "noc_operator", "noc.operator")
    noc_headers, _ = _login_active_user(client, username, password)
    me = client.get("/api/auth/me", headers=noc_headers).json()
    assert me["role"] == "noc_operator"
    assert me["role_label"] == "NOC Operatörü"
    assert "logs.manage" in me["permissions"]
    assert client.post("/api/logs/clear", headers=noc_headers, json={}).status_code == 200
    assert client.get("/api/admin/users", headers=noc_headers).status_code == 403
    assert client.post("/api/settings", headers=noc_headers, json={"ping_count": 3}).status_code == 403


def test_newly_created_user_must_change_password_before_using_api(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    username, password = _create_regular_user(client, admin_headers)
    user_headers = _login(client, username, password)
    assert client.get("/api/status", headers=user_headers).status_code == 428
    assert client.get("/api/auth/me", headers=user_headers).status_code == 200


def test_regular_user_cannot_access_admin_only_endpoints(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    username, password = _create_regular_user(client, admin_headers)
    user_headers, _ = _login_active_user(client, username, password)

    assert client.get("/api/admin/users", headers=user_headers).status_code == 403
    assert client.get("/api/admin/audit-log", headers=user_headers).status_code == 403
    assert client.post("/api/admin/users", headers=user_headers, json={
        "username": "should.fail", "password": "Another-Pass-2026!", "role": "user"
    }).status_code == 403
    assert client.post("/api/devices/scan", headers=user_headers).status_code == 403


def test_regular_user_can_access_general_endpoints(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    username, password = _create_regular_user(client, admin_headers)
    user_headers, _ = _login_active_user(client, username, password)
    assert client.get("/api/status", headers=user_headers).status_code == 200
    assert client.get("/api/auth/me", headers=user_headers).status_code == 200


def test_last_admin_cannot_be_demoted_deactivated_or_deleted(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    admin_id = client.get("/api/admin/users", headers=headers).json()["users"][0]["id"]

    demote = client.post(f"/api/admin/users/{admin_id}", headers=headers, json={"role": "user"})
    assert demote.status_code == 400

    deactivate = client.post(f"/api/admin/users/{admin_id}", headers=headers, json={"active": False})
    assert deactivate.status_code == 400

    delete = client.delete(f"/api/admin/users/{admin_id}", headers=headers)
    assert delete.status_code == 400


def test_second_admin_can_be_demoted_after_promotion(isolated_server):
    """Son admin koruması yalnızca TEK admin kaldığında devreye girmeli."""
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    created = client.post(
        "/api/admin/users",
        headers=headers,
        json={"username": "second.admin", "password": "Second-Admin-Pass-2026!", "role": "admin"},
    )
    assert created.status_code == 200
    users = client.get("/api/admin/users", headers=headers).json()["users"]
    second_admin_id = next(u["id"] for u in users if u["username"] == "second.admin")

    demote = client.post(f"/api/admin/users/{second_admin_id}", headers=headers, json={"role": "user"})
    assert demote.status_code == 200


def test_deactivating_user_immediately_revokes_active_sessions(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    username, password = _create_regular_user(client, admin_headers)
    user_headers, _ = _login_active_user(client, username, password)
    assert client.get("/api/status", headers=user_headers).status_code == 200

    users = client.get("/api/admin/users", headers=admin_headers).json()["users"]
    target_id = next(u["id"] for u in users if u["username"] == username)
    deactivate = client.post(f"/api/admin/users/{target_id}", headers=admin_headers, json={"active": False})
    assert deactivate.status_code == 200

    assert client.get("/api/status", headers=user_headers).status_code == 401


def test_password_reset_by_admin_revokes_existing_sessions(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    username, password = _create_regular_user(client, admin_headers)
    user_headers, _ = _login_active_user(client, username, password)
    assert client.get("/api/status", headers=user_headers).status_code == 200

    users = client.get("/api/admin/users", headers=admin_headers).json()["users"]
    target_id = next(u["id"] for u in users if u["username"] == username)
    reset = client.post(f"/api/admin/users/{target_id}", headers=admin_headers, json={"new_password": "Brand-New-Pass-2026!"})
    assert reset.status_code == 200

    assert client.get("/api/status", headers=user_headers).status_code == 401


def test_create_user_rejects_weak_password_and_invalid_role(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    weak = client.post("/api/admin/users", headers=headers, json={
        "username": "weak.pass", "password": "short", "role": "user"
    })
    assert weak.status_code == 400
    bad_role = client.post("/api/admin/users", headers=headers, json={
        "username": "bad.role", "password": "Perfectly-Fine-Pass-2026!", "role": "superadmin"
    })
    assert bad_role.status_code == 400


def test_create_user_rejects_duplicate_username(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _create_regular_user(client, headers, username="dupe.user")
    dupe = client.post("/api/admin/users", headers=headers, json={
        "username": "dupe.user", "password": "Another-Pass-2026!", "role": "user"
    })
    assert dupe.status_code == 409


def test_logout_invalidates_token(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    logout = client.post("/api/auth/logout", headers=headers)
    assert logout.status_code == 200
    assert client.get("/api/status", headers=headers).status_code == 401
