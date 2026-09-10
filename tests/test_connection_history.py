from types import SimpleNamespace

import pytest
import server
from conftest import persistent_test_client


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch, test_portal):
    db_path = tmp_path / "netmon-connections-test.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    monkeypatch.setattr(server, "HAS_PSUTIL", False)
    monkeypatch.setattr(server, "_resolve_connection_hostname", lambda remote_ip: "dns.google")
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server._local_wmi_cache.update({"ts": 0, "data": None})
    server.init_db()
    with persistent_test_client(server.app, test_portal) as client:
        yield SimpleNamespace(client=client, db_path=db_path, password_path=password_path)


def _session(**overrides):
    session = {
        "process_username": "DOMAIN\\alice",
        "process_name": "chrome.exe",
        "local_ip": "192.168.1.20",
        "remote_ip": "8.8.8.8",
        "remote_port": 443,
        "protocol": "TCP",
        "direction": "outbound",
        "state": "ESTABLISHED",
    }
    session.update(overrides)
    return session


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


def _create_active_viewer(client, admin_headers):
    temporary_password = "Temporary-Pass-2026!"
    created = client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"username": "history.viewer", "password": temporary_password, "role": "viewer"},
    )
    assert created.status_code == 200
    login = client.post(
        "/api/auth/login",
        json={"username": "history.viewer", "password": temporary_password},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    changed = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": temporary_password, "new_password": "Viewer-Active-Pass-2026!"},
    )
    assert changed.status_code == 200
    return headers


def test_new_connection_is_inserted_with_equal_first_and_last_seen(isolated_server):
    with server.db_conn() as conn:
        result = server._store_connection_sample(conn, [_session()], 1_700_000_000.0)
        row = conn.execute(
            "SELECT username,process_name,remote_ip,remote_port,resolved_hostname,first_seen,last_seen,closed_at "
            "FROM connections"
        ).fetchone()

    assert result == {"inserted": 1, "updated": 0, "closed": 0}
    assert row[:5] == ("DOMAIN\\alice", "chrome.exe", "8.8.8.8", 443, "dns.google")
    assert row[5] == row[6] == 1_700_000_000.0
    assert row[7] is None


def test_existing_connection_updates_last_seen_without_duplicate(isolated_server):
    with server.db_conn() as conn:
        server._store_connection_sample(conn, [_session()], 1_700_000_000.0)
        result = server._store_connection_sample(conn, [_session(state="CLOSE_WAIT")], 1_700_000_015.0)
        rows = conn.execute("SELECT first_seen,last_seen,status FROM connections ORDER BY id").fetchall()

    assert result == {"inserted": 0, "updated": 1, "closed": 0}
    assert rows == [(1_700_000_000.0, 1_700_000_015.0, "CLOSE_WAIT")]


def test_missing_connection_receives_closed_at(isolated_server):
    with server.db_conn() as conn:
        server._store_connection_sample(conn, [_session()], 1_700_000_000.0)
        result = server._store_connection_sample(conn, [], 1_700_000_030.0)
        row = conn.execute("SELECT last_seen,closed_at FROM connections").fetchone()

    assert result == {"inserted": 0, "updated": 0, "closed": 1}
    assert row == (1_700_000_000.0, 1_700_000_030.0)


def test_connection_history_filters_username_process_target_and_time(isolated_server):
    client = isolated_server.client
    admin_headers = _bootstrap_admin(client, isolated_server.password_path)
    rows = [
        (
            "alice",
            "chrome.exe",
            "10.0.0.5",
            "8.8.8.8",
            443,
            "TCP",
            "outbound",
            "ESTABLISHED",
            "dns.google",
            100.0,
            120.0,
            None,
        ),
        (
            "bob",
            "curl.exe",
            "10.0.0.5",
            "1.1.1.1",
            443,
            "TCP",
            "outbound",
            "ESTABLISHED",
            "one.one.one.one",
            200.0,
            220.0,
            None,
        ),
        (
            "alice",
            "firefox.exe",
            "10.0.0.5",
            "203.0.113.10",
            443,
            "TCP",
            "outbound",
            "CLOSED",
            "api.example.net",
            300.0,
            320.0,
            321.0,
        ),
    ]
    with server.db_conn() as conn:
        conn.executemany(
            """
            INSERT INTO connections (
                username,process_name,local_ip,remote_ip,remote_port,protocol,
                direction,status,resolved_hostname,first_seen,last_seen,closed_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        conn.commit()

    combined = client.get(
        "/api/connections/history",
        headers=admin_headers,
        params={"username": "alice", "target": "google", "since": 90, "until": 150},
    )
    assert combined.status_code == 200
    assert [item["remote_ip"] for item in combined.json()["connections"]] == ["8.8.8.8"]

    by_process_and_ip = client.get(
        "/api/connections/history",
        headers=admin_headers,
        params={"process_name": "curl.exe", "target": "1.1.1.1"},
    )
    assert by_process_and_ip.status_code == 200
    assert [item["username"] for item in by_process_and_ip.json()["connections"]] == ["bob"]

    by_time = client.get(
        "/api/connections/history",
        headers=admin_headers,
        params={"since": 210, "until": 250},
    )
    assert by_time.status_code == 200
    assert [item["remote_ip"] for item in by_time.json()["connections"]] == ["1.1.1.1"]

    invalid = client.get(
        "/api/connections/history",
        headers=admin_headers,
        params={"limit": 1001},
    )
    assert invalid.status_code == 400
    assert set(invalid.json()) == {"code", "message", "detail", "trace_id", "error"}
    assert invalid.json()["code"] == "BAD_REQUEST"
    assert invalid.json()["trace_id"] == invalid.headers["X-Trace-ID"]


def test_connection_history_requires_permission(isolated_server):
    client = isolated_server.client
    admin_headers = _bootstrap_admin(client, isolated_server.password_path)
    viewer_headers = _create_active_viewer(client, admin_headers)

    response = client.get("/api/connections/history", headers=viewer_headers)

    assert response.status_code == 403
    assert set(response.json()) == {"code", "message", "detail", "trace_id", "error"}
    assert response.json()["code"] == "PERMISSION_DENIED"
    assert response.json()["trace_id"] == response.headers["X-Trace-ID"]
