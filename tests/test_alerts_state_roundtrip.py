import sqlite3
import time

import pytest
import server
from conftest import persistent_test_client

from backend.core.operations import _migrate_alert_identity


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch, test_portal):
    db_path = tmp_path / "netmon-alert-state.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server.init_db()
    with persistent_test_client(server.app, test_portal) as client:
        yield client, password_path


def _admin_headers(client, password_path):
    initial_password = password_path.read_text(encoding="utf-8").splitlines()[1]
    login = client.post("/api/auth/login", json={"username": "admin", "password": initial_password})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    response = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "Alert-State-Pass-2026!"},
    )
    assert response.status_code == 200
    return headers


def test_alert_state_roundtrip_is_stable_for_high_precision_timestamps(isolated_server):
    client, password_path = isolated_server
    headers = _admin_headers(client, password_path)
    base = time.time()
    with server.db_conn() as conn:
        conn.executemany(
            "INSERT INTO alerts(ts,level,message,source) VALUES(?,?,?,?)",
            [(base + index / 100_000, "warning", f"Alarm {index}", "roundtrip") for index in range(20)],
        )
        conn.commit()

    inbox = client.get("/api/alerts/inbox", headers=headers)
    assert inbox.status_code == 200
    alerts = inbox.json()["alerts"]
    assert len(alerts) == 20
    assert all(isinstance(item["id"], int) for item in alerts)

    for item in alerts:
        changed = client.put(f"/api/alerts/{item['id']}/state", headers=headers, json={"is_read": True})
        assert changed.status_code == 200

    persisted = client.get("/api/alerts/inbox", headers=headers).json()
    assert persisted["unread"] == 0
    assert all(item["is_read"] is True for item in persisted["alerts"])


def test_legacy_timestamp_states_migrate_to_alert_ids():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY);
        INSERT INTO users(id) VALUES(1);
        CREATE TABLE alerts(ts REAL PRIMARY KEY,level TEXT,message TEXT,source TEXT);
        INSERT INTO alerts(ts,level,message,source) VALUES(1234.123456789,'warning','Eski alarm','test');
        CREATE TABLE alert_user_states(
            user_id INTEGER NOT NULL,
            alert_ts REAL NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            suppressed INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL,
            PRIMARY KEY(user_id,alert_ts)
        );
        INSERT INTO alert_user_states VALUES(1,1234.123456789,1,1,1235.0);
        """
    )

    _migrate_alert_identity(conn)

    alert = conn.execute("SELECT id,ts FROM alerts").fetchone()
    state = conn.execute("SELECT alert_id,is_read,suppressed FROM alert_user_states").fetchone()
    assert alert[1] == 1234.123456789
    assert state == (alert[0], 1, 1)
    conn.close()
