import sqlite3
from unittest.mock import Mock

import pytest
import server
from test_server_security import isolated_server, _bootstrap_admin


@pytest.fixture(autouse=True)
def reset_tool_rate_state(monkeypatch):
    monkeypatch.setattr(server, "_tool_rate_state", {}, raising=False)


@pytest.mark.parametrize("target", ["", "   ", "-help", "example.com;whoami", "host name"])
@pytest.mark.parametrize("endpoint", ["traceroute", "network-cmd"])
def test_diagnostic_targets_rejected_before_subprocess(isolated_server, monkeypatch, target, endpoint):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock()
    monkeypatch.setattr(server.subprocess, "run", run)
    monkeypatch.setattr(server.subprocess, "check_output", run)
    response = client.post(f"/api/tools/{endpoint}", headers=headers, json={"target": target, "action": "nslookup"})
    assert response.status_code == 400
    run.assert_not_called()


@pytest.mark.parametrize("max_hops", [-100, 0, 65, 1000000])
def test_traceroute_hop_bounds(isolated_server, monkeypatch, max_hops):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock()
    monkeypatch.setattr(server.subprocess, "check_output", run)
    response = client.post("/api/tools/traceroute", headers=headers, json={"max_hops": max_hops})
    assert response.status_code == 400
    run.assert_not_called()


@pytest.mark.parametrize("max_hops", [1, 64])
def test_traceroute_cleans_target_and_bounds_timeout(isolated_server, monkeypatch, max_hops):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock(return_value="")
    monkeypatch.setattr(server.subprocess, "check_output", run)
    response = client.post("/api/tools/traceroute", headers=headers,
                           json={"target": " example.com/path ", "max_hops": max_hops})
    assert response.status_code == 200
    assert run.call_args.args[0][-1] == "example.com"
    assert run.call_args.kwargs["timeout"] == max_hops * 2 + 10


def test_tool_limit_is_shared_across_sessions_and_endpoints(isolated_server, monkeypatch):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    monkeypatch.setattr(server, "TOOL_RATE_LIMIT_PER_MINUTE", 2)
    clock = Mock(return_value=1000.0)
    # Sadece limiter saatini değiştir; asyncio'nun kullandığı saati koru.
    from types import SimpleNamespace
    monkeypatch.setattr(server, "time", SimpleNamespace(time=server.time.time, monotonic=clock))
    token = client.post("/api/auth/login", json={"username": "admin", "password": "New-Company-Pass-2026!"}).json()["token"]
    second_headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/tools/traceroute", headers=headers, json={"target": ""}).status_code == 400
    assert client.post("/api/tools/network-cmd", headers=second_headers, json={"action": "invalid"}).status_code == 400
    for path in server._RATE_LIMITED_TOOL_PATHS:
        assert client.post(path, headers=headers, json={"target": ""}).status_code == 429
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT INTO users (username,password_hash,salt,role,active,must_change_password,created_at) "
                     "VALUES ('another','unused','unused','admin',1,0,0)")
        conn.execute("INSERT INTO sessions (token,user_id,created_at,expires_at) "
                     "SELECT 'another-token',id,0,? FROM users WHERE username='another'", (server.time.time() + 3600,))
    assert client.post("/api/tools/deep-scan", headers={"Authorization": "Bearer another-token"}).status_code == 200
    clock.return_value = 1060.0
    assert client.post("/api/tools/deep-scan", headers=headers).status_code == 200


@pytest.mark.parametrize("value, expected", [("20", 20), ("0", 15), ("-1", 15), ("bad", 15), ("1001", 15)])
def test_tool_rate_limit_environment(monkeypatch, value, expected):
    from backend.core.config import load_config
    monkeypatch.setenv("NETMON_TOOL_RATE_LIMIT_PER_MINUTE", value)
    assert load_config().tool_rate_limit_per_minute == expected
