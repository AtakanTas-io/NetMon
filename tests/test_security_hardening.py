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


@pytest.mark.parametrize("address, use_ssl", [("dc.example.com", True), ("dc.example.com", False), ("ldaps://dc.example.com", False)])
def test_ad_login_requires_verified_tls_and_provisions_user(isolated_server, monkeypatch, address, use_ssl):
    import ldap3
    import ssl
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.post("/api/settings", headers=headers, json={
        "ad_server": address, "ad_domain": "example.com", "ad_use_ssl": use_ssl,
    })
    assert response.status_code == 200
    assert client.get("/api/settings", headers=headers).json()["settings"]["ad_use_ssl"] is use_ssl
    directory = Mock(wraps=ldap3.Server)
    connection = Mock()
    monkeypatch.setattr(ldap3, "Server", directory)
    monkeypatch.setattr(ldap3, "Connection", connection)
    response = client.post("/api/auth/login", json={"username": "directory-user", "password": "Directory-password!"})
    assert response.status_code == 200
    implicit_tls = use_ssl or address.startswith("ldaps://")
    assert directory.call_args.kwargs["use_ssl"] is implicit_tls
    assert directory.call_args.kwargs["tls"].validate == ssl.CERT_REQUIRED
    assert connection.call_args.kwargs["auto_bind"] == (
        ldap3.AUTO_BIND_NO_TLS if implicit_tls else ldap3.AUTO_BIND_TLS_BEFORE_BIND
    )
    assert connection.call_args.kwargs["auto_referrals"] is False
    connection.return_value.unbind.assert_called_once()
    with sqlite3.connect(db_path) as conn:
        assert isinstance(conn.execute("SELECT password_hash FROM users WHERE username='directory-user'").fetchone()[0], str)


def test_plain_ldap_is_rejected_without_sending_credentials(isolated_server, monkeypatch, caplog):
    import ldap3
    client, db_path, password_path = isolated_server
    _bootstrap_admin(client, password_path)
    with sqlite3.connect(db_path) as conn:
        conn.executemany("INSERT INTO settings (key,value) VALUES (?,?)", [
            ("ad_server", "ldap://dc.example.com"), ("ad_domain", "example.com"),
        ])
    connection = Mock()
    monkeypatch.setattr(ldap3, "Connection", connection)
    response = client.post("/api/auth/login", json={"username": "directory-user", "password": "Never-send-this!"})
    assert response.status_code == 401
    connection.assert_not_called()
    assert "AD sunucusu şifresiz protokol kullanıyor" in caplog.text
    assert "Never-send-this" not in caplog.text


def test_ad_ssl_environment_default_and_override(monkeypatch):
    from backend.core.config import load_config
    monkeypatch.delenv("NETMON_AD_USE_SSL", raising=False)
    assert load_config().ad_use_ssl is True
    monkeypatch.setenv("NETMON_AD_USE_SSL", "false")
    assert load_config().ad_use_ssl is False


def test_ad_ssl_toggle_is_saved_by_frontend():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "frontend/js/administration.js").read_text(encoding="utf-8")
    assert 'id="setAdUseSsl" type="checkbox"' in source
    assert 'ad_use_ssl: $("setAdUseSsl")?.checked' in source
