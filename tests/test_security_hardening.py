import sqlite3
from unittest.mock import Mock

import pytest
import server
from test_server_security import _bootstrap_admin
from test_server_security import isolated_server as isolated_server


@pytest.fixture(autouse=True)
def reset_tool_rate_state(monkeypatch):
    monkeypatch.setattr(server, "_tool_rate_state", {}, raising=False)


def _headers_for_role(db_path, role: str) -> dict[str, str]:
    token = f"{role}-diagnostics-token"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (username,password_hash,salt,role,active,must_change_password,created_at) "
            "VALUES (?,?,?,?,1,0,0)",
            (f"{role}-diagnostics", "unused", "unused", role),
        )
        conn.execute(
            "INSERT INTO sessions (token,user_id,created_at,expires_at) "
            "SELECT ?,id,0,? FROM users WHERE username=?",
            (token, server.time.time() + 3600, f"{role}-diagnostics"),
        )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "path,payload",
    [
        ("/api/tools/ping", {"target": "127.0.0.1", "count": 1}),
        ("/api/tools/traceroute", {"target": "127.0.0.1", "max_hops": 1}),
        ("/api/tools/network-cmd", {"action": "hostname"}),
    ],
)
def test_active_diagnostics_require_permission(isolated_server, monkeypatch, path, payload):
    client, db_path, _ = isolated_server
    run = Mock(return_value=Mock(stdout="Reply time=1ms", stderr="", returncode=0))
    monkeypatch.setattr(server.subprocess, "run", run)
    monkeypatch.setattr(server.subprocess, "check_output", Mock(return_value=""))

    viewer_response = client.post(path, headers=_headers_for_role(db_path, "viewer"), json=payload)
    assert viewer_response.status_code == 403

    operator_response = client.post(path, headers=_headers_for_role(db_path, "noc_operator"), json=payload)
    assert operator_response.status_code == 200


@pytest.mark.parametrize("target", ["-t", "--flood"])
def test_ping_rejects_option_like_targets_before_subprocess(isolated_server, monkeypatch, target):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock()
    monkeypatch.setattr(server.subprocess, "run", run)

    response = client.post("/api/tools/ping", headers=headers, json={"target": target})

    assert response.status_code == 400
    run.assert_not_called()


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
    response = client.post(
        "/api/tools/traceroute", headers=headers, json={"target": " example.com/path ", "max_hops": max_hops}
    )
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
    token = client.post("/api/auth/login", json={"username": "admin", "password": "New-Company-Pass-2026!"}).json()[
        "token"
    ]
    second_headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/tools/traceroute", headers=headers, json={"target": ""}).status_code == 400
    assert client.post("/api/tools/network-cmd", headers=second_headers, json={"action": "invalid"}).status_code == 400
    for path in server._RATE_LIMITED_TOOL_PATHS:
        assert client.post(path, headers=headers, json={"target": ""}).status_code == 429
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (username,password_hash,salt,role,active,must_change_password,created_at) "
            "VALUES ('another','unused','unused','admin',1,0,0)"
        )
        conn.execute(
            "INSERT INTO sessions (token,user_id,created_at,expires_at) "
            "SELECT 'another-token',id,0,? FROM users WHERE username='another'",
            (server.time.time() + 3600,),
        )
    assert client.post("/api/tools/deep-scan", headers={"Authorization": "Bearer another-token"}).status_code == 200
    clock.return_value = 1060.0
    assert client.post("/api/tools/deep-scan", headers=headers).status_code == 200


def test_ping_is_rate_limited_for_same_user(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    monkeypatch.setattr(server, "TOOL_RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(
        server.subprocess,
        "run",
        Mock(return_value=Mock(stdout="Reply time=1ms", stderr="", returncode=0)),
    )

    responses = [
        client.post("/api/tools/ping", headers=headers, json={"target": "127.0.0.1", "count": 1})
        for _ in range(server.TOOL_RATE_LIMIT_PER_MINUTE + 1)
    ]

    assert [response.status_code for response in responses] == [200, 200, 429]


@pytest.mark.parametrize("value, expected", [("20", 20), ("0", 15), ("-1", 15), ("bad", 15), ("1001", 15)])
def test_tool_rate_limit_environment(monkeypatch, value, expected):
    from backend.core.config import load_config

    monkeypatch.setenv("NETMON_TOOL_RATE_LIMIT_PER_MINUTE", value)
    assert load_config().tool_rate_limit_per_minute == expected


@pytest.mark.parametrize(
    "address, use_ssl", [("dc.example.com", True), ("dc.example.com", False), ("ldaps://dc.example.com", False)]
)
def test_ad_login_requires_verified_tls_and_provisions_user(isolated_server, monkeypatch, address, use_ssl):
    import ssl

    import ldap3

    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.post(
        "/api/settings",
        headers=headers,
        json={
            "ad_server": address,
            "ad_domain": "example.com",
            "ad_use_ssl": use_ssl,
        },
    )
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
        assert isinstance(
            conn.execute("SELECT password_hash FROM users WHERE username='directory-user'").fetchone()[0], str
        )


def test_plain_ldap_is_rejected_without_sending_credentials(isolated_server, monkeypatch, caplog):
    import ldap3

    client, db_path, password_path = isolated_server
    _bootstrap_admin(client, password_path)
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO settings (key,value) VALUES (?,?)",
            [
                ("ad_server", "ldap://dc.example.com"),
                ("ad_domain", "example.com"),
            ],
        )
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


@pytest.mark.parametrize("iterations, tagged", [(200000, False), (100000, True), (600000, True), (700000, True)])
def test_password_hash_upgrade_only_on_successful_local_login(isolated_server, iterations, tagged):
    import hashlib

    client, db_path, _ = isolated_server
    password, salt = "Legacy-password-2026!", "legacy-salt"
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    stored = f"pbkdf2_sha256${iterations}${digest}" if tagged else digest
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash=?,salt=?,must_change_password=0 WHERE username='admin'", (stored, salt)
        )
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"}).status_code == 401
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT password_hash,salt FROM users WHERE username='admin'").fetchone() == (stored, salt)
    assert client.post("/api/auth/login", json={"username": "admin", "password": password}).status_code == 200
    with sqlite3.connect(db_path) as conn:
        new_hash, new_salt = conn.execute("SELECT password_hash,salt FROM users WHERE username='admin'").fetchone()
    if iterations < 600000:
        assert new_hash.startswith("pbkdf2_sha256$600000$")
        assert new_salt != salt
    else:
        assert (new_hash, new_salt) == (stored, salt)
    assert server._verify_password(password, new_salt, new_hash)
    assert not server._password_needs_rehash(new_hash)


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "bad",
        "pbkdf2_sha256$0$" + "0" * 64,
        "pbkdf2_sha256$999999999999$" + "0" * 64,
        "pbkdf2_sha256$600000$not-a-hash",
    ],
)
def test_malformed_password_hash_is_rejected(stored):
    assert server._verify_password("password", "salt", stored) is False


def test_new_password_hash_uses_random_salt_and_600000_iterations():
    salt, digest = server._hash_password("New-password!")
    other_salt, other_digest = server._hash_password("New-password!")
    assert salt != other_salt
    assert digest != other_digest
    assert digest.startswith("pbkdf2_sha256$600000$")
    assert server._verify_password("New-password!", salt, digest)
    assert not server._verify_password("wrong", salt, digest)


@pytest.mark.parametrize("change", ["logout", "expired", "inactive", "password_reset"])
def test_live_websocket_rechecks_idle_session(isolated_server, monkeypatch, change):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    token = headers["Authorization"].removeprefix("Bearer ")
    monkeypatch.setattr(server, "WS_SESSION_CHECK_INTERVAL", 0.02)
    with client.websocket_connect("/ws/live", subprotocols=["netmon", token]) as ws:
        assert ws.receive_json()["type"] == "status"
        if change == "logout":
            assert client.post("/api/auth/logout", headers=headers).status_code == 200
        else:
            statements = {
                "expired": "UPDATE sessions SET expires_at=0",
                "inactive": "UPDATE users SET active=0",
                "password_reset": "UPDATE users SET must_change_password=1",
            }
            with sqlite3.connect(db_path) as conn:
                conn.execute(statements[change])
        message = ws.receive()
        assert message["type"] == "websocket.close"
        assert message["code"] == 4401
    assert not server.manager.active


@pytest.mark.parametrize("ip", ["", "example.com", "/admin", "127.0.0.1 /admin", "999.1.1.1", "1.2.3.4;calc"])
def test_rdp_rejects_invalid_ip_before_popen(isolated_server, monkeypatch, ip):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    popen = Mock()
    monkeypatch.setattr(server.subprocess, "Popen", popen)
    monkeypatch.setattr(server.platform, "system", lambda: "Windows")
    response = client.post("/api/tools/rdp", params={"ip": ip}, headers=headers)
    assert response.status_code == 400
    popen.assert_not_called()


@pytest.mark.parametrize("ip, normalized", [("192.168.1.10", "192.168.1.10"), ("2001:0db8::1", "2001:db8::1")])
def test_rdp_accepts_ipv4_and_ipv6(isolated_server, monkeypatch, ip, normalized):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    popen = Mock()
    monkeypatch.setattr(server.subprocess, "Popen", popen)
    monkeypatch.setattr(server.platform, "system", lambda: "Windows")
    response = client.post("/api/tools/rdp", params={"ip": ip}, headers=headers)
    assert response.status_code == 200
    assert popen.call_args.args[0] == ["mstsc.exe", f"/v:{normalized}"]


@pytest.mark.asyncio
async def test_websocket_messages_cannot_postpone_session_check(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    ticks = [0.0]

    async def receive_text():
        ticks[0] += 1
        return "ping"

    ws = SimpleNamespace(
        headers={"sec-websocket-protocol": "netmon, test-token"},
        accept=AsyncMock(),
        send_text=AsyncMock(),
        close=AsyncMock(),
        receive_text=receive_text,
    )
    validation = Mock(side_effect=[True, True, False])
    monkeypatch.setattr(server, "_websocket_session_valid", validation)
    monkeypatch.setattr(server, "WS_SESSION_CHECK_INTERVAL", 2)
    monkeypatch.setattr(server, "time", SimpleNamespace(monotonic=lambda: ticks[0], time=lambda: 0))
    monkeypatch.setattr(server, "_devices_cache", {"data": []})
    monkeypatch.setattr(server, "manager", server.ConnectionManager())
    await server.ws_live(ws)
    assert ticks[0] == 4
    assert validation.call_count == 3
    ws.close.assert_awaited_once_with(code=4401)
    assert not server.manager.active
