import json

import server
from test_server_security import _bootstrap_admin
from test_server_security import isolated_server as isolated_server

from backend.routers.security import _network_quality_points


def test_visibility_summary_combines_quality_security_certificates_and_dhcp(isolated_server, monkeypatch):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    now = server.time.time()
    snapshots = [
        (now - 180, 20, 2, 0),
        (now - 120, 30, 3, 5),
        (now - 60, 40, 4, 10),
    ]
    with server.sqlite3.connect(db_path) as conn:
        for ts, internet_latency, gateway_latency, packet_loss in snapshots:
            payload = {
                "status": "warn" if packet_loss else "ok",
                "internet_test": {"average": internet_latency, "packet_loss": packet_loss},
                "gateway_test": {"average": gateway_latency, "packet_loss": 0},
            }
            conn.execute("INSERT INTO snapshots(ts,data) VALUES(?,?)", (ts, json.dumps(payload)))
        conn.executemany(
            "INSERT INTO ssl_certificates(ip,hostname,issuer,valid_to,days_left,last_checked) VALUES(?,?,?,?,?,?)",
            [
                ("10.0.0.10", "expired.local", "Test CA", "2026-01-01", -2, now),
                ("10.0.0.11", "soon.local", "Test CA", "2026-09-15", 11, now),
                ("10.0.0.12", "valid.local", "Test CA", "2027-09-15", 365, now),
            ],
        )

    server._devices_cache["data"] = [
        {"ip": "10.0.0.20", "hostname": "legacy", "type": "unknown", "open_ports": [23]},
        {"ip": "10.0.0.21", "hostname": "workstation", "type": "computer", "open_ports": [443]},
    ]
    monkeypatch.setattr(server, "_cached_firewall_status", lambda: {"state": "enabled"})
    monkeypatch.setattr(
        server,
        "get_dhcp_monitor_status",
        lambda: {
            "running": True,
            "thread_alive": True,
            "rogue_detected_count": 1,
            "last_rogue_source": "10.0.0.254",
            "last_rogue_ts": now,
        },
    )
    monkeypatch.setattr(server, "_authorized_dhcp_servers", lambda: ["10.0.0.1"])

    response = client.get("/api/visibility/summary?range=1h", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["range"] == "1h"
    assert body["network_quality"]["stats"] == {
        "samples": 3,
        "average_latency_ms": 30.0,
        "jitter_ms": 10.0,
        "average_packet_loss_pct": 5.0,
        "latest": body["network_quality"]["points"][-1],
    }
    assert body["certificates"]["total"] == 3
    assert body["certificates"]["expired"] == 1
    assert body["certificates"]["expiring_30d"] == 1
    assert [item["hostname"] for item in body["certificates"]["attention"]] == ["expired.local", "soon.local"]
    assert body["dhcp"]["authorized_server_count"] == 1
    assert body["dhcp"]["last_rogue_source"] == "10.0.0.254"
    assert body["security"]["score"] == 45
    assert {item["code"] for item in body["security"]["deductions"]} == {
        "RISKY_SERVICES",
        "UNKNOWN_ASSETS",
        "EXPIRED_CERTIFICATES",
        "EXPIRING_CERTIFICATES",
        "ROGUE_DHCP",
    }


def test_visibility_summary_rejects_unknown_range_with_standard_error(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    response = client.get("/api/visibility/summary?range=30d", headers=headers)

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert response.json()["trace_id"] == response.headers["X-Trace-ID"]


def test_network_quality_history_is_bounded_and_skips_corrupt_snapshots():
    rows = [
        (
            float(index),
            json.dumps({"status": "ok", "internet_test": {"average": index, "packet_loss": 0}}),
        )
        for index in range(500)
    ]
    rows.insert(250, (250.5, "not-json"))

    points = _network_quality_points(rows)

    assert len(points) <= 240
    assert all(point["internet_latency_ms"] is not None for point in points)
