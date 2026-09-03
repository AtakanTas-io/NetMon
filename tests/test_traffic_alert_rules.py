import time

import pytest
import server
from core import operations as ops
from test_phase4_operations import _bootstrap_admin
from test_phase4_operations import isolated_server as isolated_server


@pytest.fixture()
def rule_conn(isolated_server):
    conn = server.db_conn()
    try:
        yield conn
    finally:
        conn.close()


def traffic(conn, now, current=16_000_000, baseline=4_000_000):
    conn.executemany(
        "INSERT INTO traffic(ts,wifi_sent,wifi_recv,eth_sent,eth_recv) VALUES(?,?,?,?,?)",
        [
            (now - 90, baseline / 2, 0, 0, 0),
            (now - 70, 0, baseline * 1.5, 0, 0),
            (now - 10, 0, 0, current / 2, current / 2),
        ],
    )


def connections(conn, now, count, process="Browser.exe", start=0):
    conn.executemany(
        "INSERT INTO connections(process_name,remote_ip,first_seen) VALUES(?,?,?)",
        [(process, f"10.0.0.{i}", now - 10) for i in range(start, start + count)],
    )


def evidence(conn, kind, now, last=0, target=""):
    return ops._rule_evidence(conn, kind, 60, target, last, [], now)


def test_bandwidth_spike_uses_all_interfaces_and_previous_average(rule_conn):
    now = 1000
    traffic(rule_conn, now)
    result = evidence(rule_conn, "bandwidth_spike", now)
    assert result == [
        {"ts": 990, "current_bps": 16_000_000, "baseline_bps": 4_000_000, "multiplier": 3, "window_seconds": 60}
    ]


@pytest.mark.parametrize("current", [8_000_000, 12_000_000])
def test_bandwidth_at_or_below_threshold_does_not_trigger(rule_conn, current):
    traffic(rule_conn, 1000, current=current)
    assert evidence(rule_conn, "bandwidth_spike", 1000) == []


def test_bandwidth_custom_multiplier_and_no_duplicate_or_future_sample(rule_conn):
    traffic(rule_conn, 1000)
    assert evidence(rule_conn, "bandwidth_spike", 1000, target="5x") == []
    assert evidence(rule_conn, "bandwidth_spike", 1000, target="3.5x")[0]["multiplier"] == 3.5
    rule_conn.execute("INSERT INTO traffic VALUES(1001,999999999,0,0,0)")
    assert evidence(rule_conn, "bandwidth_spike", 1000, last=990) == []
    # Son ölçüm normalleştiğinde eski sıçrama tekrar raporlanmamalı.
    rule_conn.execute("INSERT INTO traffic VALUES(999,1,0,0,0)")
    assert evidence(rule_conn, "bandwidth_spike", 1000) == []


@pytest.mark.parametrize("baseline", [0, None])
def test_bandwidth_requires_measured_positive_baseline(rule_conn, baseline):
    if baseline is not None:
        traffic(rule_conn, 1000, baseline=baseline)
    else:
        rule_conn.execute("INSERT INTO traffic VALUES(990,999999999,0,0,0)")
    assert evidence(rule_conn, "bandwidth_spike", 1000) == []


@pytest.mark.parametrize("target", ["", "invalid", "NaNx", "infx", "-3x", "0x"])
def test_invalid_multiplier_uses_safe_default(target):
    assert ops._bandwidth_multiplier(target) == 3


def test_connection_burst_triggers_for_distinct_new_targets(rule_conn):
    connections(rule_conn, 1000, 21)
    result = evidence(rule_conn, "connection_burst", 1000)
    assert result[0]["process_name"] == "Browser.exe"
    assert result[0]["distinct_remote_ips"] == 21
    assert result[0]["window_seconds"] == 60


def test_connection_burst_below_threshold_and_duplicates_do_not_trigger(rule_conn):
    connections(rule_conn, 1000, 20)
    connections(rule_conn, 1000, 20)  # Aynı IP'ler başka socket kayıtları olabilir.
    connections(rule_conn, 1000, 20, process="Other.exe")
    connections(rule_conn, 900, 40, start=30)  # Pencere dışında.
    connections(rule_conn, 1020, 40, start=80)  # Gelecekte.
    assert evidence(rule_conn, "connection_burst", 1000) == []


def test_connection_burst_accumulates_window_but_does_not_repeat_crossing(rule_conn):
    connections(rule_conn, 1000, 20)
    assert evidence(rule_conn, "connection_burst", 1000) == []
    connections(rule_conn, 1011, 1, start=20)
    assert evidence(rule_conn, "connection_burst", 1011, last=1000)[0]["distinct_remote_ips"] == 21
    connections(rule_conn, 1012, 1, start=21)
    assert evidence(rule_conn, "connection_burst", 1012, last=1011) == []
    assert evidence(rule_conn, "connection_burst", 1011, last=1011) == []


@pytest.mark.parametrize("kind", ["offline_duration", "new_device", "rogue_dhcp", "ip_conflict", "config_diff"])
def test_existing_rule_types_keep_evidence_and_message_format(rule_conn, kind):
    rule_conn.execute(
        "INSERT INTO known_devices(mac,last_ip,hostname,first_seen,last_seen,last_status) "
        "VALUES('AA','10.0.0.1','switch',950,800,'offline')"
    )
    rule_conn.execute("INSERT INTO alerts(ts,message,source) VALUES(950,'Rogue DHCP bulundu','test')")
    rule_conn.executemany(
        "INSERT INTO device_configs(ip,config_text,config_hash,created_at) VALUES('10.0.0.1',?,?,?)",
        [("old", "hash1", 850), ("new", "hash2", 950)],
    )
    devices = [{"ip": "10.0.0.1", "mac": "AA"}, {"ip": "10.0.0.1", "mac": "BB"}]
    result = ops._rule_evidence(rule_conn, kind, 60, "", 900, devices, 1000)
    assert len(result) == 1
    assert ops._rule_message("Mevcut kural", kind, result) == "Mevcut kural: 1 doğrulanmış eşleşme"
    if kind in {"new_device", "rogue_dhcp", "config_diff"}:
        assert ops._rule_evidence(rule_conn, kind, 60, "", 1000, devices, 1001) == []


@pytest.mark.parametrize("kind", ["bandwidth_spike", "connection_burst"])
def test_new_rules_crud_evaluation_and_inbox_round_trip(isolated_server, kind):
    client, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    supported = client.get("/api/alert-rules", headers=headers).json()["supported_types"]
    assert set(supported) == {
        "offline_duration",
        "new_device",
        "rogue_dhcp",
        "ip_conflict",
        "config_diff",
        "bandwidth_spike",
        "connection_burst",
    }
    body = {"name": "Trafik alarmı", "rule_type": kind, "threshold_seconds": 60, "target": "3x"}
    created = client.post("/api/alert-rules", headers=headers, json=body)
    assert created.status_code == 200
    rule_id = created.json()["id"]
    assert client.put(f"/api/alert-rules/{rule_id}", headers=headers, json=body).status_code == 200
    now = time.time()
    with server.db_conn() as conn:
        if kind == "bandwidth_spike":
            traffic(conn, now)
        else:
            connections(conn, now, 21)
        conn.commit()
    events = client.post("/api/alert-rules/evaluate", headers=headers).json()["events"]
    assert len(events) == 1
    message = events[0]["message"]
    assert ("4.0 katına" if kind == "bandwidth_spike" else "21 farklı uzak adrese") in message
    assert client.post("/api/alert-rules/evaluate", headers=headers).json()["events"] == []
    stored = client.get("/api/alert-events", headers=headers).json()["events"][0]
    assert stored["message"] == message
    assert stored["evidence"] == events[0]["evidence"]
    inbox = client.get("/api/alerts/inbox", headers=headers).json()["alerts"]
    assert any(item["message"] == message for item in inbox)
    assert client.delete(f"/api/alert-rules/{rule_id}", headers=headers).status_code == 200
