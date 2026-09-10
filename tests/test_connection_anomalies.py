import pytest
import server


@pytest.fixture()
def isolated_database(tmp_path, monkeypatch):
    db_path = tmp_path / "netmon-connection-anomalies.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    server.init_db()
    return db_path


def _insert_connection(conn, *, username, remote_ip, first_seen, remote_port=443):
    conn.execute(
        """
        INSERT INTO connections (
            username,process_name,local_ip,remote_ip,remote_port,protocol,
            direction,status,resolved_hostname,first_seen,last_seen,closed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            username,
            "agent.exe",
            "10.0.0.20",
            remote_ip,
            remote_port,
            "TCP",
            "outbound",
            "ESTABLISHED",
            None,
            first_seen,
            first_seen,
            first_seen + 1,
        ),
    )


def test_first_seen_remote_ip_creates_info_alert(isolated_database):
    now = 1_700_000_000.0
    with server.db_conn() as conn:
        _insert_connection(conn, username="alice", remote_ip="8.8.8.8", first_seen=now)
        alerts = server._check_connection_anomalies(now, conn)
        rows = conn.execute("SELECT level,message,source FROM alerts ORDER BY ts").fetchall()

    assert len(alerts) == 1
    assert rows == [
        (
            "info",
            "İlk kez görülen bağlantı hedefi: 8.8.8.8.",
            "connections",
        )
    ]


def test_many_distinct_targets_in_five_minutes_creates_warning(isolated_database):
    now = 1_700_000_000.0
    with server.db_conn() as conn:
        for index in range(server.CONNECTION_TARGET_BURST_THRESHOLD + 1):
            _insert_connection(
                conn,
                username="alice",
                remote_ip=f"203.0.113.{index + 1}",
                remote_port=4000 + index,
                first_seen=now - 30,
            )
        alerts = server._check_connection_anomalies(now, conn)
        row = conn.execute(
            "SELECT level,message,source FROM alerts WHERE message LIKE 'Kısa sürede çok sayıda hedef:%'"
        ).fetchone()

    assert len(alerts) == 1
    assert row[0] == "warning"
    assert "kullanıcı=alice" in row[1]
    assert f"{server.CONNECTION_TARGET_BURST_THRESHOLD + 1} farklı uzak hedef" in row[1]
    assert row[2] == "connections"


def test_regular_connection_intervals_create_beacon_warning(isolated_database):
    now = 1_700_000_000.0
    timestamps = [now - 240, now - 180, now - 120, now - 60, now]
    with server.db_conn() as conn:
        for first_seen in timestamps:
            _insert_connection(
                conn,
                username="service.user",
                remote_ip="198.51.100.25",
                first_seen=first_seen,
            )
        alerts = server._check_connection_anomalies(now, conn)
        row = conn.execute(
            "SELECT level,message,source FROM alerts WHERE message LIKE 'Düzenli aralıklı bağlantı:%'"
        ).fetchone()

    assert len(alerts) == 1
    assert row[0] == "warning"
    assert "kullanıcı=service.user, hedef=198.51.100.25" in row[1]
    assert "Standart sapma 0.0 sn" in row[1]
    assert row[2] == "connections"
