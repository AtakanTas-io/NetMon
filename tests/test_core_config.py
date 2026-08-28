from backend.core.config import load_config


def test_config_uses_defaults_without_env(monkeypatch):
    for name in (
        "NETMON_PING_COUNT",
        "NETMON_SCAN_INTERVAL",
        "NETMON_SESSION_TTL_SECONDS",
        "NETMON_ANOMALY_RATIO",
    ):
        monkeypatch.delenv(name, raising=False)
    config = load_config()
    assert config.ping_count == 4
    assert config.scan_interval == 300
    assert config.session_ttl_seconds == 43200
    assert config.anomaly_ratio == 3.0


def test_config_accepts_valid_environment_overrides(monkeypatch):
    monkeypatch.setenv("NETMON_PING_COUNT", "8")
    monkeypatch.setenv("NETMON_SCAN_INTERVAL", "600")
    monkeypatch.setenv("NETMON_ANOMALY_RATIO", "4.5")
    config = load_config()
    assert config.ping_count == 8
    assert config.scan_interval == 600
    assert config.anomaly_ratio == 4.5


def test_config_rejects_invalid_or_unsafe_bounds(monkeypatch):
    monkeypatch.setenv("NETMON_PING_COUNT", "999")
    monkeypatch.setenv("NETMON_SCAN_INTERVAL", "abc")
    monkeypatch.setenv("NETMON_SESSION_TTL_SECONDS", "2")
    config = load_config()
    assert config.ping_count == 4
    assert config.scan_interval == 300
    assert config.session_ttl_seconds == 43200


def test_config_places_database_in_configured_data_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("NETMON_DATA_DIR", str(tmp_path))
    config = load_config()
    assert config.data_dir == tmp_path.resolve()
    assert config.db_path == tmp_path.resolve() / "netmon.db"
