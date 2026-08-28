"""Ortam değişkenleriyle değiştirilebilen NetMon çalışma zamanı ayarları."""

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def _env_int(name: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum or (maximum is not None and value > maximum):
        return default
    return value


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


@dataclass(frozen=True)
class RuntimeConfig:
    data_dir: Path
    db_path: Path
    traffic_sample_interval: int
    diagnostics_interval: int
    retention_hours: int
    ping_target: str
    dns_domain: str
    ping_count: int
    scan_interval: int
    subnet_override: str
    session_ttl_seconds: int
    anomaly_window_seconds: int
    anomaly_min_samples: int
    anomaly_min_baseline_bps: float
    anomaly_ratio: float
    anomaly_cooldown_seconds: int
    login_max_attempts: int
    login_lockout_seconds: int
    wmi_auth_failure_cooldown_seconds: int


def load_config() -> RuntimeConfig:
    configured_dir = os.environ.get("NETMON_DATA_DIR", "").strip()
    user_dir = Path(os.path.expanduser("~")) / ".netmon"
    if configured_dir:
        data_dir = Path(configured_dir).expanduser().resolve()
    elif getattr(sys, "frozen", False):
        data_dir = user_dir
    else:
        data_dir = Path(__file__).resolve().parents[1]
    data_dir.mkdir(parents=True, exist_ok=True)

    return RuntimeConfig(
        data_dir=data_dir,
        db_path=data_dir / "netmon.db",
        traffic_sample_interval=_env_int("NETMON_TRAFFIC_SAMPLE_INTERVAL", 1, 1, 300),
        diagnostics_interval=_env_int("NETMON_DIAGNOSTICS_INTERVAL", 15, 5, 3600),
        retention_hours=_env_int("NETMON_RETENTION_HOURS", 48, 1, 8760),
        ping_target=os.environ.get("NETMON_PING_TARGET", "8.8.8.8").strip() or "8.8.8.8",
        dns_domain=os.environ.get("NETMON_DNS_DOMAIN", "google.com").strip() or "google.com",
        ping_count=_env_int("NETMON_PING_COUNT", 4, 1, 20),
        scan_interval=_env_int("NETMON_SCAN_INTERVAL", 300, 60, 86400),
        subnet_override=os.environ.get("NETMON_SUBNET_OVERRIDE", "").strip(),
        session_ttl_seconds=_env_int("NETMON_SESSION_TTL_SECONDS", 12 * 3600, 300, 30 * 86400),
        anomaly_window_seconds=_env_int("NETMON_ANOMALY_WINDOW_SECONDS", 3600, 60, 86400),
        anomaly_min_samples=_env_int("NETMON_ANOMALY_MIN_SAMPLES", 30, 3, 10000),
        anomaly_min_baseline_bps=_env_float("NETMON_ANOMALY_MIN_BASELINE_BPS", 1_000_000, 0),
        anomaly_ratio=_env_float("NETMON_ANOMALY_RATIO", 3.0, 1.0),
        anomaly_cooldown_seconds=_env_int("NETMON_ANOMALY_COOLDOWN_SECONDS", 300, 1, 86400),
        login_max_attempts=_env_int("NETMON_LOGIN_MAX_ATTEMPTS", 5, 1, 100),
        login_lockout_seconds=_env_int("NETMON_LOGIN_LOCKOUT_SECONDS", 300, 1, 86400),
        wmi_auth_failure_cooldown_seconds=_env_int("NETMON_WMI_AUTH_COOLDOWN_SECONDS", 900, 1, 86400),
    )


RUNTIME_CONFIG = load_config()
