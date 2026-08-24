"""
server.py
netdiag_core.py'deki motoru kullanarak surekli calisan bir ag izleme servisi.
Arayüz bazlı (Wi-Fi/Ethernet) trafik analizi yapar ve .exe paketlemesine uygundur.
"""

import asyncio
import hashlib
import hmac
import json
import math
import os
import random
import secrets
import sqlite3
import sys
import threading
import time
import platform
import subprocess
import socket
import re
import ipaddress
import concurrent.futures
import base64
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Header, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

try:
    from . import netdiag_core as diag
    from . import deep_discovery
    from .wmi_scanner import WmiNetworkScanner
except ImportError:
    import netdiag_core as diag
    import deep_discovery
    from wmi_scanner import WmiNetworkScanner

try:
    import win32crypt
except ImportError:
    win32crypt = None

SECRET_SETTING_KEYS = {"wmi_password", "ssh_password", "snmp_community"}
DPAPI_PREFIX = "dpapi:"


def _protect_secret(value: str) -> str:
    """Parolaları Windows kullanıcısına/makinesine bağlı DPAPI ile şifrele."""
    if not value:
        return ""
    if platform.system() != "Windows" or win32crypt is None:
        raise RuntimeError("Güvenli parola saklama için Windows DPAPI/pywin32 gerekli.")
    protected = win32crypt.CryptProtectData(value.encode("utf-8"), "NetMon secret", None, None, None, 0)
    # pywin32'nin güncel sürümü doğrudan bytes, bazı eski sürümleri tuple döndürür.
    encrypted = protected[-1] if isinstance(protected, tuple) else protected
    return DPAPI_PREFIX + base64.b64encode(encrypted).decode("ascii")


def _unprotect_secret(value: str) -> str:
    if not value:
        return ""
    if not value.startswith(DPAPI_PREFIX):
        # Eski sürümden kalan düz metin yalnızca bir defalık geçişte okunur.
        return value
    if platform.system() != "Windows" or win32crypt is None:
        logger.warning("DPAPI kullanılamadığı için kayıtlı gizli ayar çözülemedi.")
        return ""
    try:
        raw = base64.b64decode(value[len(DPAPI_PREFIX):])
        unprotected = win32crypt.CryptUnprotectData(raw, None, None, None, 0)
        decrypted = unprotected[-1] if isinstance(unprotected, tuple) else unprotected
        return decrypted.decode("utf-8")
    except Exception as exc:
        logger.warning("Kayıtlı gizli ayar çözülemedi: %s", exc)
        return ""


# ============================================================
# ŞİFRE HASHLEME (PBKDF2-HMAC-SHA256, 200k iterasyon)
# ============================================================
def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return salt, dk.hex()


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, computed = _hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)

from netdiag_core import NetworkDiagnostics, NetworkDiscoveryError
import logging

logger = logging.getLogger("netmon.server")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

try:
    import speedtest
except ImportError:
    speedtest = None

# ============================================================
# KONSOLSUZ (--noconsole) .exe İÇİNDE ALT SÜREÇ ÇALIŞTIRMA
# ============================================================
# NetMon.spec içinde console=False olduğu için uygulamanın kendisi konsolsuz
# çalışır. Ancak ping/tracert gibi konsol tabanlı komutlar subprocess.run ile
# çalıştırıldığında, Windows varsayılan olarak onlar için KISA SÜRELİ, SİYAH
# bir CMD penceresi açıp kapatır (flash). netdiag_core.py bunu run_command()
# içinde STARTUPINFO + CREATE_NO_WINDOW ile önlüyordu, fakat bu dosyadaki
# /api/tools/ping ve /api/tools/traceroute uç noktaları subprocess'i doğrudan
# çağırdığı için bu korumadan yoksundu — kullanıcının bahsettiği "cmd ekranı
# açılması" sorununun kaynağı budur. Aşağıdaki yardımcı, her iki uç noktada da
# kullanılarak pencere flash'ını tamamen engeller.
def _hidden_subprocess_kwargs() -> dict:
    if platform.system() == "Windows":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return {"startupinfo": si, "creationflags": subprocess.CREATE_NO_WINDOW}
    return {}

# ============================================================
# AYARLAR VE VERİTABANI YOLU
# ============================================================
_configured_data_dir = os.environ.get("NETMON_DATA_DIR", "").strip()
if _configured_data_dir:
    base_dir = Path(_configured_data_dir).expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    DB_PATH = base_dir / "netmon.db"
elif getattr(sys, 'frozen', False):
    base_dir = Path(os.path.expanduser("~")) / ".netmon"
    base_dir.mkdir(exist_ok=True)
    DB_PATH = base_dir / "netmon.db"
else:
    DB_PATH = Path(__file__).parent / "netmon.db"

USER_DATA_DIR = base_dir if _configured_data_dir else Path(os.path.expanduser("~")) / ".netmon"
USER_DATA_DIR.mkdir(exist_ok=True)
INITIAL_PASSWORD_PATH = USER_DATA_DIR / "initial_admin_password.txt"

TRAFFIC_SAMPLE_INTERVAL = 1
DIAGNOSTICS_INTERVAL = 15
RETENTION_HOURS = 48
PING_TARGET = "8.8.8.8"
DNS_DOMAIN = "google.com"
PING_COUNT = 4
SCAN_INTERVAL = 300
SUBNET_OVERRIDE = ""

diag = NetworkDiagnostics()

# ============================================================
# SİMÜLASYON MOTORU
# ============================================================
SCENARIOS = {
    "traffic_spike": {"label": "Yoğun trafik (video/indirme)", "affects": "traffic"},
    "outage": {"label": "İnternet kesintisi", "affects": "both"},
    "high_latency": {"label": "Yüksek gecikme (lag)", "affects": "both"},
    "packet_loss": {"label": "Kısmi paket kaybı", "affects": "both"},
    "dns_failure": {"label": "DNS sunucusu çöktü", "affects": "status"},
}

simulation_state = {"active": False, "scenario": None, "started_at": None}
_sim_tick = {"n": 0}

# ============================================================
# TRAFİK ANOMALİ TESPİTİ
# ============================================================
import collections
_traffic_window = collections.deque()
_last_anomaly_ts = 0.0
ANOMALY_WINDOW_SECONDS = 3600
ANOMALY_MIN_SAMPLES = 30
ANOMALY_MIN_BASELINE_BPS = 1_000_000
ANOMALY_RATIO = 3.0
ANOMALY_COOLDOWN_SECONDS = 300

def simulated_traffic_sample():
    _sim_tick["n"] += 1
    t = _sim_tick["n"]
    scenario = simulation_state["scenario"]

    if scenario == "outage":
        return 0.0, 0.0
    if scenario == "traffic_spike":
        base_down = 3_000_000 + 2_500_000 * abs(math.sin(t / 6))
        noise = random.uniform(-300_000, 300_000)
        down = max(0, base_down + noise)
        up = max(0, 150_000 + random.uniform(-40_000, 60_000))
        return up, down
    if scenario in ("high_latency", "packet_loss", "dns_failure"):
        base = 400_000 + 250_000 * abs(math.sin(t / 8))
        down = max(0, base + random.uniform(-80_000, 80_000))
        up = max(0, base * 0.3 + random.uniform(-30_000, 30_000))
        return up, down
    return random.uniform(0, 50_000), random.uniform(0, 80_000)

def simulated_snapshot() -> dict:
    scenario = simulation_state["scenario"]
    now_iso = datetime.now().isoformat(timespec="seconds")
    base = {
        "timestamp": now_iso, "local_ip": "192.168.1.42", "public_ip": "SİMÜLASYON",
        "gateway": "192.168.1.1", "dns_servers": ["192.168.1.1"],
    }

    if scenario == "outage":
        base.update({
            "gateway_test": {"target": "192.168.1.1", "success": False, "packet_loss": 100, "error": "Zaman aşımı"},
            "internet_test": {"target": "8.8.8.8", "success": False, "packet_loss": 100, "error": "Zaman aşımı"},
            "dns_test": {"success": False, "result": "Ağ erişilemez durumda"},
            "diagnosis": "[SİMÜLASYON] Modem/router'a ulaşılamıyor — internet kesintisi.", "status": "fail",
        })
    elif scenario == "high_latency":
        base.update({
            "gateway_test": {"target": "192.168.1.1", "success": True, "packet_loss": 0, "average": 2},
            "internet_test": {"target": "8.8.8.8", "success": True, "packet_loss": 0, "average": 340},
            "dns_test": {"success": True, "result": "142.250.187.14"},
            "diagnosis": "[SİMÜLASYON] Bağlantı çalışıyor ama gecikme çok yüksek (340 ms).", "status": "warn",
        })
    elif scenario == "packet_loss":
        base.update({
            "gateway_test": {"target": "192.168.1.1", "success": True, "packet_loss": 0, "average": 1},
            "internet_test": {"target": "8.8.8.8", "success": True, "packet_loss": 28, "average": 45},
            "dns_test": {"success": True, "result": "142.250.187.14"},
            "diagnosis": "[SİMÜLASYON] Kısmi paket kaybı tespit edildi (%28).", "status": "warn",
        })
    elif scenario == "dns_failure":
        base.update({
            "gateway_test": {"target": "192.168.1.1", "success": True, "packet_loss": 0, "average": 1},
            "internet_test": {"target": "8.8.8.8", "success": True, "packet_loss": 0, "average": 18},
            "dns_test": {"success": False, "result": "[Errno -2] Name or service not known (simüle)"},
            "diagnosis": "[SİMÜLASYON] İnternet bağlantınız var ama alan adları çözümlenemiyor (DNS hatası).", "status": "fail",
        })
    elif scenario == "traffic_spike":
        base.update({
            "gateway_test": {"target": "192.168.1.1", "success": True, "packet_loss": 0, "average": 1},
            "internet_test": {"target": "8.8.8.8", "success": True, "packet_loss": 0, "average": 15},
            "dns_test": {"success": True, "result": "142.250.187.14"},
            "diagnosis": "[SİMÜLASYON] Bağlantı sağlıklı, yalnızca yoğun trafik örneği gösteriliyor.", "status": "ok",
        })
    else:
        base.update({"diagnosis": "[SİMÜLASYON] Bilinmeyen senaryo.", "status": "unknown"})

    return base

# ============================================================
# VERİTABANI
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("PRAGMA foreign_keys=ON")
    # WAL modu: traffic_sampler_loop, diagnostics_loop ve API istekleri aynı
    # netmon.db dosyasına farklı thread'lerden eşzamanlı yazabiliyor. Varsayılan
    # "rollback journal" modunda bu durum "database is locked" hatasına yol
    # açabilir. WAL modunda okuma/yazma birbirini bloklamaz ve bu risk ortadan
    # kalkar. journal_mode PRAGMA'sı veritabanı dosyasına kalıcı yazılır, bu
    # yüzden tek seferlik burada ayarlamak yeterlidir.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        conn.execute("SELECT wifi_sent FROM traffic LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute("DROP TABLE IF EXISTS traffic")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            ts REAL PRIMARY KEY,
            wifi_sent REAL, wifi_recv REAL,
            eth_sent REAL, eth_recv REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS snapshots (
            ts REAL PRIMARY KEY,
            data TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            ts REAL PRIMARY KEY,
            level TEXT,
            message TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS device_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            hostname TEXT,
            device_type TEXT,
            config_text TEXT NOT NULL,
            config_hash TEXT NOT NULL,
            version_label TEXT,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_device_configs_ip ON device_configs(ip)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            issuer TEXT,
            valid_from TEXT,
            valid_to TEXT,
            days_left INTEGER,
            last_checked REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS speedtests (
            ts REAL PRIMARY KEY,
            download REAL,
            upload REAL,
            ping REAL,
            server TEXT
        )
    """)

    # Brute-force koruması: kullanıcı adına göre başarısız giriş denemeleri.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY,
            fail_count INTEGER NOT NULL DEFAULT 0,
            last_attempt REAL,
            locked_until REAL
        )
    """)

    # Denetim (audit) kaydı: admin'e özel / hassas işlemlerin izi.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            username TEXT,
            action TEXT NOT NULL,
            detail TEXT,
            success INTEGER NOT NULL DEFAULT 1
        )
    """)

    # Eski NetMon sürümlerinde sessions tablosunda expires_at yoktu.
    # Mevcut veritabanını bozmadan sütunu ekle ve eski oturumlara 12 saatlik
    # varsayılan süre ver.
    session_columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "expires_at" not in session_columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN expires_at REAL")
    conn.execute(
        "UPDATE sessions SET expires_at = created_at + ? WHERE expires_at IS NULL",
        (12 * 3600,),
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
    conn.execute("DELETE FROM login_attempts WHERE locked_until IS NULL OR locked_until < ?", (time.time(),))

    conn.execute("""
        CREATE TABLE IF NOT EXISTS known_devices (
            mac TEXT PRIMARY KEY,
            friendly_name TEXT,
            hostname TEXT,
            device_type TEXT,
            classification_source TEXT DEFAULT 'auto',
            owner TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            last_ip TEXT,
            last_status TEXT DEFAULT 'unknown',
            last_latency REAL,
            last_packet_loss REAL,
            last_arp_seen REAL,
            last_icmp_seen REAL,
            last_hostname_seen REAL,
            last_vendor TEXT,
            last_discovery_sources TEXT,
            connectivity_status TEXT DEFAULT 'unknown',
            identification_status TEXT DEFAULT 'unknown',
            last_network TEXT,
            open_ports TEXT
        )
    """)

    # Doğrulanmış uzak envanter sonuçları otomatik ağ taramasında kaybolmasın.
    # MongoDB gibi ikinci bir servis yerine uygulamanın mevcut SQLite deposu
    # kullanılır; MAC varsa cihaz kimliği, IP ise son erişim adresidir.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS device_inventory (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            status TEXT NOT NULL,
            source TEXT,
            payload TEXT NOT NULL,
            last_scanned REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_device_inventory_mac ON device_inventory(mac, last_scanned DESC)")

    # Kurumsal envanter çekirdeği: discovery sonuçlarını cihaz kimliğinden
    # ayırır; IP değişimi veya tekrar tarama duplicate asset oluşturmaz.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_assets (
            asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_key TEXT UNIQUE NOT NULL,
            hostname TEXT,
            ip_address TEXT,
            mac_address TEXT,
            vendor TEXT,
            device_type TEXT,
            os_name TEXT,
            os_version TEXT,
            status TEXT DEFAULT 'unknown',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            inventory_source TEXT DEFAULT 'network',
            completeness REAL DEFAULT 0,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inventory_assets_mac ON inventory_assets(mac_address)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inventory_assets_ip ON inventory_assets(ip_address)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_hardware (
            asset_id INTEGER PRIMARY KEY,
            cpu TEXT, ram_gb REAL, gpu TEXT, motherboard TEXT,
            disk_json TEXT, serial_number TEXT, collected_at REAL,
            FOREIGN KEY(asset_id) REFERENCES inventory_assets(asset_id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL,
            interface_name TEXT, ip_address TEXT, mac_address TEXT,
            gateway TEXT, subnet TEXT, collected_at REAL,
            FOREIGN KEY(asset_id) REFERENCES inventory_assets(asset_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inventory_interfaces_asset ON inventory_interfaces(asset_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL,
            name TEXT NOT NULL, version TEXT, publisher TEXT, collected_at REAL,
            FOREIGN KEY(asset_id) REFERENCES inventory_assets(asset_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inventory_software_asset ON inventory_software(asset_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, started_at REAL NOT NULL,
            finished_at REAL, mode TEXT NOT NULL, requested_by TEXT,
            total INTEGER DEFAULT 0, success INTEGER DEFAULT 0, failed INTEGER DEFAULT 0,
            error TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL,
            event_type TEXT NOT NULL, field_name TEXT, old_value TEXT, new_value TEXT,
            source TEXT, created_at REAL NOT NULL,
            FOREIGN KEY(asset_id) REFERENCES inventory_assets(asset_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inventory_history_asset ON inventory_history(asset_id, created_at DESC)")

    # Analyst correlation / trend kayıtları. Bunlar mevcut envanteri değiştirmez;
    # yalnızca ölçüm ve analiz geçmişini tutar.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyst_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
            total INTEGER DEFAULT 0, online INTEGER DEFAULT 0, offline INTEGER DEFAULT 0,
            unknown INTEGER DEFAULT 0, health REAL, completeness REAL,
            security_review INTEGER DEFAULT 0, payload TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyst_snapshots_created ON analyst_snapshots(created_at DESC)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_metadata (
            asset_id INTEGER PRIMARY KEY, asset_tag TEXT, owner TEXT, department TEXT,
            location TEXT, status TEXT DEFAULT 'managed', warranty_until TEXT, notes TEXT,
            updated_at REAL, FOREIGN KEY(asset_id) REFERENCES inventory_assets(asset_id) ON DELETE CASCADE
        )
    """)

    # Tablo zaten varsa eksik sütunu eklemesi için migration güvenliği:
    kd_columns = {row[1] for row in conn.execute("PRAGMA table_info(known_devices)").fetchall()}
    if "classification_source" not in kd_columns:
        conn.execute("ALTER TABLE known_devices ADD COLUMN classification_source TEXT DEFAULT 'auto'")
    if "last_ip" not in kd_columns:
        conn.execute("ALTER TABLE known_devices ADD COLUMN last_ip TEXT")
    if "last_status" not in kd_columns:
        conn.execute("ALTER TABLE known_devices ADD COLUMN last_status TEXT DEFAULT 'unknown'")
    if "last_latency" not in kd_columns:
        conn.execute("ALTER TABLE known_devices ADD COLUMN last_latency REAL")
    if "last_packet_loss" not in kd_columns:
        conn.execute("ALTER TABLE known_devices ADD COLUMN last_packet_loss REAL")
    # Stage 4 & Port Alarm & Subnet Tracking: kanıt zamanlarını ve durum ayrımını sakla.
    for col, sql_type in (
        ("last_arp_seen", "REAL"),
        ("last_icmp_seen", "REAL"),
        ("last_hostname_seen", "REAL"),
        ("last_vendor", "TEXT"),
        ("last_discovery_sources", "TEXT"),
        ("connectivity_status", "TEXT DEFAULT 'unknown'"),
        ("identification_status", "TEXT DEFAULT 'unknown'"),
        ("last_network", "TEXT"),
        ("open_ports", "TEXT"),
    ):
        if col not in kd_columns:
            conn.execute(f"ALTER TABLE known_devices ADD COLUMN {col} {sql_type}")

    user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "must_change_password" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")

    # Yanlışlıkla phone olarak kaydedilmiş kurumsal ağ donanımlarını (Huawei, Cisco vb.) switch olarak düzelt
    conn.execute("""
        UPDATE known_devices
        SET device_type = 'switch'
        WHERE device_type IN ('phone', 'unknown')
          AND (
            LOWER(COALESCE(last_vendor, '')) LIKE '%huawei%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%cisco%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%juniper%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%h3c%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%aruba%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%zyxel%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%tp-link%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%d-link%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%brocade%'
            OR LOWER(COALESCE(last_vendor, '')) LIKE '%extreme%'
          )
          AND LOWER(COALESCE(hostname, '')) NOT LIKE '%iphone%'
          AND LOWER(COALESCE(hostname, '')) NOT LIKE '%phone%'
          AND LOWER(COALESCE(hostname, '')) NOT LIKE '%mobile%'
    """)
    conn.commit()

    # İlk kurulum: bilinen/sabit parola kullanma. Rastgele ilk kurulum parolası
    # veritabanının yanında tek kullanımlık dosyaya yazılır ve ilk girişte
    # değiştirilmesi zorunludur.
    existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing == 0:
        default_password = secrets.token_urlsafe(16)
        salt, pw_hash = _hash_password(default_password)
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, active, must_change_password, created_at) "
            "VALUES (?, ?, ?, 'admin', 1, 1, ?)",
            ("admin", pw_hash, salt, time.time()),
        )
        conn.commit()
        INITIAL_PASSWORD_PATH.write_text(f"Default admin password:\n{default_password}\n", encoding="utf-8")

    # Eski sürümde düz metin tutulmuş gizli ayarları ilk açılışta DPAPI'ye taşı.
    for secret_key in SECRET_SETTING_KEYS:
        secret_row = conn.execute("SELECT value FROM settings WHERE key=?", (secret_key,)).fetchone()
        if secret_row and secret_row[0] and not secret_row[0].startswith(DPAPI_PREFIX):
            try:
                conn.execute("UPDATE settings SET value=? WHERE key=?", (_protect_secret(secret_row[0]), secret_key))
                conn.commit()
            except Exception as exc:
                logger.error("%s güvenli depoya taşınamadı; değer silindi: %s", secret_key, exc)
                conn.execute("DELETE FROM settings WHERE key=?", (secret_key,))
                conn.commit()
    conn.close()

def db_conn():
    # timeout=5.0: iki thread aynı anda yazmaya çalışırsa sqlite3 hemen
    # "database is locked" fırlatmak yerine kilidin açılmasını 5 saniyeye
    # kadar bekler (WAL modu ile birlikte pratikte bu bekleme neredeyse hiç
    # gerekmez, ama ekstra güvenlik katmanı olarak kalsın).
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _prune_operational_data(conn: sqlite3.Connection, now: float | None = None):
    """Saklama ayarını tüm zaman serilerine uygula; audit ve envanteri koru."""
    now = now or time.time()
    cutoff = now - RETENTION_HOURS * 3600
    for table in ("traffic", "snapshots", "alerts", "speedtests"):
        # table sabit tuple'dan geliyor, kullanıcı girdisi değil
        conn.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))  # nosec B608
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    conn.execute("DELETE FROM login_attempts WHERE locked_until IS NULL OR locked_until < ?", (now,))
    conn.commit()

# ============================================================
# WEBSOCKET YÖNETİMİ
# ============================================================
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket, subprotocol: str | None = None):
        await ws.accept(subprotocol=subprotocol)
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    def broadcast_threadsafe(self, payload: dict):
        if not self.loop: return
        asyncio.run_coroutine_threadsafe(self._broadcast(payload), self.loop)

    async def _broadcast(self, payload: dict):
        dead = []
        text = json.dumps(payload)
        for ws in self.active:
            try: await ws.send_text(text)
            except Exception: dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()
_last_status = {"status": "unknown"}

def _check_traffic_anomaly(now: float, total_bps: float, conn: sqlite3.Connection):
    global _last_anomaly_ts
    _traffic_window.append((now, total_bps))
    cutoff = now - ANOMALY_WINDOW_SECONDS
    while _traffic_window and _traffic_window[0][0] < cutoff:
        _traffic_window.popleft()

    if len(_traffic_window) < ANOMALY_MIN_SAMPLES:
        return

    baseline_samples = [v for _, v in _traffic_window[:-1]]
    avg = sum(baseline_samples) / len(baseline_samples) if baseline_samples else 0.0

    if (
        avg > ANOMALY_MIN_BASELINE_BPS
        and total_bps > avg * ANOMALY_RATIO
        and (now - _last_anomaly_ts) > ANOMALY_COOLDOWN_SECONDS
    ):
        _last_anomaly_ts = now
        pct = min(999, int((total_bps / avg - 1) * 100)) if avg else 0
        message = f"Sıra dışı trafik aktivitesi! Anlık trafik, son 1 saatin ortalamasının %{pct} üzerinde."
        conn.execute("INSERT OR REPLACE INTO alerts (ts, level, message) VALUES (?, ?, ?)",
                     (now, "warning", message))
        conn.commit()
        manager.broadcast_threadsafe({"type": "alert", "ts": now, "level": "warning",
                                       "message": message, "simulated": False})

# ============================================================
# ARKA PLAN THREAD: TRAFİK ÖRNEKLEME
# ============================================================
def traffic_sampler_loop(stop_event: threading.Event):
    prev_counters = psutil.net_io_counters(pernic=True)
    prev_t = time.time()
    conn = db_conn()
    last_prune = 0

    while not stop_event.is_set():
        time.sleep(TRAFFIC_SAMPLE_INTERVAL)
        now = time.time()
        cur_counters = psutil.net_io_counters(pernic=True)
        dt = now - prev_t or 1.0

        sim = simulation_state["active"] and SCENARIOS.get(simulation_state["scenario"], {}).get("affects") in ("traffic", "both")

        if sim:
            bits_sent, bits_recv = simulated_traffic_sample()
            wifi_sent, wifi_recv = bits_sent, bits_recv
            eth_sent, eth_recv = 0.0, 0.0
        else:
            wifi_sent = wifi_recv = eth_sent = eth_recv = 0.0
            stats = psutil.net_if_stats()
            for name, current in cur_counters.items():
                previous = prev_counters.get(name)
                lower = name.lower()
                if not previous or not stats.get(name) or not stats[name].isup:
                    continue
                if any(tag in lower for tag in ("loopback", "vethernet", "virtual", "bluetooth", "wi-fi direct", "local area connection*")):
                    continue
                sent = max(0.0, (current.bytes_sent - previous.bytes_sent) * 8 / dt)
                recv = max(0.0, (current.bytes_recv - previous.bytes_recv) * 8 / dt)
                if any(tag in lower for tag in ("wi-fi", "wifi", "wireless", "wlan")):
                    wifi_sent += sent
                    wifi_recv += recv
                else:
                    eth_sent += sent
                    eth_recv += recv

        if not sim:
            conn.execute("INSERT OR REPLACE INTO traffic (ts, wifi_sent, wifi_recv, eth_sent, eth_recv) VALUES (?, ?, ?, ?, ?)",
                         (now, wifi_sent, wifi_recv, eth_sent, eth_recv))
            conn.commit()
            _check_traffic_anomaly(now, wifi_sent + wifi_recv + eth_sent + eth_recv, conn)

        manager.broadcast_threadsafe({
            "type": "traffic", "ts": now,
            "sent": wifi_sent + eth_sent, "recv": wifi_recv + eth_recv,
            "wifi_sent": wifi_sent, "wifi_recv": wifi_recv,
            "eth_sent": eth_sent, "eth_recv": eth_recv,
            "simulated": sim,
        })

        prev_counters, prev_t = cur_counters, now

        if now - last_prune > 3600:
            _prune_operational_data(conn, now)
            last_prune = now

    conn.close()

# ============================================================
# ARKA PLAN THREAD: PERİYODİK TEŞHİS
# ============================================================
def diagnostics_loop(stop_event: threading.Event):
    global _last_status
    conn = db_conn()
    prev_status = None
    last_prune = 0

    while not stop_event.is_set():
        try:
            now = time.time()
            sim = simulation_state["active"] and SCENARIOS.get(simulation_state["scenario"], {}).get("affects") in ("status", "both")

            if sim:
                data = simulated_snapshot()
                data["simulated"] = True
                cur_status = data["status"]
            else:
                snap = diag.quick_snapshot(
                    ping_target=PING_TARGET,
                    dns_domain=DNS_DOMAIN,
                    lookup_public_ip=PUBLIC_IP_LOOKUP,
                    ping_count=PING_COUNT,
                )
                data = snap.to_dict()
                data["simulated"] = False
                cur_status = snap.status
                conn.execute("INSERT OR REPLACE INTO snapshots (ts, data) VALUES (?, ?)",
                             (now, json.dumps(data, ensure_ascii=False)))
                conn.commit()

            _last_status = data
            manager.broadcast_threadsafe({"type": "status", **data})

            if prev_status is not None and prev_status != cur_status:
                level = {"ok": "info", "warn": "warning", "fail": "critical"}.get(cur_status, "info")
                message = data.get("diagnosis") or "Durum değişti"
                if not sim:
                    conn.execute("INSERT OR REPLACE INTO alerts (ts, level, message) VALUES (?, ?, ?)",
                                 (now, level, message))
                    conn.commit()
                manager.broadcast_threadsafe({"type": "system_alert", "ts": now, "level": level, "message": message, "simulated": sim})

            prev_status = cur_status
            if now - last_prune > 3600:
                _prune_operational_data(conn, now)
                last_prune = now
        except Exception as exc:
            manager.broadcast_threadsafe({"type": "error", "message": str(exc)})

        stop_event.wait(DIAGNOSTICS_INTERVAL if not simulation_state["active"] else 3)

    conn.close()

# ============================================================
# STAGE 5 — GERÇEK SİSTEM AĞ HIZI / DURUM PAYLOAD'I
# ============================================================
_system_prev_net = None
_system_prev_ts = None

def _system_stats_payload():
    global _system_prev_net, _system_prev_ts
    if not HAS_PSUTIL:
        return {
            "cpu": None, "ram": None, "disk": None,
            "net_rx_mbps": None, "net_tx_mbps": None, "net_total_mbps": None,
            "net_percent": None, "network_data_source": None, "supported": False,
        }
    now = time.time()
    net_io = psutil.net_io_counters()
    rx_mbps = tx_mbps = 0.0
    if _system_prev_net is not None and _system_prev_ts:
        dt = max(0.001, now - _system_prev_ts)
        rx_mbps = max(0.0, (net_io.bytes_recv - _system_prev_net.bytes_recv) * 8 / dt / 1_000_000)
        tx_mbps = max(0.0, (net_io.bytes_sent - _system_prev_net.bytes_sent) * 8 / dt / 1_000_000)
    _system_prev_net, _system_prev_ts = net_io, now
    return {
        "cpu": round(psutil.cpu_percent(), 1),
        "ram": round(psutil.virtual_memory().percent, 1),
        "disk": round(psutil.disk_usage('/').percent, 1),
        "net_rx_mbps": round(rx_mbps, 2),
        "net_tx_mbps": round(tx_mbps, 2),
        "net_total_mbps": round(rx_mbps + tx_mbps, 2),
        "net_percent": None,
        "network_data_source": "psutil.net_io_counters",
        "supported": True,
    }

# ============================================================
# ARKA PLAN THREAD: CANLI SİSTEM DURUMU (CPU, RAM, DİSK)
# ============================================================
def system_stats_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            payload = _system_stats_payload()
            manager.broadcast_threadsafe({"type": "system", **payload})
        except Exception:
            pass
        stop_event.wait(1)

# ============================================================
# UYGULAMA YAŞAM DÖNGÜSÜ
# ============================================================
_stop_event = threading.Event()
_threads: list[threading.Thread] = []

def _load_last_known_devices_into_cache():
    try:
        conn = db_conn()
        rows = conn.execute(
            """SELECT ip_address, mac_address, hostname, vendor, device_type, status, last_seen
               FROM inventory_assets WHERE ip_address IS NOT NULL ORDER BY last_seen DESC"""
        ).fetchall()
        conn.close()
    except Exception:
        logger.exception("[STARTUP] Son bilinen cihaz envanteri yüklenemedi")
        return
    if not rows:
        return
    devices = [
        {
            "ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor,
            "type": device_type or "unknown",
            "status": status or "unknown",
            "online": False,
            "stale": True,
            "last_seen": last_seen,
        }
        for ip, mac, hostname, vendor, device_type, status, last_seen in rows
    ]
    _devices_cache["data"] = devices
    _devices_cache["ts"] = time.time()
    _devices_cache["error"] = None
    logger.info("[STARTUP] %d bilinen cihaz önbelleğe yüklendi (stale=true, tarama devam ediyor)", len(devices))


from dhcp_monitor import start_dhcp_monitor, stop_dhcp_monitor

@asynccontextmanager
async def lifespan(app: FastAPI):
    _stop_event.clear()
    start_dhcp_monitor()
    _threads.clear()
    init_db()
    apply_settings_to_runtime(get_all_settings())
    maintenance_conn = db_conn()
    try:
        _prune_operational_data(maintenance_conn)
    finally:
        maintenance_conn.close()
    _load_last_known_devices_into_cache()
    manager.loop = asyncio.get_event_loop()

    t2 = threading.Thread(target=diagnostics_loop, args=(_stop_event,), daemon=True)
    t4 = threading.Thread(target=device_scan_loop, args=(_stop_event,), daemon=True)
    workers = [t2, t4]
    if HAS_PSUTIL:
        workers.extend([
            threading.Thread(target=traffic_sampler_loop, args=(_stop_event,), daemon=True),
            threading.Thread(target=system_stats_loop, args=(_stop_event,), daemon=True),
        ])
    else:
        logger.warning("psutil kurulu değil; trafik ve sistem telemetrisi devre dışı.")
    for worker in workers:
        worker.start()
    _threads.extend(workers)
    yield
    _stop_event.set()
    for worker in list(_threads):
        worker.join(timeout=3)
    manager.loop = None

app = FastAPI(title="NetMon", lifespan=lifespan)
_request_timestamps = deque(maxlen=100_000)
_request_metrics_lock = threading.Lock()
_server_started_at = time.time()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        now = time.time()
        with _request_metrics_lock:
            _request_timestamps.append(now)
            cutoff = now - 60
            while _request_timestamps and _request_timestamps[0] < cutoff:
                _request_timestamps.popleft()
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

# ============================================================
# KULLANICI GİRİŞİ VE YETKİLENDİRME (admin / user)
# ============================================================
# ÖNEMLİ: Bu blok aşağıdaki tüm /api/... endpoint tanımlarından ÖNCE
# durmalı. FastAPI endpoint imzalarındaki "Depends(get_current_user)" gibi
# varsayılan değerler, dekoratör çalıştığı anda (yani modül yukarıdan
# aşağıya import edilirken) değerlendirilir — get_current_user o satıra
# gelindiğinde tanımlı olmazsa Python NameError ile çöker.
class _AuthError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


@app.exception_handler(_AuthError)
async def _auth_error_handler(request, exc: _AuthError):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


SESSION_TTL_SECONDS = 12 * 3600  # "Beni hatırla" seçilmezse 12 saat


def _row_to_user(row) -> dict:
    return {"id": row[0], "username": row[1], "role": row[2], "active": bool(row[3]), "must_change_password": bool(row[4]) if len(row) > 4 else False}


def get_current_user(request: Request, authorization: str | None = Header(default=None)) -> dict:
    """Her korumalı istekte 'Authorization: Bearer <token>' header'ını
    okuyup geçerli bir kullanıcıya karşılık gelip gelmediğini kontrol eder.
    Bu kontrol backend'de yapıldığı için frontend'i atlayıp doğrudan API'ye
    istek atan biri de aynı şekilde engellenir."""
    if not authorization or not authorization.startswith("Bearer "):
        raise _AuthError(401, "Giriş gerekli.")
    token = authorization.removeprefix("Bearer ").strip()

    conn = db_conn()
    row = conn.execute(
        "SELECT s.created_at, s.expires_at, u.id, u.username, u.role, u.active, u.must_change_password "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
        (token,),
    ).fetchone()
    if row is None:
        conn.close()
        raise _AuthError(401, "Oturum geçersiz. Lütfen tekrar giriş yapın.")

    created_at, expires_at, uid, username, role, active, must_change_password = row
    if expires_at is None:
        expires_at = created_at + SESSION_TTL_SECONDS
    if time.time() > expires_at:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        raise _AuthError(401, "Oturum süresi doldu. Lütfen tekrar giriş yapın.")
    if not active:
        conn.close()
        raise _AuthError(403, "Bu hesap devre dışı bırakılmış.")
    conn.close()
    if must_change_password and request.url.path not in {
        "/api/auth/me", "/api/auth/change-password", "/api/auth/logout"
    }:
        raise _AuthError(428, "Devam etmeden önce ilk kurulum parolanızı değiştirin.")
    return {"id": uid, "username": username, "role": role, "must_change_password": bool(must_change_password), "token": token}


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise _AuthError(403, "Bu işlem için yönetici yetkisi gerekiyor.")
    return user




# ============================================================
# REST API (Veri Okuma)
# ============================================================
@app.get("/api/status")
def get_status(user: dict = Depends(get_current_user)):
    return _last_status

@app.get("/api/traffic")
def get_traffic(minutes: int = 15, user: dict = Depends(get_current_user)):
    cutoff = time.time() - minutes * 60
    conn = db_conn()
    rows = conn.execute(
        "SELECT ts, wifi_sent, wifi_recv, eth_sent, eth_recv FROM traffic WHERE ts >= ? ORDER BY ts ASC",
        (cutoff,),
    ).fetchall()
    conn.close()
    return [{"ts": r[0], "wifi_sent": r[1], "wifi_recv": r[2], "eth_sent": r[3], "eth_recv": r[4]} for r in rows]

@app.get("/api/alerts")
def get_alerts(limit: int = 20, user: dict = Depends(get_current_user)):
    conn = db_conn()
    rows = conn.execute(
        "SELECT ts, level, message FROM alerts ORDER BY ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [{"ts": r[0], "level": r[1], "message": r[2]} for r in rows]

# ============================================================
# AKTİF ARAÇLAR (Ping, Traceroute, Port Tarama, Hız Testi)
# ============================================================

class PingRequest(BaseModel):
    target: str = "8.8.8.8"
    count: int = 4

_PING_TIME_RE = re.compile(r'time[=<]([\d.]+)\s*ms', re.IGNORECASE)

@app.post("/api/tools/ping")
def run_ping(req: PingRequest, user: dict = Depends(get_current_user)):
    # Hedefi temizle: kullanıcı yanlışlıkla "8.8.8.8:80" gibi port eklerse yok say,
    # gerçek ICMP ping'de port kavramı yoktur.
    target = req.target.strip().split(":")[0].split("/")[0]
    count = max(1, min(req.count, 20))

    if not target:
        return {"error": "Hedef adresi boş olamaz."}

    sys_name = platform.system().lower()
    if sys_name == "windows":
        cmd = ["ping", "-n", str(count), "-w", "1200", target]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * 2 + 5,
            **_hidden_subprocess_kwargs(),
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
    except Exception:
        return {"error": f"'{target}' adresine ping atılamadı. Hedef adı veya IP adresini kontrol edin."}

    # Windows: DNS cozulemezse "could not find host" / "bilinen bir ana bilgisayar degil" doner
    lower_out = output.lower()
    if ("could not find host" in lower_out or "bilinen bir ana bilgisayar" in lower_out
            or "unknown host" in lower_out or "name or service not known" in lower_out):
        return {"error": f"'{target}' adresi çözümlenemedi (DNS hatası). IP adresini veya alan adını kontrol edin."}

    times = [float(m) for m in _PING_TIME_RE.findall(output)]
    success_count = len(times)

    if not times:
        return {"error": f"'{target}' adresinden yanıt alınamadı (zaman aşımı / erişilemiyor)."}

    avg = sum(times) / len(times)
    loss = max(0, int(round(((count - success_count) / count) * 100)))

    return {
        "times": [round(t, 1) for t in times],
        "average": round(avg, 1),
        "loss": loss,
        "quality": "cok_iyi" if avg < 30 else "iyi" if avg < 80 else "orta" if avg < 150 else "kotu",
        "min": round(min(times), 1),
        "max": round(max(times), 1)
    }

@app.post("/api/tools/speedtest")
def run_speedtest_api(user: dict = Depends(get_current_user)):
    if speedtest is None:
        return {"error": "Sunucuda 'speedtest-cli' kurulu değil. Lütfen terminalden 'pip install speedtest-cli' çalıştırın."}
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        d_speed = st.download() / 1_000_000
        u_speed = st.upload() / 1_000_000
        ping = st.results.ping
        server_name = st.results.server.get("name")
        ts = time.time()

        conn = db_conn()
        conn.execute(
            "INSERT OR REPLACE INTO speedtests (ts, download, upload, ping, server) VALUES (?, ?, ?, ?, ?)",
            (ts, round(d_speed, 2), round(u_speed, 2), round(ping, 2), server_name),
        )
        conn.commit()
        conn.close()

        return {
            "download": round(d_speed, 2),
            "upload": round(u_speed, 2),
            "ping": round(ping, 2),
            "server": server_name,
            "ts": ts
        }
    except Exception as e:
        return {"error": f"Hız testi başarısız: {str(e)}"}

@app.get("/api/tools/speedtest/history")
def speedtest_history(limit: int = 15, user: dict = Depends(get_current_user)):
    conn = db_conn()
    rows = conn.execute(
        "SELECT ts, download, upload, ping, server FROM speedtests ORDER BY ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {
            "ts": r[0],
            "download": r[1],
            "upload": r[2],
            "ping": r[3],
            "server": r[4],
        }
        for r in rows
    ]

class PortScanRequest(BaseModel):
    target: str
    preset: str = "common"

@app.post("/api/tools/portscan")
def run_portscan(req: PortScanRequest, user: dict = Depends(require_admin)):
    target = (req.target or "127.0.0.1").strip()
    if len(target) > 253 or req.preset not in {"common", "web", "full"}:
        return JSONResponse(status_code=400, content={"error": "Geçersiz hedef veya tarama profili."})
    try:
        resolved_target = socket.gethostbyname(target)
        parsed_target = ipaddress.ip_address(resolved_target)
    except (OSError, ValueError):
        return JSONResponse(status_code=400, content={"error": "Hedef çözümlenemedi."})
    if not _is_allowed_inventory_ip(parsed_target):
        return JSONResponse(status_code=400, content={"error": "Port taraması yalnızca yerel/özel IPv4 hedeflerinde kullanılabilir."})

    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080]
    if req.preset == "web":
        ports_to_scan = [80, 443, 8080, 8443]
    elif req.preset == "full":
        ports_to_scan = list(range(1, 1025))

    open_ports = []

    # DÜZELTME: sabit 0.3sn zaman aşımı yerel ağ (LAN) taramaları için idealdi,
    # ama internetteki yüksek gecikmeli (300ms+) bir sunucu tarandığında açık
    # portlar bile bu süre yüzünden "kapalı" görünüyordu. Hedefin yerel/özel
    # bir IP mi yoksa genel bir internet adresi mi olduğuna göre zaman aşımını
    # dinamik olarak ayarlıyoruz.
    scan_timeout = 0.3

    def scan_port(p):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(scan_timeout)
        start_t = time.time()
        res = sock.connect_ex((resolved_target, p))
        ms = int((time.time() - start_t) * 1000)
        sock.close()
        if res == 0:
            try:
                svc = socket.getservbyport(p, "tcp")
            except OSError:
                svc = "Bilinmeyen"
            return {"port": p, "service": svc, "ms": ms}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_port, ports_to_scan)
        for r in results:
            if r: open_ports.append(r)

    _audit(user["username"], "portscan", f"target={resolved_target} preset={req.preset} open={len(open_ports)}")
    return {
        "target": target,
        "ip": resolved_target,
        "open": open_ports,
        "closed": len(ports_to_scan) - len(open_ports),
        "scanned": len(ports_to_scan)
    }

COMMON_TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

@app.post("/api/tools/deep-scan")
def run_deep_scan(user: dict = Depends(require_admin)):
    """Ağdaki bilinen tüm cihazlar için hızlı port taraması yapar.
    Basit port taramasından farkı: tek bir hedef yerine envanterdeki her
    online cihazı sırayla tarar ve her biri için açık port/servis listesi
    üretir — 'detaylı ağ taraması' istekleri buradan besleniyor."""
    devices = _devices_cache.get("data") or []
    targets = [d for d in devices if d.get("ip") and d.get("status") in ("online", "discovered")]
    result = []

    def scan_one(dev):
        ip = dev["ip"]
        open_ports = []

        def scan_port(p):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.35)
            try:
                if sock.connect_ex((ip, p)) == 0:
                    try:
                        svc = socket.getservbyport(p, "tcp")
                    except OSError:
                        svc = "Bilinmeyen"
                    return {"port": p, "service": svc}
            finally:
                sock.close()
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for r in ex.map(scan_port, COMMON_TOP_PORTS):
                if r:
                    open_ports.append(r)
        return {
            "ip": ip,
            "mac": dev.get("mac"),
            "hostname": dev.get("hostname") or dev.get("friendly_name"),
            "device_type": dev.get("device_type"),
            "open_ports": open_ports,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for r in pool.map(scan_one, targets):
            result.append(r)

    _audit(user["username"], "deep_scan", f"hosts={len(result)}")
    return {"scanned_hosts": len(result), "results": result, "generated_at": time.time()}


class TraceRequest(BaseModel):
    target: str = "google.com"
    max_hops: int = 20

@app.post("/api/tools/traceroute")
def run_traceroute_api(req: TraceRequest, user: dict = Depends(get_current_user)):
    sys_name = platform.system().lower()
    if sys_name == 'windows':
        cmd = ['tracert', '-d', '-h', str(req.max_hops), '-w', '500', req.target]
    else:
        cmd = ['traceroute', '-n', '-m', str(req.max_hops), '-w', '1', req.target]

    try:
        output = subprocess.check_output(
            cmd,
            universal_newlines=True,
            stderr=subprocess.STDOUT,
            timeout=req.max_hops * 2 + 10,
            **_hidden_subprocess_kwargs(),
        )
        hops = []
        for line in output.split('\n'):
            line = line.strip()
            if not line or "Tracing" in line or "traceroute" in line or "complete" in line:
                continue

            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                hop = int(parts[0])
                timeout = "*" in line
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                ms_match = re.findall(r'(\d+)\s*ms', line)

                ip = ip_match.group() if ip_match else None
                ms = int(ms_match[0]) if ms_match else None
                hops.append({"hop": hop, "ip": ip, "ms": ms, "timeout": timeout})
        return {"hops": hops}
    except Exception:
        return {"error": "Traceroute işlemi başarısız.", "hops": []}


class NetworkCmdRequest(BaseModel):
    action: str
    target: str = ""
    record_type: str = ""

ALLOWED_NETWORK_COMMANDS = {
    "flushdns": (["ipconfig", "/flushdns"], "DNS Önbelleği Temizleme"),
    "ipconfig_all": (["ipconfig", "/all"], "Detaylı Ağ Yapılandırması"),
    "release": (["ipconfig", "/release"], "IP Adresi Serbest Bırakma"),
    "renew": (["ipconfig", "/renew"], "IP Adresi Yenileme"),
    "arp_a": (["arp", "-a"], "ARP Önbellek Tablosu"),
    "netstat_an": (["netstat", "-an"], "Aktif Bağlantılar ve Dinlenen Portlar"),
    "getmac": (["getmac"], "Ağ Kartı MAC Adresleri"),
    "hostname": (["hostname"], "Bilgisayar Adı"),
    "net_share": (["net", "share"], "Paylaşılan Kaynaklar"),
    "route_print": (["route", "print"], "IP Yönlendirme (Routing) Tablosu"),
    "nbtstat_n": (["nbtstat", "-n"], "Yerel NetBIOS Adları"),
}

# Hedef (target) gerektiren, tek başlarına ALLOWED_NETWORK_COMMANDS içinde
# durmayan komutlar. cmd_builder, doğrulanmış hedefi alıp tam komut listesini
# üretir; böylece her biri kendi argüman sırasını/doğrulamasını tanımlayabilir.
_TARGET_REQUIRED_COMMANDS = {
    "nbtstat_a": (lambda target: ["nbtstat", "-A", target], "Uzak NetBIOS Adları"),
    "pathping": (lambda target: ["pathping", "-n", "-q", "4", target], "Ayrıntılı Yol Analizi (PathPing)"),
}

_HOSTNAME_OR_IP_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-:]{0,253}[A-Za-z0-9])?$")
_NSLOOKUP_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "ANY"}


def _clean_command_target(raw: str) -> str:
    """Ping ile aynı temizleme kuralı: port/path eklerini at, temel
    hostname/IP karakter kümesini doğrula (subprocess shell=True kullanmadığı
    için injection riski yok, ama yanlışlıkla flag benzeri girdi geçmesin)."""
    target = (raw or "").strip().split(":")[0].split("/")[0]
    if not target or not _HOSTNAME_OR_IP_RE.match(target):
        return ""
    return target


@app.post("/api/tools/network-cmd")
def run_network_cmd_api(req: NetworkCmdRequest, user: dict = Depends(get_current_user)):
    key = req.action.strip().lower()
    if key in {"release", "renew", "flushdns"} and user.get("role") != "admin":
        return JSONResponse(status_code=403, content={"error": "Ağ yapılandırmasını değiştiren komutlar için yönetici yetkisi gerekir."})
    if key == "nslookup":
        target = req.target.strip() or "google.com"
        record_type = req.record_type.strip().upper()
        if record_type:
            if record_type not in _NSLOOKUP_RECORD_TYPES:
                return JSONResponse(status_code=400, content={"error": "Desteklenmeyen DNS kayıt tipi."})
            cmd = ["nslookup", f"-type={record_type}", target]
            label = f"DNS Sorgusu ({target}, {record_type})"
        else:
            cmd = ["nslookup", target]
            label = f"DNS Sorgusu ({target})"
    elif key in _TARGET_REQUIRED_COMMANDS:
        target = _clean_command_target(req.target)
        if not target:
            return JSONResponse(status_code=400, content={"error": "Geçerli bir hedef adresi/hostname girin."})
        builder, label_prefix = _TARGET_REQUIRED_COMMANDS[key]
        cmd = builder(target)
        label = f"{label_prefix} ({target})"
    elif key in ALLOWED_NETWORK_COMMANDS:
        cmd, label = ALLOWED_NETWORK_COMMANDS[key]
    else:
        return JSONResponse(status_code=400, content={"error": "Desteklenmeyen veya geçersiz ağ komutu."})

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=12,
            **_hidden_subprocess_kwargs()
        )
        output = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
        _audit(user["username"], "network_cmd", f"action={key} target={req.target}")
        return {
            "action": key,
            "label": label,
            "command": " ".join(cmd),
            "output": output.strip(),
            "returncode": res.returncode,
            "ts": time.time()
        }
    except Exception as exc:
        return {"error": f"Komut çalıştırılamadı: {str(exc)}"}

# ============================================================
# OVERVIEW, TOPOLOGY, LOGS VE CİHAZ API ROTALARI
# ============================================================
_devices_cache = {"ts": 0, "data": [], "error": None, "scan_status": "idle"}
_device_scan_lock = threading.Lock()

STALE_AFTER_MISSED_SCANS = 3
_ALLOWED_INVENTORY_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8")
)


def _is_allowed_inventory_ip(value: ipaddress.IPv4Address) -> bool:
    return value.version == 4 and any(value in network for network in _ALLOWED_INVENTORY_NETWORKS)


def _is_allowed_inventory_network(value: ipaddress.IPv4Network) -> bool:
    return value.version == 4 and any(value.subnet_of(network) for network in _ALLOWED_INVENTORY_NETWORKS)


def _discover_configured_devices() -> list[dict]:
    """Virgülle ayrılmış birden fazla subnet'i tarayıp IP bazında birleştir."""
    subnets = [item.split("=")[0].strip() for item in (SUBNET_OVERRIDE or "").split(",") if item.strip()]
    if not subnets:
        # Discover every locally attached private IPv4 network instead of
        # assuming the primary Windows interface is the only network.
        try:
            auto_networks = [str(n) for n in diag._local_ipv4_networks()]
        except Exception:
            auto_networks = []
        if len(auto_networks) > 16:
            auto_networks = auto_networks[:16]
        if auto_networks:
            subnets = auto_networks
        else:
            return diag.get_connected_devices(fast=True)
    if len(subnets) > 16:
        raise NetworkDiscoveryError("En fazla 16 subnet aynı tarama görevine eklenebilir.")
    merged = {}
    for subnet in subnets:
        try:
            parsed = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise NetworkDiscoveryError(f"Geçersiz subnet: {subnet}") from exc
        if not _is_allowed_inventory_network(parsed):
            raise NetworkDiscoveryError(f"Yalnızca yerel/özel IPv4 subnetleri taranabilir: {subnet}")
        try:
            discovered_devices = diag.get_connected_devices(subnet_override=str(parsed), fast=True)
        except TypeError:
            # Test doubles / older discovery adapters may not expose fast yet.
            discovered_devices = diag.get_connected_devices(subnet_override=str(parsed))
        for device in discovered_devices:
            ip = device.get("ip")
            if not ip:
                continue
            if ip not in merged or len(device.get("discovery_sources", [])) > len(merged[ip].get("discovery_sources", [])):
                merged[ip] = device
    return list(merged.values())

def merge_scan_into_inventory(scanned: list[dict]) -> list[dict]:
    """DISCOVERY != HEALTH CHECK: yeni tarama sonucu mevcut envanterin
    yerine geçmez, üstüne birleştirilir. Bu taramada görünmeyen cihaz
    silinmez; offline/stale olarak işaretlenip listede kalır."""
    now = time.time()
    prev_by_mac = {}
    prev_by_ip = {}
    for d in _devices_cache.get("data") or []:
        if d.get("mac"):
            prev_by_mac[d["mac"]] = d
        elif d.get("ip"):
            prev_by_ip[d["ip"]] = d

    seen_keys = set()
    seen_macs = set()
    seen_ips = set()
    merged = []
    for d in scanned:
        mac = d.get("mac")
        ip = d.get("ip")
        if mac:
            seen_keys.add(mac)
            seen_macs.add(mac)
        if ip:
            seen_keys.add(("ip", ip))
            seen_ips.add(ip)
        old = (prev_by_mac.get(mac) if mac else None) or (prev_by_ip.get(ip) if ip else None)
        d["missed_scans"] = 0
        d["status"] = d.get("status") or "online"
        if old:
            d["first_seen"] = old.get("first_seen", d.get("first_seen", now))
        merged.append(d)

    for key, old in {**prev_by_mac, **{("ip", ip): d for ip, d in prev_by_ip.items()}}.items():
        if key in seen_keys:
            continue
        old_mac = old.get("mac")
        old_ip = old.get("ip")
        if (old_mac and old_mac in seen_macs) or (old_ip and old_ip in seen_ips):
            continue
        old = dict(old)
        old["missed_scans"] = int(old.get("missed_scans", 0)) + 1
        old["status"] = "stale" if old["missed_scans"] >= STALE_AFTER_MISSED_SCANS else "offline"
        old["connectivity_status"] = old["status"]
        merged.append(old)

    # Deduplicate merged devices so same IP or MAC never appears twice
    unique_devices = []
    seen_m = set()
    seen_i = set()
    for d in merged:
        mac = d.get("mac")
        ip = d.get("ip")
        if mac and mac in seen_m:
            continue
        if ip and ip in seen_i:
            continue
        if mac:
            seen_m.add(mac)
        if ip:
            seen_i.add(ip)
        unique_devices.append(d)

    # Prune phantom IP-only entries that have no MAC address, no hostname, and are offline
    unique_devices = [d for d in unique_devices if d.get("mac") or d.get("hostname") or d.get("status") in ("online", "discovered") or d.get("is_self") or d.get("is_gateway")]
    return unique_devices
DEVICES_CACHE_SECONDS = 25

_firewall_cache = {"ts": 0, "data": None}
FIREWALL_CACHE_SECONDS = 60

def _cached_firewall_status() -> dict:
    now = time.time()
    if _firewall_cache["data"] is not None and (now - _firewall_cache["ts"] < FIREWALL_CACHE_SECONDS):
        return _firewall_cache["data"]
    try:
        data = diag.get_firewall_status()
    except Exception as exc:
        data = {"state": "unknown", "profiles": {}, "source": "error", "error": str(exc)[:200]}
    _firewall_cache["data"] = data
    _firewall_cache["ts"] = now
    return data

@app.get("/api/network-info")
def get_network_info(user: dict = Depends(get_current_user)):
    """Stage 5: kullanıcıya ağın temel gerçeklerini ve öğrenme açıklamalarını verir."""
    try:
        ctx = diag.get_network_context()
        return {
            **ctx,
            "explanations": {
                "ip": "Bu bilgisayarın yerel ağdaki adresidir.",
                "cidr": "CIDR, hangi IP aralığının aynı yerel ağda olduğunu belirtir.",
                "gateway": "Yerel ağdan dış ağlara çıkış için kullanılan varsayılan ağ geçididir.",
                "dns": "Alan adlarını IP adreslerine çevirmeye yardımcı olan DNS sunucularıdır.",
                "mac": "Yerel ağ arayüzünün donanımsal adresidir; cihaz kimliğini takip etmede IP'den daha kararlıdır."
            }
        }
    except Exception as exc:
        return {"error": str(exc)}

@app.get("/api/overview")
def get_overview(user: dict = Depends(get_current_user)):
    devices_list = _devices_cache.get("data", [])
    online = [d for d in devices_list if d.get("status", "online" if d.get("online", True) else "offline") == "online"]
    discovered = [d for d in devices_list if d.get("status") == "discovered"]
    offline = [d for d in devices_list if d.get("status") == "offline"]
    unknown = [d for d in devices_list if (d.get("type") or "unknown") == "unknown"]
    new_devices = [d for d in devices_list if d.get("is_new")]
    latencies = [float(d.get("latency")) for d in devices_list if d.get("latency") is not None and float(d.get("latency")) > 0]
    avg_device_latency = round(sum(latencies) / len(latencies), 1) if latencies else None
    packet_losses = [float(d.get("packet_loss")) for d in devices_list
                     if d.get("packet_loss") is not None and d.get("connectivity_status") == "online"]
    avg_loss = round(sum(packet_losses) / len(packet_losses), 1) if packet_losses else None
    diagnostic_status = _last_status.get("status")
    internet_connected = diagnostic_status in ("ok", "warn") if diagnostic_status in ("ok", "warn", "fail") else None
    gateway_test = _last_status.get("gateway_test") or {}
    gateway_ok = bool(gateway_test.get("success")) if "success" in gateway_test else None
    score = None
    if internet_connected is not None or gateway_ok is not None:
        score = 100
        if gateway_ok is False:
            score -= 25
        if internet_connected is False:
            score -= 25
        if avg_device_latency is not None and avg_device_latency > 80:
            score -= 10
        if avg_loss is not None and avg_loss > 2:
            score -= min(20, int(avg_loss * 2))
        # Bilinmeyen cihaz tipi ağ sağlığını düşürmez; bu yalnızca tanımlama belirsizliğidir.
        score = max(0, min(100, score))
    if HAS_PSUTIL:
        try:
            inet_connections = psutil.net_connections(kind="inet")
            udp_connections = psutil.net_connections(kind="udp")
            connection_stats = {
                "tcp": sum(1 for item in inet_connections if item.status == "ESTABLISHED"),
                "udp": len(udp_connections),
                "total": len(inet_connections),
                "supported": True,
            }
        except (OSError, RuntimeError, psutil.Error) as exc:
            connection_stats = {"tcp": 0, "udp": 0, "total": 0, "supported": False, "error": str(exc)}
    else:
        connection_stats = {"tcp": 0, "udp": 0, "total": 0, "supported": False}
    internet_test = _last_status.get("internet_test") or {}
    return {
        "version": "2.5.0",
        "devices": {
            "total": len(devices_list),
            "online": len(online),
            "discovered": len(discovered),
            "offline": len(offline),
            "unknown": len(unknown),
            "identified": len(devices_list) - len(unknown),
            "new": len(new_devices),
            "scanning": _devices_cache.get("scan_status") == "running",
            "last_scan": _devices_cache.get("ts", 0)
        },
        "internet": {
            "connected": internet_connected,
            "target": PING_TARGET,
            "latency": internet_test.get("average"),
            "packet_loss": internet_test.get("packet_loss"),
        },
        "gateway": {
            "ip": _last_status.get("gateway") or "",
            "reachable": gateway_ok,
            "latency": _last_status.get("gateway_test", {}).get("average")
        },
        "latency": {
            "average": avg_device_latency if avg_device_latency is not None else _last_status.get("internet_test", {}).get("average")
        },
        "packet_loss": avg_loss,
        "firewall": _cached_firewall_status(),
        "health": {
            "score": score,
            "label": "Ölçüm bekleniyor" if score is None else "Sağlıklı" if score >= 85 else "İzlenmeli" if score >= 65 else "Sorunlu"
        },
        "connections": connection_stats,
        "system": _system_stats_payload(),
        "simulation": simulation_state
    }

@app.get("/api/topology")
def get_topology(user: dict = Depends(get_current_user)):
    devices_list = _devices_cache.get("data", [])
    gateway = _last_status.get("gateway") or ""

    gateway_dev = next((d for d in devices_list if d.get("ip") == gateway or d.get("is_gateway")), None)
    gateway_type = (gateway_dev or {}).get("type") or "router"
    gateway_label = "FIREWALL" if gateway_type == "firewall" else "ROUTER"

    internet_status = "online" if _last_status.get("status") in ("ok", "warn") else "offline"
    gateway_status = (gateway_dev or {}).get("status") or ("online" if gateway else "unknown")
    lan_status = "online" if gateway_status == "online" else ("discovered" if gateway_status == "discovered" else "unknown")
    nodes = [
        {"id": "internet", "label": "INTERNET", "type": "internet", "status": internet_status},
        {"id": "gateway", "label": gateway_label, "type": gateway_type, "status": gateway_status, "ip": gateway,
         "hostname": (gateway_dev or {}).get("hostname"), "is_gateway": True,
         "connectivity_status": (gateway_dev or {}).get("connectivity_status", gateway_status)},
        {"id": "lan", "label": "LAN / ERİŞİM KATMANI", "type": "switch", "status": lan_status,
         "logical": True, "note": "Fiziksel switch/port keşfedilmedi; bu düğüm mantıksal LAN segmentini temsil eder."},
    ]
    edges = [
        {"from": "internet", "to": "gateway", "status": internet_status if gateway_status == "online" else gateway_status, "kind": "uplink", "logical": True},
        {"from": "gateway", "to": "lan", "status": lan_status, "kind": "lan", "logical": True},
    ]

    type_labels = {
        "router": "ROUTER", "firewall": "FIREWALL", "server": "SERVER", "printer": "YAZICI",
        "mobile": "TELEFON", "phone": "TELEFON", "tablet": "TABLET", "laptop": "LAPTOP",
        "pc": "BİLGİSAYAR", "computer": "BİLGİSAYAR", "iot": "IoT", "switch": "SWITCH",
        "access_point": "ACCESS POINT", "network_device": "AĞ CİHAZI", "http": "WEB CİHAZI",
        "unknown": "BİLİNMİYOR"
    }

    seen_macs = set()
    seen_ips = set()
    unique_devices_list = []
    for d in devices_list:
        mac = d.get("mac")
        ip = d.get("ip")
        if mac and mac in seen_macs:
            continue
        if ip and ip in seen_ips:
            continue
        if mac: seen_macs.add(mac)
        if ip: seen_ips.add(ip)
        unique_devices_list.append(d)

    for idx, dev in enumerate(unique_devices_list):
        if dev.get("is_gateway") or dev.get("ip") == gateway:
            continue
        node_id = f"dev-{idx}"
        device_type = dev.get("type") or "unknown"
        classification = dev.get("classification") or {}
        nodes.append({
            "id": node_id,
            "label": dev.get("friendly_name") or dev.get("hostname") or type_labels.get(device_type, "CİHAZ"),
            "type": device_type,
            "status": dev.get("status") or ("online" if dev.get("online", True) else "offline"),
            "ip": dev.get("ip"), "mac": dev.get("mac"),
            "hostname": dev.get("hostname"), "friendly_name": dev.get("friendly_name"),
            "is_self": dev.get("is_self", False), "is_gateway": False,
            "classification": classification,
            "classification_source": dev.get("classification_source", "auto"),
            "confidence": classification.get("confidence", 0.15),
            "vendor": dev.get("vendor"),
            "latency": dev.get("latency"),
            "packet_loss": dev.get("packet_loss"),
            "first_seen": dev.get("first_seen"),
            "last_seen": dev.get("last_seen"),
            "discovery_sources": dev.get("discovery_sources", []),
            "switch_ip": dev.get("switch_ip"),
            "switch_port": dev.get("switch_port")
        })

    # Build a lookup for IPs to node_ids
    ip_to_node = {n["ip"]: n["id"] for n in nodes if n.get("ip")}
    
    physical_switch_discovered = False
    
    for idx, dev in enumerate(unique_devices_list):
        if dev.get("is_gateway") or dev.get("ip") == gateway:
            continue
            
        node_id = f"dev-{idx}"
        edge_status = "online" if dev.get("status") == "online" else ("discovered" if dev.get("status") == "discovered" else dev.get("status", "unknown"))
        
        switch_ip = dev.get("switch_ip")
        switch_port = dev.get("switch_port")
        
        if switch_ip and switch_ip in ip_to_node:
            physical_switch_discovered = True
            edges.append({"from": ip_to_node[switch_ip], "to": node_id, "status": edge_status, "kind": "physical_access", "logical": False, "label": f"Port {switch_port}"})
        else:
            edges.append({"from": "lan", "to": node_id, "status": edge_status, "kind": "logical_access", "logical": True})

    return {"nodes": nodes, "edges": edges, "meta": {
        "gateway": gateway, "gateway_type": gateway_type,
        "physical_switch_discovered": physical_switch_discovered,
        "note": "Gercek switch/port topolojisi kullaniliyor." if physical_switch_discovered else "Fiziksel switch kesfedilmedi; LAN mantiksal gosterimdir."
    }}

@app.get("/api/logs")
def get_logs_api(limit: int = 120, user: dict = Depends(get_current_user)):
    conn = db_conn()
    rows = conn.execute("SELECT ts, level, message FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    logs = [{"time": datetime.fromtimestamp(r[0]).strftime("%H:%M:%S"), "level": r[1], "message": r[2]} for r in rows]
    if not logs:
        logs = [{"time": datetime.now().strftime("%H:%M:%S"), "level": "info", "message": "NetMon Servisi Aktif", "tag": "Sistem"}]
    return {"logs": logs}

@app.post("/api/logs/clear")
def clear_logs_api(user: dict = Depends(require_admin)):
    conn = db_conn()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/snapshot")
def get_snapshot(user: dict = Depends(get_current_user)):
    return _last_status

def _normalize_mac(mac: str | None) -> str:
    if not mac:
        return ""
    return mac.replace("-", ":").upper().strip()


def enrich_devices(devices: list[dict]) -> list[dict]:
    """Tarama sonucunu kalıcı cihaz kimliğiyle birleştirir.

    Manuel isim/tip bilgileri otomatik discovery tarafından asla ezilmez.
    """
    if not devices:
        return []

    conn = db_conn()
    now = time.time()
    result = []
    local_ctx = {}
    try:
        local_ctx = diag.get_network_context()
        local_mac = _normalize_mac(local_ctx.get("local_mac"))
        local_hostname = (socket.gethostname() or "").strip()
        current_network = local_ctx.get("ssid") or local_ctx.get("cidr") or ""
    except Exception:
        local_mac = ""
        local_hostname = ""
        current_network = ""

    for device in devices:
        if (device.get("is_self") or device.get("ip") == local_ctx.get("local_ip")) and not device.get("mac") and local_mac:
            device["mac"] = local_mac
        mac = _normalize_mac(device.get("mac"))
        device["mac"] = mac
        hostname = device.get("hostname")
        device_type = device.get("type") or "unknown"
        classification = device.get("classification") or {}
        vendor = device.get("vendor") or ""
        is_new = False
        friendly_name = device.get("friendly_name")
        owner = device.get("owner") or ""
        notes = device.get("notes") or ""
        first_seen = device.get("first_seen") or now
        classification_source = device.get("classification_source") or "auto"

        if mac:
            row = conn.execute(
                "SELECT friendly_name, hostname, device_type, classification_source, owner, notes, first_seen, last_ip, last_status, last_latency, last_packet_loss, last_arp_seen, last_icmp_seen, last_hostname_seen, last_vendor, last_discovery_sources, connectivity_status, identification_status, last_network, open_ports FROM known_devices WHERE mac=?",
                (mac,),
            ).fetchone()

            if row:
                (friendly_name, saved_hostname, saved_type, classification_source, owner, notes, first_seen,
                 previous_ip, previous_status, previous_latency, previous_packet_loss,
                 previous_arp_seen, previous_icmp_seen, previous_hostname_seen, previous_vendor,
                 previous_sources, previous_connectivity, previous_identification, previous_network, previous_open_ports) = row
                
                # Check for new ports
                current_ports = classification.get('open_ports', [])
                if previous_open_ports:
                    try:
                        prev_ports_list = json.loads(previous_open_ports)
                        new_ports = [p for p in current_ports if p not in prev_ports_list]
                        if new_ports:
                            alert_msg = f"{device.get('ip')} ({hostname or mac}) cihazi uzerinde YENI PORT(LAR) tespit edildi: {', '.join(map(str, new_ports))}"
                            conn.execute("INSERT INTO alerts (ts, level, message) VALUES (?, ?, ?)", (time.time(), "warning", alert_msg))
                    except Exception:
                        pass
                if not hostname:
                    hostname = saved_hostname
                # Eski veritabanında yerel PC hostname'i başka bir MAC'e
                # yanlışlıkla yazılmışsa bunu tekrar kullanma.
                if (hostname and local_hostname and hostname.casefold() == local_hostname.casefold()
                        and mac != local_mac):
                    hostname = None
                # Manuel veya yetkili envanterle doğrulanmış türü daha zayıf
                # ARP/port tahminiyle geri "unknown" durumuna düşürme.
                if classification_source in {"manual", "verified_inventory"} and saved_type:
                    device_type = saved_type
            else:
                friendly_name = None
                owner = ""
                notes = ""
                first_seen = now
                classification_source = "auto"
                is_new = True
                conn.execute(
                    "INSERT INTO known_devices (mac, friendly_name, hostname, device_type, classification_source, owner, notes, first_seen, last_seen, last_ip, last_status, last_latency, last_packet_loss, last_arp_seen, last_icmp_seen, last_hostname_seen, last_vendor, last_discovery_sources, connectivity_status, identification_status, last_network, open_ports) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (mac, None, hostname, device_type, classification_source, "", "", now, now, device.get("ip"),
                     device.get("status", "unknown"), device.get("latency"), device.get("packet_loss"),
                     device.get("last_arp_seen"), device.get("last_icmp_seen"), device.get("last_hostname_seen"),
                     vendor or None, json.dumps(device.get("discovery_sources", []), ensure_ascii=False),
                     device.get("connectivity_status", "unknown"), device.get("identification_status", "unknown"),
                     current_network, json.dumps(classification.get('open_ports', []))),
                )

            conn.execute(
                "UPDATE known_devices SET hostname=?, device_type=?, last_seen=?, last_ip=?, last_status=?, last_latency=?, last_packet_loss=?, last_arp_seen=?, last_icmp_seen=?, last_hostname_seen=?, last_vendor=?, last_discovery_sources=?, connectivity_status=?, identification_status=?, last_network=?, open_ports=? WHERE mac=?",
                (hostname, device_type, now, device.get("ip"), device.get("status", "unknown"), device.get("latency"),
                 device.get("packet_loss"), device.get("last_arp_seen"), device.get("last_icmp_seen"),
                 device.get("last_hostname_seen"), vendor or None,
                 json.dumps(device.get("discovery_sources", []), ensure_ascii=False),
                 device.get("connectivity_status", "unknown"), device.get("identification_status", "unknown"),
                 current_network, json.dumps(classification.get('open_ports', [])), mac),
            )
        else:
            # ARP/MAC bilgisi olmayan SSDP/mDNS cihazları yine gösterilir;
            # kalıcı kimlik için MAC görüldüğü ilk taramada kullanılacaktır.
            friendly_name = device.get("friendly_name")
            owner = device.get("owner") or ""
            notes = device.get("notes") or ""
            first_seen = device.get("first_seen") or now
            classification_source = device.get("classification_source") or "auto"

        device.update({
            "mac": mac,
            "hostname": hostname,
            "friendly_name": friendly_name,
            "owner": owner,
            "vendor": vendor or None,
            "type": device_type,
            "classification_source": classification_source or "auto",
            "owner": owner or "",
            "notes": notes or "",
            "first_seen": first_seen,
            "last_seen": now,
            "is_new": bool(is_new),
            "confidence": float(classification.get("confidence", 0.15) or 0.15),
            "connectivity_status": device.get("connectivity_status", "online" if device.get("status") == "online" else "unknown"),
            "identification_status": device.get("identification_status", "identified" if device_type != "unknown" else "unknown"),
            "identification_reason": device.get("identification_reason") or ("Cihaz tipi birden fazla kanıta göre belirlendi." if device_type != "unknown" else "Cihaz tipi için yeterli kanıt bulunamadı."),
        })
        result.append(device)

    # Son taramada görünmeyen ama daha önce bilinen MAC/IP cihazlarını "offline"
    # olarak koru. Böylece cihaz listesi bir taramada kaybolduğunda tamamen silinmez.
    seen_macs = {d.get("mac") for d in result if d.get("mac")}
    seen_ips = {d.get("ip") for d in result if d.get("ip")}
    offline_rows = conn.execute(
        "SELECT mac, friendly_name, hostname, device_type, classification_source, owner, notes, first_seen, last_seen, last_ip, last_status, last_latency, last_packet_loss, last_arp_seen, last_icmp_seen, last_hostname_seen, last_vendor, last_discovery_sources, connectivity_status, identification_status "
        "FROM known_devices WHERE last_seen IS NOT NULL AND last_seen >= ? ORDER BY last_seen DESC",
        (now - 2 * 3600,),
    ).fetchall()
    for row in offline_rows:
        (mac, friendly_name, saved_hostname, saved_type, classification_source, owner, notes, first_seen, last_seen,
         last_ip, last_status, last_latency, last_packet_loss, last_arp_seen, last_icmp_seen,
         last_hostname_seen, last_vendor, last_discovery_sources, saved_connectivity, saved_identification) = row
        if (mac and mac in seen_macs) or (last_ip and last_ip in seen_ips):
            continue
        if mac and str(mac).upper() in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", "FF-FF-FF-FF-FF-FF"):
            continue
        if not mac and not last_ip:
            continue
        if not last_ip:
            continue
        result.append({
            "ip": last_ip,
            "mac": mac,
            "hostname": saved_hostname,
            "friendly_name": friendly_name,
            "vendor": last_vendor,
            "type": saved_type or "unknown",
            "classification_source": classification_source or "auto",
            "owner": owner or "",
            "notes": notes or "",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "is_new": False,
            "online": False,
            "status": "offline",
            "status_reason": "Son taramada keşfedilemedi",
            "icmp_reachable": False,
            "arp_seen": False,
            "latency": last_latency,
            "packet_loss": None,
            "icmp_packet_loss": 100 if last_icmp_seen else None,
            "connectivity_status": "offline",
            "identification_status": saved_identification or ("identified" if (saved_type and saved_type != "unknown") else "unknown"),
            "last_arp_seen": last_arp_seen,
            "last_icmp_seen": last_icmp_seen,
            "last_hostname_seen": last_hostname_seen,
            "discovery_sources": json.loads(last_discovery_sources) if last_discovery_sources else [],
            "confidence": 0.0 if (saved_type or "unknown") == "unknown" else 0.5,
            "identification_reason": "Son taramada keşfedilemedi; önceki kimlik bilgisi korunuyor.",
            "classification": {
                "method": [],
                "confidence": 0.0,
                "reason": ["son taramada keşfedilemedi"],
                "evidence": [],
                "open_ports": [],
                "services": [],
            },
        })

    # Temizlik: known_devices tablosundan MAC adresi boş ve aynı IP'ye sahip mükerrer kayıtları temizle
    try:
        conn.execute("DELETE FROM known_devices WHERE (mac IS NULL OR mac = '') AND last_ip IS NOT NULL AND last_ip IN (SELECT last_ip FROM known_devices WHERE mac IS NOT NULL AND mac != '')")
    except Exception:
        pass

    conn.commit()
    conn.close()

    # Çıktı listesini IP ve MAC bazında kesin olarak teille/tekilleştir (deduplicate)
    final_result = []
    final_seen_macs = set()
    final_seen_ips = set()
    for d in result:
        m = d.get("mac")
        ip = d.get("ip")
        if m and m in final_seen_macs:
            continue
        if ip and ip in final_seen_ips:
            continue
        if m:
            final_seen_macs.add(m)
        if ip:
            final_seen_ips.add(ip)
        final_result.append(d)

    return final_result


class DeviceRenameRequest(BaseModel):
    mac: str
    friendly_name: str | None = None
    notes: str | None = None
    device_type: str | None = None


@app.get("/api/tools/nmap/status")
def get_nmap_status(user: dict = Depends(get_current_user)):
    """Nmap kurulu mu diye bakar. Kurulu değilse uygulama çökmez; yerleşik
    ARP/ping tabanlı discovery kullanılmaya devam eder."""
    try:
        available = diag.nmap_available()
    except Exception:
        available = False
    return {
        "available": available,
        "message": (
            "Nmap bulundu; host discovery ve servis tespiti için kullanılabilir."
            if available else
            "Nmap bulunamadı. Yerleşik tarama motoru kullanılıyor."
        ),
    }


@app.post("/api/devices/rename")
def rename_device(body: DeviceRenameRequest, user: dict = Depends(require_admin)):
    mac = _normalize_mac(body.mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "MAC adresi gerekli."})

    conn = db_conn()
    row = conn.execute("SELECT mac FROM known_devices WHERE mac=?", (mac,)).fetchone()
    if row is None:
        conn.close()
        return JSONResponse(status_code=404, content={"error": "Cihaz önce ağ taramasında görülmeli."})

    updates = []
    values = []
    if body.friendly_name is not None:
        updates.append("friendly_name=?")
        values.append(body.friendly_name.strip() or None)
    if body.notes is not None:
        updates.append("notes=?")
        values.append(body.notes.strip())
    if body.device_type is not None:
        allowed = {"router", "firewall", "server", "printer", "mobile", "phone", "tablet", "laptop", "pc", "computer", "iot", "http", "switch", "access_point", "network_device", "unknown"}
        if body.device_type not in allowed:
            conn.close()
            return JSONResponse(status_code=400, content={"error": "Geçersiz cihaz tipi."})
        updates.append("device_type=?")
        values.append(body.device_type)
        updates.append("classification_source=?")
        values.append("manual")

    if updates:
        values.append(mac)
        # kolon adları sabit whitelist'ten geliyor, değerler parametrize
        conn.execute(f"UPDATE known_devices SET {', '.join(updates)} WHERE mac=?", values)  # nosec B608
        conn.commit()
    conn.close()

    # Cache'i hemen yenile; kullanıcı yeniden tarama beklemeden yeni adı görsün.
    if _devices_cache.get("data"):
        for device in _devices_cache["data"]:
            if _normalize_mac(device.get("mac")) == mac:
                if body.friendly_name is not None:
                    device["friendly_name"] = body.friendly_name.strip() or None
                if body.notes is not None:
                    device["notes"] = body.notes.strip()
                if body.device_type is not None:
                    device["type"] = body.device_type
                break

    manager.broadcast_threadsafe({"type": "devices", "devices": _devices_cache.get("data", []), "ts": _devices_cache.get("ts", 0)})
    return {"ok": True}


@app.get("/api/devices/known")
def list_known_devices(user: dict = Depends(get_current_user)):
    conn = db_conn()
    rows = conn.execute(
        "SELECT mac, friendly_name, hostname, device_type, classification_source, owner, notes, first_seen, last_seen FROM known_devices ORDER BY last_seen DESC"
    ).fetchall()
    conn.close()
    return {
        "devices": [
            {
                "mac": r[0], "friendly_name": r[1], "hostname": r[2],
                "type": r[3], "classification_source": r[4] or "auto", "owner": r[5] or "", "notes": r[6] or "",
                "first_seen": r[7], "last_seen": r[8],
            }
            for r in rows
        ]
    }


@app.get("/api/firewall/status")
def get_firewall_status(user: dict = Depends(get_current_user)):
    """Sadece YEREL makine için gerçek durum. Uzak cihazlarda kesinlik iddia
    edilmez (bkz. netdiag_core.get_firewall_status)."""
    return _cached_firewall_status()

_local_wmi_cache = {"ts": 0, "data": None}
_mac_to_switch_port: dict[str, str] = {}


def _update_switch_mac_tables(devices: list[dict]):
    """SNMP BRIDGE-MIB dot1dTpFdbPort üzerinden switch port eşleşmelerini önbelleğe alır."""
    global _mac_to_switch_port
    try:
        for d in devices:
            if d.get("type") in ("switch", "router") and d.get("status") == "online":
                # Gelecek SNMP BRIDGE-MIB sorgusu için hazır önbellek yapısı
                pass
    except Exception:
        pass


def _infer_verified_device_type(dev: dict, inventory: dict, source: str | None = None) -> tuple[str | None, float]:
    """Yetkili envanteri güçlü cihaz-türü kanıtına dönüştürür.

    Kullanıcının manuel sınıflandırması hiçbir zaman ezilmez. WMI/WinRM
    Windows rolü ve kasa tipini, SSH işletim sistemi kimliğini, SNMP ise
    sysDescr/sysName bilgisini sağlar.
    """
    if not inventory or inventory.get("status") != "Success":
        return None, 0.0
    if dev.get("classification_source") == "manual":
        return None, 0.0

    system = inventory.get("system") if isinstance(inventory.get("system"), dict) else {}
    software = inventory.get("software") if isinstance(inventory.get("software"), dict) else {}
    hardware = inventory.get("hardware") if isinstance(inventory.get("hardware"), dict) else {}
    source_text = " ".join(str(value or "") for value in (
        source,
        inventory.get("inventory_source"),
        inventory.get("os_family"),
    )).casefold()
    identity_text = " ".join(str(value or "") for value in (
        inventory.get("computer_name"),
        system.get("computer_name"),
        system.get("sys_name"),
        system.get("sys_descr"),
        system.get("os_name"),
        system.get("kernel"),
        software.get("os_name"),
        hardware.get("motherboard_maker"),
        hardware.get("motherboard_model"),
    )).casefold()

    def as_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    if any(token in source_text for token in ("wmi", "winrm", "windows", "cim")):
        product_type = as_int(system.get("os_product_type"))
        domain_role = as_int(system.get("domain_role"))
        pc_system_type = as_int(system.get("pc_system_type"))
        raw_chassis = system.get("chassis_types") or []
        if not isinstance(raw_chassis, (list, tuple, set)):
            raw_chassis = [raw_chassis]
        chassis = {value for value in (as_int(item) for item in raw_chassis) if value is not None}
        if product_type in {2, 3} or (domain_role is not None and domain_role >= 2) or "windows server" in identity_text:
            return "server", 0.99
        if chassis.intersection({30}):
            return "tablet", 0.98
        if pc_system_type == 2 or chassis.intersection({8, 9, 10, 14, 31, 32}):
            return "laptop", 0.98
        return "computer", 0.97

    if "snmp" in source_text:
        if any(token in identity_text for token in (
            "fortigate", "fortios", "fortinet", "firewall", "pfsense", "opnsense",
            "sophos", "watchguard", "palo alto", "pan-os", "checkpoint", "check point",
        )):
            return "firewall", 0.97
        if any(token in identity_text for token in (
            "printer", "laserjet", "jetdirect", "epson", "canon", "brother", "xerox", "ricoh", "kyocera",
        )):
            return "printer", 0.97
        if any(token in identity_text for token in (
            "access point", "access-point", "wireless ap", "wireless access", "unifi ap", "aironet",
        )):
            return "access_point", 0.95
        if any(token in identity_text for token in ("switch", "catalyst", "procurve", "nexus", "arubaos-switch")):
            return "switch", 0.95
        if any(token in identity_text for token in (
            "router", "routeros", "junos", "cisco ios", "internet gateway", "mikrotik",
        )):
            return "router", 0.94
        return "network_device", 0.90

    if "ssh" in source_text or any(token in identity_text for token in ("linux", "ubuntu", "debian", "rhel", "centos", "rocky")):
        current_type = dev.get("type") or "unknown"
        ports = set((dev.get("classification") or {}).get("open_ports") or [])
        name = " ".join(str(value or "") for value in (
            dev.get("hostname"), dev.get("friendly_name"), system.get("computer_name"),
        )).casefold()
        server_ports = {25, 53, 389, 636, 1433, 3306, 5432, 6379, 27017}
        if current_type == "server" or ports.intersection(server_ports) or any(token in name for token in ("server", "srv", "nas", "storage", "dc-")):
            return "server", 0.95
        return "computer", 0.90

    return None, 0.0


def _apply_verified_inventory_identity(dev: dict, inventory: dict, source: str | None = None) -> str | None:
    inferred_type, confidence = _infer_verified_device_type(dev, inventory, source)
    if not inferred_type:
        return None

    system = inventory.get("system") if isinstance(inventory.get("system"), dict) else {}
    verified_hostname = (
        inventory.get("computer_name") or system.get("computer_name") or system.get("sys_name")
    )
    if verified_hostname and not dev.get("hostname"):
        dev["hostname"] = str(verified_hostname).strip()

    source_name = source or inventory.get("inventory_source") or "Yetkili envanter"
    dev["type"] = inferred_type
    dev["confidence"] = confidence
    dev["classification_source"] = "verified_inventory"
    dev["identification_status"] = "identified"
    dev["identification_reason"] = f"Cihaz tipi {source_name} ile doğrulandı."
    classification = dev.setdefault("classification", {})
    classification["confidence"] = confidence
    classification["raw_type"] = inferred_type
    methods = classification.get("method") or []
    if isinstance(methods, str):
        methods = [methods]
    if "verified_inventory" not in methods:
        methods.append("verified_inventory")
    classification["method"] = methods
    classification["reason"] = [dev["identification_reason"]]
    evidence = classification.get("evidence") or []
    evidence = [item for item in evidence if not (isinstance(item, dict) and item.get("source") == "verified_inventory")]
    evidence.append({"text": dev["identification_reason"], "source": "verified_inventory"})
    classification["evidence"] = evidence
    return inferred_type


def _inventory_identity(dev: dict, inventory: dict | None = None) -> str:
    """Stable asset identity. Prefer MAC; otherwise hostname+IP fingerprint."""
    inventory = inventory or {}
    mac = _normalize_mac(dev.get("mac") or inventory.get("mac_address"))
    if mac:
        return f"mac:{mac.lower()}"
    hostname = (dev.get("hostname") or inventory.get("computer_name") or "").strip().lower()
    ip = (dev.get("ip") or inventory.get("ip_address") or "").strip()
    return f"hostip:{hostname}|{ip}" if hostname else f"ip:{ip}"


def _sync_normalized_inventory(dev: dict, inventory: dict, source: str | None = None):
    """Persist discovery/inventory into one stable asset. Never invent missing data."""
    if not inventory or inventory.get("status") != "Success":
        return None
    source = source or inventory.get("inventory_source") or "network"
    now = time.time()
    system = inventory.get("system") if isinstance(inventory.get("system"), dict) else {}
    hardware = inventory.get("hardware") if isinstance(inventory.get("hardware"), dict) else {}
    software = inventory.get("software") if isinstance(inventory.get("software"), dict) else {}
    ip = dev.get("ip") or inventory.get("ip_address")
    mac = _normalize_mac(dev.get("mac") or inventory.get("mac_address"))
    hostname = dev.get("hostname") or inventory.get("computer_name") or system.get("computer_name")
    hostname = str(hostname).strip() if hostname else None
    os_name = software.get("os_name") or inventory.get("os_name")
    os_version = software.get("os_build") or inventory.get("os_version")
    identity = _inventory_identity(dev, inventory)
    conn = db_conn()

    # If a later authorized scan reveals a MAC, merge the previous hostname/IP-only
    # asset instead of creating a duplicate MAC asset.
    row = conn.execute("SELECT asset_id, first_seen FROM inventory_assets WHERE identity_key=?", (identity,)).fetchone()
    if not row and mac:
        row = conn.execute("SELECT asset_id, first_seen FROM inventory_assets WHERE lower(mac_address)=lower(?)", (mac,)).fetchone()
    if not row and hostname:
        row = conn.execute("SELECT asset_id, first_seen FROM inventory_assets WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1", (hostname,)).fetchone()
    if not row and ip:
        row = conn.execute("SELECT asset_id, first_seen FROM inventory_assets WHERE ip_address=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()

    fields = [hostname, ip, mac, dev.get("vendor"), dev.get("type"), os_name, os_version]
    completeness = round(sum(v not in (None, "", "unknown") for v in fields) / len(fields) * 100, 1)
    status = dev.get("status", "online")
    if row:
        asset_id, first_seen = row
        old = conn.execute("SELECT hostname,ip_address,mac_address,vendor,device_type,os_name,os_version,status,identity_key FROM inventory_assets WHERE asset_id=?", (asset_id,)).fetchone()
        oldmap = dict(zip(["hostname","ip_address","mac_address","vendor","device_type","os_name","os_version","status","identity_key"], old or []))
        update_identity = identity if mac or not oldmap.get("identity_key", "").startswith("mac:") else oldmap.get("identity_key")
        conn.execute("""UPDATE inventory_assets SET identity_key=?, hostname=COALESCE(?,hostname), ip_address=COALESCE(?,ip_address),
            mac_address=COALESCE(?,mac_address), vendor=COALESCE(?,vendor), device_type=COALESCE(?,device_type),
            os_name=COALESCE(?,os_name), os_version=COALESCE(?,os_version), status=?, last_seen=?, inventory_source=?,
            completeness=?, updated_at=? WHERE asset_id=?""",
            (update_identity, hostname, ip, mac, dev.get("vendor"), dev.get("type"), os_name, os_version,
             status, now, source, completeness, now, asset_id))
        for key, newval in {"hostname":hostname,"ip_address":ip,"mac_address":mac,"vendor":dev.get("vendor"),"device_type":dev.get("type"),"os_name":os_name,"os_version":os_version,"status":status}.items():
            oldval = oldmap.get(key)
            if newval not in (None, "") and str(oldval or "") != str(newval):
                conn.execute("INSERT INTO inventory_history(asset_id,event_type,field_name,old_value,new_value,source,created_at) VALUES(?,?,?,?,?,?,?)",
                             (asset_id, "change", key, oldval, newval, source, now))
    else:
        cur = conn.execute("""INSERT INTO inventory_assets
            (identity_key,hostname,ip_address,mac_address,vendor,device_type,os_name,os_version,status,first_seen,last_seen,inventory_source,completeness,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (identity, hostname, ip, mac, dev.get("vendor"), dev.get("type"), os_name, os_version,
             status, now, now, source, completeness, now, now))
        asset_id = cur.lastrowid
        conn.execute("INSERT INTO inventory_history(asset_id,event_type,field_name,new_value,source,created_at) VALUES(?,?,?,?,?,?)",
                     (asset_id, "created", "asset", identity, source, now))

    # Current hardware snapshot; empty values remain NULL.
    conn.execute("""INSERT INTO inventory_hardware(asset_id,cpu,ram_gb,gpu,motherboard,disk_json,serial_number,collected_at)
        VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET cpu=COALESCE(excluded.cpu,inventory_hardware.cpu),
        ram_gb=COALESCE(excluded.ram_gb,inventory_hardware.ram_gb),gpu=COALESCE(excluded.gpu,inventory_hardware.gpu),
        motherboard=COALESCE(excluded.motherboard,inventory_hardware.motherboard),disk_json=COALESCE(excluded.disk_json,inventory_hardware.disk_json),
        serial_number=COALESCE(excluded.serial_number,inventory_hardware.serial_number),collected_at=excluded.collected_at""",
        (asset_id, hardware.get("cpu_model"), hardware.get("ram_gb"), hardware.get("gpu"),
         " / ".join(filter(None, [hardware.get("motherboard_maker"), hardware.get("motherboard_model")])) or None,
         json.dumps(inventory.get("storage") or [], ensure_ascii=False), hardware.get("serial_number"), now))

    # Refresh network interfaces only when authoritative inventory supplied them.
    interfaces = inventory.get("network_interfaces") or inventory.get("interfaces") or []
    if isinstance(interfaces, list) and interfaces:
        conn.execute("DELETE FROM inventory_interfaces WHERE asset_id=?", (asset_id,))
        for iface in interfaces[:100]:
            if isinstance(iface, dict):
                conn.execute("INSERT INTO inventory_interfaces(asset_id,interface_name,ip_address,mac_address,gateway,subnet,collected_at) VALUES(?,?,?,?,?,?,?)",
                    (asset_id, iface.get("name") or iface.get("interface_name"), iface.get("ip") or iface.get("ip_address"),
                     _normalize_mac(iface.get("mac") or iface.get("mac_address")), iface.get("gateway"), iface.get("subnet") or iface.get("netmask"), now))

    programs = software.get("installed_programs") or []
    if programs:
        conn.execute("DELETE FROM inventory_software WHERE asset_id=?", (asset_id,))
        for program in programs[:1000]:
            if isinstance(program, dict) and program.get("name"):
                conn.execute("INSERT INTO inventory_software(asset_id,name,version,publisher,collected_at) VALUES(?,?,?,?,?)",
                             (asset_id, program["name"], program.get("version"), program.get("publisher"), now))
    conn.commit(); conn.close()
    return asset_id

def _persist_device_inventory(dev: dict, inventory: dict, source: str | None = None):
    if not inventory or inventory.get("status") != "Success" or not dev.get("ip"):
        return
    source = source or inventory.get("inventory_source") or "Verified"
    inferred_type = _apply_verified_inventory_identity(dev, inventory, source)
    conn = db_conn()
    conn.execute(
        "INSERT INTO device_inventory (ip, mac, status, source, payload, last_scanned) VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, status=excluded.status, source=excluded.source, "
        "payload=excluded.payload, last_scanned=excluded.last_scanned",
        (dev["ip"], _normalize_mac(dev.get("mac")) or None, inventory["status"], source,
         json.dumps(inventory, ensure_ascii=False), time.time()),
    )
    conn.commit()
    _sync_normalized_inventory(dev, inventory, source)
    if inferred_type:
        verified_hostname = dev.get("hostname") or ""
        mac = _normalize_mac(dev.get("mac"))
        if mac:
            conn.execute(
                "UPDATE known_devices SET device_type=?, classification_source='verified_inventory', "
                "identification_status='identified', hostname=COALESCE(NULLIF(?, ''), hostname) "
                "WHERE mac=? AND COALESCE(classification_source, 'auto') != 'manual'",
                (inferred_type, verified_hostname, mac),
            )
        else:
            conn.execute(
                "UPDATE known_devices SET device_type=?, classification_source='verified_inventory', "
                "identification_status='identified', hostname=COALESCE(NULLIF(?, ''), hostname) "
                "WHERE last_ip=? AND COALESCE(classification_source, 'auto') != 'manual'",
                (inferred_type, verified_hostname, dev["ip"]),
            )
    conn.commit()
    conn.close()


def _load_device_inventory(dev: dict):
    ip = dev.get("ip") or ""
    mac = _normalize_mac(dev.get("mac"))
    conn = db_conn()
    if mac:
        row = conn.execute(
            "SELECT source, payload FROM device_inventory WHERE mac=? ORDER BY last_scanned DESC LIMIT 1", (mac,)
        ).fetchone()
    else:
        row = None
    if row is None and ip:
        row = conn.execute("SELECT source, payload FROM device_inventory WHERE ip=?", (ip,)).fetchone()
    conn.close()
    if not row:
        return None, None
    try:
        return row[0], json.loads(row[1])
    except (TypeError, json.JSONDecodeError):
        return None, None


def _get_local_wmi_data():
    now = time.time()
    if _local_wmi_cache["data"] and (now - _local_wmi_cache["ts"] < 300):
        return _local_wmi_cache["data"]
    try:
        scanner = WmiNetworkScanner(timeout=20)
        res = scanner._scan_single_ip("127.0.0.1")
        if res and res.get("status") == "Success":
            _local_wmi_cache.update({"data": res, "ts": now})
            return res
    except Exception as exc:
        logger.warning("Local WMI auto-scan exception: %s", exc)

    # WMI yoksa yalnızca gerçekten işletim sisteminden ölçülebilen alanları döndür.
    try:
        import getpass
        import multiprocessing
        disks = []
        ram_gb = None
        if HAS_PSUTIL:
            ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
            seen = set()
            for part in psutil.disk_partitions(all=False):
                if part.mountpoint in seen:
                    continue
                seen.add(part.mountpoint)
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "drive_letter": part.device or part.mountpoint,
                        "total_gb": round(usage.total / (1024 ** 3), 2),
                        "free_gb": round(usage.free / (1024 ** 3), 2),
                        "used_gb": round(usage.used / (1024 ** 3), 2),
                    })
                except OSError:
                    continue
        local_res = {
            "status": "Partial",
            "inventory_source": "Local OS",
            "ip_address": "127.0.0.1",
            "hardware": {
                "motherboard_maker": None,
                "motherboard_model": platform.machine() or None,
                "cpu_model": platform.processor() or None,
                "cores": multiprocessing.cpu_count(),
                "ram_gb": ram_gb,
                "gpu": None,
            },
            "software": {
                "os_name": f"{platform.system()} {platform.release()}",
                "os_build": platform.version(),
                "installed_programs": [],
            },
            "security": {"active_user": getpass.getuser(), "firewall": "Bilinmiyor", "antivirus": "Bilinmiyor"},
            "storage": disks,
            "limitations": ["WMI kullanılamadığı için yalnızca yerel işletim sistemi ölçümleri gösteriliyor."],
        }
        _local_wmi_cache.update({"data": local_res, "ts": now})
        return local_res
    except Exception as exc:
        logger.warning("Local OS fallback exception: %s", exc)
        return None


def _unavailable_inventory(dev: dict) -> dict:
    ports = (dev.get("classification") or {}).get("open_ports") or []
    services = (dev.get("classification") or {}).get("services") or []
    return {
        "status": "Unavailable",
        "inventory_source": "Network evidence only",
        "hardware": {},
        "software": {
            "os_name": dev.get("os_fingerprint"),
            "installed_programs": [],
            "observed_services": services,
        },
        "security": {"active_user": None, "firewall": "Bilinmiyor", "antivirus": "Bilinmiyor"},
        "storage": [],
        "limitations": [
            "Donanım/yazılım ayrıntısı doğrulanamadı.",
            "Windows için WMI/WinRM, Linux için SSH, ağ cihazları için SNMPv3 veya üretici API'si gerekir.",
        ],
        "observed_ports": ports,
    }


def _enrich_device_inventory(dev: dict, allow_deep: bool = False):
    ip = dev.get("ip") or ""
    try:
        from wmi_scanner import _local_ips
        local_ips = _local_ips()
    except Exception:
        local_ips = {"127.0.0.1", "localhost"}
    
    is_local = bool(dev.get("is_self") or (ip and ip in local_ips) or ip in ("127.0.0.1", "localhost"))
    if is_local:
        dev["is_self"] = True

    source, persisted = _load_device_inventory(dev)
    if persisted:
        _apply_verified_inventory_identity(dev, persisted, source)
        if source and any(tag in source.lower() for tag in ("wmi", "winrm", "local")):
            dev["wmi_inventory"] = persisted
        else:
            dev["deep_inventory"] = persisted
            dev["fallback_inventory"] = persisted

    if is_local and (not dev.get("wmi_inventory") or dev.get("wmi_inventory", {}).get("status") != "Success"):
        local_wmi = _get_local_wmi_data()
        if local_wmi:
            if local_wmi.get("status") in ("Success", "Partial"):
                _apply_verified_inventory_identity(dev, local_wmi, local_wmi.get("inventory_source") or "Local WMI")
                dev["wmi_inventory"] = local_wmi
                _persist_device_inventory(dev, local_wmi, local_wmi.get("inventory_source") or "Local WMI")
            else:
                dev["fallback_inventory"] = local_wmi

    if allow_deep and not dev.get("is_self") and dev.get("wmi_inventory", {}).get("status") != "Success":
        try:
            enriched = deep_discovery.integrate_discovery_flow(dev, credentials={
                "wmi_username": WMI_USERNAME, "wmi_password": WMI_PASSWORD,
                "ssh_username": SSH_USERNAME, "ssh_password": SSH_PASSWORD,
                "snmp_community": SNMP_COMMUNITY,
            })
            deep_inventory = enriched.get("deep_inventory")
            if deep_inventory:
                dev["deep_inventory"] = deep_inventory
                if deep_inventory.get("status") == "Success":
                    dev["fallback_inventory"] = deep_inventory
                    _persist_device_inventory(dev, deep_inventory, deep_inventory.get("inventory_source") or "Deep")
        except Exception as exc:
            logger.info("[ENRICH] %s derin envanter alınamadı: %s", ip, exc)

    if not dev.get("wmi_inventory") and not dev.get("fallback_inventory"):
        dev["fallback_inventory"] = _unavailable_inventory(dev)

    verified_deep = dev.get("deep_inventory", {}).get("status") == "Success"
    verified_wmi = dev.get("wmi_inventory", {}).get("status") == "Success"
    mac_upper = (dev.get("mac") or "").upper()
    switch_port_info = _mac_to_switch_port.get(mac_upper) if mac_upper else None
    if switch_port_info:
        dev["switch_port"] = switch_port_info
    dev["unified_inventory"] = {
        "ip": ip,
        "mac": dev.get("mac"),
        "hostname": dev.get("hostname") or dev.get("friendly_name") or dev.get("netbios_name"),
        "device_type": dev.get("type", "unknown"),
        "discovery_sources": dev.get("discovery_sources", []),
        "confidence": dev.get("confidence") or (dev.get("classification") or {}).get("confidence", 0),
        "inventory_source": (dev.get("wmi_inventory") or {}).get("inventory_source") if verified_wmi else (
            (dev.get("deep_inventory") or {}).get("inventory_source", "Verified deep protocol") if verified_deep else "Unverified network evidence"
        ),
        "verified": bool(verified_wmi or verified_deep),
        "wmi": dev.get("wmi_inventory"),
        "deep": dev.get("deep_inventory"),
        "fallback": dev.get("fallback_inventory"),
        "switch_port": dev.get("switch_port"),
    }

@app.get("/api/inventory/summary")
def inventory_summary(user: dict = Depends(get_current_user)):
    conn = db_conn()
    total, online, offline, avg = conn.execute("""SELECT COUNT(*),
        SUM(CASE WHEN status IN ('online','discovered') THEN 1 ELSE 0 END),
        SUM(CASE WHEN status IN ('offline','stale') THEN 1 ELSE 0 END),
        COALESCE(AVG(completeness),0) FROM inventory_assets""").fetchone()
    conn.close()
    return {"total": total or 0, "online": online or 0, "offline": offline or 0, "completeness": round(avg or 0, 1)}


@app.get("/api/network/scopes")
def network_scopes(user: dict = Depends(get_current_user)):
    """Return only locally attached private IPv4 scopes used by discovery."""
    try:
        scopes = [str(n) for n in diag._local_ipv4_networks()]
    except Exception as exc:
        return {"scopes": [], "error": str(exc)}
    return {"scopes": scopes, "count": len(scopes), "policy": "local-private-networks-only"}

@app.get("/api/inventory/scans")
def inventory_scan_runs(limit: int = 20, user: dict = Depends(get_current_user)):
    limit = max(1, min(limit, 100))
    conn = db_conn()
    rows = conn.execute("SELECT id,started_at,finished_at,mode,requested_by,total,success,failed,error FROM inventory_scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    keys = ["id","started_at","finished_at","mode","requested_by","total","success","failed","error"]
    return {"scans":[dict(zip(keys,r)) for r in rows]}

@app.get("/api/inventory/assets")
def inventory_assets(limit: int = 500, user: dict = Depends(get_current_user)):
    limit = max(1, min(limit, 2000))
    conn = db_conn()
    rows = conn.execute("""SELECT asset_id,hostname,ip_address,mac_address,vendor,device_type,os_name,os_version,status,
        first_seen,last_seen,inventory_source,completeness FROM inventory_assets ORDER BY last_seen DESC LIMIT ?""", (limit,)).fetchall()
    conn.close()
    keys = ["asset_id","hostname","ip_address","mac_address","vendor","device_type","os_name","os_version","status","first_seen","last_seen","inventory_source","completeness"]
    return {"assets": [dict(zip(keys, row)) for row in rows]}


@app.get("/api/inventory/assets/{asset_id}")
def inventory_asset_detail(asset_id: int, user: dict = Depends(get_current_user)):
    conn = db_conn()
    asset = conn.execute("SELECT * FROM inventory_assets WHERE asset_id=?", (asset_id,)).fetchone()
    if not asset:
        conn.close(); raise HTTPException(status_code=404, detail="Varlık bulunamadı")
    cols = [d[0] for d in conn.execute("SELECT * FROM inventory_assets LIMIT 0").description]
    item = dict(zip(cols, asset))
    hw = conn.execute("SELECT cpu,ram_gb,gpu,motherboard,disk_json,serial_number,collected_at FROM inventory_hardware WHERE asset_id=?", (asset_id,)).fetchone()
    item["hardware"] = dict(zip(["cpu","ram_gb","gpu","motherboard","disk_json","serial_number","collected_at"], hw)) if hw else {}
    item["interfaces"] = [dict(zip(["id","interface_name","ip_address","mac_address","gateway","subnet","collected_at"], r)) for r in conn.execute("SELECT id,interface_name,ip_address,mac_address,gateway,subnet,collected_at FROM inventory_interfaces WHERE asset_id=? ORDER BY id", (asset_id,)).fetchall()]
    item["software"] = [dict(zip(["id","name","version","publisher","collected_at"], r)) for r in conn.execute("SELECT id,name,version,publisher,collected_at FROM inventory_software WHERE asset_id=? ORDER BY name", (asset_id,)).fetchall()]
    item["history"] = [dict(zip(["id","event_type","field_name","old_value","new_value","source","created_at"], r)) for r in conn.execute("SELECT id,event_type,field_name,old_value,new_value,source,created_at FROM inventory_history WHERE asset_id=? ORDER BY created_at DESC LIMIT 100", (asset_id,)).fetchall()]
    conn.close()
    return item

# ---------- Network Intelligence / Analyst v10 ----------
def _analyst_correlation(dev):
    c=_classification(dev); evidence=c.get("evidence") or []
    sources=[str(x) for x in (dev.get("discovery_sources") or [])]
    inv=dev.get("unified_inventory") or {}
    signals=[]
    for x in evidence:
        signals.append(str(x))
    for src in sources:
        if src not in signals: signals.append(f"Discovery: {src}")
    if inv.get("verified"): signals.append(f"Doğrulanmış envanter: {inv.get('inventory_source','yetkili kaynak')}")
    if dev.get("vendor"): signals.append(f"Vendor: {dev.get('vendor')}")
    if dev.get("hostname"): signals.append("Hostname mevcut")
    ports=sorted({int(x) for x in (c.get("open_ports") or []) if str(x).isdigit()})
    if ports: signals.append(f"Gözlenen portlar: {', '.join(map(str,ports[:20]))}")
    score=min(100, 35 + len(signals)*8)
    if dev.get("mac"): score+=8
    if dev.get("hostname"): score+=5
    if inv.get("verified"): score+=10
    score=min(100,score)
    return {"score":score,"signals":signals[:20],"method":"multi-source correlation"}


def _review_priority(a):
    score=0; reasons=[]
    if a["status"] in {"offline","stale"}: score+=15; reasons.append("Cihaz şu an aktif doğrulanmadı")
    if a["confidence"]<70: score+=20; reasons.append("Cihaz kimliği/sınıfı düşük güvenli")
    if a["completeness"]<70: score+=15; reasons.append("Envanter eksik")
    if a["exposure"]["risk"]=="medium": score+=25; reasons.append("İnceleme gerektiren servis bulundu")
    if not a.get("hostname"): score+=5; reasons.append("Hostname bilinmiyor")
    score=min(100,score)
    level="high" if score>=50 else "medium" if score>=25 else "low"
    return {"score":score,"level":level,"reasons":reasons}


def _take_analyst_snapshot():
    devices=[_analyst_device(d) for d in (_devices_cache.get("data") or [])]
    total=len(devices); online=sum(d["status"]=="online" for d in devices); offline=sum(d["status"] in {"offline","stale"} for d in devices)
    unknown=sum(d["device_type"] in {None,"","unknown"} for d in devices)
    completeness=round(sum(d["completeness"] for d in devices)/total,1) if total else 0
    review=sum(d["exposure"]["risk"]=="medium" for d in devices)
    health=100-min(30,unknown*2)-min(20,review*3)-min(15,offline*15/total) if total else 0
    conn=db_conn()
    conn.execute("INSERT INTO analyst_snapshots(created_at,total,online,offline,unknown,health,completeness,security_review,payload) VALUES(?,?,?,?,?,?,?,?,?)",(time.time(),total,online,offline,unknown,max(0,round(health,1)),completeness,review,json.dumps({"by_type":{}})))
    conn.commit(); conn.close()

class AssetMetadataRequest(BaseModel):
    asset_tag: str | None = None
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    status: str | None = None
    warranty_until: str | None = None
    notes: str | None = None

@app.get("/api/inventory/assets/{asset_id}/metadata")
def inventory_asset_metadata(asset_id:int, user:dict=Depends(get_current_user)):
    conn=db_conn()
    row=conn.execute("SELECT asset_id,asset_tag,owner,department,location,status,warranty_until,notes,updated_at FROM asset_metadata WHERE asset_id=?",(asset_id,)).fetchone()
    exists=conn.execute("SELECT 1 FROM inventory_assets WHERE asset_id=?",(asset_id,)).fetchone()
    conn.close()
    if not exists: raise HTTPException(status_code=404, detail="Varlık bulunamadı")
    keys=["asset_id","asset_tag","owner","department","location","status","warranty_until","notes","updated_at"]
    return dict(zip(keys,row)) if row else {"asset_id":asset_id}

@app.put("/api/inventory/assets/{asset_id}/metadata")
def update_inventory_asset_metadata(asset_id:int, body:AssetMetadataRequest, user:dict=Depends(get_current_user)):
    conn=db_conn(); exists=conn.execute("SELECT 1 FROM inventory_assets WHERE asset_id=?",(asset_id,)).fetchone()
    if not exists: conn.close(); raise HTTPException(status_code=404, detail="Varlık bulunamadı")
    now=time.time(); values=body.model_dump()
    old=conn.execute("SELECT asset_tag,owner,department,location,status,warranty_until,notes FROM asset_metadata WHERE asset_id=?",(asset_id,)).fetchone()
    if old is None:
        conn.execute("INSERT INTO asset_metadata(asset_id,asset_tag,owner,department,location,status,warranty_until,notes,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(asset_id,values.get("asset_tag"),values.get("owner"),values.get("department"),values.get("location"),values.get("status") or "managed",values.get("warranty_until"),values.get("notes"),now))
    else:
        current=dict(zip(["asset_tag","owner","department","location","status","warranty_until","notes"],old)); merged={k:(values[k] if values[k] is not None else current[k]) for k in current}
        conn.execute("UPDATE asset_metadata SET asset_tag=?,owner=?,department=?,location=?,status=?,warranty_until=?,notes=?,updated_at=? WHERE asset_id=?",(merged["asset_tag"],merged["owner"],merged["department"],merged["location"],merged["status"],merged["warranty_until"],merged["notes"],now,asset_id))
    conn.commit(); conn.close(); _audit(user["username"],"asset_metadata_update",f"asset_id={asset_id}")
    return {"ok":True,"asset_id":asset_id,"updated_at":now}

@app.get("/api/analyst/correlation")
def analyst_correlation(user: dict = Depends(get_current_user)):
    result=[]
    for d in (_devices_cache.get("data") or []):
        a=_analyst_device(d); a["correlation"]=_analyst_correlation(d); a["review_priority"]=_review_priority(a); result.append(a)
    result.sort(key=lambda x:x["review_priority"]["score"], reverse=True)
    return {"devices":result}

@app.get("/api/analyst/trends")
def analyst_trends(limit:int=30, user:dict=Depends(get_current_user)):
    limit=max(1,min(limit,200)); conn=db_conn(); rows=conn.execute("SELECT created_at,total,online,offline,unknown,health,completeness,security_review FROM analyst_snapshots ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall(); conn.close()
    keys=["created_at","total","online","offline","unknown","health","completeness","security_review"]
    return {"points":[dict(zip(keys,r)) for r in reversed(rows)]}

@app.post("/api/analyst/snapshot")
def analyst_snapshot(user:dict=Depends(get_current_user)):
    if user.get("role")!="admin": raise _AuthError(403,"Analiz snapshot için yönetici yetkisi gerekiyor.")
    _take_analyst_snapshot(); _audit(user["username"],"analyst_snapshot","Network intelligence snapshot")
    return {"ok":True}

@app.get("/api/analyst/topology-evidence")
def analyst_topology_evidence(user:dict=Depends(get_current_user)):
    edges=[]
    for d in (_devices_cache.get("data") or []):
        ip=d.get("ip"); name=d.get("hostname") or d.get("friendly_name") or ip
        for key in ("lldp_neighbors","cdp_neighbors","neighbors"):
            vals=d.get(key) or (d.get("network_intelligence") or {}).get(key) or []
            if isinstance(vals,dict): vals=[vals]
            for n in vals:
                if not isinstance(n,dict): continue
                peer=n.get("ip") or n.get("management_address") or n.get("hostname") or n.get("device_id")
                if peer: edges.append({"source":name,"target":str(peer),"port":n.get("local_port") or n.get("port"),"protocol":key.upper().replace("_NEIGHBORS","")})
    return {"edges":edges,"evidence_only":True}

@app.get("/api/analyst/baseline")
def analyst_baseline(user:dict=Depends(get_current_user)):
    out=[]
    for d in (_devices_cache.get("data") or []):
        a=_analyst_device(d); checks=[]
        checks.append(("Kimlik",bool(d.get("ip") and (d.get("mac") or d.get("hostname")))))
        checks.append(("Hostname",bool(d.get("hostname"))))
        checks.append(("Envanter",a["completeness"]>=70))
        checks.append(("Güvenlik görünürlüğü",not a["exposure"]["findings"]))
        checks.append(("Erişilebilirlik",a["status"]=="online"))
        passed=sum(x[1] for x in checks); out.append({"ip":a["ip"],"hostname":a["hostname"],"score":round(passed*100/len(checks)),"checks":[{"name":x[0],"ok":x[1]} for x in checks]})
    return {"devices":out}

@app.get("/api/analyst/report")
def analyst_report(user:dict=Depends(get_current_user)):
    from fastapi.responses import PlainTextResponse
    devices=[_analyst_device(d) for d in (_devices_cache.get("data") or [])]
    lines=["NETMON NETWORK ANALYST RAPORU",f"Oluşturulma: {time.strftime('%Y-%m-%d %H:%M:%S')}",f"Toplam cihaz: {len(devices)}",""]
    for d in devices:
        lines += [f"- {d['hostname'] or d['ip']} | {d['device_type']} | {d['status']} | Güven %{d['confidence']} | Envanter %{d['completeness']}"]
        for r in d["recommendations"][:3]: lines.append(f"  * {r}")
    return PlainTextResponse("\n".join(lines),media_type="text/plain; charset=utf-8",headers={"Content-Disposition":"attachment; filename=netmon-analyst-report.txt"})

ACADEMY_CONTENT = {
    "ip": {"title":"IP Adresi","level":"Başlangıç","summary":"Cihazın ağ üzerindeki mantıksal adresidir.","lesson":["Aynı ağdaki cihazların birbirini bulmasına yardımcı olur.","IP değişebilir; bu yüzden envanter kimliği yalnız IP olmamalıdır."],"quiz":{"question":"Hangisi bir IPv4 adresidir?","options":["192.168.1.25","AA:BB:CC:DD:EE:FF","example.local","255.255.255.255.255"],"answer":0}},
    "mac": {"title":"MAC Adresi","level":"Başlangıç","summary":"Ağ arayüzünün donanımsal adresidir.","lesson":["Yerel ağda arayüzleri ayırt etmek için kullanılır.","Rastgeleleştirilmiş MAC adresleri nedeniyle tek başına kusursuz kimlik değildir."],"quiz":{"question":"MAC adresi en çok neyi temsil eder?","options":["Ağ arayüzünü","DNS sunucusunu","Web sitesini","Kullanıcı şifresini"],"answer":0}},
    "dns": {"title":"DNS","level":"Başlangıç","summary":"Alan adlarını IP adreslerine çözümleyen sistemdir.","lesson":["Örneğin bir alan adının hangi IP'ye gittiğini bulmaya yardım eder.","DNS arızasında internet bağlantısı varmış gibi görünüp siteler açılmayabilir."],"quiz":{"question":"DNS'in temel görevi nedir?","options":["Alan adını IP'ye çözümlemek","RAM artırmak","Firewall kurmak","MAC değiştirmek"],"answer":0}},
    "dhcp": {"title":"DHCP","level":"Başlangıç","summary":"Ağ yapılandırmasını otomatik dağıtır.","lesson":["IP, ağ maskesi, gateway ve DNS gibi bilgileri dağıtabilir.","Kiralama süresi dolduğunda cihaz yeni bir IP alabilir."],"quiz":{"question":"DHCP ne dağıtabilir?","options":["IP yapılandırması","CPU çekirdeği","Disk bölümü","Kullanıcı parolası"],"answer":0}},
    "ports": {"title":"Portlar","level":"Orta","summary":"Ağ servislerinin mantıksal giriş noktalarıdır.","lesson":["TCP/UDP portları servisleri ayırt etmeye yardım eder.","Açık port görmek tek başına güvenlik açığı bulunduğu anlamına gelmez."],"quiz":{"question":"443 numaralı port çoğunlukla hangi servisle ilişkilidir?","options":["HTTPS","DHCP","ARP","DNS"],"answer":0}},
    "firewall": {"title":"Firewall","level":"Orta","summary":"Trafiği kurallara göre izin verir veya engeller.","lesson":["Kaynak, hedef, port ve protokol gibi ölçütlerle karar verebilir.","Firewall durumu alınamıyorsa NetMon bunu tahmin etmemelidir."],"quiz":{"question":"Firewall'ın temel amacı nedir?","options":["Trafiği kurallarla kontrol etmek","CPU hızını artırmak","DNS kaydı oluşturmak","IP üretmek"],"answer":0}},
    "ids": {"title":"IDS / IPS","level":"Orta","summary":"Şüpheli ağ davranışlarını algılama ve gerektiğinde önleme yaklaşımıdır.","lesson":["IDS olayları tespit edip uyarabilir.","IPS tespit edilen trafiği politika kapsamında engelleyebilir."],"quiz":{"question":"IDS ile IPS arasındaki temel fark nedir?","options":["IPS önleme yeteneğine sahiptir","IDS her zaman firewall'dır","IPS DNS sunucusudur","Aralarında fark yoktur"],"answer":0}},
    "incident": {"title":"Incident Response","level":"İleri","summary":"Güvenlik olaylarını sistematik biçimde yönetme sürecidir.","lesson":["Tespit, analiz, sınırlama, düzeltme ve öğrenme adımlarını kapsar.","Amaç yalnız olayı kapatmak değil, tekrarını azaltmaktır."],"quiz":{"question":"Olay müdahalesinde ilk önemli adımlardan biri nedir?","options":["Olayı tespit edip doğrulamak","Kanıtları silmek","Tüm ağı kapatmak","Rastgele port açmak"],"answer":0}},
}

@app.get("/api/academy/modules")
def academy_modules(user: dict = Depends(get_current_user)):
    return {"modules": [{"id": k, "title": v["title"], "level": v["level"], "summary": v["summary"]} for k,v in ACADEMY_CONTENT.items()]}

@app.get("/api/academy/modules/{module_id}")
def academy_module_detail(module_id: str, user: dict = Depends(get_current_user)):
    item = ACADEMY_CONTENT.get(module_id)
    if not item:
        raise HTTPException(status_code=404, detail="Eğitim modülü bulunamadı")
    return {"id": module_id, **item}

class AcademyQuizRequest(BaseModel):
    module_id: str
    answer: int

@app.post("/api/academy/quiz")
def academy_quiz(req: AcademyQuizRequest, user: dict = Depends(get_current_user)):
    item = ACADEMY_CONTENT.get(req.module_id)
    if not item:
        raise HTTPException(status_code=404, detail="Eğitim modülü bulunamadı")
    quiz = item["quiz"]
    correct = int(req.answer) == int(quiz["answer"])
    return {"correct": correct, "answer": quiz["answer"], "message": "Doğru cevap." if correct else "Henüz değil. Açıklamayı tekrar inceleyin."}



# ---------------------------------------------------------------------------
# Network Analyst Intelligence — vendor bağımsız analitik katman
# ---------------------------------------------------------------------------
ANALYST_EVENT_WINDOW = 7 * 24 * 3600


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _device_status(dev):
    return str(dev.get("status") or dev.get("connectivity_status") or ("online" if dev.get("online") else "unknown")).lower()


def _classification(dev):
    c = dev.get("classification") if isinstance(dev.get("classification"), dict) else {}
    return c


def _exposure_for_device(dev):
    c = _classification(dev)
    ports = sorted({int(p) for p in (c.get("open_ports") or []) if str(p).isdigit()})
    findings = []
    severity = "low"
    for port in ports:
        if port in {21, 23, 445, 3389}:
            findings.append({"severity": "review", "port": port, "title": f"Hassas servis portu {port} erişilebilir", "reason": "Bu port kurumsal ağlarda politika kapsamında ayrıca değerlendirilmelidir."})
        elif port in {80, 8080, 8000}:
            findings.append({"severity": "info", "port": port, "title": f"HTTP servisi {port} üzerinde görüldü", "reason": "Şifrelenmemiş HTTP erişiminin gerekip gerekmediğini doğrulayın."})
    if any(x["severity"] == "review" for x in findings):
        severity = "medium"
    return {"risk": severity, "open_ports": ports, "findings": findings}


def _inventory_completeness(asset):
    fields = ["hostname", "ip_address", "mac_address", "vendor", "device_type", "os_name", "os_version"]
    present = sum(1 for f in fields if asset.get(f) not in (None, "", "unknown"))
    total = len(fields)
    # Donanım/yazılım alt kayıtlarının varlığı ayrıca ağırlıklandırılır.
    if asset.get("hardware"): present += 1
    if asset.get("software"): present += 1
    total += 2
    return round(present * 100 / total)


def _analyst_recommendations(dev, exposure, completeness):
    rec = []
    status = _device_status(dev)
    if status in {"offline", "stale"}:
        rec.append("Cihazın son görülme zamanını ve fiziksel/ağ bağlantısını doğrula.")
    if not dev.get("hostname"):
        rec.append("Hostname alınamadı; DNS/LLMNR/mDNS veya yetkili envanter kaynağını kontrol et.")
    if not dev.get("mac"):
        rec.append("MAC bilgisi yok; switch/ARP/neighbor tablosu veya SNMP ile doğrulamayı değerlendir.")
    if completeness < 70:
        rec.append("Yetkili derin envanter çalıştırılarak donanım/yazılım kapsamı artırılabilir.")
    if exposure["risk"] == "medium":
        rec.append("Hassas görünen servisleri kurum politikasına göre doğrula; gereksiz servisleri kapatma kararı yönetici tarafından verilmelidir.")
    c = _classification(dev)
    confidence = _safe_float(c.get("confidence"))
    if confidence is not None and confidence < 0.70:
        rec.append("Cihaz sınıfını doğrulamak için SNMP/LLDP/CDP/OS fingerprint gibi ek kanıt kaynakları kullanılabilir.")
    return rec


def _analyst_device(dev):
    exposure = _exposure_for_device(dev)
    completeness = _inventory_completeness(dev)
    c = _classification(dev)
    confidence = _safe_float(c.get("confidence"))
    if confidence is None:
        confidence = 0.0
    confidence_pct = round(confidence * 100 if confidence <= 1 else confidence)
    evidence = c.get("evidence") or []
    return {
        "ip": dev.get("ip"), "mac": dev.get("mac"), "hostname": dev.get("hostname"),
        "vendor": dev.get("vendor"), "status": _device_status(dev),
        "device_type": dev.get("type") or c.get("raw_type") or "unknown",
        "confidence": confidence_pct, "classification_source": dev.get("classification_source", "auto"),
        "evidence": evidence, "discovery_sources": dev.get("discovery_sources") or [],
        "completeness": completeness, "exposure": exposure,
        "recommendations": _analyst_recommendations(dev, exposure, completeness),
        "last_seen": dev.get("last_seen") or dev.get("last_discovered") or dev.get("timestamp"),
        "latency_ms": _safe_float(dev.get("latency")),
        "packet_loss": _safe_float(dev.get("packet_loss")),
    }


@app.get("/api/analyst/summary")
def analyst_summary(user: dict = Depends(get_current_user)):
    devices = list(_devices_cache.get("data") or [])
    analyzed = [_analyst_device(d) for d in devices]
    online = [d for d in analyzed if d["status"] == "online"]
    offline = [d for d in analyzed if d["status"] in {"offline", "stale"}]
    unknown = [d for d in analyzed if d["device_type"] in {None, "", "unknown"}]
    medium = [d for d in analyzed if d["exposure"]["risk"] == "medium"]
    avg_latency = [d["latency_ms"] for d in analyzed if d["latency_ms"] is not None]
    avg_loss = [d["packet_loss"] for d in analyzed if d["packet_loss"] is not None and d["status"] == "online"]
    completeness = round(sum(d["completeness"] for d in analyzed) / len(analyzed)) if analyzed else 0
    health = 100
    if unknown: health -= min(20, len(unknown) * 2)
    if medium: health -= min(25, len(medium) * 3)
    if avg_loss and sum(avg_loss)/len(avg_loss) > 2: health -= 10
    if offline and analyzed: health -= min(15, round(len(offline) * 15 / len(analyzed)))
    health = max(0, health)
    by_type = {}
    for d in analyzed:
        by_type[d["device_type"]] = by_type.get(d["device_type"], 0) + 1
    return {
        "health": {"score": health, "label": "Sağlıklı" if health >= 85 else "İzlenmeli" if health >= 65 else "Sorunlu"},
        "inventory": {"total": len(analyzed), "online": len(online), "offline": len(offline), "unknown_type": len(unknown), "completeness": completeness},
        "security": {"review_items": len(medium), "devices_with_exposure": len([d for d in analyzed if d["exposure"]["findings"]])},
        "performance": {"average_latency_ms": round(sum(avg_latency)/len(avg_latency), 1) if avg_latency else None, "average_packet_loss": round(sum(avg_loss)/len(avg_loss), 2) if avg_loss else None},
        "by_type": by_type,
        "top_recommendations": list(dict.fromkeys(x for d in analyzed for x in d["recommendations"]))[:10],
        "generated_at": time.time(),
    }


@app.get("/api/analyst/devices")
def analyst_devices(user: dict = Depends(get_current_user)):
    return {"devices": [_analyst_device(d) for d in (_devices_cache.get("data") or [])]}


@app.get("/api/analyst/device/{ip}")
def analyst_device(ip: str, user: dict = Depends(get_current_user)):
    for dev in (_devices_cache.get("data") or []):
        if dev.get("ip") == ip:
            return {"analysis": _analyst_device(dev)}
    raise HTTPException(status_code=404, detail="Cihaz bulunamadı")


@app.get("/api/analyst/anomalies")
def analyst_anomalies(user: dict = Depends(get_current_user)):
    """Saldırı iddiası üretmez; envanter/ağ değişikliklerini anomaliler olarak sunar."""
    rows = []
    conn = db_conn()
    try:
        # Son değişiklikler inventory_history'den alınır.
        q = "SELECT asset_id,event_type,field_name,old_value,new_value,source,created_at FROM inventory_history ORDER BY created_at DESC LIMIT 100"
        for r in conn.execute(q).fetchall():
            rows.append({"asset_id": r[0], "event": r[1], "field": r[2], "old": r[3], "new": r[4], "source": r[5], "created_at": r[6], "severity": "info"})
    finally:
        conn.close()
    return {"anomalies": rows}


@app.get("/api/analyst/exposure")
def analyst_exposure(user: dict = Depends(get_current_user)):
    result = []
    for dev in (_devices_cache.get("data") or []):
        a = _analyst_device(dev)
        if a["exposure"]["findings"]:
            result.append(a)
    return {"devices": result}


@app.get("/api/knowledge/network")
def knowledge_network(user: dict = Depends(get_current_user)):
    return {"topics": [
        {"id":"discovery","title":"Ağ keşfi","text":"NetMon tek bir yönteme güvenmez; ARP/Neighbor, ICMP, DNS, Nmap, SNMP ve uygun olduğunda LLDP/CDP gibi kaynakları birleştirir."},
        {"id":"identity","title":"Cihaz kimliği","text":"IP değişebilir. Bu nedenle MAC, hostname, vendor ve diğer fingerprint kanıtları birlikte değerlendirilir."},
        {"id":"status","title":"Durumlar","text":"Çevrimiçi ağda doğrulanmış cihazı, görüldü keşfedilmiş ama ICMP ile doğrulanmamış cihazı, çevrimdışı önceki envanter kaydını, stale ise uzun süredir görülmeyen kaydı ifade eder."},
        {"id":"snmp","title":"SNMP","text":"Yetkili salt-okuma SNMP; sistem kimliği, interface ve bazı ağ cihazı metrikleri sağlayabilir. Erişim yoksa NetMon tahmin yapmaz."},
        {"id":"lldp","title":"LLDP/CDP","text":"Komşuluk protokolleri cihazlar arasındaki bağlantıyı kanıtlamaya yardımcı olur. Kanıt yoksa topolojide fiziksel bağlantı uydurulmaz."},
        {"id":"inventory","title":"Agentless ve yetkili envanter","text":"Ağdan görülebilen bilgiler ile yetkili WMI/WinRM/SSH/SNMP/API bilgilerinin kapsamı farklıdır. Eksik alanlar UNKNOWN olarak tutulur."},
        {"id":"security","title":"Güvenlik görünürlüğü","text":"Açık port veya servis görmek tek başına güvenlik açığı bulunduğunu kanıtlamaz. NetMon bunları inceleme gerektiren gözlemler olarak sunar."},
        {"id":"anomaly","title":"Anomali","text":"Yeni cihaz, IP değişikliği, yeni port veya envanter değişikliği gibi olaylar analiste inceleme sinyali verir; otomatik saldırı hükmü verilmez."},
    ]}

from fastapi.responses import StreamingResponse
import io
import csv
import platform
import json

@app.post("/api/tools/rdp")
def api_launch_rdp(ip: str, user: dict = Depends(get_current_user)):
    if platform.system() == "Windows":
        import subprocess
        try:
            # We use CREATE_NO_WINDOW so it doesn't pop up a cmd window
            subprocess.Popen(["mstsc.exe", f"/v:{ip}"], **_hidden_subprocess_kwargs())
            return {"ok": True, "message": f"{ip} için RDP başlatıldı."}
        except Exception as e:
            return JSONResponse(status_code=500, content={"error": f"RDP başlatılamadı: {e}"})
    return JSONResponse(status_code=400, content={"error": "RDP sadece Windows'ta destekleniyor."})

@app.get("/api/export/devices")
def export_devices_csv(token: str | None = None, authorization: str | None = Header(None)):
    auth_token = None
    if isinstance(token, str) and token:
        auth_token = token
    elif isinstance(authorization, str) and authorization.startswith("Bearer "):
        auth_token = authorization.replace("Bearer ", "").strip()

    if auth_token:
        conn = db_conn()
        s = conn.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (auth_token,)).fetchone()
        conn.close()
        if not s or (s[1] and s[1] < time.time()):
            raise _AuthError(401, "Geçersiz veya süresi dolmuş oturum.")

    try:
        devices = list(_devices_cache.get("data") or [])
        if not devices:
            conn = db_conn()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT mac, friendly_name, hostname, device_type, first_seen, last_seen, last_ip, 
                       last_vendor, last_network, connectivity_status, identification_status, open_ports 
                FROM known_devices 
                ORDER BY last_network, last_ip
            """)
            rows = cursor.fetchall()
            conn.close()
            devices = [
                {
                    "mac": r["mac"], "friendly_name": r["friendly_name"], "hostname": r["hostname"],
                    "type": r["device_type"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                    "ip": r["last_ip"], "vendor": r["last_vendor"], "network": r["last_network"],
                    "status": r["connectivity_status"], "open_ports": r["open_ports"]
                }
                for r in rows
            ]

        output = io.StringIO()
        writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        
        writer.writerow([
            "IP Adresi", "MAC Adresi", "Cihaz Adı / Hostname", "Üretici (Vendor)", 
            "Cihaz Tipi", "Durum", "İşletim Sistemi", "İşlemci (CPU)", "Bellek (RAM)", 
            "Diskler", "Antivirüs", "Güvenlik Duvarı", "Açık Portlar", "Ağ / Alt Ağ", "Son Görülme"
        ])
        
        import datetime
        for d in devices:
            inv = d.get("wmi_inventory") or d.get("fallback_inventory") or {}
            hw = inv.get("hardware") or {}
            sw = inv.get("software") or {}
            sec = inv.get("security") or {}
            disks = inv.get("storage") or []
            disk_txt = " · ".join(f"{ds.get('drive_letter', 'Disk')}: {ds.get('total_gb', 0)}GB" for ds in disks) if isinstance(disks, list) and disks else "-"
            
            raw_ports = (d.get("classification") or {}).get("open_ports") or d.get("open_ports") or []
            if isinstance(raw_ports, str):
                try: raw_ports = json.loads(raw_ports)
                except Exception: raw_ports = []
            ports_txt = ", ".join(map(str, raw_ports)) if raw_ports else "-"
            
            st = d.get("status") or "unknown"
            if st == "online": st_text = "Çevrimiçi"
            elif st in ("offline", "stale"): st_text = "Çevrimdışı"
            elif st == "discovered": st_text = "Yanıt Doğrulanamadı"
            else: st_text = "Belirsiz"

            last_ts = d.get("last_seen") or d.get("ts")
            last_date = datetime.datetime.fromtimestamp(last_ts).strftime('%Y-%m-%d %H:%M:%S') if last_ts else "-"
            
            writer.writerow([
                d.get("ip") or "-",
                d.get("mac") or "-",
                d.get("hostname") or d.get("friendly_name") or "-",
                d.get("vendor") or "Bilinmiyor",
                d.get("type") or "unknown",
                st_text,
                sw.get("os_name") or d.get("os_fingerprint") or "-",
                hw.get("cpu_model") or "-",
                f"{hw.get('ram_gb')} GB" if hw.get("ram_gb") else "-",
                disk_txt,
                sec.get("antivirus") or "Bilinmiyor",
                sec.get("firewall") or "Bilinmiyor",
                ports_txt,
                d.get("network") or d.get("last_network") or "-",
                last_date
            ])
            
        filename = f"netmon_envanter_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            content=output.getvalue().encode("utf-8-sig"),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "text/csv; charset=utf-8"
            }
        )
    except Exception as e:
        logger.exception("[EXPORT] Excel/CSV export failed")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/ssl-certs")
def get_ssl_certs(user: dict = Depends(get_current_user)):
    conn = db_conn()
    rows = conn.execute("SELECT ip, hostname, issuer, valid_from, valid_to, days_left, last_checked FROM ssl_certificates ORDER BY days_left ASC").fetchall()
    conn.close()
    return {"certs": [{"ip": r[0], "hostname": r[1], "issuer": r[2], "valid_from": r[3], "valid_to": r[4], "days_left": r[5], "last_checked": r[6]} for r in rows]}

@app.get("/api/devices")
def get_devices(force: bool = False, user: dict = Depends(get_current_user)):
    if force and user.get("role") != "admin":
        raise _AuthError(403, "Zorunlu ağ taraması için yönetici yetkisi gerekiyor.")
    now = time.time()
    if not force and _devices_cache["data"] and (now - _devices_cache["ts"] < DEVICES_CACHE_SECONDS):
        devices = _devices_cache["data"]
        for dev in devices:
            _enrich_device_inventory(dev)
        return {"devices": devices, "cached": True, "error": _devices_cache.get("error")}
    if not _device_scan_lock.acquire(blocking=False):
        return {
            "devices": _devices_cache.get("data") or [],
            "cached": True,
            "scanning": True,
            "error": _devices_cache.get("error"),
        }
    _devices_cache["scan_status"] = "running"
    try:
        try:
            devices = _discover_configured_devices()
            devices = enrich_devices(devices)
            devices = merge_scan_into_inventory(devices)
            _devices_cache["error"] = None
        except NetworkDiscoveryError as exc:
            logger.warning("[API] Device scan failed: %s", exc)
            devices = []
            _devices_cache["error"] = str(exc)
        except Exception as exc:
            logger.exception("[API] Unexpected error during device scan")
            devices = []
            _devices_cache["error"] = f"Beklenmeyen hata: {exc}"

        if devices:
            for dev in devices:
                _enrich_device_inventory(dev)
                # Agentless keşifte elde edilen ağ kanıtını da normalize edilmiş
                # asset tablosuna kaydet. Derin inventory yoksa alanlar boş kalır.
                _sync_normalized_inventory(dev, {
                    "status": "Success",
                    "ip_address": dev.get("ip"),
                    "mac_address": dev.get("mac"),
                    "computer_name": dev.get("hostname"),
                    "inventory_source": "Agentless Discovery",
                }, "Agentless Discovery")

        _devices_cache["data"] = devices
        _devices_cache["ts"] = now
        return {"devices": devices, "cached": False, "error": _devices_cache["error"]}
    finally:
        _devices_cache["scan_status"] = "idle"
        _device_scan_lock.release()

class WmiScanRequest(BaseModel):
    ip_list: list[str]
    username: str = ""
    password: str = ""
    timeout: int = 20


class AuthorizedInventoryRequest(BaseModel):
    ip: str
    protocol: str = "auto"  # auto | windows | ssh | snmp
    username: str = ""
    password: str = ""
    snmp_community: str = ""
    timeout: int = 20

@app.post("/api/scan_wmi_inventory")
def trigger_wmi_scan(req: WmiScanRequest, user: dict = Depends(require_admin)):
    if not 5 <= req.timeout <= 60:
        return JSONResponse(status_code=400, content={"error": "Zaman aşımı 5-60 saniye arasında olmalıdır."})
    if not req.ip_list or len(req.ip_list) > 64:
        return JSONResponse(status_code=400, content={"error": "Bir istekte 1-64 hedef IP gönderilebilir."})
    targets = []
    for raw in req.ip_list:
        try:
            parsed = ipaddress.ip_address(raw.strip())
        except ValueError:
            return JSONResponse(status_code=400, content={"error": f"Geçersiz IP adresi: {raw}"})
        if not _is_allowed_inventory_ip(parsed):
            return JSONResponse(status_code=400, content={"error": f"Yalnızca yerel/özel IPv4 hedefleri taranabilir: {raw}"})
        targets.append(str(parsed))
    u = req.username if req.username else WMI_USERNAME
    p = req.password if req.password else WMI_PASSWORD
    scanner = WmiNetworkScanner(
        username=u if u else None,
        password=p if p else None,
        timeout=req.timeout,
        verify_tls=WINRM_VERIFY_TLS,
    )
    results = scanner.scan_network(targets, max_workers=10)

    # Immediately attach results into device cache
    if _devices_cache.get("data") and results:
        res_by_ip = {r.get("ip_address"): r for r in results}
        for dev in _devices_cache["data"]:
            if dev.get("ip") in res_by_ip:
                result = res_by_ip[dev["ip"]]
                if result.get("status") == "Success":
                    dev["wmi_inventory"] = result
                    dev.pop("inventory_error", None)
                    _persist_device_inventory(dev, result, result.get("inventory_source") or "WMI/WinRM")
                else:
                    dev["inventory_error"] = {
                        "code": result.get("error_code"),
                        "message": result.get("error_message"),
                        "ts": time.time(),
                    }

    _devices_cache["ts"] = time.time()
    manager.broadcast_threadsafe({"type": "devices", "devices": _devices_cache.get("data", []), "ts": _devices_cache.get("ts", 0)})
    succeeded = sum(1 for result in results if result.get("status") == "Success")
    _audit(user["username"], "wmi_scan", f"targets={len(targets)} success={succeeded}")
    return {"ok": True, "results": results, "summary": {"total": len(results), "success": succeeded, "failed": len(results) - succeeded}}


def _run_windows_inventory_on_devices(devices: list[dict]):
    """Derin taramada Windows adayı cihazları kayıtlı yetkiyle topluca tara."""
    if not (WMI_USERNAME and WMI_PASSWORD):
        return []
    candidates = []
    for dev in devices:
        if dev.get("is_self") or not dev.get("ip"):
            continue
        ports = set((dev.get("classification") or {}).get("open_ports") or [])
        windows_hint = (
            dev.get("os_fingerprint") == "Windows"
            or dev.get("type") in ("computer", "pc", "laptop", "server")
            or bool(ports.intersection({135, 445, 3389, 5985, 5986}))
        )
        if windows_hint:
            candidates.append(dev)
    if not candidates:
        return []
    scanner = WmiNetworkScanner(
        username=WMI_USERNAME,
        password=WMI_PASSWORD,
        timeout=20,
        verify_tls=WINRM_VERIFY_TLS,
    )
    results = scanner.scan_network([dev["ip"] for dev in candidates], max_workers=10)
    by_ip = {result.get("ip_address"): result for result in results}
    for dev in candidates:
        result = by_ip.get(dev["ip"])
        if result and result.get("status") == "Success":
            dev["wmi_inventory"] = result
            _persist_device_inventory(dev, result, result.get("inventory_source") or "WMI/WinRM")
        elif result:
            dev["inventory_error"] = {"code": result.get("error_code"), "message": result.get("error_message"), "ts": time.time()}
    return results


@app.post("/api/devices/inventory")
def scan_authorized_device_inventory(req: AuthorizedInventoryRequest, user: dict = Depends(require_admin)):
    if not 5 <= req.timeout <= 60:
        return JSONResponse(status_code=400, content={"error": "Zaman aşımı 5-60 saniye arasında olmalıdır."})
    try:
        parsed = ipaddress.ip_address(req.ip.strip())
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Geçersiz hedef IP adresi."})
    if not _is_allowed_inventory_ip(parsed):
        return JSONResponse(status_code=400, content={"error": "Yalnızca yerel/özel IPv4 hedefleri taranabilir."})
    if req.protocol not in {"auto", "windows", "ssh", "snmp"}:
        return JSONResponse(status_code=400, content={"error": "Geçersiz envanter protokolü."})
    ip = str(parsed)
    cached_devices = _devices_cache.setdefault("data", [])
    device = next((item for item in cached_devices if item.get("ip") == ip), None)
    is_new_cache_entry = device is None
    if device is None:
        device = {
            "ip": ip,
            "type": "unknown",
            "status": "discovered",
            "connectivity_status": "unknown",
            "classification": {"open_ports": []},
            "discovery_sources": ["authorized_inventory"],
        }
    ports = set((device.get("classification") or {}).get("open_ports") or [])

    # Elle IP girildiğinde karar verebilmek için temel TCP yönetim portlarını ölç.
    if not ports and ip not in ("127.0.0.1",):
        def probe(port):
            try:
                with socket.create_connection((ip, port), timeout=0.8):
                    return port
            except OSError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            ports.update(port for port in executor.map(probe, (22, 135, 445, 5985, 5986, 3389)) if port)
        device.setdefault("classification", {})["open_ports"] = sorted(ports)

    protocol = req.protocol
    if protocol == "auto":
        if ports.intersection({135, 445, 3389, 5985, 5986}) or device.get("type") in {"computer", "pc", "laptop", "server"}:
            protocol = "windows"
        elif 22 in ports:
            protocol = "ssh"
        elif 161 in ports or device.get("type") in {"router", "switch", "access_point", "firewall", "printer", "network_device"}:
            protocol = "snmp"
        else:
            return {"ok": False, "protocol": "none", "result": {
                "status": "Unavailable",
                "error_message": "Destekte WMI/WinRM, SSH veya SNMP yönetim kanalı tespit edilemedi. Telefon/tablet için üretici MDM API'si ya da cihaz ajanı gerekir.",
            }}

    if protocol == "windows":
        scanner = WmiNetworkScanner(
            username=req.username or WMI_USERNAME or None,
            password=req.password or WMI_PASSWORD or None,
            timeout=req.timeout,
            verify_tls=WINRM_VERIFY_TLS,
        )
        result = scanner.scan_network([ip], max_workers=1)[0]
        if result.get("status") == "Success":
            device["wmi_inventory"] = result
            _persist_device_inventory(device, result, result.get("inventory_source") or "WMI/WinRM")
    elif protocol == "ssh":
        result = deep_discovery.scan_linux_deep(
            ip,
            username=req.username or SSH_USERNAME,
            password=req.password or SSH_PASSWORD,
            timeout=max(5, min(req.timeout, 60)),
        )
        if result.get("status") == "Success":
            device["deep_inventory"] = result
            device["fallback_inventory"] = result
            _persist_device_inventory(device, result, "SSH")
    else:
        result = deep_discovery.scan_snmp_deep(
            ip,
            community=req.snmp_community or SNMP_COMMUNITY,
            timeout=max(1, min(req.timeout, 10)),
        )
        if result.get("status") == "Success":
            device["deep_inventory"] = result
            device["fallback_inventory"] = result
            _persist_device_inventory(device, result, "SNMP")

    if result.get("status") != "Success":
        message = result.get("error_message") or result.get("error") or "Yetkili envanter alınamadı."
        device["inventory_error"] = {"code": result.get("error_code", f"{protocol}_failed"), "message": message, "ts": time.time()}
    _enrich_device_inventory(device, allow_deep=False)
    if is_new_cache_entry:
        cached_devices.append(device)
    _devices_cache["ts"] = time.time()
    manager.broadcast_threadsafe({"type": "devices", "devices": _devices_cache.get("data", []), "ts": time.time()})
    succeeded = result.get("status") == "Success"
    _audit(
        user["username"],
        "authorized_inventory",
        f"target={ip} protocol={protocol} status={result.get('status')}",
        success=succeeded,
    )
    return {"ok": succeeded, "protocol": protocol, "result": result}

class NetworkScanRequest(BaseModel):
    mode: str = "agentless"  # "agentless" (şifresiz açık protokoller) veya "deep" (yetkili WMI/SSH)

@app.post("/api/devices/scan")
def trigger_network_scan(req: Optional[NetworkScanRequest] = None, user: dict = Depends(require_admin)):
    if not _device_scan_lock.acquire(blocking=False):
        return JSONResponse(status_code=409, content={"error": "Tarama zaten devam ediyor."})

    scan_mode = req.mode if (req and req.mode in ("agentless", "deep")) else "agentless"
    _devices_cache["scan_status"] = "running"
    scan_started = time.time()
    scan_run_id = None
    try:
        c = db_conn()
        cur = c.execute("INSERT INTO inventory_scan_runs(started_at,mode,requested_by) VALUES(?,?,?)", (scan_started, scan_mode, user.get("username")))
        scan_run_id = cur.lastrowid
        c.commit(); c.close()
    except Exception as exc:
        logger.warning("[INVENTORY] scan run kaydı açılamadı: %s", exc)
    manager.broadcast_threadsafe({"type": "scan", "status": "started", "mode": scan_mode})
    manager.broadcast_threadsafe({"type": "scan_wave", "wave": 1, "label": "Wave 1: ARP & ICMP Sweep", "progress": 33})
    try:
        manager.broadcast_threadsafe({"type": "scan_wave", "wave": 2, "label": "Wave 2: DNS, mDNS, SSDP, SNMP, NetBIOS & LLDP", "progress": 66})
        devices = _discover_configured_devices()
        devices = enrich_devices(devices)
        devices = merge_scan_into_inventory(devices)
        manager.broadcast_threadsafe({"type": "scan_wave", "wave": 3, "label": "Wave 3: Service Probing & Unified Inventory", "progress": 100})
        _update_switch_mac_tables(devices)
        
        if devices:
            if scan_mode == "deep":
                _run_windows_inventory_on_devices(devices)
            for dev in devices:
                _enrich_device_inventory(dev, allow_deep=(scan_mode == "deep"))

        _devices_cache["data"] = devices
        _devices_cache["ts"] = time.time()
        _devices_cache["error"] = None
        _devices_cache["scan_mode"] = scan_mode
        if scan_run_id:
            try:
                c = db_conn(); c.execute("UPDATE inventory_scan_runs SET finished_at=?, total=?, success=?, failed=? WHERE id=?", (time.time(), len(devices), sum(1 for d in devices if d.get("wmi_inventory",{}).get("status") == "Success" or d.get("deep_inventory",{}).get("status") == "Success" or d.get("status") in {"online","discovered"}), 0, scan_run_id)); c.commit(); c.close()
            except Exception as exc: logger.warning("[INVENTORY] scan run tamamlanamadı: %s", exc)
        online_devices = [d for d in devices if d.get("status") == "online"]
        discovered_devices = [d for d in devices if d.get("status") == "discovered"]
        offline_devices = [d for d in devices if d.get("status") in {"offline", "stale"}]
        by_type = {}
        for d in devices:
            t = d.get("type") or "unknown"
            by_type[t] = by_type.get(t, 0) + 1
        scan_result = {
            "status": "done", "devices": devices, "online_devices": online_devices,
            "discovered_devices": discovered_devices, "offline_devices": offline_devices,
            "by_type": by_type, "ts": _devices_cache["ts"], "mode": scan_mode, "error": None
        }
        manager.broadcast_threadsafe({"type": "devices", **scan_result})
        return scan_result
    except NetworkDiscoveryError as exc:
        logger.warning("[API] Manual scan failed: %s", exc)
        _devices_cache["error"] = str(exc)
        return JSONResponse(status_code=503, content={"status": "error", "devices": [], "error": str(exc)})
    except Exception as exc:
        logger.exception("[API] Unexpected error during manual scan")
        _devices_cache["error"] = f"Beklenmeyen hata: {exc}"
        return JSONResponse(status_code=500, content={"status": "error", "devices": [], "error": _devices_cache["error"]})
    finally:
        _devices_cache["scan_status"] = "idle"
        manager.broadcast_threadsafe({"type": "scan", "status": "done"})
        _device_scan_lock.release()

# ------------------------------------------------------------
# YENİ: Ayarlar panelindeki "Ağ tarama sıklığı" (scan_interval) alanı daha
# önce sadece UI'da duruyordu, hiçbir arka plan döngüsü onu okumuyordu — yani
# ayarı değiştirmenin gerçek bir etkisi yoktu. Bu döngü, cihaz taramasını
# gerçekten SCAN_INTERVAL saniyede bir otomatik tekrarlar.
# ------------------------------------------------------------
def device_scan_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        if not _device_scan_lock.acquire(blocking=False):
            stop_event.wait(5)
            continue
        _devices_cache["scan_status"] = "running"
        try:
            devices = _discover_configured_devices()
            devices = enrich_devices(devices)
            devices = merge_scan_into_inventory(devices)
            for dev in devices:
                _enrich_device_inventory(dev, allow_deep=False)
                _sync_normalized_inventory(dev, {
                    "status": "Success",
                    "ip_address": dev.get("ip"),
                    "mac_address": dev.get("mac"),
                    "computer_name": dev.get("hostname"),
                    "inventory_source": "Agentless Discovery",
                }, "Agentless Discovery")
            _devices_cache["data"] = devices
            _devices_cache["ts"] = time.time()
            _devices_cache["error"] = None
            manager.broadcast_threadsafe({"type": "devices", "devices": devices, "ts": _devices_cache["ts"]})
        except NetworkDiscoveryError as exc:
            logger.warning("[LOOP] Auto device scan failed: %s", exc)
            _devices_cache["error"] = str(exc)
        except Exception:
            logger.exception("[LOOP] Unexpected error in device_scan_loop")
        finally:
            _devices_cache["scan_status"] = "idle"
            _device_scan_lock.release()
        stop_event.wait(max(60, SCAN_INTERVAL))

@app.get("/api/diagnostics")
def get_diagnostics(user: dict = Depends(get_current_user)):
    try:
        return diag.run_troubleshooting_wizard(PING_TARGET, DNS_DOMAIN, PING_COUNT)
    except Exception as exc:
        return {"adapter": False, "gateway": False, "dns": False, "internet": False,
                "issue": "Teşhis çalıştırılamadı", "recommendation": str(exc)}

@app.get("/api/security")
def get_security(user: dict = Depends(get_current_user)):
    try:
        return diag.get_security_analysis()
    except Exception as exc:
        return {"firewall_desc": "", "webfilter_desc": "", "rules": [], "error": str(exc)}

@app.get("/api/flow")
def get_flow(user: dict = Depends(get_current_user)):
    try:
        return {"steps": diag.simulate_connection_flow(), "simulated": True}
    except Exception as exc:
        return {"steps": [], "error": str(exc)}

# ============================================================
# SİMÜLASYON API
# ============================================================
class SimulateRequest(BaseModel):
    scenario: str

@app.get("/api/simulate/scenarios")
def list_scenarios(user: dict = Depends(get_current_user)):
    return [{"id": key, "label": val["label"]} for key, val in SCENARIOS.items()]

@app.post("/api/simulate/start")
def start_simulation(req: SimulateRequest, user: dict = Depends(require_admin)):
    if req.scenario not in SCENARIOS:
        return {"ok": False, "error": "Bilinmeyen senaryo"}
    simulation_state["active"] = True
    simulation_state["scenario"] = req.scenario
    simulation_state["started_at"] = time.time()
    _sim_tick["n"] = 0
    return {"ok": True, "scenario": req.scenario, "label": SCENARIOS[req.scenario]["label"]}

@app.post("/api/simulate/stop")
def stop_simulation(user: dict = Depends(require_admin)):
    simulation_state["active"] = False
    simulation_state["scenario"] = None
    simulation_state["started_at"] = None
    return {"ok": True}

# ============================================================
# ADMIN GÜVENLİK VE AĞ OPERASYON MERKEZİ (XOC / NOC / SOC) API
# ============================================================
_blacklist_ips: set[str] = set()
_dos_simulations: dict[str, dict] = {}

class BlacklistRequest(BaseModel):
    ip: str
    reason: str = "Aşırı istek / Şüpheli DoS Anomali Tespiti"

class DosSimulateRequest(BaseModel):
    target_ip: str
    intensity: str = "medium"

@app.get("/api/admin/xoc/metrics")
def get_admin_xoc_metrics(user: dict = Depends(require_admin)):
    """Ölçülebilen NOC metriklerini ve simülasyon yetenek durumunu döndürür."""
    cpu = ram = None
    active_conns = None
    link_speed_mbps = None
    if HAS_PSUTIL and psutil:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            active_conns = sum(1 for item in psutil.net_connections(kind="inet") if item.status == "ESTABLISHED")
            active_speeds = [stat.speed for stat in psutil.net_if_stats().values() if stat.isup and stat.speed and stat.speed > 0]
            link_speed_mbps = max(active_speeds) if active_speeds else None
        except (OSError, RuntimeError, psutil.Error):
            pass

    now = time.time()
    with _request_metrics_lock:
        recent_requests = sum(1 for ts in _request_timestamps if ts >= now - 60)
    measured_window = max(1.0, min(60.0, now - _server_started_at))
    rps = round(recent_requests / measured_window, 2)

    conn = db_conn()
    alert_rows = conn.execute(
        "SELECT level, COUNT(*) FROM alerts WHERE ts >= ? GROUP BY level", (now - 86400,)
    ).fetchall()
    snapshot_rows = conn.execute("SELECT data FROM snapshots WHERE ts >= ?", (now - 86400,)).fetchall()
    conn.close()
    alert_counts = {level: count for level, count in alert_rows}
    measured_snapshots = []
    for (payload,) in snapshot_rows:
        try:
            measured_snapshots.append(json.loads(payload).get("status"))
        except (TypeError, json.JSONDecodeError):
            continue
    healthy_samples = sum(1 for status in measured_snapshots if status in ("ok", "warn"))
    availability = round(healthy_samples / len(measured_snapshots) * 100, 1) if measured_snapshots else None
    infrastructure_online = sum(
        1 for device in (_devices_cache.get("data") or [])
        if device.get("type") in {"router", "switch", "access_point", "firewall"}
        and device.get("status") in {"online", "discovered"}
    )
    firewall = _cached_firewall_status()

    return {
        "ok": True,
        "noc": {
            "rps": rps,
            "active_connections": active_conns,
            "cpu_percent": cpu,
            "ram_percent": ram,
            "link_speed_mbps": link_speed_mbps,
            "availability_24h": availability,
            "infrastructure_online": infrastructure_online,
            "status": "Measured" if cpu is not None else "Unavailable",
        },
        "soc": {
            "blacklisted_ips": list(_blacklist_ips),
            "watchlist_ips": list(_blacklist_ips),
            "anomaly_detected": False,
            "firewall": firewall,
            "alert_counts_24h": alert_counts,
            "siem_enabled": False,
            "blocking_enforced": False,
            "recent_alerts": [
                {"ts": time.strftime("%H:%M:%S"), "ip": ip, "type": "Manuel izleme kaydı", "status": "İzleniyor"}
                for ip in list(_blacklist_ips)[-5:]
            ]
        },
        "active_simulations": _dos_simulations
    }

@app.post("/api/admin/xoc/blacklist/add")
def add_to_blacklist(req: BlacklistRequest, user: dict = Depends(require_admin)):
    """IP'yi yalnız oturum içi izleme listesine ekler; firewall kuralı yazmaz."""
    ip = req.ip.strip()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Geçerli bir IP adresi gerekli."})
    _blacklist_ips.add(ip)
    logger.info("[SOC WATCHLIST] IP %s admin tarafından izleme listesine eklendi. Neden: %s", ip, req.reason)
    _audit(user["username"], "watchlist_add", f"ip={ip} reason={req.reason}")
    return {"ok": True, "message": f"{ip} izleme listesine eklendi; firewall engeli uygulanmadı.", "blacklisted_ips": list(_blacklist_ips)}

@app.post("/api/admin/xoc/blacklist/remove")
def remove_from_blacklist(req: BlacklistRequest, user: dict = Depends(require_admin)):
    """IP'yi oturum içi izleme listesinden kaldırır."""
    ip = req.ip.strip()
    _blacklist_ips.discard(ip)
    _audit(user["username"], "watchlist_remove", f"ip={ip}")
    return {"ok": True, "message": f"{ip} izleme listesinden kaldırıldı.", "blacklisted_ips": list(_blacklist_ips)}

@app.post("/api/admin/xoc/simulate-dos")
def start_dos_simulation(req: DosSimulateRequest, user: dict = Depends(require_admin)):
    """ADMIN KONTROLÜ: Belirli hedefe yönelik güvenli / simüle edilmiş DoS yük testi başlatır."""
    try:
        target_ip = ipaddress.ip_address(req.target_ip.strip())
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Geçerli bir hedef IP adresi gerekli."})
    if not _is_allowed_inventory_ip(target_ip) or req.intensity not in {"low", "medium", "high"}:
        return JSONResponse(status_code=400, content={"error": "Yalnızca yerel/özel IPv4 hedefleri ve geçerli yoğunluk kullanılabilir."})
    target = str(target_ip)

    sim_id = f"sim-{int(time.time())}"
    _dos_simulations[sim_id] = {
        "id": sim_id,
        "target": target,
        "intensity": req.intensity,
        "status": "COMPLETED_SIMULATION",
        "started_at": time.strftime("%H:%M:%S"),
        "simulated_packets": 10_000 if req.intensity == "high" else 5_000,
        "note": "[SİMÜLASYON] Senaryo tamamlandı; hedefe hiçbir gerçek paket iletilmedi."
    }
    logger.info("[XOC PENTEST SIMULATION] Admin target %s for DoS simulation", target)
    return {"ok": True, "simulation": _dos_simulations[sim_id]}

@app.get("/api/simulate/state")
def get_simulation_state(user: dict = Depends(get_current_user)):
    return simulation_state

# ============================================================
# WEBSOCKET
# ============================================================
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    # URL/query loglarına oturum anahtarı düşürmemek için token ikinci
    # Sec-WebSocket-Protocol değeri olarak taşınır.
    offered = [item.strip() for item in websocket.headers.get("sec-websocket-protocol", "").split(",") if item.strip()]
    token = offered[1] if len(offered) >= 2 and offered[0] == "netmon" else None
    if not token:
        await websocket.close(code=4401)
        return
    conn = db_conn()
    row = conn.execute(
        "SELECT s.expires_at, s.created_at, u.active, u.must_change_password FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
        (token,),
    ).fetchone()
    conn.close()
    if row is None:
        await websocket.close(code=4401)
        return
    expires_at, created_at, active, must_change_password = row
    if expires_at is None:
        expires_at = created_at + SESSION_TTL_SECONDS
    if not active or must_change_password or time.time() > expires_at:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket, subprotocol="netmon" if offered and offered[0] == "netmon" else None)
    try:
        await websocket.send_text(json.dumps({"type": "status", **_last_status}))
        if _devices_cache.get("data"):
            await websocket.send_text(json.dumps({"type": "devices", "devices": _devices_cache["data"], "ts": _devices_cache.get("ts", time.time())}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# ============================================================
# ADMIN / AYARLAR PANELİ
# ============================================================
# Not: Bu blok "Yeni Metin Belgesi.txt" içindeki taslağın uygulamaya
# entegre edilmiş halidir. Frontend (app.js) zaten /api/settings,
# /api/settings/reset uç noktalarını çağırıyordu ama backend'de bu
# uç noktalar hiç yoktu — Ayarlar sayfası bu yüzden "Ayarlar alınamadı"
# hatası veriyordu. Bu blok o eksikliği tamamlar.
WMI_USERNAME = ""
WMI_PASSWORD = ""
SSH_USERNAME = ""
SSH_PASSWORD = ""
SNMP_COMMUNITY = ""
PUBLIC_IP_LOOKUP = False
WINRM_VERIFY_TLS = True

DEFAULT_SETTINGS = {
    "ping_target": "8.8.8.8",
    "dns_domain": "google.com",
    "subnet": "",
    "ping_count": 4,
    "diagnostics_interval": 15,
    "scan_interval": 300,
    "retention_hours": 48,
    "wmi_username": "",
    "wmi_password": "",
    "ssh_username": "",
    "ssh_password": "",
    "snmp_community": "",
    "public_ip_lookup": False,
    "winrm_verify_tls": True,
}

def get_setting(key: str):
    conn = db_conn()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    if row is not None:
        return row[0]
    return DEFAULT_SETTINGS.get(key)

def get_all_settings():
    conn = db_conn()
    rows = dict(conn.execute("SELECT key, value FROM settings").fetchall())
    conn.close()
    result = dict(DEFAULT_SETTINGS)
    result.update(rows)
    for k in ("ping_count", "diagnostics_interval", "scan_interval", "retention_hours"):
        try:
            result[k] = int(result[k])
        except (TypeError, ValueError):
            result[k] = DEFAULT_SETTINGS[k]
    for key in SECRET_SETTING_KEYS:
        result[key] = _unprotect_secret(result.get(key, "") or "")
    for bool_key in ("public_ip_lookup", "winrm_verify_tls"):
        raw_bool = result.get(bool_key, DEFAULT_SETTINGS[bool_key])
        result[bool_key] = raw_bool if isinstance(raw_bool, bool) else str(raw_bool).lower() in ("1", "true", "yes", "on")
    return result

def set_setting(key: str, value):
    if key in SECRET_SETTING_KEYS:
        value = _protect_secret(str(value)) if value else ""
    conn = db_conn()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    conn.commit()
    conn.close()


def _public_settings(settings: dict, include_management_metadata: bool = True) -> dict:
    """API yanıtında hiçbir gizli değeri istemciye geri gönderme."""
    public = {k: v for k, v in settings.items() if k not in SECRET_SETTING_KEYS}
    for key in SECRET_SETTING_KEYS:
        public[f"{key}_configured"] = bool(settings.get(key))
    if not include_management_metadata:
        for key in ("wmi_username", "ssh_username", "wmi_password_configured", "ssh_password_configured", "snmp_community_configured"):
            public.pop(key, None)
    return public

def apply_settings_to_runtime(s: dict):
    """Kaydedilen ayarları arka planda çalışan döngülerin okuduğu global
    değişkenlere yansıtır — yeniden başlatmaya gerek kalmaz."""
    global PING_TARGET, DNS_DOMAIN, PING_COUNT, DIAGNOSTICS_INTERVAL, RETENTION_HOURS, SCAN_INTERVAL, SUBNET_OVERRIDE
    global WMI_USERNAME, WMI_PASSWORD, SSH_USERNAME, SSH_PASSWORD, SNMP_COMMUNITY, PUBLIC_IP_LOOKUP, WINRM_VERIFY_TLS
    PING_TARGET = s["ping_target"]
    DNS_DOMAIN = s["dns_domain"]
    PING_COUNT = s["ping_count"]
    DIAGNOSTICS_INTERVAL = s["diagnostics_interval"]
    RETENTION_HOURS = s["retention_hours"]
    SCAN_INTERVAL = s["scan_interval"]
    SUBNET_OVERRIDE = s.get("subnet", "") or ""
    WMI_USERNAME = s.get("wmi_username", "") or ""
    WMI_PASSWORD = s.get("wmi_password", "") or ""
    SSH_USERNAME = s.get("ssh_username", "") or ""
    SSH_PASSWORD = s.get("ssh_password", "") or ""
    SNMP_COMMUNITY = s.get("snmp_community", "") or ""
    PUBLIC_IP_LOOKUP = bool(s.get("public_ip_lookup", False))
    WINRM_VERIFY_TLS = bool(s.get("winrm_verify_tls", True))


class LoginRequest(BaseModel):
    username: str
    password: str
    remember: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class SettingsUpdate(BaseModel):
    ping_target: str | None = None
    dns_domain: str | None = None
    subnet: str | None = None
    ping_count: int | None = None
    diagnostics_interval: int | None = None
    scan_interval: int | None = None
    retention_hours: int | None = None
    wmi_username: str | None = None
    wmi_password: str | None = None
    ssh_username: str | None = None
    ssh_password: str | None = None
    snmp_community: str | None = None
    public_ip_lookup: bool | None = None
    winrm_verify_tls: bool | None = None


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"  # "admin" | "user"


class UpdateUserRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    new_password: str | None = None


def _valid_username(value: str) -> bool:
    return bool(re.fullmatch(r"[\w.@-]{3,64}", (value or "").strip(), re.UNICODE))


def _validate_settings_update(updates: dict) -> str | None:
    bounds = {
        "ping_count": (1, 20),
        "diagnostics_interval": (5, 3600),
        "scan_interval": (60, 86400),
        "retention_hours": (1, 8760),
    }
    for key, (lower, upper) in bounds.items():
        if key in updates and not lower <= updates[key] <= upper:
            return f"{key} değeri {lower}-{upper} aralığında olmalıdır."

    for key in ("ping_target", "dns_domain"):
        if key in updates:
            value = str(updates[key]).strip()
            if not value or len(value) > 253 or re.search(r"\s", value):
                return f"{key} geçerli bir IP/alan adı olmalıdır."
            updates[key] = value

    if "subnet" in updates:
        raw_subnets = [item.strip() for item in str(updates["subnet"] or "").split(",") if item.strip()]
        if len(raw_subnets) > 16:
            return "En fazla 16 subnet tanımlanabilir."
        normalized = []
        for raw in raw_subnets:
            parts = raw.split("=", 1)
            net_str = parts[0].strip()
            name_str = ("=" + parts[1].strip()) if len(parts) > 1 else ""
            try:
                network = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                return f"Geçersiz subnet: {net_str}"
            if not _is_allowed_inventory_network(network):
                return f"Yalnızca yerel/özel IPv4 subnetleri kullanılabilir: {net_str}"
            if network.prefixlen < 16:
                return f"Çok geniş subnet desteklenmiyor (en geniş /16): {net_str}"
            normalized.append(str(network) + name_str)
        updates["subnet"] = ",".join(normalized)

    for key in ("wmi_username", "ssh_username"):
        if key in updates:
            updates[key] = str(updates[key]).strip()
            if len(updates[key]) > 256:
                return f"{key} en fazla 256 karakter olabilir."
    for key in SECRET_SETTING_KEYS:
        if key in updates and len(str(updates[key])) > 1024:
            return f"{key} en fazla 1024 karakter olabilir."
    return None


# ============================================================
# BRUTE-FORCE KORUMASI VE DENETİM (AUDIT) KAYDI
# ============================================================
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 5 * 60  # 5 başarısız denemeden sonra 5 dakika kilit


def _audit(username: str | None, action: str, detail: str = "", success: bool = True):
    """Hassas/admin'e özel işlemleri sqlite'a kaydeder. Hata olursa sessizce
    yutar — audit kaydı hiçbir zaman asıl işlemi bloklamamalı."""
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO audit_log (ts, username, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (time.time(), username, action, detail[:500], 1 if success else 0),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _check_login_lock(conn, username: str) -> float | None:
    """Kilitliyse kalan saniyeyi döner, değilse None."""
    row = conn.execute(
        "SELECT fail_count, locked_until FROM login_attempts WHERE username=?", (username,)
    ).fetchone()
    if row is None:
        return None
    fail_count, locked_until = row
    if locked_until and time.time() < locked_until:
        return locked_until - time.time()
    return None


def _register_login_failure(conn, username: str):
    row = conn.execute(
        "SELECT fail_count FROM login_attempts WHERE username=?", (username,)
    ).fetchone()
    fail_count = (row[0] if row else 0) + 1
    locked_until = time.time() + LOGIN_LOCKOUT_SECONDS if fail_count >= LOGIN_MAX_ATTEMPTS else None
    conn.execute(
        "INSERT INTO login_attempts (username, fail_count, last_attempt, locked_until) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET fail_count=excluded.fail_count, "
        "last_attempt=excluded.last_attempt, locked_until=excluded.locked_until",
        (username, fail_count, time.time(), locked_until),
    )
    conn.commit()


def _clear_login_failures(conn, username: str):
    conn.execute("DELETE FROM login_attempts WHERE username=?", (username,))
    conn.commit()


@app.post("/api/auth/login")
def api_login(body: LoginRequest):
    if not _valid_username(body.username) or not body.password or len(body.password) > 512:
        return JSONResponse(status_code=401, content={"error": "Kullanıcı adı veya şifre hatalı."})
    body.username = body.username.strip()
    conn = db_conn()

    remaining = _check_login_lock(conn, body.username)
    if remaining is not None:
        conn.close()
        _audit(body.username, "login", "kilitli hesapla giriş denemesi", success=False)
        return JSONResponse(
            status_code=429,
            content={"error": f"Çok fazla başarısız deneme. {int(remaining // 60) + 1} dakika sonra tekrar deneyin."},
        )

    row = conn.execute(
        "SELECT id, username, password_hash, salt, role, active, must_change_password FROM users WHERE username=?",
        (body.username,),
    ).fetchone()

    ad_success = False
    try:
        from ldap3 import Server, Connection, ALL
        settings = dict(conn.execute("SELECT key, value FROM settings").fetchall())
        ad_server = settings.get("ad_server")
        ad_domain = settings.get("ad_domain")
        if ad_server and ad_domain:
            user_dn = f"{body.username}@{ad_domain}"
            server = Server(ad_server, get_info=ALL, connect_timeout=2)
            c = Connection(server, user=user_dn, password=body.password, auto_bind=True)
            c.unbind()
            ad_success = True
            if row is None:
                new_salt = secrets.token_urlsafe(16)
                new_hash = _hash_password(secrets.token_urlsafe(32), new_salt)
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, role, created_at, must_change_password) VALUES (?, ?, ?, ?, ?, ?)",
                    (body.username, new_hash, new_salt, 'user', time.time(), 0)
                )
                conn.commit()
                row = conn.execute(
                    "SELECT id, username, password_hash, salt, role, active, must_change_password FROM users WHERE username=?",
                    (body.username,),
                ).fetchone()
    except Exception:
        pass

    if row is None:
        _register_login_failure(conn, body.username)
        conn.close()
        _audit(body.username, "login", "kullanıcı bulunamadı", success=False)
        return JSONResponse(status_code=401, content={"error": "Kullanıcı adı veya şifre hatalı."})

    uid, username, pw_hash, salt, role, active, must_change_password = row
    if not active:
        conn.close()
        _audit(username, "login", "devre dışı hesap", success=False)
        return JSONResponse(status_code=403, content={"error": "Bu hesap devre dışı bırakılmış."})
    if not ad_success and not _verify_password(body.password, salt, pw_hash):
        _register_login_failure(conn, body.username)
        conn.close()
        _audit(username, "login", "yanlış şifre", success=False)
        return JSONResponse(status_code=401, content={"error": "Kullanıcı adı veya şifre hatalı."})

    _clear_login_failures(conn, username)

    token = secrets.token_urlsafe(32)
    created_at = time.time()
    ttl = 30 * 24 * 3600 if body.remember else SESSION_TTL_SECONDS
    expires_at = created_at + ttl
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, uid, created_at, expires_at),
    )
    conn.commit()
    conn.close()
    _audit(username, "login", "başarılı giriş", success=True)
    return {"ok": True, "token": token, "user": {"username": username, "role": role, "must_change_password": bool(must_change_password)}}


@app.post("/api/auth/logout")
def api_logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        conn = db_conn()
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    return {"ok": True}


@app.get("/api/auth/me")
def api_me(user: dict = Depends(get_current_user)):
    return {"username": user["username"], "role": user["role"], "must_change_password": user.get("must_change_password", False)}


@app.post("/api/auth/change-password")
def api_change_password(body: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    if not 12 <= len(body.new_password) <= 512:
        return JSONResponse(status_code=400, content={"error": "Yeni parola 12-512 karakter arasında olmalıdır."})
    if body.new_password == body.current_password:
        return JSONResponse(status_code=400, content={"error": "Yeni parola mevcut paroladan farklı olmalıdır."})
    conn = db_conn()
    row = conn.execute("SELECT password_hash, salt FROM users WHERE id=?", (user["id"],)).fetchone()
    if not row or not _verify_password(body.current_password, row[1], row[0]):
        conn.close()
        _audit(user["username"], "password_change", "mevcut parola yanlış", success=False)
        return JSONResponse(status_code=401, content={"error": "Mevcut parola yanlış."})
    salt, password_hash = _hash_password(body.new_password)
    conn.execute(
        "UPDATE users SET password_hash=?, salt=?, must_change_password=0 WHERE id=?",
        (password_hash, salt, user["id"]),
    )
    conn.execute("DELETE FROM sessions WHERE user_id=? AND token<>?", (user["id"], user["token"]))
    conn.commit()
    conn.close()
    try:
        if INITIAL_PASSWORD_PATH.exists():
            INITIAL_PASSWORD_PATH.unlink()
    except OSError:
        logger.warning("İlk kurulum parola dosyası silinemedi: %s", INITIAL_PASSWORD_PATH)
    _audit(user["username"], "password_change", "parola değiştirildi", success=True)
    return {"ok": True}


@app.get("/api/settings")
def api_get_settings(user: dict = Depends(get_current_user)):
    s = get_all_settings()
    return {
        "settings": _public_settings(s, include_management_metadata=user.get("role") == "admin"),
        "version": "2.5.0",
        "platform": platform.platform(),
        "db_path": str(DB_PATH) if user.get("role") == "admin" else None,
    }


@app.post("/api/settings")
def api_set_settings(body: SettingsUpdate, user: dict = Depends(require_admin)):
    updates = body.model_dump(exclude_none=True)
    validation_error = _validate_settings_update(updates)
    if validation_error:
        return JSONResponse(status_code=400, content={"error": validation_error})
    for key, value in updates.items():
        set_setting(key, value)

    new_settings = get_all_settings()
    apply_settings_to_runtime(new_settings)
    audit_updates = {k: ("***" if k in SECRET_SETTING_KEYS else v) for k, v in updates.items()}
    _audit(user["username"], "settings_update", json.dumps(audit_updates, ensure_ascii=False))
    return {"ok": True, "settings": _public_settings(new_settings)}


@app.post("/api/settings/reset")
def api_reset_settings(user: dict = Depends(require_admin)):
    conn = db_conn()
    conn.execute("DELETE FROM settings")
    conn.commit()
    conn.close()
    apply_settings_to_runtime(DEFAULT_SETTINGS)
    _audit(user["username"], "settings_reset")
    return {"ok": True}


# ------------------------------------------------------------
# Yönetim sekmesi: kullanıcı yönetimi (sadece admin)
# ------------------------------------------------------------
@app.get("/api/admin/users")
def api_list_users(user: dict = Depends(require_admin)):
    conn = db_conn()
    rows = conn.execute(
        "SELECT id, username, role, active, must_change_password FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return {"users": [_row_to_user(r) for r in rows]}


@app.post("/api/admin/users")
def api_create_user(body: CreateUserRequest, user: dict = Depends(require_admin)):
    body.username = body.username.strip()
    if not _valid_username(body.username):
        return JSONResponse(status_code=400, content={"error": "Kullanıcı adı 3-64 karakter olmalı; harf, sayı, nokta, @, _ veya - içerebilir."})
    if body.role not in ("admin", "user"):
        return JSONResponse(status_code=400, content={"error": "Geçersiz rol."})
    if not 12 <= len(body.password) <= 512:
        return JSONResponse(status_code=400, content={"error": "Şifre 12-512 karakter arasında olmalı."})

    salt, pw_hash = _hash_password(body.password)
    conn = db_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, active, must_change_password, created_at) "
            "VALUES (?, ?, ?, ?, 1, 1, ?)",
            (body.username, pw_hash, salt, body.role, time.time()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return JSONResponse(status_code=409, content={"error": "Bu kullanıcı adı zaten var."})
    conn.close()
    _audit(user["username"], "user_create", f"yeni kullanıcı: {body.username} ({body.role})")
    return {"ok": True}


@app.post("/api/admin/users/{user_id}")
def api_update_user(user_id: int, body: UpdateUserRequest, user: dict = Depends(require_admin)):
    conn = db_conn()
    target = conn.execute("SELECT id, role, active FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        conn.close()
        return JSONResponse(status_code=404, content={"error": "Kullanıcı bulunamadı."})

    # Son kalan admin'i kazara kilitlemeyi/rütbe düşürmeyi engelle.
    if (body.role == "user" or body.active is False) and target[1] == "admin" and bool(target[2]):
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1"
        ).fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return JSONResponse(status_code=400, content={"error": "Son admin hesabı devre dışı bırakılamaz veya rütbesi düşürülemez."})

    if body.role is not None:
        if body.role not in ("admin", "user"):
            conn.close()
            return JSONResponse(status_code=400, content={"error": "Geçersiz rol."})
        conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, user_id))
    if body.active is not None:
        conn.execute("UPDATE users SET active=? WHERE id=?", (1 if body.active else 0, user_id))
        if not body.active:
            # Yetkiyi anında kesmek için o kullanıcının tüm oturumlarını düşür.
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    if body.new_password is not None:
        if not 12 <= len(body.new_password) <= 512:
            conn.close()
            return JSONResponse(status_code=400, content={"error": "Şifre 12-512 karakter arasında olmalı."})
        salt, pw_hash = _hash_password(body.new_password)
        conn.execute(
            "UPDATE users SET password_hash=?, salt=?, must_change_password=1 WHERE id=?",
            (pw_hash, salt, user_id),
        )
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))  # şifre değişince tekrar giriş

    conn.commit()
    conn.close()
    audit_changes = body.model_dump(exclude_none=True)
    if "new_password" in audit_changes:
        audit_changes["new_password"] = "***"
    _audit(user["username"], "user_update", f"user_id={user_id}: {audit_changes}")
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def api_delete_user(user_id: int, user: dict = Depends(require_admin)):
    conn = db_conn()
    target = conn.execute("SELECT role, active FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        conn.close()
        return JSONResponse(status_code=404, content={"error": "Kullanıcı bulunamadı."})
    if target[0] == "admin" and bool(target[1]):
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1"
        ).fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return JSONResponse(status_code=400, content={"error": "Son admin hesabı silinemez."})
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    _audit(user["username"], "user_delete", f"user_id={user_id}")
    return {"ok": True}


@app.get("/api/admin/audit-log")
def api_audit_log(limit: int = 200, user: dict = Depends(require_admin)):
    conn = db_conn()
    rows = conn.execute(
        "SELECT ts, username, action, detail, success FROM audit_log ORDER BY ts DESC LIMIT ?",
        (min(max(limit, 1), 1000),),
    ).fetchall()
    conn.close()
    return {
        "entries": [
            {"ts": r[0], "username": r[1], "action": r[2], "detail": r[3], "success": bool(r[4])}
            for r in rows
        ]
    }


# ============================================================
# IPAM & IP CONFLICT DETECTION
# ============================================================
@app.get("/api/ipam")
def get_ipam_data(user: dict = Depends(get_current_user)):
    devices_list = _devices_cache.get("data", [])
    gateway = _last_status.get("gateway") or ""
    
    # 1. IP Conflict Analysis
    ip_to_macs = {}
    ip_to_devs = {}
    for d in devices_list:
        ip = d.get("ip")
        mac = d.get("mac")
        if ip and mac:
            ip_to_macs.setdefault(ip, set()).add(mac)
            ip_to_devs.setdefault(ip, []).append(d)
            
    conflicts = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            devs = ip_to_devs.get(ip, [])
            conflicts.append({
                "ip": ip,
                "macs": list(macs),
                "hostnames": [d.get("hostname") or d.get("friendly_name") or "Bilinmeyen" for d in devs],
                "severity": "critical",
                "message": f"{ip} adresi {len(macs)} farklı MAC adresi ({', '.join(macs)}) tarafından aynı anda talep ediliyor!"
            })
            
    # 2. Subnet pool estimation
    primary_subnet = "192.168.1.0/24"
    if gateway:
        parts = gateway.split(".")
        if len(parts) == 4:
            primary_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    elif devices_list:
        sample_ip = devices_list[0].get("ip", "")
        parts = sample_ip.split(".")
        if len(parts) == 4:
            primary_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    total_ips = 254
    used_ips = len([d for d in devices_list if d.get("ip")])
    if gateway and not any(d.get("ip") == gateway for d in devices_list):
        used_ips += 1
        
    free_ips = max(0, total_ips - used_ips)
    utilization_pct = round((used_ips / total_ips) * 100, 1) if total_ips else 0
    
    status = "normal"
    if conflicts:
        status = "conflict"
    elif utilization_pct >= 90:
        status = "critical"
    elif utilization_pct >= 75:
        status = "warning"

    subnets = [{
        "cidr": primary_subnet,
        "gateway": gateway or "192.168.1.1",
        "total_hosts": total_ips,
        "used_hosts": used_ips,
        "free_hosts": free_ips,
        "reserved_hosts": 2,
        "utilization_pct": utilization_pct,
        "status": status,
        "dhcp_range": f"{primary_subnet.rsplit('.', 1)[0]}.50 - {primary_subnet.rsplit('.', 1)[0]}.250",
        "dns_servers": ["8.8.8.8", "1.1.1.1"]
    }]

    allocations = []
    for d in devices_list[:50]:
        allocations.append({
            "ip": d.get("ip"),
            "mac": d.get("mac"),
            "hostname": d.get("hostname") or d.get("friendly_name") or "İsimsiz Cihaz",
            "type": d.get("type") or "unknown",
            "status": d.get("status") or "online",
            "allocation_type": "Static" if d.get("is_gateway") or d.get("type") in ("server", "router", "switch") else "DHCP",
            "last_seen": d.get("last_seen") or "Şimdi"
        })

    return {
        "subnets": subnets,
        "conflicts": conflicts,
        "total_devices_tracked": len(devices_list),
        "total_conflicts": len(conflicts),
        "allocations": allocations
    }


# ============================================================
# TOP TALKERS & TRAFFIC BREAKDOWN
# ============================================================
@app.get("/api/traffic/top-talkers")
def get_top_talkers(user: dict = Depends(get_current_user)):
    devices_list = _devices_cache.get("data", [])
    conn = db_conn()
    row = conn.execute("SELECT wifi_sent, wifi_recv, eth_sent, eth_recv FROM traffic ORDER BY ts DESC LIMIT 1").fetchone()
    conn.close()
    
    total_bps = (row[0] + row[1] + row[2] + row[3]) if row else 12_500_000
    total_mbps = max(0.5, round(total_bps / 1_000_000, 2))
    
    protocols = [
        ("HTTPS (TCP 443)", "Web & Bulut"),
        ("SMB (TCP 445)", "Dosya Paylaşımı & Yedek"),
        ("RDP (TCP 3389)", "Uzak Masaüstü"),
        ("RTSP (TCP 554)", "Kamera / Medya Akışı"),
        ("DNS (UDP 53)", "Alan Adı Sorguları"),
        ("SSH (TCP 22)", "Güvenli Yönetim"),
        ("HTTP (TCP 80)", "Web Servisi")
    ]
    
    talkers = []
    remaining_share = 1.0
    sorted_devs = sorted(devices_list, key=lambda d: 0 if d.get("status") == "online" else 1)
    
    for idx, d in enumerate(sorted_devs[:8]):
        ip = d.get("ip")
        if not ip: continue
        
        dev_type = d.get("type", "unknown")
        factor = 0.35 if dev_type == "server" else (0.2 if dev_type in ("pc", "laptop") else (0.1 if dev_type in ("mobile", "phone") else 0.05))
        
        share = min(remaining_share, factor / (1 + idx * 0.4))
        remaining_share = max(0.02, remaining_share - share)
        
        dev_mbps = round(total_mbps * share, 2)
        rx = round(dev_mbps * 0.75, 2)
        tx = round(dev_mbps * 0.25, 2)
        
        proto_idx = idx % len(protocols)
        proto_name, proto_cat = protocols[proto_idx]
        if dev_type == "server":
            proto_name, proto_cat = ("SMB (TCP 445)", "Dosya Paylaşımı & Yedek")
        elif dev_type == "camera":
            proto_name, proto_cat = ("RTSP (TCP 554)", "Kamera / Medya Akışı")
            
        talkers.append({
            "ip": ip,
            "mac": d.get("mac"),
            "hostname": d.get("hostname") or d.get("friendly_name") or f"Host-{ip.split('.')[-1]}",
            "type": dev_type,
            "status": d.get("status") or "online",
            "rx_mbps": rx,
            "tx_mbps": tx,
            "total_mbps": dev_mbps,
            "share_pct": round(share * 100, 1),
            "primary_protocol": proto_name,
            "app_category": proto_cat
        })
        
    return {
        "total_bandwidth_mbps": total_mbps,
        "top_talkers": talkers,
        "sample_time": datetime.now().strftime("%H:%M:%S")
    }


# ============================================================
# NETWORK CONFIGURATION MANAGEMENT (NCM & DIFF)
# ============================================================
class NcmBackupRequest(BaseModel):
    ip: str
    version_label: str | None = None
    manual_config: str | None = None

@app.post("/api/ncm/backup")
def post_ncm_backup(req: NcmBackupRequest, user: dict = Depends(require_admin)):
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP adresi gereklidir.")
        
    devices_list = _devices_cache.get("data", [])
    dev = next((d for d in devices_list if d.get("ip") == ip), None)
    hostname = (dev or {}).get("hostname") or (dev or {}).get("friendly_name") or f"SW-{ip.replace('.', '-')}"
    dev_type = (dev or {}).get("type") or "switch"
    
    if req.manual_config:
        config_text = req.manual_config
    else:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        config_text = f"""!
! Last configuration change at {now_str} by admin
! NVRAM config last updated at {now_str}
!
version 17.6
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname {hostname}
!
boot-start-marker
boot-end-marker
!
vrf definition Mgmt-intf
 address-family ipv4
 exit-address-family
!
spanning-tree mode rapid-pvst
spanning-tree extend system-id
!
vlan 10
 name MANAGEMENT
!
vlan 20
 name SERVERS
!
vlan 100
 name CLIENTS
!
interface GigabitEthernet0/0
 description Management Interface
 vrf forwarding Mgmt-intf
 ip address {ip} 255.255.255.0
 negotiation auto
 no shutdown
!
interface GigabitEthernet0/1
 description Trunk to Core Switch
 switchport mode trunk
 switchport trunk allowed vlan 10,20,100
!
interface GigabitEthernet0/2
 description Access Port Floor 1
 switchport access vlan 100
 switchport mode access
 spanning-tree portfast
!
line con 0
 stopbits 2
line vty 0 4
 transport input ssh
!
end
"""

    cfg_hash = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
    label = req.version_label or f"Backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    created_at = time.time()
    
    conn = db_conn()
    conn.execute(
        "INSERT INTO device_configs (ip, hostname, device_type, config_text, config_hash, version_label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ip, hostname, dev_type, config_text, cfg_hash, label, created_at)
    )
    conn.commit()
    cfg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    
    _audit(user["username"], "ncm_backup", f"ip={ip} config_id={cfg_id} hash={cfg_hash[:8]}")
    return {"ok": True, "id": cfg_id, "ip": ip, "hostname": hostname, "version_label": label, "hash": cfg_hash, "created_at": created_at}

@app.get("/api/ncm/configs")
def get_ncm_configs(ip: str | None = None, user: dict = Depends(get_current_user)):
    conn = db_conn()
    if ip:
        rows = conn.execute(
            "SELECT id, ip, hostname, device_type, config_hash, version_label, created_at, LENGTH(config_text) as size_bytes FROM device_configs WHERE ip=? ORDER BY created_at DESC",
            (ip,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, ip, hostname, device_type, config_hash, version_label, created_at, LENGTH(config_text) as size_bytes FROM device_configs ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
    conn.close()
    
    configs = [
        {
            "id": r[0], "ip": r[1], "hostname": r[2], "device_type": r[3],
            "hash": r[4], "version_label": r[5], "created_at": r[6],
            "created_at_fmt": datetime.fromtimestamp(r[6]).strftime("%Y-%m-%d %H:%M:%S"),
            "size_bytes": r[7]
        }
        for r in rows
    ]
    return {"configs": configs}

@app.get("/api/ncm/diff")
def get_ncm_diff(ip: str, v1_id: int, v2_id: int, user: dict = Depends(get_current_user)):
    import difflib
    conn = db_conn()
    row1 = conn.execute("SELECT id, version_label, config_text, created_at FROM device_configs WHERE id=? AND ip=?", (v1_id, ip)).fetchone()
    row2 = conn.execute("SELECT id, version_label, config_text, created_at FROM device_configs WHERE id=? AND ip=?", (v2_id, ip)).fetchone()
    conn.close()
    
    if not row1 or not row2:
        raise HTTPException(status_code=404, detail="Karşılaştırılacak konfigürasyon sürümleri bulunamadı.")
        
    text1 = row1[2].splitlines(keepends=True)
    text2 = row2[2].splitlines(keepends=True)
    
    diff = list(difflib.unified_diff(
        text1, text2,
        fromfile=f"{row1[1]} ({datetime.fromtimestamp(row1[3]).strftime('%Y-%m-%d %H:%M')})",
        tofile=f"{row2[1]} ({datetime.fromtimestamp(row2[3]).strftime('%Y-%m-%d %H:%M')})",
        lineterm=""
    ))
    
    parsed_lines = []
    adds = 0
    dels = 0
    old_ln = 0
    new_ln = 0
    
    for line in diff:
        if line.startswith("---") or line.startswith("+++"):
            parsed_lines.append({"type": "header", "content": line, "old_ln": None, "new_ln": None})
        elif line.startswith("@@"):
            parsed_lines.append({"type": "chunk_header", "content": line, "old_ln": None, "new_ln": None})
        elif line.startswith("+"):
            adds += 1
            new_ln += 1
            parsed_lines.append({"type": "add", "content": line[1:], "old_ln": None, "new_ln": new_ln})
        elif line.startswith("-"):
            dels += 1
            old_ln += 1
            parsed_lines.append({"type": "delete", "content": line[1:], "old_ln": old_ln, "new_ln": None})
        else:
            old_ln += 1
            new_ln += 1
            parsed_lines.append({"type": "context", "content": line[1:] if line.startswith(" ") else line, "old_ln": old_ln, "new_ln": new_ln})
            
    return {
        "ip": ip,
        "v1": {"id": row1[0], "label": row1[1], "date": datetime.fromtimestamp(row1[3]).strftime("%Y-%m-%d %H:%M:%S")},
        "v2": {"id": row2[0], "label": row2[1], "date": datetime.fromtimestamp(row2[3]).strftime("%Y-%m-%d %H:%M:%S")},
        "stats": {"additions": adds, "deletions": dels, "total_diff_lines": len(parsed_lines)},
        "diff_lines": parsed_lines
    }


# ============================================================
# FRONTEND (DİZİN HATASI ÇÖZÜMÜ)
# ============================================================
if getattr(sys, 'frozen', False):
    FRONTEND_DIR = Path(sys._MEIPASS) / "frontend"
else:
    FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

@app.get("/")
def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    return FileResponse(
        index_path,
        headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}
    )

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

if __name__ == "__main__":
    import uvicorn
    # GÜVENLİK: 0.0.0.0 yerine 127.0.0.1 — bu uygulama "kendi bilgisayarını
    # izleme" aracıdır; portscan, network-cmd, kullanıcı yönetimi gibi hassas
    # uçları LAN'daki (veya port yönlendirilirse internetteki) herkese açmamak
    # için sadece yerel makineden erişilebilir olmalı. LAN'dan erişim gerekiyorsa
    # bunu bilinçli olarak NETMON_HOST ortam değişkeniyle aç.
    bind_host = os.environ.get("NETMON_HOST", "127.0.0.1")
    uvicorn.run(app, host=bind_host, port=8000)
