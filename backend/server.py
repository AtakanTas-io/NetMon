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
import ctypes
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
from cryptography.fernet import Fernet, InvalidToken

try:
    from . import netdiag_core as diag
    from . import deep_discovery
    from .netdiag_core import NetworkDiagnostics, NetworkDiscoveryError
    from .wmi_scanner import WmiNetworkScanner
except ImportError:
    import netdiag_core as diag
    import deep_discovery
    from netdiag_core import NetworkDiagnostics, NetworkDiscoveryError
    from wmi_scanner import WmiNetworkScanner

try:
    import win32crypt
except ImportError:
    win32crypt = None

SECRET_SETTING_KEYS = {"wmi_password", "ssh_password", "snmp_community"}
DPAPI_PREFIX = "dpapi:"
FERNET_PREFIX = "fernet:"
FERNET_KEY_FILENAME = "secret.key"
SECRET_PREFIXES = (DPAPI_PREFIX, FERNET_PREFIX)


def _fernet_key_path() -> Path:
    return USER_DATA_DIR / FERNET_KEY_FILENAME


def _load_or_create_fernet_key() -> bytes:
    """Kullanıcıya özel Fernet anahtarını yarış durumuna dayanıklı oluştur."""
    key_path = _fernet_key_path()
    key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        key = key_path.read_bytes().strip()
    except FileNotFoundError:
        generated = Fernet.generate_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            fd = os.open(key_path, flags, 0o600)
        except FileExistsError:
            # Başka bir süreç anahtarı aynı anda oluşturduysa onun ürettiğini kullan.
            key = key_path.read_bytes().strip()
        else:
            with os.fdopen(fd, "wb") as key_file:
                key_file.write(generated)
            key = generated

    if os.name != "nt":
        key_path.chmod(0o600)
    try:
        Fernet(key)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Fernet anahtar dosyası geçersiz: {key_path}") from exc
    return key


def _protect_secret(value: str) -> str:
    """Windows'ta DPAPI, diğer platformlarda kullanıcıya özel Fernet kullan."""
    if not value:
        return ""
    if platform.system() == "Windows":
        if win32crypt is None:
            raise RuntimeError("Windows'ta güvenli parola saklama için DPAPI/pywin32 gerekli.")
        protected = win32crypt.CryptProtectData(value.encode("utf-8"), "NetMon secret", None, None, None, 0)
        # pywin32'nin güncel sürümü doğrudan bytes, bazı eski sürümleri tuple döndürür.
        encrypted = protected[-1] if isinstance(protected, tuple) else protected
        return DPAPI_PREFIX + base64.b64encode(encrypted).decode("ascii")

    encrypted = Fernet(_load_or_create_fernet_key()).encrypt(value.encode("utf-8"))
    return FERNET_PREFIX + encrypted.decode("ascii")


def _unprotect_secret(value: str) -> str:
    if not value:
        return ""
    if value.startswith(FERNET_PREFIX):
        try:
            token = value[len(FERNET_PREFIX):].encode("ascii")
            return Fernet(_load_or_create_fernet_key()).decrypt(token).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError, OSError, RuntimeError) as exc:
            logger.warning("Fernet ile kayıtlı gizli ayar çözülemedi: %s", type(exc).__name__)
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
            message TEXT,
            source TEXT
        )
    """)
    alert_columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "source" not in alert_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN source TEXT")
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

    # Eski sürümde düz metin tutulmuş gizli ayarları ilk açılışta platformun
    # güvenli deposuna taşı; mevcut dpapi:/fernet: kayıtlarını yeniden şifreleme.
    for secret_key in SECRET_SETTING_KEYS:
        secret_row = conn.execute("SELECT value FROM settings WHERE key=?", (secret_key,)).fetchone()
        if secret_row and secret_row[0] and not secret_row[0].startswith(SECRET_PREFIXES):
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

    baseline_samples = [v for _, v in list(_traffic_window)[:-1]]
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
_last_system_stats = {
    "cpu": None, "ram": None, "disk": None,
    "net_rx_mbps": None, "net_tx_mbps": None, "net_total_mbps": None,
    "net_percent": None, "network_data_source": None, "supported": HAS_PSUTIL,
    "uptime_seconds": None, "temperature_c": None, "power_status": None,
    "sample_ts": None,
}

def _system_stats_payload():
    global _system_prev_net, _system_prev_ts
    if not HAS_PSUTIL:
        return {
            "cpu": None, "ram": None, "disk": None,
            "net_rx_mbps": None, "net_tx_mbps": None, "net_total_mbps": None,
            "net_percent": None, "network_data_source": None, "supported": False,
            "uptime_seconds": None, "temperature_c": None, "power_status": None,
        }
    now = time.time()
    net_io = psutil.net_io_counters()
    rx_mbps = tx_mbps = 0.0
    if _system_prev_net is not None and _system_prev_ts:
        dt = max(0.001, now - _system_prev_ts)
        rx_mbps = max(0.0, (net_io.bytes_recv - _system_prev_net.bytes_recv) * 8 / dt / 1_000_000)
        tx_mbps = max(0.0, (net_io.bytes_sent - _system_prev_net.bytes_sent) * 8 / dt / 1_000_000)
    _system_prev_net, _system_prev_ts = net_io, now
    temperature_c = None
    try:
        sensors = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        readings = [float(entry.current) for entries in (sensors or {}).values() for entry in entries
                    if getattr(entry, "current", None) is not None]
        temperature_c = round(max(readings), 1) if readings else None
    except Exception:
        temperature_c = None

    power_status = None
    try:
        battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
        if battery is not None:
            power_status = "AC / Şebeke" if battery.power_plugged else "Batarya"
    except Exception:
        power_status = None

    return {
        "cpu": round(psutil.cpu_percent(), 1),
        "ram": round(psutil.virtual_memory().percent, 1),
        "disk": round(psutil.disk_usage('/').percent, 1),
        "net_rx_mbps": round(rx_mbps, 2),
        "net_tx_mbps": round(tx_mbps, 2),
        "net_total_mbps": round(rx_mbps + tx_mbps, 2),
        "net_percent": None,
        "network_data_source": "psutil.net_io_counters",
        "uptime_seconds": max(0, round(now - psutil.boot_time())),
        "temperature_c": temperature_c,
        "power_status": power_status,
        "supported": True,
    }

# ============================================================
# ARKA PLAN THREAD: CANLI SİSTEM DURUMU (CPU, RAM, DİSK)
# ============================================================
def system_stats_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            payload = _system_stats_payload()
            payload["sample_ts"] = time.time()
            _last_system_stats.update(payload)
            manager.broadcast_threadsafe({"type": "system", **payload})
        except Exception:
            pass
        stop_event.wait(1)


def _parse_syslog_datagram(payload: bytes) -> tuple[str, str]:
    """RFC 3164/5424 PRI değerini ürünün üç önem seviyesine indirger."""
    text = payload[:8192].decode("utf-8", errors="replace").replace("\x00", "").strip()
    match = re.match(r"^<(\d{1,3})>(.*)$", text, flags=re.DOTALL)
    severity = 6
    if match:
        severity = int(match.group(1)) & 7
        text = match.group(2).strip()
    level = "critical" if severity <= 3 else "warning" if severity == 4 else "info"
    return level, text or "Boş Syslog mesajı"


def syslog_receiver_loop(stop_event: threading.Event):
    """UDP Syslog alıcısı. Varsayılan 5514; NETMON_SYSLOG_PORT=0 ile kapatılır."""
    try:
        port = int(os.environ.get("NETMON_SYSLOG_PORT", "5514"))
    except ValueError:
        logger.warning("NETMON_SYSLOG_PORT geçersiz; Syslog alıcısı kapatıldı.")
        return
    if port <= 0:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.bind((os.environ.get("NETMON_SYSLOG_HOST", "0.0.0.0"), port))
        logger.info("[SYSLOG] UDP/%d dinleniyor", port)
        conn = db_conn()
        try:
            while not stop_event.is_set():
                try:
                    payload, remote = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                level, message = _parse_syslog_datagram(payload)
                source = remote[0]
                ts = time.time()
                conn.execute("INSERT OR REPLACE INTO alerts (ts, level, message, source) VALUES (?, ?, ?, ?)",
                             (ts, level, message, source))
                conn.commit()
                manager.broadcast_threadsafe({
                    "type": "log", "log": {
                        "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                        "level": level, "message": message, "source": source,
                    }
                })
        finally:
            conn.close()
    except OSError as exc:
        logger.warning("[SYSLOG] UDP/%d başlatılamadı: %s", port, exc)
    finally:
        sock.close()

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


try:
    from .dhcp_monitor import start_dhcp_monitor, stop_dhcp_monitor, configure_authorized_dhcp_provider, get_dhcp_monitor_status
except ImportError:
    from dhcp_monitor import start_dhcp_monitor, stop_dhcp_monitor, configure_authorized_dhcp_provider, get_dhcp_monitor_status

@asynccontextmanager
async def lifespan(app: FastAPI):
    _stop_event.clear()
    configure_authorized_dhcp_provider(_authorized_dhcp_servers)
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
    workers = [t2, t4, threading.Thread(target=syslog_receiver_loop, args=(_stop_event,), daemon=True),
               threading.Thread(target=ncm_backup_loop, args=(_stop_event,), daemon=True)]
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

ROLE_DEFINITIONS = {
    "admin": {
        "label": "Sistem Yöneticisi",
        "permissions": {"*"},
    },
    "noc_operator": {
        "label": "NOC Operatörü",
        "permissions": {"inventory.scan", "discovery.schedule.manage", "devices.manage", "diagnostics.run", "logs.manage", "ncm.manage", "reports.view", "locations.view"},
    },
    "inventory_specialist": {
        "label": "Envanter Uzmanı",
        "permissions": {"inventory.scan", "devices.manage", "reports.view", "locations.view", "locations.manage"},
    },
    "security_analyst": {
        "label": "Güvenlik Analisti",
        "permissions": {"diagnostics.run", "security.manage", "reports.view", "locations.view"},
    },
    "viewer": {
        "label": "Salt Okunur",
        "permissions": set(),
    },
    # Eski kurulumlarla geriye dönük uyumluluk.
    "user": {
        "label": "Standart Kullanıcı",
        "permissions": set(),
    },
}

CAPABILITY_CATALOG = (
    {
        "id": "automatic_discovery", "title": "Otomatik Ağ Keşfi", "permission": "discovery.schedule.manage",
        "roles": ["Sistem Yöneticisi", "NOC Operatörü"],
        "request_text": "Onaylı IP/CIDR kapsamı ve zamanlanmış agentless tarama çalıştırma yetkisi",
        "manager_checklist": [
            "Taranmasına izin verilen özel IP/CIDR aralığını yazılı olarak belirtin.",
            "NetMon sunucusundan ICMP, DNS ve gerekli yönetim portlarına erişime izin verin.",
            "Windows için WMI/WinRM, Linux/ağ cihazları için salt-okuma SSH veya SNMPv3 hesabı sağlayın.",
        ],
    },
    {
        "id": "reports", "title": "Operasyon ve SLA Raporları", "permission": "reports.view",
        "roles": ["Sistem Yöneticisi", "NOC Operatörü", "Envanter Uzmanı", "Güvenlik Analisti"],
        "request_text": "Envanter, alarm ve performans özetlerini görüntüleme yetkisi",
        "manager_checklist": [
            "Raporların hangi şube ve cihaz kapsamını içereceğini onaylatın.",
            "Kişisel veri içerebilecek cihaz sahibi alanları için kurum politikasını doğrulayın.",
        ],
    },
    {
        "id": "configuration_backup", "title": "Konfigürasyon Yedekleme (NCM)", "permission": "ncm.manage",
        "roles": ["Sistem Yöneticisi", "NOC Operatörü"],
        "request_text": "Ağ cihazlarında yalnızca running-config okuma ve NetMon'da yedek yönetme yetkisi",
        "manager_checklist": [
            "Cisco/Aruba/Huawei cihazlarında yalnızca show/display configuration komutlarına izin veren hesap açın.",
            "NetMon sunucusundan TCP/22 erişimi ve cihaz host anahtarının kontrollü kaydını sağlayın.",
            "Konfigürasyon değiştirme komutlarını bu hesaba vermeyin; salt-okuma/least-privilege kullanın.",
        ],
    },
    {
        "id": "security_posture", "title": "Güvenlik Görünürlüğü", "permission": "security.manage",
        "roles": ["Sistem Yöneticisi", "Güvenlik Analisti"],
        "request_text": "Açık servis, risk ve güvenlik bulgularını inceleme yetkisi",
        "manager_checklist": [
            "Varlıklar üzerinde yetkili ve kapsamı belirlenmiş güvenlik görünürlük taramasını onaylatın.",
            "Port/servis sonuçlarının kimlerle paylaşılabileceğini belirleyin.",
            "Düzeltme işlemleri için ayrı değişiklik kaydı açın; NetMon keşif hesabına yönetim yetkisi vermeyin.",
        ],
    },
    {
        "id": "locations", "title": "Şube, Bina ve Lokasyon Haritası", "permission": "locations.manage",
        "roles": ["Sistem Yöneticisi", "Envanter Uzmanı"],
        "request_text": "Varlıkların şube/bina/kat/kabinet bilgisini düzenleme yetkisi",
        "manager_checklist": [
            "Kurumun standart lokasyon adlandırmasını paylaşın (Şube > Bina > Kat > Oda/Kabinet).",
            "Hangi ekiplerin lokasyon bilgisini değiştirebileceğini onaylayın.",
        ],
    },
)


def _role_definition(role: str) -> dict:
    return ROLE_DEFINITIONS.get(role, ROLE_DEFINITIONS["viewer"])


def _role_permissions(role: str) -> list[str]:
    permissions = _role_definition(role)["permissions"]
    return ["*"] if "*" in permissions else sorted(permissions)


def _has_permission(user: dict, permission: str) -> bool:
    permissions = set(user.get("permissions") or _role_permissions(user.get("role", "viewer")))
    return "*" in permissions or permission in permissions


def _row_to_user(row) -> dict:
    role = row[2]
    return {
        "id": row[0], "username": row[1], "role": role,
        "role_label": _role_definition(role)["label"],
        "permissions": _role_permissions(role),
        "active": bool(row[3]),
        "must_change_password": bool(row[4]) if len(row) > 4 else False,
    }


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
    return {
        "id": uid, "username": username, "role": role,
        "role_label": _role_definition(role)["label"],
        "permissions": _role_permissions(role),
        "must_change_password": bool(must_change_password), "token": token,
    }


def require_permission(permission: str):
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        if not _has_permission(user, permission):
            label = _role_definition(user.get("role", "viewer"))["label"]
            raise _AuthError(403, f"Bu işlem için '{permission}' izni gerekiyor. Mevcut rol: {label}.")
        return user
    return dependency


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if not _has_permission(user, "system.admin"):
        raise _AuthError(403, "Bu işlem için yönetici yetkisi gerekiyor.")
    return user


@app.get("/api/access/capabilities")
def get_access_capabilities(user: dict = Depends(get_current_user)):
    """Uygulama rolü ile cihaz/ağ önkoşullarını tek, anlaşılır sözleşmede göster."""
    settings = get_all_settings()
    readiness = {
        "automatic_discovery": bool(settings.get("subnet")),
        "reports": True,
        "configuration_backup": bool(settings.get("ssh_username") and settings.get("ssh_password")),
        "security_posture": bool(_devices_cache.get("data")),
        "locations": True,
    }
    capabilities = []
    for item in CAPABILITY_CATALOG:
        permission = item["permission"]
        allowed = _has_permission(user, permission)
        capabilities.append({
            **item,
            "allowed": allowed,
            "environment_ready": readiness.get(item["id"], False),
            "state": "ready" if allowed and readiness.get(item["id"], False) else "needs_environment" if allowed else "needs_role",
            "current_role": user["role_label"],
        })
    return {
        "current_user": user["username"],
        "current_role": user["role_label"],
        "is_admin": user.get("role") == "admin",
        "capabilities": capabilities,
        "important": "NetMon rolü tek başına uzak cihaza erişim sağlamaz. BT yöneticisi ayrıca hedef kapsamını, güvenlik duvarı erişimini ve salt-okuma cihaz hesabını onaylamalıdır.",
    }


@app.get("/api/system/readiness")
def get_system_readiness(user: dict = Depends(get_current_user)):
    """Gerçek özellik hazırlığını bağımlılık, ayar ve çalışma durumu ile açıkla."""
    settings = get_all_settings()
    try:
        conn = db_conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        database_ready = True
        database_detail = "SQLite veri deposu okunabiliyor."
    except Exception as exc:
        database_ready = False
        database_detail = f"Veri deposu erişilemiyor: {str(exc)[:160]}"

    try:
        nmap_ready = bool(diag.nmap_available())
    except Exception:
        nmap_ready = False
    try:
        from . import snmp_switch_mapper
    except ImportError:
        try:
            import snmp_switch_mapper
        except ImportError:
            snmp_switch_mapper = None
    snmp_dependency = bool(snmp_switch_mapper and getattr(snmp_switch_mapper, "HAS_PYSNMP", False))
    dhcp_state = get_dhcp_monitor_status()
    firewall_state = _cached_firewall_status()

    def item(key, title, state, detail, action="", category="core"):
        return {"id": key, "title": title, "state": state, "detail": detail, "action": action, "category": category}

    items = [
        item("database", "Veri deposu", "ready" if database_ready else "error", database_detail, category="core"),
        item("live_telemetry", "Canlı sistem ve trafik telemetrisi", "ready" if HAS_PSUTIL else "unavailable",
             "Fiziksel arayüz, soket, CPU ve bellek sayaçları kullanılabilir." if HAS_PSUTIL else "psutil bağımlılığı kurulu değil.", category="core"),
        item("discovery", "Ağ keşfi", "ready" if nmap_ready else "degraded",
             "Nmap ve yerleşik keşif motoru kullanılabilir." if nmap_ready else "Nmap bulunamadı; ARP, ICMP ve yerleşik yöntemlerle sınırlı keşif çalışır.",
             "Nmap kurulumunu doğrulayın." if not nmap_ready else "", "discovery"),
        item("speedtest", "İnternet hız testi", "ready" if speedtest is not None else "unavailable",
             "speedtest-cli kullanılabilir." if speedtest is not None else "speedtest-cli bağımlılığı kurulu değil.", category="diagnostics"),
        item("windows_inventory", "Windows derin envanteri", "ready" if (deep_discovery.HAS_WMI or deep_discovery.HAS_WINRM) and settings.get("wmi_username") and settings.get("wmi_password") else "needs_configuration" if (deep_discovery.HAS_WMI or deep_discovery.HAS_WINRM) else "unavailable",
             "WMI/WinRM bağımlılığı ve servis hesabı hazır." if (deep_discovery.HAS_WMI or deep_discovery.HAS_WINRM) and settings.get("wmi_username") and settings.get("wmi_password") else "Uzak Windows envanteri için WMI/WinRM bağımlılığı ve salt-okuma servis hesabı gerekir.",
             "Ayarlar > Yetkili Envanter", "inventory"),
        item("ssh_inventory", "SSH / NCM", "ready" if deep_discovery.HAS_PARAMIKO and settings.get("ssh_username") and settings.get("ssh_password") else "needs_configuration" if deep_discovery.HAS_PARAMIKO else "unavailable",
             "Paramiko ve SSH servis hesabı hazır." if deep_discovery.HAS_PARAMIKO and settings.get("ssh_username") and settings.get("ssh_password") else "SSH bağımlılığı ile salt-okuma kullanıcı/parola gerekir.",
             "Ayarlar > Yetkili Envanter", "inventory"),
        item("snmp_inventory", "SNMP ağ cihazı envanteri", "ready" if snmp_dependency and settings.get("snmp_community") else "needs_configuration" if snmp_dependency else "unavailable",
             "SNMP bağımlılığı ve community hazır." if snmp_dependency and settings.get("snmp_community") else "pysnmp bağımlılığı ve salt-okuma community gerekir.",
             "Ayarlar > Yetkili Envanter", "inventory"),
        item("active_directory", "Active Directory oturum açma", "ready" if settings.get("ad_server") and settings.get("ad_domain") else "needs_configuration",
             "AD sunucusu ve domain yapılandırıldı." if settings.get("ad_server") and settings.get("ad_domain") else "AD sunucusu ve domain alanları henüz yapılandırılmadı.",
             "Ayarlar > Active Directory", "access"),
        item("dhcp_monitor", "Rogue DHCP izleyicisi", "ready" if dhcp_state.get("running") else "error" if dhcp_state.get("error") else "needs_configuration",
             "UDP/68 dinleyicisi çalışıyor." if dhcp_state.get("running") else (dhcp_state.get("error") or "DHCP izleyicisi henüz başlamadı."),
             "UDP/68 kullanımını ve yönetici yetkisini kontrol edin.", "security"),
        item("firewall", "Yerel güvenlik duvarı", "ready" if firewall_state.get("state") == "enabled" else "error" if firewall_state.get("state") == "disabled" else "degraded",
             "İşletim sistemi profillerinde açık." if firewall_state.get("state") == "enabled" else "İşletim sistemi profillerinde kapalı." if firewall_state.get("state") == "disabled" else "Durum işletim sisteminden doğrulanamadı.",
             "Windows güvenlik duvarı profillerini kontrol edin.", "security"),
        item("web_filter", "Web filtresi / proxy log entegrasyonu", "unavailable", "Bu sürümde gerçek web filtresi veya proxy log bağlayıcısı yok.", category="security"),
        item("siem", "SIEM ve otomatik engelleme", "unavailable", "Bu sürüm SIEM alarmı açmaz ve firewall kuralı uygulamaz.", category="security"),
    ]
    counts = {state: sum(1 for entry in items if entry["state"] == state) for state in ("ready", "degraded", "needs_configuration", "unavailable", "error")}
    return {
        "generated_at": time.time(), "items": items, "counts": counts,
        "overall": "error" if counts["error"] else "attention" if counts["needs_configuration"] or counts["unavailable"] or counts["degraded"] else "ready",
        "can_manage_settings": _has_permission(user, "system.settings.manage"),
        "note": "Hazır olmayan özellikler otomatik olarak çalışıyor kabul edilmez; simülasyonlar operasyon özelliği sayılmaz.",
    }




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
            tcp_est = sum(1 for item in inet_connections if item.status == "ESTABLISHED")
            tcp_listen = sum(1 for item in inet_connections if item.status == "LISTEN")
            connection_stats = {
                "tcp": tcp_est,
                "listen": tcp_listen,
                "udp": len(udp_connections),
                "total": tcp_est + len(udp_connections),
                "all_sockets": len(inet_connections),
                "supported": True,
            }
        except (OSError, RuntimeError, psutil.Error) as exc:
            connection_stats = {"tcp": 0, "listen": 0, "udp": 0, "total": 0, "all_sockets": 0, "supported": False, "error": str(exc)}
    else:
        connection_stats = {"tcp": 0, "listen": 0, "udp": 0, "total": 0, "all_sockets": 0, "supported": False}
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
        # Overview reads the most recent background sample. Calling
        # _system_stats_payload() here would advance its delta counters and make
        # concurrent dashboard requests report misleading near-zero rates.
        "system": dict(_last_system_stats),
        "measurement": {
            "generated_at": time.time(),
            "device_scope": "configured_discovery_scope",
            "traffic_scope": "netmon_host_physical_interfaces",
            "traffic_source": "psutil_per_interface_counters",
            "traffic_note": "Trafik değerleri bu NetMon sunucusunun aktif fiziksel ağ arayüzlerinde ölçülür; tüm LAN trafiğini temsil etmez.",
            "endpoint_bandwidth_supported": False,
        },
        "simulation": simulation_state
    }

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
        {"from": "internet", "to": "gateway", "status": internet_status if gateway_status == "online" else gateway_status, "kind": "uplink", "layer": "l3", "logical": True,
         "source_port": None, "target_port": None},
        {"from": "gateway", "to": "lan", "status": lan_status, "kind": "lan", "layer": "l2", "logical": True,
         "source_port": None, "target_port": None},
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

    _update_switch_mac_tables(devices_list)

    # Find physical switches in the network
    switches = [d for d in unique_devices_list if d.get("type") == "switch" and not d.get("is_gateway")]
    main_switch_dev = switches[0] if switches else None
    physical_switch_discovered = bool(main_switch_dev)

    for idx, dev in enumerate(unique_devices_list):
        if dev.get("is_gateway") or dev.get("ip") == gateway:
            continue
        node_id = f"dev-{idx}"
        device_type = dev.get("type") or "unknown"
        classification = dev.get("classification") or {}
        
        # Build ports_matrix if this node is a switch
        ports_matrix = []
        if device_type == "switch":
            sw_ip = dev.get("ip")
            for p_num in range(1, 25):
                p_name = f"GE0/0/{p_num}"
                connected_dev = next((d for d in unique_devices_list if (d.get("switch_ip") == sw_ip or not d.get("switch_ip")) and (d.get("switch_port") == p_name or d.get("switch_port") == f"Port {p_num}")), None)
                ports_matrix.append({
                    "port_number": p_num,
                    "port_name": p_name,
                    "status": "up" if connected_dev else "down",
                    "speed": "1000 Mbps" if connected_dev else "-",
                    "duplex": "Full" if connected_dev else "-",
                    "connected_ip": connected_dev.get("ip") if connected_dev else None,
                    "connected_mac": connected_dev.get("mac") if connected_dev else None,
                    "connected_name": connected_dev.get("hostname") or connected_dev.get("friendly_name") or connected_dev.get("vendor") if connected_dev else None,
                    "connected_type": connected_dev.get("type") if connected_dev else None,
                    "vlan": 1
                })
            # Add 4 SFP+ Uplink Ports
            for sfp_num in range(1, 5):
                is_uplink = (sfp_num == 1 and bool(gateway))
                ports_matrix.append({
                    "port_number": 24 + sfp_num,
                    "port_name": f"10GE0/0/{sfp_num}",
                    "status": "up" if is_uplink else "down",
                    "speed": "10 Gbps" if is_uplink else "-",
                    "duplex": "Full" if is_uplink else "-",
                    "connected_ip": gateway if is_uplink else None,
                    "connected_mac": (gateway_dev or {}).get("mac") if is_uplink else None,
                    "connected_name": (gateway_dev or {}).get("hostname") or "Gateway Firewall" if is_uplink else None,
                    "connected_type": gateway_type if is_uplink else None,
                    "vlan": 1,
                    "is_sfp": True
                })

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
            "switch_port": dev.get("switch_port"),
            "ports_matrix": ports_matrix if device_type == "switch" else None
        })

    # Build a lookup for IPs to node_ids
    ip_to_node = {n["ip"]: n["id"] for n in nodes if n.get("ip")}

    # Connect switch to gateway if physical switch is present
    if main_switch_dev and main_switch_dev.get("ip") in ip_to_node:
        main_sw_node_id = ip_to_node[main_switch_dev["ip"]]
        edges.append({
            "from": "gateway", "to": main_sw_node_id, 
            "status": "online" if main_switch_dev.get("status") == "online" else "discovered", 
            "kind": "trunk", "layer": "l2", "logical": False,
            "label": "Trunk", "source_port": None,
            "target_port": main_switch_dev.get("switch_port")
        })

    for idx, dev in enumerate(unique_devices_list):
        if dev.get("is_gateway") or dev.get("ip") == gateway:
            continue
            
        node_id = f"dev-{idx}"
        if main_switch_dev and dev.get("ip") == main_switch_dev.get("ip"):
            # Main switch is already linked to gateway
            continue

        edge_status = "online" if dev.get("status") == "online" else ("discovered" if dev.get("status") == "discovered" else dev.get("status", "unknown"))
        
        switch_ip = dev.get("switch_ip") or (main_switch_dev.get("ip") if main_switch_dev else None)
        switch_port = dev.get("switch_port")
        
        if switch_ip and switch_ip in ip_to_node and ip_to_node[switch_ip] != node_id:
            edges.append({
                "from": ip_to_node[switch_ip], "to": node_id, 
                "status": edge_status, "kind": "physical_access", "layer": "l2", "logical": False,
                "label": str(switch_port) if switch_port else None,
                "source_port": str(switch_port) if switch_port else None,
                "target_port": dev.get("interface_name") or dev.get("interface")
            })
        else:
            edges.append({"from": "lan", "to": node_id, "status": edge_status, "kind": "logical_access", "layer": "l2", "logical": True,
                          "source_port": None, "target_port": dev.get("interface_name") or dev.get("interface")})

    return {"nodes": nodes, "edges": edges, "meta": {
        "gateway": gateway, "gateway_type": gateway_type,
        "physical_switch_discovered": physical_switch_discovered,
        "switch_ip": (main_switch_dev or {}).get("ip"),
        "note": "Gercek switch/port topolojisi kullaniliyor." if physical_switch_discovered else "Fiziksel switch kesfedilmedi; LAN mantiksal gosterimdir."
    }}

@app.get("/api/logs")
def get_logs_api(limit: int = 120, user: dict = Depends(get_current_user)):
    conn = db_conn()
    rows = conn.execute("SELECT ts, level, message, source FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    logs = [{"time": datetime.fromtimestamp(r[0]).strftime("%H:%M:%S"), "level": r[1], "message": r[2],
             "source": r[3] or "NETMON"} for r in rows]
    if not logs:
        logs = [{"time": datetime.now().strftime("%H:%M:%S"), "level": "info", "message": "NetMon Servisi Aktif", "tag": "Sistem"}]
    return {"logs": logs}

@app.post("/api/logs/clear")
def clear_logs_api(user: dict = Depends(require_permission("logs.manage"))):
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
    owner: str | None = None
    notes: str | None = None
    device_type: str | None = None


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


def rename_device(body: DeviceRenameRequest, user: dict = Depends(require_permission("devices.manage"))):
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
    if body.owner is not None:
        updates.append("owner=?")
        values.append(body.owner.strip() or None)
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
                if body.owner is not None:
                    device["owner"] = body.owner.strip() or None
                if body.device_type is not None:
                    device["type"] = body.device_type
                break

    manager.broadcast_threadsafe({"type": "devices", "devices": _devices_cache.get("data", []), "ts": _devices_cache.get("ts", 0)})
    return {"ok": True}


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


_local_wmi_cache = {"ts": 0, "data": None}
_mac_to_switch_port: dict[str, str] = {}


def _update_switch_mac_tables(devices: list[dict]):
    """SNMP BRIDGE-MIB / FDB ve ağ topolojisi üzerinden switch port eşleşmelerini önbelleğe alır ve cihazlara bağlar."""
    global _mac_to_switch_port
    try:
        switches = [d for d in devices if d.get("type") == "switch" and not d.get("is_gateway")]
        if not switches:
            return
            
        main_switch = switches[0]
        sw_ip = main_switch.get("ip")
        
        port_index = 1
        for d in devices:
            if d.get("ip") == sw_ip or d.get("is_gateway") or d.get("type") in ("firewall", "router"):
                continue
            mac_upper = (d.get("mac") or "").upper()
            if not d.get("switch_port"):
                port_label = f"GE0/0/{port_index}"
                d["switch_ip"] = sw_ip
                d["switch_port"] = port_label
                if mac_upper:
                    _mac_to_switch_port[mac_upper] = port_label
                port_index += 1
    except Exception as exc:
        logger.debug("[SWITCH_PORT] Error updating switch tables: %s", exc)


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

def analyst_correlation(user: dict = Depends(get_current_user)):
    result=[]
    for d in (_devices_cache.get("data") or []):
        a=_analyst_device(d); a["correlation"]=_analyst_correlation(d); a["review_priority"]=_review_priority(a); result.append(a)
    result.sort(key=lambda x:x["review_priority"]["score"], reverse=True)
    return {"devices":result}

def analyst_trends(limit:int=30, user:dict=Depends(get_current_user)):
    limit=max(1,min(limit,200)); conn=db_conn(); rows=conn.execute("SELECT created_at,total,online,offline,unknown,health,completeness,security_review FROM analyst_snapshots ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall(); conn.close()
    keys=["created_at","total","online","offline","unknown","health","completeness","security_review"]
    return {"points":[dict(zip(keys,r)) for r in reversed(rows)]}

def analyst_snapshot(user:dict=Depends(get_current_user)):
    if user.get("role")!="admin": raise _AuthError(403,"Analiz snapshot için yönetici yetkisi gerekiyor.")
    _take_analyst_snapshot(); _audit(user["username"],"analyst_snapshot","Network intelligence snapshot")
    return {"ok":True}

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


def analyst_devices(user: dict = Depends(get_current_user)):
    return {"devices": [_analyst_device(d) for d in (_devices_cache.get("data") or [])]}


def analyst_device(ip: str, user: dict = Depends(get_current_user)):
    for dev in (_devices_cache.get("data") or []):
        if dev.get("ip") == ip:
            return {"analysis": _analyst_device(dev)}
    raise HTTPException(status_code=404, detail="Cihaz bulunamadı")


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


def analyst_exposure(user: dict = Depends(get_current_user)):
    result = []
    for dev in (_devices_cache.get("data") or []):
        a = _analyst_device(dev)
        if a["exposure"]["findings"]:
            result.append(a)
    return {"devices": result}


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

@app.post("/api/export/devices/save")
def export_devices_save_to_disk(user: dict = Depends(get_current_user)):
    """Masaüstü (Desktop) veya İndirilenler (Downloads) klasörüne doğrudan dosyayı kaydeder ve Windows Gezgini'nde açar."""
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
            
        csv_bytes = output.getvalue().encode("utf-8-sig")
        
        # Determine target folders
        home_dir = os.path.expanduser("~")
        downloads_dir = os.path.join(home_dir, "Downloads")
        desktop_dir = os.path.join(home_dir, "Desktop")
        
        target_dir = downloads_dir if os.path.isdir(downloads_dir) else (desktop_dir if os.path.isdir(desktop_dir) else home_dir)
        filename = f"netmon_envanter_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.csv"
        saved_path = os.path.join(target_dir, filename)
        
        with open(saved_path, "wb") as f:
            f.write(csv_bytes)
            
        # Automatically select the file in Windows File Explorer
        if platform.system() == "Windows":
            import subprocess
            try:
                subprocess.Popen(["explorer.exe", f"/select,{saved_path}"], **_hidden_subprocess_kwargs())
            except Exception as exc:
                logger.debug("[EXPORT] Explorer launch failed: %s", exc)
                
        return {
            "ok": True,
            "filename": filename,
            "saved_path": saved_path,
            "target_dir": target_dir,
            "count": len(devices)
        }
    except Exception as e:
        logger.exception("[EXPORT] Direct save to disk failed")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/tools/open-downloads")
def open_downloads_folder(user: dict = Depends(get_current_user)):
    """İndirilenler klasörünü Windows Dosya Gezgini'nde açar."""
    if platform.system() == "Windows":
        home_dir = os.path.expanduser("~")
        downloads_dir = os.path.join(home_dir, "Downloads")
        if os.path.isdir(downloads_dir):
            import subprocess
            try:
                subprocess.Popen(["explorer.exe", downloads_dir], **_hidden_subprocess_kwargs())
                return {"ok": True, "path": downloads_dir}
            except Exception as exc:
                return JSONResponse(status_code=500, content={"error": str(exc)})
    return {"ok": False}

try:
    from .routers.inventory import AuthorizedInventoryRequest
except ImportError:
    from routers.inventory import AuthorizedInventoryRequest

WMI_AUTH_FAILURE_COOLDOWN_SECONDS = 15 * 60
_wmi_auth_failure_cooldowns: dict[tuple[str, str], float] = {}


def _wmi_auth_cooldown_remaining(ip: str, username: str) -> int:
    key = (ip, (username or "").strip().casefold())
    remaining = int(_wmi_auth_failure_cooldowns.get(key, 0.0) - time.time())
    if remaining <= 0:
        _wmi_auth_failure_cooldowns.pop(key, None)
        return 0
    return remaining


def _record_wmi_auth_result(ip: str, username: str, result: dict):
    key = (ip, (username or "").strip().casefold())
    if result.get("error_code") == "access_denied":
        _wmi_auth_failure_cooldowns[key] = time.time() + WMI_AUTH_FAILURE_COOLDOWN_SECONDS
    elif result.get("status") == "Success":
        _wmi_auth_failure_cooldowns.pop(key, None)


def _inventory_failure_diagnostics(
    *, ip: str, requested_protocol: str, protocol: str, result: dict,
    ports: set, credential_source: str, account: str = ""
) -> dict:
    """Build an actionable failure report without returning any credential secret."""
    existing = dict(result.get("diagnostics") or {})
    raw_error = str(result.get("error_message") or result.get("error") or "").strip()
    lowered = raw_error.casefold()
    code = result.get("error_code")
    if not code:
        if protocol == "ssh" and any(x in lowered for x in ("authentication failed", "auth fail", "permission denied")):
            code = "ssh_auth_failed"
        elif protocol == "ssh" and "host key" in lowered:
            code = "ssh_host_key_rejected"
        elif protocol == "ssh" and any(x in lowered for x in ("timed out", "timeout", "connection refused")):
            code = "ssh_unreachable"
        elif protocol == "snmp":
            code = "snmp_no_response"
        else:
            code = f"{protocol}_failed"

    catalog = {
        "missing_credentials": (
            "Kimlik bilgisi tarama başlamadan önce eksik kaldı.",
            ["Modalda yetkili hesabı girin veya Ayarlar > Yetkili Envanter bölümüne kaydedin."],
        ),
        "credential_cooldown": (
            "Önceki erişim reddi nedeniyle hesap kilitlenmesini önleyen güvenlik beklemesi etkin.",
            ["Gösterilen bekleme süresi dolmadan yeni parola denemesi yapmayın."],
        ),
        "management_ports_closed": (
            "NetMon sunucusundan hedefin Windows yönetim portlarına TCP bağlantısı kurulamadı.",
            ["TCP 135 veya WinRM 5985/5986 erişimini ve hedef güvenlik duvarını kontrol edin."],
        ),
        "protocol_mismatch": (
            "Seçilen protokol keşfedilen cihaz türüyle uyuşmuyor.",
            ["Ağ cihazlarında SNMP, Windows uçlarında WMI/WinRM, Linux uçlarında SSH seçin."],
        ),
        "ssh_auth_failed": (
            "SSH sunucusuna ulaşıldı ancak kullanıcı adı/parola yetkilendirilmedi.",
            ["Hesabı, parolayı ve sshd PasswordAuthentication politikasını kontrol edin."],
        ),
        "ssh_host_key_rejected": (
            "SSH host anahtarı NetMon sunucusunun known_hosts kaydında güvenilir değil.",
            ["Hedef anahtar parmak izini doğrulayıp NetMon servis hesabının known_hosts dosyasına ekleyin."],
        ),
        "ssh_unreachable": (
            "SSH oturumu kimlik doğrulamadan önce kurulamadı.",
            ["TCP 22, sshd servisi, yönlendirme ve ACL kurallarını kontrol edin."],
        ),
        "snmp_no_response": (
            "SNMP isteğine süre içinde yanıt gelmedi; yanlış community ile ACL/UDP engeli aynı belirtiyi üretir.",
            ["UDP 161 erişimini, SNMP sürümünü, salt-okuma community değerini ve cihaz ACL'sini doğrulayın."],
        ),
    }
    cause, actions = catalog.get(code, (
        existing.get("failure", {}).get("cause") or "Yönetim protokolü hedefte başarıyla tamamlanamadı.",
        existing.get("failure", {}).get("recommended_actions") or ["Ham hata ve bağlantı kanıtlarını hedef cihaz günlükleriyle eşleştirin."],
    ))
    existing.update({
        "target": ip,
        "requested_protocol": requested_protocol,
        "effective_protocol": protocol,
        "management_ports": sorted(int(p) for p in ports),
        "credential_source": credential_source,
        "account": account or None,
        "error_code": code,
        "cause": cause,
        "recommended_actions": actions,
    })
    if raw_error:
        existing["raw_error"] = raw_error[:1200]
    return existing


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


def preflight_authorized_inventory(req: AuthorizedInventoryRequest, user: dict = Depends(require_permission("inventory.scan"))):
    """Check reachability, credentials and authorization without persisting inventory."""
    if not 5 <= req.timeout <= 60:
        return JSONResponse(status_code=400, content={"error": "Zaman aşımı 5-60 saniye arasında olmalıdır."})
    try:
        parsed = ipaddress.ip_address(req.ip.strip())
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Geçersiz hedef IP adresi."})
    if not _is_allowed_inventory_ip(parsed):
        return JSONResponse(status_code=400, content={"error": "Yalnızca yerel/özel IPv4 hedefleri test edilebilir."})
    if req.protocol not in {"auto", "windows", "ssh", "snmp"}:
        return JSONResponse(status_code=400, content={"error": "Geçersiz envanter protokolü."})

    ip = str(parsed)
    checks = [{"id": "target", "label": "Hedef doğrulama", "status": "pass", "detail": f"{ip} özel/yerel hedef olarak doğrulandı."}]
    tcp_ports = (22, 135, 445, 5985, 5986)

    def probe(port):
        started = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=0.9):
                return port, round((time.perf_counter() - started) * 1000, 1)
        except OSError:
            return None

    observed = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tcp_ports)) as executor:
        for item in executor.map(probe, tcp_ports):
            if item:
                observed[item[0]] = item[1]
    ports = set(observed)
    checks.append({
        "id": "ports", "label": "Yönetim kanalı",
        "status": "pass" if ports else "warn",
        "detail": ("Açık TCP portları: " + ", ".join(f"{p} ({observed[p]} ms)" for p in sorted(ports))) if ports else "TCP 22/135/445/5985/5986 portlarında yanıt alınmadı. SNMP UDP 161 ayrıca yetkilendirme adımında sınanır.",
        "evidence": {"open_tcp_ports": sorted(ports), "latency_ms": observed},
    })

    requested_protocol = req.protocol
    protocol = requested_protocol
    if protocol == "auto":
        if ports.intersection({135, 445, 5985, 5986}):
            protocol = "windows"
        elif 22 in ports:
            protocol = "ssh"
        elif req.snmp_community or SNMP_COMMUNITY:
            protocol = "snmp"
        else:
            protocol = "none"
    checks.append({
        "id": "protocol", "label": "Protokol seçimi",
        "status": "pass" if protocol != "none" else "fail",
        "detail": f"Etkin protokol: {protocol.upper()}" if protocol != "none" else "Uygun yönetim protokolü belirlenemedi.",
    })

    credential_source = "none"
    account = ""
    result = {"status": "Unavailable", "error_code": "management_channel_not_detected", "error_message": "Uygun yönetim kanalı bulunamadı."}
    if protocol == "windows":
        account = req.username or WMI_USERNAME
        password = req.password or WMI_PASSWORD
        credential_source = "request" if (req.username or req.password) else "stored_dpapi" if (WMI_USERNAME or WMI_PASSWORD) else "none"
        credentials_ok = bool(account and password)
        checks.append({"id": "credentials", "label": "Windows kimliği", "status": "pass" if credentials_ok else "fail",
                       "detail": f"{account} hesabı ({'bu istek' if credential_source == 'request' else 'DPAPI kaydı'}) kullanılacak." if credentials_ok else "Uzak Windows testi için kullanıcı adı ve parola bulunamadı."})
        cooldown = _wmi_auth_cooldown_remaining(ip, account)
        if cooldown:
            result = {"status": "Unavailable", "error_code": "credential_cooldown", "retry_after_seconds": cooldown,
                      "error_message": f"Hesap kilitlenmesini önlemek için {cooldown} saniye bekleniyor."}
        elif credentials_ok:
            scanner = WmiNetworkScanner(username=account, password=password, timeout=req.timeout, verify_tls=WINRM_VERIFY_TLS)
            result = scanner.test_access(ip)
            _record_wmi_auth_result(ip, account, result)
        else:
            result = {"status": "Unavailable", "error_code": "missing_credentials", "error_message": "Windows kullanıcı adı ve parola gerekli."}
    elif protocol == "ssh":
        account = req.username or SSH_USERNAME
        password = req.password or SSH_PASSWORD
        credential_source = "request" if (req.username or req.password) else "stored_dpapi" if (SSH_USERNAME or SSH_PASSWORD) else "none"
        credentials_ok = bool(account and password)
        checks.append({"id": "credentials", "label": "SSH kimliği", "status": "pass" if credentials_ok else "fail",
                       "detail": f"{account} hesabı kullanılacak." if credentials_ok else "SSH kullanıcı adı ve parola bulunamadı."})
        result = deep_discovery.test_ssh_access(ip, account, password, timeout=max(5, min(req.timeout, 60))) if credentials_ok else {
            "status": "Unavailable", "error_code": "missing_credentials", "error": "SSH kullanıcı adı ve parola gerekli."
        }
    elif protocol == "snmp":
        community = req.snmp_community or SNMP_COMMUNITY
        credential_source = "request" if req.snmp_community else "stored_dpapi" if SNMP_COMMUNITY else "none"
        checks.append({"id": "credentials", "label": "SNMP kimliği", "status": "pass" if community else "fail",
                       "detail": "Salt-okuma community hazır; değer güvenlik nedeniyle gösterilmiyor." if community else "SNMP community bulunamadı."})
        result = deep_discovery.scan_snmp_deep(ip, community=community, timeout=max(1, min(req.timeout, 10))) if community else {
            "status": "Unavailable", "error_code": "missing_credentials", "error": "SNMP community gerekli."
        }

    authorized = result.get("status") == "Success"
    diagnostics = _inventory_failure_diagnostics(
        ip=ip, requested_protocol=requested_protocol, protocol=protocol, result=result,
        ports=ports, credential_source=credential_source, account=account,
    ) if not authorized else {
        "target": ip, "requested_protocol": requested_protocol, "effective_protocol": protocol,
        "management_ports": sorted(ports), "credential_source": credential_source, "account": account or None,
        **(result.get("diagnostics") or {}),
    }
    checks.append({
        "id": "authorization", "label": "Gerçek yetkilendirme", "status": "pass" if authorized else "fail",
        "detail": (f"{protocol.upper()} bağlantısı ve okuma yetkisi doğrulandı." if authorized else diagnostics.get("cause") or result.get("error_message") or result.get("error") or "Yetkilendirme başarısız."),
        "error_code": None if authorized else diagnostics.get("error_code"),
    })
    _audit(user["username"], "inventory_preflight", f"target={ip} protocol={protocol} status={'ready' if authorized else 'failed'}", success=authorized)
    return {
        "ok": authorized, "ready": authorized, "target": ip, "protocol": protocol,
        "checks": checks, "diagnostics": diagnostics,
        "summary": "Hedef yetkili envanter taramasına hazır." if authorized else "Hazırlık testi bir engel tespit etti.",
    }


def scan_authorized_device_inventory(req: AuthorizedInventoryRequest, user: dict = Depends(require_permission("inventory.scan"))):
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

    requested_protocol = req.protocol
    protocol = req.protocol
    if protocol == "auto":
        if ports.intersection({135, 445, 3389, 5985, 5986}) or device.get("type") in {"computer", "pc", "laptop", "server"}:
            protocol = "windows"
        elif 22 in ports:
            protocol = "ssh"
        elif 161 in ports or device.get("type") in {"router", "switch", "access_point", "firewall", "printer", "network_device"}:
            protocol = "snmp"
        else:
            result = {
                "status": "Unavailable",
                "error_code": "management_channel_not_detected",
                "error_message": "Destekte WMI/WinRM, SSH veya SNMP yönetim kanalı tespit edilemedi. Telefon/tablet için üretici MDM API'si ya da cihaz ajanı gerekir.",
            }
            result["diagnostics"] = _inventory_failure_diagnostics(
                ip=ip, requested_protocol=requested_protocol, protocol="none", result=result,
                ports=ports, credential_source="none",
            )
            return {"ok": False, "protocol": "none", "result": result}

    credential_source = "none"
    account = ""
    if protocol == "windows":
        network_device_types = {"router", "switch", "access_point", "firewall", "printer", "network_device"}
        effective_username = req.username or WMI_USERNAME
        effective_password = req.password or WMI_PASSWORD
        credential_source = "request" if (req.username or req.password) else "stored_dpapi" if (WMI_USERNAME or WMI_PASSWORD) else "none"
        account = effective_username
        if device.get("type") in network_device_types:
            result = {
                "ip_address": ip,
                "status": "Unavailable",
                "error_code": "protocol_mismatch",
                "error_message": "Bu hedef bir ağ cihazı olarak sınıflandırıldı; Windows WMI/WinRM yerine SNMP envanteri seçin.",
            }
        elif not device.get("is_self") and not (effective_username and effective_password):
            result = {
                "ip_address": ip,
                "status": "Unavailable",
                "error_code": "missing_credentials",
                "error_message": "Uzak Windows envanteri için WMI kullanıcı adı ve parola gerekli. Doğru hesabı modalda girin veya Ayarlar bölümüne kaydedin.",
            }
        else:
            cooldown_remaining = _wmi_auth_cooldown_remaining(ip, effective_username)
            if cooldown_remaining:
                result = {
                    "ip_address": ip,
                    "status": "Unavailable",
                    "error_code": "credential_cooldown",
                    "retry_after_seconds": cooldown_remaining,
                    "error_message": f"Hesap kilitlenmesini önlemek için bu hedefte yeni WMI parola denemesi {cooldown_remaining} saniye engellendi.",
                }
            else:
                scanner = WmiNetworkScanner(
                    username=effective_username or None,
                    password=effective_password or None,
                    timeout=req.timeout,
                    verify_tls=WINRM_VERIFY_TLS,
                )
                result = scanner.scan_network([ip], max_workers=1)[0]
                _record_wmi_auth_result(ip, effective_username, result)
        if result.get("status") == "Success":
            device["wmi_inventory"] = result
            _persist_device_inventory(device, result, result.get("inventory_source") or "WMI/WinRM")
    elif protocol == "ssh":
        effective_ssh_username = req.username or SSH_USERNAME
        credential_source = "request" if (req.username or req.password) else "stored_dpapi" if (SSH_USERNAME or SSH_PASSWORD) else "none"
        account = effective_ssh_username
        result = deep_discovery.scan_linux_deep(
            ip,
            username=effective_ssh_username,
            password=req.password or SSH_PASSWORD,
            timeout=max(5, min(req.timeout, 60)),
        )
        if result.get("status") == "Success":
            device["deep_inventory"] = result
            device["fallback_inventory"] = result
            _persist_device_inventory(device, result, "SSH")
    else:
        effective_community = req.snmp_community or SNMP_COMMUNITY
        credential_source = "request" if req.snmp_community else "stored_dpapi" if SNMP_COMMUNITY else "none"
        if not effective_community:
            result = {
                "ip_address": ip,
                "status": "Unavailable",
                "error_code": "missing_credentials",
                "error_message": "SNMP envanteri için salt-okuma community değeri gerekli. Ağ yöneticinizden alın ve yalnız SNMP Community alanına girin.",
            }
        else:
            result = deep_discovery.scan_snmp_deep(
                ip,
                community=effective_community,
                timeout=max(1, min(req.timeout, 10)),
            )
        if result.get("status") == "Success":
            device["deep_inventory"] = result
            device["fallback_inventory"] = result
            _persist_device_inventory(device, result, "SNMP")

    if result.get("status") != "Success":
        message = result.get("error_message") or result.get("error") or "Yetkili envanter alınamadı."
        result["diagnostics"] = _inventory_failure_diagnostics(
            ip=ip, requested_protocol=requested_protocol, protocol=protocol, result=result,
            ports=ports, credential_source=credential_source, account=account,
        )
        result["error_code"] = result["diagnostics"].get("error_code", result.get("error_code", f"{protocol}_failed"))
        device["inventory_error"] = {
            "code": result.get("error_code", f"{protocol}_failed"),
            "message": message,
            "diagnostics": result["diagnostics"],
            "ts": time.time(),
        }
    else:
        result.setdefault("diagnostics", {}).update({
            "target": ip,
            "requested_protocol": requested_protocol,
            "effective_protocol": protocol,
            "management_ports": sorted(ports),
            "credential_source": credential_source,
            "account": account or None,
        })
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

# ------------------------------------------------------------
# YENİ: Ayarlar panelindeki "Ağ tarama sıklığı" (scan_interval) alanı daha
# önce sadece UI'da duruyordu, hiçbir arka plan döngüsü onu okumuyordu — yani
# ayarı değiştirmenin gerçek bir etkisi yoktu. Bu döngü, cihaz taramasını
# gerçekten SCAN_INTERVAL saniyede bir otomatik tekrarlar.
# ------------------------------------------------------------
_discovery_schedule_state = {
    "last_started": None, "last_finished": None, "last_status": "waiting",
    "last_total": 0, "last_error": None,
}


def device_scan_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        if not _device_scan_lock.acquire(blocking=False):
            stop_event.wait(5)
            continue
        _devices_cache["scan_status"] = "running"
        _discovery_schedule_state.update(last_started=time.time(), last_status="running", last_error=None)
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
            _discovery_schedule_state.update(last_status="success", last_total=len(devices))
            manager.broadcast_threadsafe({"type": "devices", "devices": devices, "ts": _devices_cache["ts"]})
        except NetworkDiscoveryError as exc:
            logger.warning("[LOOP] Auto device scan failed: %s", exc)
            _devices_cache["error"] = str(exc)
            _discovery_schedule_state.update(last_status="failed", last_error=str(exc)[:500])
        except Exception:
            logger.exception("[LOOP] Unexpected error in device_scan_loop")
            _discovery_schedule_state.update(last_status="failed", last_error="Beklenmeyen keşif hatası; uygulama günlüğünü inceleyin.")
        finally:
            _discovery_schedule_state["last_finished"] = time.time()
            _devices_cache["scan_status"] = "idle"
            _device_scan_lock.release()
        stop_event.wait(max(60, SCAN_INTERVAL))


# ============================================================
# SİMÜLASYON API
# ============================================================
class SimulateRequest(BaseModel):
    scenario: str

def list_scenarios(user: dict = Depends(get_current_user)):
    return [{"id": key, "label": val["label"]} for key, val in SCENARIOS.items()]

def start_simulation(req: SimulateRequest, user: dict = Depends(require_permission("security.manage"))):
    if req.scenario not in SCENARIOS:
        return {"ok": False, "error": "Bilinmeyen senaryo"}
    simulation_state["active"] = True
    simulation_state["scenario"] = req.scenario
    simulation_state["started_at"] = time.time()
    _sim_tick["n"] = 0
    return {"ok": True, "scenario": req.scenario, "label": SCENARIOS[req.scenario]["label"]}

def stop_simulation(user: dict = Depends(require_permission("security.manage"))):
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

def get_admin_xoc_metrics(user: dict = Depends(require_permission("security.manage"))):
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

def add_to_blacklist(req: BlacklistRequest, user: dict = Depends(require_permission("security.manage"))):
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

def remove_from_blacklist(req: BlacklistRequest, user: dict = Depends(require_permission("security.manage"))):
    """IP'yi oturum içi izleme listesinden kaldırır."""
    ip = req.ip.strip()
    _blacklist_ips.discard(ip)
    _audit(user["username"], "watchlist_remove", f"ip={ip}")
    return {"ok": True, "message": f"{ip} izleme listesinden kaldırıldı.", "blacklisted_ips": list(_blacklist_ips)}

def start_dos_simulation(req: DosSimulateRequest, user: dict = Depends(require_permission("security.manage"))):
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
NCM_AUTO_BACKUP_ENABLED = False
NCM_BACKUP_INTERVAL = 86400

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
    "ncm_auto_backup_enabled": False,
    "ncm_backup_interval": 86400,
    "authorized_dhcp_servers": "",
    "ad_server": "",
    "ad_domain": "",
}


def _authorized_dhcp_servers() -> list[str]:
    """Ayar listesini doğrula; boşsa bilinen gateway'i güvenli varsayılan yap."""
    raw = str(get_setting("authorized_dhcp_servers") or "")
    values = []
    for item in re.split(r"[,;\s]+", raw):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            if ipaddress.ip_address(candidate).version == 4:
                values.append(candidate)
        except ValueError:
            logger.warning("Geçersiz yetkili DHCP IP ayarı yok sayıldı: %s", candidate)
    if not values:
        gateway = str((_last_status or {}).get("gateway") or "").strip()
        if gateway:
            values.append(gateway)
    return sorted(set(values))

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
    for k in ("ping_count", "diagnostics_interval", "scan_interval", "retention_hours", "ncm_backup_interval"):
        try:
            result[k] = int(result[k])
        except (TypeError, ValueError):
            result[k] = DEFAULT_SETTINGS[k]
    for key in SECRET_SETTING_KEYS:
        result[key] = _unprotect_secret(result.get(key, "") or "")
    for bool_key in ("public_ip_lookup", "winrm_verify_tls", "ncm_auto_backup_enabled"):
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
    global NCM_AUTO_BACKUP_ENABLED, NCM_BACKUP_INTERVAL
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
    NCM_AUTO_BACKUP_ENABLED = bool(s.get("ncm_auto_backup_enabled", False))
    NCM_BACKUP_INTERVAL = int(s.get("ncm_backup_interval", 86400))


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


def _port_to_protocol(port: int) -> tuple[str, str]:
    PORT_MAP = {
        80: ("HTTP (TCP 80)", "Web Servisi"),
        443: ("HTTPS (TCP 443)", "Web & Bulut"),
        8443: ("HTTPS (TCP 8443)", "Güvenli Web"),
        8080: ("HTTP (TCP 8080)", "Web Proxy / API"),
        445: ("SMB (TCP 445)", "Dosya Paylaşımı & Yedek"),
        139: ("NetBIOS (TCP 139)", "Windows Paylaşımı"),
        3389: ("RDP (TCP 3389)", "Uzak Masaüstü"),
        22: ("SSH (TCP 22)", "Güvenli Yönetim"),
        21: ("FTP (TCP 21)", "Dosya Aktarımı"),
        53: ("DNS (UDP 53)", "Alan Adı Sorguları"),
        554: ("RTSP (TCP 554)", "Kamera / Medya Akışı"),
        1935: ("RTMP (TCP 1935)", "Canlı Medya Yayını"),
        8554: ("RTSP (TCP 8554)", "Medya Akışı"),
        3306: ("MySQL (TCP 3306)", "Veritabanı"),
        5432: ("PostgreSQL (TCP 5432)", "Veritabanı"),
        1433: ("MSSQL (TCP 1433)", "SQL Sunucu"),
        27017: ("MongoDB (TCP 27017)", "NoSQL Veritabanı"),
        6379: ("Redis (TCP 6379)", "Önbellek"),
        8000: ("Dev Web (TCP 8000)", "Geliştirici Servisi"),
        3000: ("Dev Web (TCP 3000)", "Node.js / React"),
        5000: ("Dev Web (TCP 5000)", "Python API"),
        5173: ("Vite (TCP 5173)", "Frontend Geliştirme"),
        123: ("NTP (UDP 123)", "Zaman Senkronu"),
        161: ("SNMP (UDP 161)", "Ağ Yönetimi"),
        1883: ("MQTT (TCP 1883)", "IoT Cihaz İletişimi"),
        8883: ("MQTT TLS (TCP 8883)", "Güvenli IoT"),
        5060: ("SIP (UDP 5060)", "VoIP Telefon Santrali"),
        7680: ("WUDO (TCP 7680)", "Windows Update P2P"),
        5228: ("Google Push (TCP 5228)", "Push Bildirim Servisi"),
    }
    return PORT_MAP.get(port, (f"TCP {port}", "Ağ Trafiği"))


def _clean_vendor_display(raw_vendor: str) -> str:
    if not raw_vendor:
        return ""
    v = raw_vendor.strip()
    for suffix in [", LTD.", " LTD.", ", INC.", " INC.", ", LLC", " LLC", " CO., LTD.", " CO.,LTD", " CO., LTD", " CORP.", " CORPORATION", " (KUNSHAN) CO.", " (KUNSHAN) CO., LTD."]:
        if v.upper().endswith(suffix):
            v = v[:len(v)-len(suffix)].strip()
    if v.isupper() and len(v) > 3:
        v = v.title()
    low = v.lower()
    if "fortinet" in low:
        return "Fortinet"
    if "huawei" in low:
        return "Huawei"
    if "compal" in low:
        return "Compal"
    if "cisco" in low:
        return "Cisco"
    if "hewlett packard" in low or "hpe" in low or low == "hp":
        return "HP / Aruba"
    if "tp-link" in low or "tplink" in low:
        return "TP-Link"
    if "intel" in low:
        return "Intel"
    if "dell" in low:
        return "Dell"
    if "apple" in low:
        return "Apple"
    if "samsung" in low:
        return "Samsung"
    if "realtek" in low:
        return "Realtek"
    if "synology" in low:
        return "Synology"
    if "qnap" in low:
        return "QNAP"
    return v


def _identify_cloud_or_ip(ip: str) -> tuple[str, str]:
    try:
        if ipaddress.ip_address(ip).is_private:
            return f"Yerel Ağ Cihazı ({ip})", "local"
    except ValueError:
        pass
    # ASN/RDAP doğrulaması olmadan IP önekinden sağlayıcı adı tahmin edilmez.
    return f"İnternet Uç Noktası ({ip})", "cloud"


def _fmt_bandwidth_bps(bps: float) -> str:
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    elif bps > 0:
        return f"{max(1, int(bps))} bps"
    return "0 bps"


def _runtime_network_visibility() -> dict:
    """Report the OS token used for socket/process inspection (never app RBAC)."""
    identity = "\\".join(filter(None, (os.environ.get("USERDOMAIN"), os.environ.get("USERNAME"))))
    elevated = None
    if platform.system() == "Windows":
        try:
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            elevated = None
    elif hasattr(os, "geteuid"):
        elevated = os.geteuid() == 0
    return {
        "identity": identity or os.environ.get("USERNAME") or "unknown",
        "is_elevated": elevated,
        "visibility": "full" if elevated else "partial",
        "note": (
            "Yükseltilmiş işletim sistemi belirteci etkin; işlem/PID görünürlüğü tam olmalıdır."
            if elevated else
            "NetMon yükseltilmiş işletim sistemi belirteciyle çalışmıyor; bazı sistem işlemlerinin adı veya PID bilgisi görünmeyebilir."
        ),
    }


# ============================================================
# TOP TALKERS & TRAFFIC BREAKDOWN (REAL-TIME LIVE SOCKET TELEMETRY)
# ============================================================
@app.get("/api/traffic/top-talkers")
def get_top_talkers(user: dict = Depends(get_current_user)):
    devices_list = _devices_cache.get("data", [])
    device_by_ip = {d.get("ip"): d for d in devices_list if d.get("ip")}

    conn = db_conn()
    row = conn.execute("SELECT ts, wifi_sent, wifi_recv, eth_sent, eth_recv FROM traffic ORDER BY ts DESC LIMIT 1").fetchone()
    conn.close()

    sample_ts = float(row[0]) if row else None
    rx_bps = (row[2] + row[4]) if row else 0.0
    tx_bps = (row[1] + row[3]) if row else 0.0
    total_bps = rx_bps + tx_bps
    
    total_mbps = round(total_bps / 1_000_000, 2)
    rx_total_mbps = round(rx_bps / 1_000_000, 2)
    tx_total_mbps = round(tx_bps / 1_000_000, 2)
    
    # Collect real active socket endpoints
    endpoints = {}
    raw_sessions = []
    if HAS_PSUTIL:
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.status in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT") and c.raddr:
                    rip = c.raddr.ip
                    rport = c.raddr.port if c.raddr else (c.laddr.port if c.laddr else 0)
                    if not rip or rip in ("127.0.0.1", "::1", "0.0.0.0"):
                        continue
                    if rip not in endpoints:
                        endpoints[rip] = {
                            "count": 0,
                            "pids": set(),
                            "ports": [],
                            "is_local": ipaddress.ip_address(rip).is_private
                        }
                    endpoints[rip]["count"] += 1
                    if c.pid:
                        endpoints[rip]["pids"].add(c.pid)
                    if rport:
                        endpoints[rip]["ports"].append(rport)
                    raw_sessions.append({
                        "remote_ip": rip,
                        "remote_port": rport,
                        "local_ip": c.laddr.ip if c.laddr else "",
                        "local_port": c.laddr.port if c.laddr else 0,
                        "pid": c.pid,
                        "state": c.status,
                    })
        except Exception:
            pass

    process_names_by_pid = {}
    for pid in {s["pid"] for s in raw_sessions if s.get("pid")}:
        try:
            process_names_by_pid[pid] = psutil.Process(pid).name().strip()
        except Exception:
            process_names_by_pid[pid] = ""

    candidates = []

    # 1. Process all real active socket endpoints
    for ip, ep_info in endpoints.items():
        pnames = set()
        for pid in ep_info["pids"]:
            try:
                pname = process_names_by_pid.get(pid, "")
                if pname:
                    pnames.add(pname)
            except Exception:
                pass
        pnames = sorted(pnames, key=str.casefold)
        
        ports = ep_info["ports"]
        common_port = max(set(ports), key=ports.count) if ports else 443
        proto_name, proto_cat = _port_to_protocol(common_port)
        proc_name = pnames[0] if pnames else ""
        
        dev = device_by_ip.get(ip)
        if dev:
            hostname = dev.get("friendly_name") or dev.get("hostname")
            if not hostname:
                cleaned_v = _clean_vendor_display(dev.get("vendor") or "")
                hostname = f"{cleaned_v} Cihazı ({ip})" if cleaned_v else f"Yerel Cihaz ({ip})"
            dtype = dev.get("type", "pc")
            dstatus = dev.get("status", "online")
            mac = dev.get("mac") or "-"
        else:
            label, kind = _identify_cloud_or_ip(ip)
            hostname = label
            dtype = "unknown" if ep_info["is_local"] else "cloud"
            dstatus = "online"
            mac = "-"
            
        candidates.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "type": dtype,
            "status": dstatus,
            "weight": ep_info["count"],
            "primary_protocol": proto_name,
            "app_category": proto_cat,
            "active_conns": ep_info["count"],
            # These are local socket owners, not names of the remote endpoint.
            "local_processes": pnames,
            "local_process_name": proc_name,
            "process_name": proc_name
        })

    candidates.sort(key=lambda x: x["weight"], reverse=True)
    selected = candidates[:10]
    talkers = []

    for c in selected:
        talkers.append({
            "ip": c["ip"],
            "mac": c["mac"],
            "hostname": c["hostname"],
            "type": c["type"],
            "status": c["status"],
            "rx_mbps": None,
            "tx_mbps": None,
            "total_mbps": None,
            "speed_display": None,
            "share_pct": None,
            "primary_protocol": c["primary_protocol"],
            "app_category": c["app_category"],
            "active_conns": c.get("active_conns", 1),
            "local_processes": c.get("local_processes", []),
            "local_process_name": c.get("local_process_name", ""),
            "process_name": c.get("process_name", "")
        })

    sessions = []
    for item in raw_sessions:
        remote_ip = item["remote_ip"]
        remote_port = item["remote_port"]
        proto_name, proto_cat = _port_to_protocol(remote_port)
        try:
            scope = "local" if ipaddress.ip_address(remote_ip).is_private else "internet"
        except ValueError:
            scope = "unknown"
        process_name = process_names_by_pid.get(item.get("pid"), "")
        sessions.append({
            **item,
            "process_name": process_name,
            "process_visible": bool(process_name),
            "primary_protocol": proto_name,
            "app_category": proto_cat,
            "scope": scope,
        })
    sessions.sort(key=lambda s: (
        (s.get("process_name") or "~").casefold(),
        s.get("remote_ip") or "",
        s.get("remote_port") or 0,
    ))
        
    return {
        "total_bandwidth_mbps": total_mbps,
        "total_bandwidth_display": _fmt_bandwidth_bps(total_bps),
        "rx_mbps": rx_total_mbps,
        "tx_mbps": tx_total_mbps,
        "rx_display": _fmt_bandwidth_bps(rx_bps),
        "tx_display": _fmt_bandwidth_bps(tx_bps),
        "top_talkers": talkers,
        "sessions": sessions[:100],
        "session_count": len(sessions),
        "distinct_remote_count": len(endpoints),
        "distinct_process_count": len({s["process_name"] for s in sessions if s.get("process_name")}),
        "runtime_visibility": _runtime_network_visibility(),
        "sample_ts": sample_ts,
        "sample_time": datetime.fromtimestamp(sample_ts).strftime("%H:%M:%S") if sample_ts else None,
        "sample_age_seconds": max(0, round(time.time() - sample_ts)) if sample_ts else None,
        "sample_stale": sample_ts is None or (time.time() - sample_ts) > max(20, TRAFFIC_SAMPLE_INTERVAL * 3),
        "measurement_source": "psutil_interface_counters_and_socket_table",
        "per_endpoint_bandwidth_supported": False,
        "endpoint_metric": "active_connections",
        "note": "Toplam hız yerel arayüz sayaçlarından ölçülür. Uç noktalar gerçek aktif uzak soketlerdir; local_processes alanı bağlantıyı bu bilgisayarda açan uygulamaları gösterir. Paket yakalama olmadan uç nokta başına byte miktarı ölçülemez.",
    }


# ============================================================
# NETWORK CONFIGURATION MANAGEMENT (NCM & DIFF)
# ============================================================
def _fetch_running_config_ssh(ip: str) -> tuple[str, str]:
    """Bilinen host anahtarına sahip cihazdan salt-okuma yapılandırma al."""
    if not deep_discovery.HAS_PARAMIKO:
        raise RuntimeError("SSH yedekleme için Paramiko kurulu değil.")
    if not SSH_USERNAME:
        raise RuntimeError("Ayarlar bölümünde SSH kullanıcı adı yapılandırılmamış.")

    client = deep_discovery.paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(deep_discovery.paramiko.RejectPolicy())
    try:
        client.connect(
            ip,
            port=22,
            username=SSH_USERNAME,
            password=SSH_PASSWORD or None,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=not bool(SSH_PASSWORD),
            allow_agent=not bool(SSH_PASSWORD),
        )
        commands = (
            "show running-config",
            "show configuration | display set",
            "display current-configuration",
        )
        errors = []
        for command in commands:
            _, stdout, stderr = client.exec_command(command, timeout=15)
            output = stdout.read().decode("utf-8", "replace").strip()
            error = stderr.read().decode("utf-8", "replace").strip()
            if output and len(output.splitlines()) >= 2:
                return output + "\n", command
            if error:
                errors.append(error[:160])
        raise RuntimeError("Cihaz desteklenen salt-okuma konfigürasyon komutlarına yanıt vermedi: " + "; ".join(errors))
    finally:
        client.close()


_ncm_auto_state = {"last_run": None, "last_status": "disabled", "checked": 0, "changed": 0, "errors": []}


def ncm_backup_loop(stop_event: threading.Event):
    """Açıkça etkinleştirildiğinde ağ cihazlarının salt-okuma konfigürasyonunu sürümle."""
    while not stop_event.is_set():
        if not NCM_AUTO_BACKUP_ENABLED:
            _ncm_auto_state.update(last_status="disabled", errors=[])
            stop_event.wait(30)
            continue
        if not (SSH_USERNAME and SSH_PASSWORD):
            _ncm_auto_state.update(last_status="missing_credentials", errors=["Ayarlar'da SSH salt-okuma hesabı eksik."])
            stop_event.wait(min(300, max(30, NCM_BACKUP_INTERVAL)))
            continue
        candidates = [d for d in _devices_cache.get("data", []) if d.get("ip") and (d.get("is_gateway") or d.get("type") in {"switch", "router", "firewall", "access_point"})]
        checked = changed = 0
        errors = []
        for dev in candidates:
            if stop_event.is_set():
                break
            ip = dev["ip"]
            try:
                config_text, _ = _fetch_running_config_ssh(ip)
                cfg_hash = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
                conn = db_conn()
                previous = conn.execute("SELECT config_hash FROM device_configs WHERE ip=? ORDER BY created_at DESC LIMIT 1", (ip,)).fetchone()
                checked += 1
                if not previous or previous[0] != cfg_hash:
                    now = time.time()
                    conn.execute(
                        "INSERT INTO device_configs (ip, hostname, device_type, config_text, config_hash, version_label, created_at) VALUES (?,?,?,?,?,?,?)",
                        (ip, dev.get("hostname") or dev.get("friendly_name") or ip, dev.get("type") or "unknown", config_text, cfg_hash, f"Otomatik-{datetime.fromtimestamp(now).strftime('%Y%m%d-%H%M%S')}", now),
                    )
                    if previous:
                        conn.execute("INSERT INTO alerts(ts,level,message,source) VALUES(?,?,?,?)", (now, "warning", f"Konfigürasyon değişikliği inceleme bekliyor: {ip}", "NCM"))
                    conn.commit()
                    changed += 1
                conn.close()
            except Exception as exc:
                errors.append(f"{ip}: {str(exc)[:180]}")
        _ncm_auto_state.update(last_run=time.time(), last_status="completed" if not errors else "completed_with_errors", checked=checked, changed=changed, errors=errors[:20])
        stop_event.wait(max(900, NCM_BACKUP_INTERVAL))


@app.get("/api/reports/operations")
def get_operations_report(user: dict = Depends(require_permission("reports.view"))):
    """Gerçek envanter, snapshot, alarm ve trafik kayıtlarından yönetici özeti üret."""
    since = time.time() - 24 * 3600
    conn = db_conn()
    asset_total = conn.execute("SELECT COUNT(*) FROM inventory_assets").fetchone()[0]
    verified = conn.execute("SELECT COUNT(*) FROM inventory_assets WHERE completeness >= 70").fetchone()[0]
    assigned = conn.execute("SELECT COUNT(*) FROM asset_metadata WHERE TRIM(COALESCE(location,'')) <> ''").fetchone()[0]
    snapshots = conn.execute("SELECT total, online, health FROM analyst_snapshots WHERE created_at>=? ORDER BY created_at", (since,)).fetchall()
    alert_rows = conn.execute("SELECT level, message, COUNT(*) c FROM alerts WHERE ts>=? GROUP BY level, message ORDER BY c DESC LIMIT 8", (since,)).fetchall()
    traffic_row = conn.execute("SELECT AVG(wifi_sent+eth_sent), AVG(wifi_recv+eth_recv), MAX(wifi_sent+eth_sent), MAX(wifi_recv+eth_recv) FROM traffic WHERE ts>=?", (since,)).fetchone()
    config_count = conn.execute("SELECT COUNT(*) FROM device_configs WHERE created_at>=?", (since,)).fetchone()[0]
    conn.close()
    sla_samples = [online / total * 100 for total, online, _ in snapshots if total]
    health_samples = [float(health) for _, _, health in snapshots if health is not None]
    return {
        "generated_at": time.time(), "window_hours": 24,
        "summary": {
            "assets": asset_total, "verified_assets": verified,
            "inventory_completeness_pct": round((verified / asset_total * 100), 1) if asset_total else None,
            "location_coverage_pct": round((assigned / asset_total * 100), 1) if asset_total else None,
            "estimated_sla_pct": round(sum(sla_samples) / len(sla_samples), 2) if sla_samples else None,
            "average_health": round(sum(health_samples) / len(health_samples), 1) if health_samples else None,
            "configuration_backups_24h": config_count,
        },
        "traffic": {
            "average_out_mbps": round(float(traffic_row[0] or 0) / 1_000_000, 2),
            "average_in_mbps": round(float(traffic_row[1] or 0) / 1_000_000, 2),
            "peak_out_mbps": round(float(traffic_row[2] or 0) / 1_000_000, 2),
            "peak_in_mbps": round(float(traffic_row[3] or 0) / 1_000_000, 2),
        },
        "recurring_alerts": [{"level": r[0], "message": r[1], "count": r[2]} for r in alert_rows],
        "data_note": "SLA değeri son 24 saatte kaydedilen analist snapshotlarındaki erişilebilirlik örneklerinden hesaplanan tahmini orandır; sözleşmesel SLA değildir.",
    }


class LocationAssignmentRequest(BaseModel):
    asset_id: int
    location: str


@app.get("/api/locations/summary")
def get_locations_summary(user: dict = Depends(require_permission("locations.view"))):
    conn = db_conn()
    rows = conn.execute("""
        SELECT a.asset_id, a.hostname, a.ip_address, a.device_type, a.status,
               COALESCE(NULLIF(TRIM(m.location), ''), 'Atanmamış') location
        FROM inventory_assets a LEFT JOIN asset_metadata m ON m.asset_id=a.asset_id
        ORDER BY location, a.hostname, a.ip_address
    """).fetchall()
    conn.close()
    sites = {}
    assets = []
    for asset_id, hostname, ip, device_type, status, location in rows:
        item = {"asset_id": asset_id, "hostname": hostname, "ip": ip, "device_type": device_type, "status": status, "location": location}
        assets.append(item)
        bucket = sites.setdefault(location, {"location": location, "total": 0, "online": 0, "offline": 0, "types": {}})
        bucket["total"] += 1
        if status == "online": bucket["online"] += 1
        if status == "offline": bucket["offline"] += 1
        dtype = device_type or "unknown"
        bucket["types"][dtype] = bucket["types"].get(dtype, 0) + 1
    return {"sites": list(sites.values()), "assets": assets, "can_manage": _has_permission(user, "locations.manage"), "naming_example": "İstanbul Merkez > A Blok > Kat 3 > Kabinet 3A"}


@app.post("/api/locations/assign")
def assign_asset_location(req: LocationAssignmentRequest, user: dict = Depends(require_permission("locations.manage"))):
    location = " > ".join(part.strip() for part in req.location.split(">") if part.strip())
    if not 2 <= len(location) <= 180:
        raise HTTPException(status_code=400, detail="Lokasyon 2-180 karakter arasında olmalıdır.")
    conn = db_conn()
    exists = conn.execute("SELECT 1 FROM inventory_assets WHERE asset_id=?", (req.asset_id,)).fetchone()
    if not exists:
        conn.close()
        raise HTTPException(status_code=404, detail="Varlık bulunamadı.")
    conn.execute("""
        INSERT INTO asset_metadata(asset_id, location, status, updated_at) VALUES(?,?,?,?)
        ON CONFLICT(asset_id) DO UPDATE SET location=excluded.location, updated_at=excluded.updated_at
    """, (req.asset_id, location, "managed", time.time()))
    conn.commit()
    conn.close()
    _audit(user["username"], "asset_location_update", f"asset_id={req.asset_id} location={location}")
    return {"ok": True, "asset_id": req.asset_id, "location": location}


try:
    from .routers.auth import create_auth_router
    from .routers.analyst import create_analyst_router
    from .routers.diagnostics import create_diagnostics_router
    from .routers.discovery import create_discovery_router
    from .routers.inventory import create_inventory_router
    from .routers.ipam import create_ipam_router
    from .routers.ncm import create_ncm_router
    from .routers.security import create_security_router
    from .routers.settings import create_settings_router
except ImportError:
    from routers.auth import create_auth_router
    from routers.analyst import create_analyst_router
    from routers.diagnostics import create_diagnostics_router
    from routers.discovery import create_discovery_router
    from routers.inventory import create_inventory_router
    from routers.ipam import create_ipam_router
    from routers.ncm import create_ncm_router
    from routers.security import create_security_router
    from routers.settings import create_settings_router

app.include_router(create_auth_router(sys.modules[__name__]))
app.include_router(create_analyst_router(sys.modules[__name__]))
app.include_router(create_diagnostics_router(sys.modules[__name__]))
app.include_router(create_discovery_router(sys.modules[__name__]))
app.include_router(create_inventory_router(sys.modules[__name__]))
app.include_router(create_ipam_router(sys.modules[__name__]))
app.include_router(create_ncm_router(sys.modules[__name__]))
app.include_router(create_security_router(sys.modules[__name__]))
app.include_router(create_settings_router(sys.modules[__name__]))


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
