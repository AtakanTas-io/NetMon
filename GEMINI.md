# Netmon — Proje Hafıza Dosyası

Bu dosya Antigravity tarafından her konuşmada otomatik yüklenir.
Netmon projesiyle ilgili temel bilgileri içerir; tekrar dosya okumaya gerek kalmaz.

---

## Proje Genel Yapısı

```
Netmon/
├── backend/
│   ├── server.py          # FastAPI ana sunucu (~4000+ satır)
│   ├── netdiag_core.py    # Ağ teşhis motoru (ping, traceroute, nmap, ARP)
│   ├── deep_discovery.py  # SNMP, mDNS, SSDP derin keşif
│   ├── wmi_scanner.py     # WMI/WinRM üzerinden Windows envanter taraması
│   ├── netmon.db          # SQLite WAL modlu veritabanı (prod)
│   └── desktop_app.py     # pywebview masaüstü sarmalayıcı
├── frontend/
│   ├── index.html         # Tek sayfalık uygulama
│   └── app.js             # Tüm frontend (~260 KB, vanilla JS)
├── tests/                 # 80 pytest testi (9 dosya)
├── pytest.ini             # testpaths=tests, --tb=short, filterwarnings
└── requirements.txt       # fastapi, uvicorn, psutil, pywebview, paramiko, pysnmp, ldap3
```

---

## Teknoloji Yığını

| Katman | Teknoloji |
|---|---|
| API | FastAPI + Uvicorn |
| DB | SQLite (WAL modu, `PRAGMA synchronous=NORMAL`) |
| Auth | PBKDF2-HMAC-SHA256 (200k iter), Bearer token |
| Gizli ayarlar | Windows DPAPI (`win32crypt`) → `dpapi:` prefix |
| Frontend | Vanilla JS, Chart.js (UMD) |
| Paketleme | PyInstaller (--onefile, --noconsole) |
| Testler | pytest + FastAPI TestClient (httpx) |

---

## Kritik Server.py Sabitleri ve Varsayılanlar

```python
# DEFAULT_SETTINGS (tek yetkili kaynak)
scan_interval       = 300      # saniye — cihaz tarama periyodu
diagnostics_interval= 15       # saniye — ping/DNS kontrol periyodu
retention_hours     = 48       # saat  — trafik/snapshot saklama süresi
ping_count          = 4        # ICMP paket sayısı
ping_target         = "8.8.8.8"
dns_domain          = "google.com"

# Anomaly detection (trafik)
ANOMALY_WINDOW_SECONDS   = 3600  # 1 saatlik pencere
ANOMALY_MIN_SAMPLES      = 30
ANOMALY_MIN_BASELINE_BPS = 50_000
ANOMALY_RATIO            = 3.0
ANOMALY_COOLDOWN_SECONDS = 300

# Auth
SESSION_TTL_SECONDS  = 12 * 3600  # 12 saat (normal)
SESSION_TTL_REMEMBER = 30 * 24 * 3600  # 30 gün (beni hatırla)
LOGIN_MAX_ATTEMPTS   = 5
LOGIN_LOCKOUT_SECONDS= 300  # 5 dakika kilit
```

---

## Veritabanı Şeması (Tablo Özeti)

| Tablo | Açıklama |
|---|---|
| `users` | id, username, password_hash, salt, role, active, must_change_password |
| `sessions` | token (PK), user_id, created_at, expires_at |
| `login_attempts` | username (PK), fail_count, last_attempt, locked_until |
| `audit_log` | id, ts, username, action, detail, success |
| `settings` | key (PK), value |
| `traffic` | ts (PK), wifi_sent, wifi_recv, eth_sent, eth_recv |
| `snapshots` | ts (PK), data (JSON) |
| `alerts` | ts (PK), level, message |
| `known_devices` | mac (PK), friendly_name, hostname, device_type, ... |
| `device_inventory` | ip (PK), mac, status, source, payload, last_scanned |
| `inventory_assets` | asset_id, identity_key (UNIQUE), hostname, ip_address, ... |
| `inventory_hardware` | asset_id (PK/FK) |
| `inventory_interfaces` | id, asset_id (FK) |
| `inventory_software` | id, asset_id (FK) |
| `inventory_scan_runs` | id, started_at, finished_at, mode, ... |
| `inventory_history` | id, asset_id (FK), event_type, field_name, old/new_value |
| `analyst_snapshots` | id, created_at, total, online, offline, health, completeness |
| `asset_metadata` | asset_id (PK/FK), asset_tag, owner, department, location, ... |
| `speedtests` | ts (PK), download, upload, ping, server |
| `syslog_messages` | id (PK), ts, source_ip, severity, message (UDP 5140) |
| `device_configs` | ip (PK), ts, config_text (NCM Backups) |
| `ssl_certificates` | ip (PK), hostname, issuer, valid_from, valid_to, days_left, last_checked |

---

## Güvenlik Mimarisi

- **İlk kurulum:** `secrets.token_urlsafe(16)` ile rastgele parola → `~/.netmon/initial_admin_password.txt`
- **must_change_password=1:** İlk girişte parola değiştirme zorunlu (428 döner)
- **DPAPI:** `wmi_password`, `ssh_password`, `snmp_community` → `dpapi:` prefix ile şifreli
- **Brute-force:** Kullanıcı adı bazlı; 5 başarısız → 5 dk kilit (IP bazlı değil — bilinen eksiklik)
- **Gizli ayarlar API'ye asla dönmez:** `SECRET_SETTING_KEYS` maskeleme
- **Security headers:** X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer
- **Son admin koruması:** Tek admin demote/deaktif/sil edilemiyor
- **Session revoke:** Şifre sıfırlama veya deaktivasyon → anında tüm oturumlar iptal
- **Active Directory/LDAP:** Eğer Ayarlar menüsünden `ad_server` ve `ad_domain` yapılandırılmışsa, `api_login` sırasında önce AD'ye bind denemesi yapılır. Başarılı olursa lokal DB'de otomatik `user` hesabına çevrilir/oluşturulur. (Lokal auth çalışmaya devam eder).

---

## API Endpoint Kategorileri

| Prefix | Yetki | Açıklama |
|---|---|---|
| `/api/auth/*` | public/token | Login, logout, me, change-password |
| `/api/status`, `/api/traffic`, `/api/alerts` | user+ | Temel izleme verileri |
| `/api/tools/*` | user+ (bazıları admin) | Ping, traceroute, portscan, speedtest |
| `/api/devices/*` | user+/admin | Cihaz listesi, tarama, envanter |
| `/api/inventory/*` | user+ | Varlık envanteri CRUD |
| `/api/analyst/*` | user+ | Analiz, anomali, trend, rapor |
| `/api/admin/*` | admin | Kullanıcı yönetimi, audit log |
| `/api/settings` | user(GET)/admin(POST) | Ayar okuma/yazma (Webhook URL, AD, DHCP) |
| `/api/ipam` | user+ | Subnet IP havuzu (IPAM) haritalaması (Boş/Dolu IP'ler) |
| `/api/syslog` | user+ | Syslog sunucusuna gelen logları döndürür |
| `/api/ncm/backup` | admin | Ağ cihazından konfigürasyon yedeği alır |
| `/api/ssl-certs` | user+ | Altyapı cihazlarının SSL/TLS sertifika geçerlilik sürelerini döndürür |
| `/ws` | token | WebSocket: trafik, status, system olayları (NetFlow Top Talkers içerir) |

---

## Test Altyapısı

```
# Çalıştırma komutu
python -m pytest tests/ -v --basetemp="C:/Temp/pytest_netmon"

# Her test dosyasındaki isolated_server fixture:
# - tmp_path altında ayrı DB + şifre dosyası
# - server.DB_PATH ve INITIAL_PASSWORD_PATH monkeypatch ile değiştirilir
# - _devices_cache ve _local_wmi_cache sıfırlanır

# _bootstrap_admin(client, password_path):
# 1. password_path'ten rastgele ilk parolayı okur (satır index [1])
# 2. Login → must_change_password=True doğrular
# 3. "New-Company-Pass-2026!" ile değiştirir
# 4. Parola dosyasının silindiğini doğrular
```

---

## Bilinen Açıklar / Gelecek İyileştirmeler

1. **IP bazlı brute-force koruması yok** — farklı username'lerle dağıtık saldırı mümkün
2. **`remember=True` (30 gün TTL) için test yok**
3. **`httpx2` geçişi yapılmadı** — `StarletteDeprecationWarning` hâlâ görünüyor (1 uyarı)
4. **Subnet filtresi /16'dan daha geniş kabul etmiyor** — çok büyük kurumsal ağlarda sorun

---

## Önemli Kod Notları

- `_hidden_subprocess_kwargs()`: Windows'ta CMD penceresi açılmasını önler (CREATE_NO_WINDOW)
- `_is_allowed_inventory_ip()`: Port taraması ve envanter yalnızca RFC-1918 + loopback
- `enrich_devices()`: MAC ile known_devices'a yazar; manuel tip/isim otomatik taramayla ezilmez
- `merge_scan_into_cache()`: Görünmeyen cihaz silinmez, `missed_scans` ile stale/offline işaretlenir
- `_traffic_window`: `deque` (O(1) popleft) — önceden `list.pop(0)` O(n) idi (düzeltildi)
- WAL + `timeout=5.0`: Çoklu thread yazması güvenli
- `INITIAL_PASSWORD_PATH`: `~/.netmon/initial_admin_password.txt` (frozen) veya test tmp_path'i
- `start_ssl_monitor()`: `cryptography` modülü bağımlılığını önlemek için Windows PowerShell `X509Certificate2` parser kullanır.
- `start_dhcp_monitor()`: `SO_REUSEADDR` kullanarak UDP 68 portuna bind olur ve BOOTP Reply paketlerini izleyerek yetkisiz DHCP sunucularını loglar.
- `_update_switch_mac_tables()`: `pysnmp` kullanarak ağ cihazlarındaki `BRIDGE-MIB::dot1dTpFdbPort` tablosunu okuyup `_mac_to_switch_port` önbelleğinde saklar. Cihaz detayında Fiziksel Konum olarak yansır.
