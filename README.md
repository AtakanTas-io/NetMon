<div align="center">
  <h1>🌐 NetMon</h1>
  <h3>Kurumsal Siber Topoloji, Güvenlik & Ağ Varlık İzleme Sistemi</h3>

  <p align="center">
    <strong>Yerel ağınızdaki cihazları ajansız keşfedin, gerçek fiziksel switch topolojisini çıkarın, siber tehditleri tespit edin ve derin donanım/yazılım envanteri yönetin.</strong>
  </p>

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/PyWebView-5.0+-8A2BE2?style=for-the-badge&logo=python&logoColor=white" alt="PyWebView">
    <img src="https://img.shields.io/badge/Tests-80%20Passed%20(100%25)-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" alt="Tests">
    <img src="https://img.shields.io/badge/License-MIT-4CAF50?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-555555?style=for-the-badge&logo=windows&logoColor=white" alt="Platform">
  </p>
</div>

<hr/>

**NetMon**, yerel ağınızdaki tüm aktif donanımları ajansız (agentless) keşfeden, SNMP Bridge MIB ile switch portlarına kadar gerçek fiziksel topolojiyi çıkaran, Rogue DHCP ve port değişimlerini gerçek zamanlı izleyen modern bir NMS (Network Management System) ve Siber Güvenlik platformudur.

---

## 🛡️ 5 Temel Siber Güvenlik Modülü (2026)

NetMon, standart ağ izleyicilerinden farklı olarak entegre siber savunma yetenekleriyle donatılmıştır:

1. 🚨 **Rogue DHCP Tesbiti:** Ağda izinsiz veya sahte IP dağıtan cihazları UDP 68 (BOOTREPLY) seviyesinde anlık yakalar ve ağ yöneticisine acil güvenlik alarmı üretir.
2. 🔍 **Port Değişim Alarmı (Port Anomaly):** Cihazlarda daha önce kapalı olan hassas servis portları (örn. `TCP 445 SMB`, `TCP 3389 RDP`, `TCP 22 SSH`) sonradan açılırsa anında anomali kaydı oluşturur.
3. 🔌 **Fiziksel Switch Eşleşmesi:** Ağ anahtarlarındaki `BRIDGE-MIB::dot1dTpFdbPort` tablolarını SNMP üzerinden okuyarak her istemcinin fiziksel olarak hangi Switch IP'sine ve Port numarasına takılı olduğunu haritalar.
4. 🗺️ **Gerçek Fiziksel Topoloji:** Cihazları soyut bir bulut yerine doğrudan bağlı oldukları Switch ve Router portlarına bağlayan gerçekçi hiyerarşik siber ağ şeması sunar.
5. ⚠️ **Eski / Riskli OS Analizi:** Windows XP, Windows 7, Windows 8 veya Server 2008 gibi desteği bitmiş (EOL) ve güvenlik açığı barındıran işletim sistemlerini otomatik tespit eder ve arayüzde `Riskli OS` olarak işaretler.

---

## 🌟 Diğer Öne Çıkan Özellikler

* 🤖 **Akıllı Otomatik Profilleme (Fingerprinting):** OUI MAC satıcı veritabanı, mDNS (Bonjour), SSDP (UPnP) ve TTL verileriyle cihaz modellerini (iOS, Android, Akıllı TV, IoT) otomatik sınıflandırma.
* 🔑 **WMI / WinRM / SSH Derin Envanter Taraması:** Yetkili erişimle CPU modeli, RAM, GPU, anakart, disk kullanımı, yüklü yazılımlar ve aktif servisleri çekme.
* 🔒 **Active Directory & Kurumsal Güvenlik:** LDAP/AD entegrasyonu, Windows DPAPI şifreli gizli anahtar saklama, PBKDF2-HMAC-SHA256 kullanıcı güvenliği ve IPAM (IP Adres Yönetimi).
* 📊 **Gerçek Zamanlı Trafik & Telemetri:** WebSocket tabanlı canlı bant genişliği (Mbps), radyal sayaçlar ve anomali uyarıları.
* ⚡ **Masaüstü & Web Seçenekleri:** PyWebView ile yerel masaüstü uygulaması veya web tarayıcı üzerinden yönetim.

---

## 🏗️ Proje Mimarisi

```text
Netmon/
├── backend/                 # Python FastAPI Backend & Ağ Teşhis Motorları
│   ├── server.py            # FastAPI REST & WebSocket Ana Sunucusu
│   ├── netdiag_core.py      # Ping, traceroute, ARP ve Nmap motoru
│   ├── deep_discovery.py    # mDNS, SSDP, SNMP derin keşif
│   ├── dhcp_monitor.py      # Rogue DHCP dinleyici servisi
│   ├── snmp_switch_mapper.py# Switch MAC/Port MIB çözümleyici
│   ├── wmi_scanner.py       # Windows WMI/WinRM envanter tarayıcı
│   ├── desktop_app.py       # PyWebView masaüstü kabuğu
│   └── netmon.db            # SQLite WAL modlu yerel veritabanı
├── frontend/                # Vanilla JS / HTML5 Modern Siber Panel
│   ├── index.html           # SPA Tek Sayfalık Arayüz
│   └── app.js               # Canlı Topoloji, WebSocket ve UI Mantığı
├── tests/                   # 80+ Otomatik Pytest Testleri (Güvenlik, Envanter)
├── .github/workflows/       # GitHub Actions CI/CD Pipeline (Python 3.10-3.13)
└── docs/                    # Mimari ve Teknik Dokümantasyon
```

---

## 🚀 Hızlı Başlangıç

### Sistem Gereksinimleri
* **İşletim Sistemi:** Windows 10/11, Windows Server (veya Linux / macOS - Web Modu)
* **Python:** 3.10, 3.11, 3.12 veya 3.13

### Tek Tıkla Kurulum & Başlatma (Windows)
```cmd
calistir.bat
```

### Manuel Kurulum (Terminal)
```bash
# 1. Sanal ortamı oluşturun ve aktif edin
python -m venv .venv
.venv\Scripts\activate   # Linux/macOS için: source .venv/bin/activate

# 2. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 3. Masaüstü uygulamasını başlatın
python backend/desktop_app.py
```

> [!IMPORTANT]
> **İlk Giriş & Güvenlik:** Kurulum sırasında sabit bir parola atanmaz. Rastgele üretilen güvenli yönetici parolası `%USERPROFILE%\.netmon\initial_admin_password.txt` dosyasına yazılır. Kullanıcı adı `admin`'dir. İlk girişte parola değişimi zorunludur.

---

## 🧪 Test ve Kalite Güvence (QA)

Tüm modüller, güvenlik duvarı kuralları, oturum güvenliği ve envanter motorları pytest entegrasyon testleri ile denetlenmektedir:

```bash
python -m pytest tests/ -v --basetemp="C:/Temp/pytest_netmon"
```

* **80 Test %100 Başarı:** Brute-force kilitleri, yetkisiz token engelleme, son yönetici koruması, DPAPI gizli anahtar maskeleme, switch topoloji doğrulaması.

---

## 📄 Lisans & Katkı

Bu proje [MIT Lisansı](LICENSE) altında geliştirilmektedir. Katkıda bulunmak için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını inceleyebilirsiniz.

